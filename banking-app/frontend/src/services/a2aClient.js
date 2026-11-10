// A2A 1.0 client for calling other agents THROUGH the Warden gateway (JSON-RPC binding).
// The browser never talks to Warden's A2A endpoint directly: it posts to the banking backend's relay,
// which authenticates the user's Okta token and adds the Warden credentials server-side (from the
// Warden Credential Vault). Pure fetch — no browser/Okta imports — so it can be exercised from Node too.
//
// When an approval policy holds the call, sendA2AMessage throws A2AApprovalPendingError; the chat then polls
// the ticket (interpretApprovalStatus) and shows the answer once an admin approves, like MCP approvals.

export class A2AError extends Error {
  constructor(message, { status = null, code = null } = {}) {
    super(message);
    this.name = 'A2AError';
    this.status = status;
    this.code = code;
  }
}

/**
 * Warden is holding the call until an admin approves it (an A2A approval policy). The call has NOT run yet:
 * poll /api/approvals/<ticketId>/status and feed the payload to interpretApprovalStatus().
 */
export class A2AApprovalPendingError extends A2AError {
  constructor({ ticketId, pollUrl, expiresAt, timeoutAction, reason, status }) {
    super(`Approval required${reason ? ` (${reason})` : ''}`, { status, code: -32011 });
    this.name = 'A2AApprovalPendingError';
    this.ticketId = ticketId;
    this.pollUrl = pollUrl;
    this.expiresAt = expiresAt;
    this.timeoutAction = timeoutAction;
    this.reason = reason;
  }
}

const FAILED_STATES = ['TASK_STATE_FAILED', 'TASK_STATE_REJECTED', 'TASK_STATE_CANCELED', 'failed', 'rejected', 'canceled'];

/**
 * Turns an A2A JSON-RPC `result` into { state, taskId, text, data[], endpoint }. Works for a direct reply and for
 * the result stored on an approval ticket. 1.0 wraps the reply ({task} / {message}); 0.3 returns a bare Task.
 * Throws A2AError if the remote agent ended the task as failed/rejected/canceled.
 */
export function normaliseA2AResult(result, endpoint = null, httpStatus = null) {
  const task = result?.task || result?.message || result || {};
  const state = task.status?.state || 'TASK_STATE_COMPLETED';
  if (FAILED_STATES.includes(state)) {
    const why = (task.status?.message?.parts || []).map(p => p.text).filter(Boolean).join(' ');
    throw new A2AError(why || `The remote agent ended the task as ${state}`, { status: httpStatus });
  }

  const texts = [], data = [];
  for (const art of task.artifacts || []) {
    for (const part of art.parts || []) {
      if (part.text !== undefined) texts.push(part.text);
      if (part.data !== undefined) data.push(part.data);
    }
  }
  for (const part of task.parts || []) if (part.text !== undefined) texts.push(part.text);

  return { state, taskId: task.id || null, text: texts.join('\n'), data, endpoint };
}

/**
 * Reads the payload of GET /api/approvals/<id>/status for an A2A ticket and says what the chat should do:
 *   { state: 'pending' }                     keep polling (waiting for an admin, or approved and being forwarded)
 *   { state: 'done', result }                approved and answered; result is normaliseA2AResult's shape
 *   { state: 'denied', message }             an admin said no
 *   { state: 'expired', autoAction }         nobody decided in time
 *   { state: 'failed', message }             approved, but the call could not be completed (for example a policy
 *                                            changed in the meantime, the agent went away, or it returned an error)
 */
export function interpretApprovalStatus(s) {
  if (!s || typeof s !== 'object') return { state: 'pending' };
  if (s.status === 'executed' && s.result) {
    try { return { state: 'done', result: normaliseA2AResult(s.result) }; }
    catch (e) { return { state: 'failed', message: e.message }; }
  }
  if (s.status === 'denied') return { state: 'denied', message: s.error || 'Request denied by an admin' };
  if (s.status === 'expired') return { state: 'expired', autoAction: s.timeout_action === 'approve' ? 'approved' : 'denied' };
  if (s.error) return { state: 'failed', message: s.error };
  return { state: 'pending' };
}

const newId = () => (globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`);

/**
 * Sends one A2A SendMessage via the backend relay (which forwards it to Warden) and normalises the result.
 * Returns { state, taskId, text, data[], endpoint }. Throws A2AError on denial/failure.
 * `authToken` is the user's Okta access token; it is the only credential the browser supplies.
 */
export async function sendA2AMessage({ relayUrl, authToken, question, skillId, contextId }) {
  let res;
  try {
    res = await fetch(relayUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
      },
      body: JSON.stringify({ question, ...(skillId ? { skillId } : {}), contextId: contextId || newId() }),
    });
  } catch (e) {
    throw new A2AError(`Could not reach the banking backend (${e.message})`);
  }
  const endpoint = relayUrl;

  let body;
  try { body = await res.json(); } catch { throw new A2AError(`Gateway returned a non-JSON response (HTTP ${res.status})`, { status: res.status }); }

  if (body.error) {
    // The relay's own errors are plain strings; Warden's are JSON-RPC error objects.
    if (typeof body.error === 'string') {
      throw new A2AError(`${body.error}${body.detail ? ` (${body.detail})` : ''}`, { status: res.status });
    }
    const d = typeof body.error.data === 'object' && body.error.data ? body.error.data : {};
    if (body.error.code === -32011 && d.ticket_id) {
      throw new A2AApprovalPendingError({
        ticketId: d.ticket_id, pollUrl: d.poll_url, expiresAt: d.expires_at, timeoutAction: d.timeout_action, reason: d.reason, status: res.status,
      });
    }
    const reason = d.reason ? ` (${d.reason})` : '';
    throw new A2AError(`${body.error.message}${reason}`, { status: res.status, code: body.error.code });
  }

  return normaliseA2AResult(body.result, endpoint, res.status);
}
