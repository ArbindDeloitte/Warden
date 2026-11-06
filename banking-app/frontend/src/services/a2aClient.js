// A2A 1.0 client for calling other agents THROUGH the Warden gateway (JSON-RPC binding).
// Pure fetch — no browser/Okta imports — so it can be exercised from Node as well.

export class A2AError extends Error {
  constructor(message, { status = null, code = null } = {}) {
    super(message);
    this.name = 'A2AError';
    this.status = status;
    this.code = code;
  }
}

const newId = () => (globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`);

/**
 * Sends one A2A SendMessage via Warden and normalises the result.
 * Returns { state, taskId, text, data[], endpoint }. Throws A2AError on denial/failure.
 */
export async function sendA2AMessage({ baseUrl, vsId, targetId, agentToken, apiKey, userToken, question, skillId, contextId }) {
  const endpoint = `${baseUrl.replace(/\/$/, '')}/a2a/${vsId}/${targetId}`;
  const params = {
    message: { messageId: newId(), contextId: contextId || newId(), role: 'ROLE_USER', parts: [{ text: question }] },
    ...(skillId ? { metadata: { skillId } } : {}),
  };

  let res;
  try {
    res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'A2A-Version': '1.0',
        'X-Agent-Token': agentToken,
        ...(apiKey ? { 'X-API-Key': apiKey } : {}),
        ...(userToken ? { 'X-User-Token': `Bearer ${userToken}` } : {}),
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: newId(), method: 'SendMessage', params }),
    });
  } catch (e) {
    throw new A2AError(`Could not reach the Warden gateway (${e.message})`);
  }

  let body;
  try { body = await res.json(); } catch { throw new A2AError(`Gateway returned a non-JSON response (HTTP ${res.status})`, { status: res.status }); }

  if (body.error) {
    const reason = typeof body.error.data === 'object' && body.error.data?.reason ? ` (${body.error.data.reason})` : '';
    throw new A2AError(`${body.error.message}${reason}`, { status: res.status, code: body.error.code });
  }

  const task = body.result?.task || body.result?.message || {};
  const state = task.status?.state || 'TASK_STATE_COMPLETED';
  if (['TASK_STATE_FAILED', 'TASK_STATE_REJECTED', 'TASK_STATE_CANCELED'].includes(state)) {
    const why = (task.status?.message?.parts || []).map(p => p.text).filter(Boolean).join(' ');
    throw new A2AError(why || `The remote agent ended the task as ${state}`, { status: res.status });
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
