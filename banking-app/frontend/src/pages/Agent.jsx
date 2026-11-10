import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useOktaAuth } from '@okta/okta-react';
import { banking } from '../services/api.js';
import { mcpBanking, scanMessage, ApprovalPendingError, pollApprovalStatus, askCreditCardAgent, isA2AConfigured, A2AError, A2AApprovalPendingError, interpretA2aApproval, A2A_AGENT_NAME } from '../services/mcpProxy.js';

// ── format helpers ────────────────────────────────────────────────────────────
function fmtCurrency(amount, currency = 'USD') {
  return new Intl.NumberFormat('en-US', { style: 'currency', currency: currency || 'USD' }).format(Number(amount) || 0);
}
function fmtDate(str) {
  if (!str) return '';
  return new Date(str).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}
function fmtTime(date) {
  return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
}

// ── intent detection ──────────────────────────────────────────────────────────
function detectIntent(text) {
  const t = text.toLowerCase().trim();
  // Credit card questions are handled by a separate agent over A2A (via Warden)
  const cardCtx = /\b(cards?|visa|mastercard)\b/.test(t);
  if (cardCtx && /\b(freeze|lock|block|suspend)\b/.test(t)) return 'card_freeze';
  if (cardCtx && /\b(transaction[s]?|purchase[s]?|spend|spent|recent|history|statement)\b/.test(t)) return 'card_transactions';
  if (cardCtx || /\b(rewards?|credit limit)\b/.test(t)) return 'card_details';
  if (/\b(new payment|send money|pay (someone|a person)|make (a )?payment|create (a )?payment|wire)\b/.test(t)) return 'new_payment';
  if (/\b(approve|confirm)\b.*\b(payment|transfer)\b|\b(payment|transfer).*\b(approve|confirm)\b/.test(t)) return 'approve_payments';
  if (/\b(account[s]?|my (bank|wallet|money)|overview|portfolio|show all)\b/.test(t)) return 'list_accounts';
  if (/\b(balance[s]?|how much|funds available|available funds)\b/.test(t)) return 'balance';
  if (/\b(transaction[s]?|history|recent|spent|purchases|statement|activity)\b/.test(t)) return 'transactions';
  if (/\b(standing.?order[s]?|recurring|subscription[s]?|regular payment[s]?|auto.?pay)\b/.test(t)) return 'standing_orders';
  if (/\b(transfer[s]?|international|abroad|overseas|external)\b/.test(t)) return 'transfers';
  if (/\b(payment[s]?|paid|sent|outgoing|invoices?)\b/.test(t)) return 'list_payments';
  if (/\b(help|what can you|commands?|menu|options?|what do you)\b/.test(t)) return 'help';
  if (/\b(hi|hello|hey|good (morning|afternoon|evening)|howdy)\b/.test(t)) return 'greet';
  return 'unknown';
}

// ── rich message content renderers ────────────────────────────────────────────
function AccountCards({ accounts, onSelect, selectable }) {
  if (!accounts?.length) return <p style={s.empty}>No accounts found.</p>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 10 }}>
      {accounts.map((acct, i) => {
        const id = acct.id || acct.accountId;
        const name = acct.name || acct.accountName || acct.nickname || 'Account';
        const type = acct.accountType || acct.type || '';
        const balance = acct.balance?.amount ?? acct.currentBalance ?? acct.balance ?? 0;
        const currency = acct.balance?.currency || acct.currency || 'USD';
        const acctNum = acct.accountNumber || acct.identification || '';
        return (
          <div
            key={id}
            onClick={() => selectable && onSelect?.(acct, i + 1)}
            style={{ ...s.dataCard, cursor: selectable ? 'pointer' : 'default' }}
            onMouseEnter={e => { if (selectable) e.currentTarget.style.background = 'rgba(255,255,255,0.22)'; }}
            onMouseLeave={e => { if (selectable) e.currentTarget.style.background = s.dataCard.background; }}
          >
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontWeight: 600, fontSize: 13 }}>
                {selectable && <span style={s.numBadge}>{i + 1}</span>} {name}
              </div>
              <div style={{ fontSize: 11, opacity: 0.65, marginTop: 2 }}>
                {type}{acctNum ? ` · ****${acctNum.slice(-4)}` : ''}
              </div>
            </div>
            <div style={{ fontWeight: 700, fontSize: 15 }}>{fmtCurrency(balance, currency)}</div>
          </div>
        );
      })}
    </div>
  );
}

function TxnTable({ transactions, currency }) {
  if (!transactions?.length) return <p style={s.empty}>No transactions found.</p>;
  return (
    <div style={{ marginTop: 10, overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
        <thead>
          <tr>
            {['Date', 'Description', 'Amount'].map(h => (
              <th key={h} style={{ ...s.th, textAlign: h === 'Amount' ? 'right' : 'left' }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {transactions.slice(0, 15).map((tx, i) => {
            const amt = tx.amount?.amount ?? tx.amount ?? 0;
            const cur = tx.amount?.currency || tx.currency || currency || 'USD';
            const isCredit = (tx.creditDebitIndicator || tx.type || '').toLowerCase() === 'credit';
            const desc = tx.transactionInformation || tx.description || tx.narrative || '—';
            return (
              <tr key={tx.transactionId || tx.id || i} style={{ borderBottom: '1px solid rgba(255,255,255,0.07)' }}>
                <td style={{ ...s.td, whiteSpace: 'nowrap' }}>{fmtDate(tx.valueDateTime || tx.bookingDateTime || tx.date)}</td>
                <td style={{ ...s.td, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{desc}</td>
                <td style={{ ...s.td, textAlign: 'right', fontWeight: 600, color: isCredit ? '#86efac' : '#fca5a5', whiteSpace: 'nowrap' }}>
                  {isCredit ? '+' : '-'}{fmtCurrency(Math.abs(parseFloat(amt)), cur)}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {transactions.length > 15 && (
        <p style={{ fontSize: 11, opacity: 0.6, marginTop: 6, textAlign: 'center' }}>
          Showing 15 of {transactions.length} transactions
        </p>
      )}
    </div>
  );
}

function PaymentList({ payments, onApprove }) {
  if (!payments?.length) return <p style={s.empty}>No payments found.</p>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 10 }}>
      {payments.map((pmt, i) => {
        const id = pmt.paymentId || pmt.id;
        const to = pmt.to_name || pmt.creditorAccount?.name || pmt.toName || pmt.recipientName || 'Unknown';
        const amt = pmt.instructedAmount?.amount || pmt.amount?.amount || pmt.amount || 0;
        const cur = pmt.instructedAmount?.currency || pmt.amount?.currency || pmt.currency || 'USD';
        const status = (pmt.status || 'unknown').toLowerCase();
        const isPending = status === 'pending';
        return (
          <div key={id || i} style={{ ...s.dataCard, gap: 10 }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontWeight: 600, fontSize: 13 }}>{i + 1}. {to}</div>
              <div style={{ fontSize: 11, marginTop: 2 }}>
                <span style={{ ...s.statusPill, background: isPending ? 'rgba(245,158,11,0.25)' : 'rgba(34,197,94,0.2)', color: isPending ? '#fcd34d' : '#86efac' }}>{status}</span>
                {id && <span style={{ opacity: 0.55 }}>ID: {String(id).slice(0, 10)}</span>}
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
              <span style={{ fontWeight: 700 }}>{fmtCurrency(amt, cur)}</span>
              {isPending && onApprove && (
                <button onClick={() => onApprove(id, to, fmtCurrency(amt, cur))} style={s.approveBtn}>
                  Approve
                </button>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function StandingOrderList({ orders }) {
  if (!orders?.length) return <p style={s.empty}>No standing orders found.</p>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 10 }}>
      {orders.map((so, i) => {
        const id = so.standingOrderId || so.id;
        const to = so.creditorName || so.reference || 'Unknown';
        const amt = so.firstPaymentAmount?.amount || so.amount || 0;
        const cur = so.firstPaymentAmount?.currency || so.currency || 'USD';
        const freq = so.frequency || so.paymentFrequency || '';
        const status = (so.status || '').toLowerCase();
        return (
          <div key={id || i} style={s.dataCard}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontWeight: 600, fontSize: 13 }}>{i + 1}. {to}</div>
              <div style={{ fontSize: 11, opacity: 0.65, marginTop: 2 }}>{freq}{status ? ` · ${status}` : ''}</div>
            </div>
            <div style={{ fontWeight: 700 }}>{fmtCurrency(amt, cur)}</div>
          </div>
        );
      })}
    </div>
  );
}

// Render simple markdown-ish formatting in agent text
function AgentText({ text }) {
  const lines = text.split('\n');
  return (
    <div style={{ lineHeight: 1.6 }}>
      {lines.map((line, i) => {
        const formatted = line
          .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
          .replace(/`(.+?)`/g, '<code style="background:rgba(255,255,255,0.15);padding:1px 5px;border-radius:3px;font-family:monospace;font-size:12px">$1</code>');
        if (line.startsWith('• ') || line.startsWith('- ')) {
          return <div key={i} style={{ paddingLeft: 14, marginBottom: 2 }} dangerouslySetInnerHTML={{ __html: '· ' + formatted.replace(/^[•\-]\s*/, '') }} />;
        }
        return <div key={i} style={{ marginBottom: line === '' ? 6 : 2 }} dangerouslySetInnerHTML={{ __html: formatted || '&nbsp;' }} />;
      })}
    </div>
  );
}

// ── style tokens ──────────────────────────────────────────────────────────────
const s = {
  dataCard: {
    background: 'rgba(255,255,255,0.14)',
    border: '1px solid rgba(255,255,255,0.18)',
    borderRadius: 8,
    padding: '9px 13px',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    transition: 'background 0.15s',
  },
  numBadge: {
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: 18,
    height: 18,
    background: 'rgba(255,255,255,0.2)',
    borderRadius: 4,
    fontSize: 10,
    fontWeight: 700,
    marginRight: 4,
    verticalAlign: 'middle',
  },
  statusPill: {
    display: 'inline-block',
    fontSize: 10,
    fontWeight: 600,
    padding: '1px 6px',
    borderRadius: 4,
    marginRight: 6,
    textTransform: 'capitalize',
  },
  approveBtn: {
    background: 'rgba(34,197,94,0.18)',
    border: '1px solid rgba(34,197,94,0.4)',
    color: '#86efac',
    borderRadius: 5,
    padding: '3px 10px',
    fontSize: 11,
    cursor: 'pointer',
    fontFamily: 'inherit',
    fontWeight: 600,
  },
  th: { padding: '4px 8px', opacity: 0.65, fontWeight: 500, borderBottom: '1px solid rgba(255,255,255,0.15)', fontSize: 11 },
  td: { padding: '5px 8px' },
  empty: { opacity: 0.6, marginTop: 8, fontSize: 13 },
};

// ── A2A: credit card agent result panels ──────────────────────────────────────
const NETWORK_GRADIENT = {
  Visa: 'linear-gradient(135deg,#1e3a8a,#4f46e5)',
  Mastercard: 'linear-gradient(135deg,#9a3412,#be123c)',
};

function A2AFlow({ trace }) {
  const denied = trace.outcome === 'denied';
  const failed = trace.outcome === 'error';
  const G = '#34d399', R = '#f87171', N = '#94a3b8';
  const Node = ({ icon, title, sub, color }) => (
    <div style={{ flex: '1 1 0', minWidth: 96, border: `1px solid ${color}55`, background: `${color}14`, borderRadius: 10, padding: '7px 8px', textAlign: 'center' }}>
      <div style={{ fontSize: 16 }}>{icon}</div>
      <div style={{ fontSize: 11, fontWeight: 700 }}>{title}</div>
      <div style={{ fontSize: 10, color, fontWeight: 600, marginTop: 1 }}>{sub}</div>
    </div>
  );
  const Arrow = ({ color }) => <div style={{ color, fontSize: 14, fontWeight: 700 }}>→</div>;
  return (
    <div style={{ marginTop: 10, paddingTop: 10, borderTop: '1px solid rgba(255,255,255,0.12)' }}>
      <div style={{ fontSize: 10, opacity: 0.6, textTransform: 'uppercase', letterSpacing: 0.6, marginBottom: 6 }}>A2A call trace</div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        <Node icon="🤖" title="SecureBank Assistant" sub="caller" color={G} />
        <Arrow color={denied || failed ? R : G} />
        <Node icon="🛡" title="Warden A2A gateway"
          sub={denied ? '✗ blocked by Warden' : failed ? '✗ call failed' : '✓ policy · ✓ scan'}
          color={denied || failed ? R : G} />
        <Arrow color={denied || failed ? N : G} />
        <Node icon="💳" title="Credit Card Agent"
          sub={denied ? 'not reached' : failed ? 'no response' : trace.state === 'TASK_STATE_COMPLETED' ? 'completed' : (trace.state || 'done')}
          color={denied || failed ? N : G} />
      </div>
      <div style={{ fontSize: 10, opacity: 0.55, marginTop: 6 }}>
        {trace.skill && <>skill <b>{trace.skill}</b></>}
        {trace.taskId && <> · task <code>{String(trace.taskId).slice(0, 8)}…</code></>}
        {trace.state && !denied && !failed && <> · {trace.state.replace('TASK_STATE_', '')}</>}
      </div>
    </div>
  );
}

function CreditCardTiles({ cards, redacted }) {
  if (!cards?.length) return <p style={s.empty}>No cards found.</p>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginTop: 10 }}>
      {cards.map(c => {
        const limit = Number(c.limit) || 0, bal = Number(c.balance) || 0;
        const util = limit ? Math.min(100, Math.round((bal / limit) * 100)) : 0;
        const frozen = c.status === 'FROZEN';
        return (
          <div key={c.last4} style={{ background: NETWORK_GRADIENT[c.network] || NETWORK_GRADIENT.Visa, borderRadius: 12, padding: '12px 14px', boxShadow: '0 2px 10px rgba(0,0,0,0.25)', opacity: frozen ? 0.8 : 1 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ fontWeight: 700, fontSize: 13 }}>{c.product}</div>
              <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 8px', borderRadius: 10, background: frozen ? 'rgba(248,113,113,0.25)' : 'rgba(52,211,153,0.25)', color: frozen ? '#fecaca' : '#a7f3d0' }}>
                {frozen ? '❄ FROZEN' : 'ACTIVE'}
              </span>
            </div>
            <div style={{ fontFamily: 'monospace', fontSize: 15, letterSpacing: 2, margin: '8px 0 10px', opacity: 0.95 }}>
              •••• •••• •••• {c.last4} <span style={{ fontSize: 11, letterSpacing: 0, opacity: 0.7, marginLeft: 6 }}>{c.network}</span>
            </div>
            <div style={{ display: 'flex', gap: 18, fontSize: 11 }}>
              {[['Limit', limit], ['Balance', bal], ['Available', Number(c.available ?? limit - bal)]].map(([k, v]) => (
                <div key={k}><div style={{ opacity: 0.65 }}>{k}</div><div style={{ fontWeight: 700, fontSize: 14 }}>{fmtCurrency(v)}</div></div>
              ))}
            </div>
            <div style={{ height: 5, borderRadius: 3, background: 'rgba(255,255,255,0.2)', margin: '9px 0 6px' }}>
              <div style={{ width: `${util}%`, height: '100%', borderRadius: 3, background: util > 80 ? '#fca5a5' : '#a7f3d0' }} />
            </div>
            <div style={{ fontSize: 11, opacity: 0.8, display: 'flex', flexWrap: 'wrap', gap: '2px 12px' }}>
              <span>Min payment <b>{fmtCurrency(c.minPayment)}</b> due <b>{fmtDate(c.dueDate)}</b></span>
              <span>APR {c.apr}%</span>
              <span>⭐ {Number(c.rewardsPoints).toLocaleString('en-US')} pts</span>
            </div>
          </div>
        );
      })}
      {redacted && (
        <div style={{ fontSize: 11, color: '#a7f3d0' }}>🛡 <b>Warden (outbound):</b> the agent's response included full card numbers — they were redacted before reaching the assistant.</div>
      )}
    </div>
  );
}

function CardTxnTable({ transactions }) {
  if (!transactions?.length) return <p style={s.empty}>No card transactions found.</p>;
  return (
    <div style={{ marginTop: 10, overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
        <thead><tr>{['Date', 'Merchant', 'Category', 'Amount'].map(h => (
          <th key={h} style={{ ...s.th, textAlign: h === 'Amount' ? 'right' : 'left' }}>{h}</th>
        ))}</tr></thead>
        <tbody>
          {transactions.map((t, i) => (
            <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.07)' }}>
              <td style={{ ...s.td, whiteSpace: 'nowrap' }}>{fmtDate(t.date)}</td>
              <td style={s.td}>{t.merchant} <span style={{ opacity: 0.5 }}>••{t.card}</span></td>
              <td style={{ ...s.td, opacity: 0.75 }}>{t.category}</td>
              <td style={{ ...s.td, textAlign: 'right', fontWeight: 600, color: '#fca5a5', whiteSpace: 'nowrap' }}>-{fmtCurrency(t.amount)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── quick action chips ────────────────────────────────────────────────────────
// The assistant is two agents behind one chat. Every message is first screened by the common chat
// virtual server (scanMessage); the selected agent then makes its own calls through Warden.
const AGENTS = {
  mcp: {
    name: 'Banking Agent', protocol: 'MCP', color: '#1d4ed8',
    blurb: 'Calls banking tools on the Banking MCP server',
    flow: ['Chat scan', 'Banking Agent', 'Warden · MCP gateway', 'Banking MCP server'],
    chips: [
      { label: 'My Accounts', icon: '💳', text: 'Show my accounts' },
      { label: 'Balance', icon: '💰', text: 'Check my balance' },
      { label: 'Transactions', icon: '📋', text: 'Recent transactions' },
      { label: 'Payments', icon: '💸', text: 'List my payments' },
      { label: 'Standing Orders', icon: '🔄', text: 'Standing orders' },
      { label: 'New Payment', icon: '➕', text: 'New payment' },
    ],
  },
  a2a: {
    name: 'Credit Card Agent', protocol: 'A2A', color: '#0f766e',
    blurb: 'Asks a separate Credit Card Agent over A2A',
    flow: ['Chat scan', 'SecureBank Agent', 'Warden · A2A gateway', 'Credit Card Agent'],
    chips: [
      { label: 'Credit Cards', icon: '🏦', text: 'Show my credit card details' },
      { label: 'Card Spending', icon: '🧾', text: 'Show my recent credit card transactions' },
      // Avoid brand/number words here: the chat's Presidio rule masks "Visa" (ORGANIZATION) and "4242" (DATE_TIME).
      { label: 'Freeze Card', icon: '❄️', text: 'Freeze my credit card' },
    ],
  },
};
const A2A_INTENTS = new Set(['card_details', 'card_transactions', 'card_freeze']);
const SHARED_INTENTS = new Set(['greet', 'help', 'unknown']);

const HELP_TEXT = `Here's what I can help you with:

**💳 Accounts** — View all your accounts and balances
**📋 Transactions** — Browse recent transaction history
**💸 Payments** — List, create, and approve payments
**🔄 Standing Orders** — View recurring payment schedules
**🌐 Transfers** — View external transfers
Just type naturally — for example:
• "Show my accounts"
• "Check balance on my savings"
• "Recent transactions"
• "New payment"

For credit cards, switch to the **Credit Card Agent** using the selector at the top.`;

const HELP_TEXT_A2A = `The **Credit Card Agent** is a separate agent. I ask it over A2A, through Warden:

**🏦 Card details** — limits, balances and rewards
**🧾 Card spending** — recent card transactions
**❄️ Freeze a card** — blocked by Warden policy in this demo

Try:
• "Show my credit card details"
• "Show my recent credit card transactions"
• "Freeze my credit card"

For accounts and payments, switch to the **Banking Agent** using the selector at the top.`;

// ── initial message ───────────────────────────────────────────────────────────
function makeMsg(role, type, content, data = null) {
  return { id: `${Date.now()}-${Math.random()}`, role, type, content, data, ts: new Date() };
}

function welcomeMsg(agentKey) {
  return agentKey === 'a2a'
    ? makeMsg('agent', 'text', 'You are talking to the **Credit Card Agent** over **A2A**.\n\nI can show your card details and card spending. Every message is screened by Warden first, then passed to the card agent through the Warden A2A gateway.\n\nWhat would you like to know?')
    : makeMsg('agent', 'text', 'Hi! I\'m your **SecureBank AI assistant**.\n\nI can help you check accounts, view transactions, manage payments, and more.\n\nWhat would you like to do today?');
}

// ── main component ────────────────────────────────────────────────────────────
export default function Agent() {
  const { authState } = useOktaAuth();
  const user = authState?.idToken?.claims || {};
  const userName = user.name || user.given_name || 'there';

  const [agentKey, setAgentKey] = useState('mcp');
  const agent = AGENTS[agentKey];
  // Chat-scan findings are attributed to the selected agent (undefined = the chat's default agent)
  const scanAgentName = agentKey === 'a2a' ? A2A_AGENT_NAME : undefined;
  const [messages, setMessages] = useState(() => [welcomeMsg('mcp')]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [pendingAction, setPendingAction] = useState(null);
  const [cachedAccounts, setCachedAccounts] = useState(null);
  // Approval polling: { ticketId, msgId, toolName, kind: 'mcp' | 'a2a', skill }
  const [approvalPolling, setApprovalPolling] = useState(null);
  const approvalIntervalRef = useRef(null);

  const messagesEndRef = useRef(null);
  const inputRef = useRef(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  // Poll approval status every 5 seconds
  useEffect(() => {
    if (!approvalPolling) {
      if (approvalIntervalRef.current) {
        clearInterval(approvalIntervalRef.current);
        approvalIntervalRef.current = null;
      }
      return;
    }

    const { ticketId, msgId, toolName, kind, skill } = approvalPolling;

    const check = async () => {
      try {
        const status = await pollApprovalStatus(ticketId, kind);

        if (kind === 'a2a') {
          // The Credit Card Agent call that an A2A approval policy is holding
          const outcome = interpretA2aApproval(status);
          if (outcome.state === 'pending') return; // waiting for an admin, or approved and being forwarded
          clearInterval(approvalIntervalRef.current);
          approvalIntervalRef.current = null;
          setApprovalPolling(null);
          if (outcome.state === 'done') {
            updateMsg(msgId, "✅ **Approved** by an admin — here is the Credit Card Agent's answer.");
            await showA2aResult(outcome.result, skill); // goes through the same outbound chat scan as a direct answer
          } else if (outcome.state === 'denied') {
            updateMsg(msgId, '🚫 **Denied** — an admin denied your request to the Credit Card Agent.');
          } else if (outcome.state === 'expired') {
            updateMsg(msgId, `⏱ **Timed out** — The approval window expired and the request was auto-${outcome.autoAction}.`);
          } else {
            updateMsg(msgId, `⚠️ **The approved request could not be completed**\n\n• ${outcome.message}`);
          }
          return;
        }

        if (status.status === 'executed') {
          clearInterval(approvalIntervalRef.current);
          approvalIntervalRef.current = null;
          setApprovalPolling(null);
          // Use the tool_name from the ticket (more reliable than extracting from message)
          const resolvedTool = status.tool_name || toolName;
          const { type, content, data } = parseMcpResult(status.result, resolvedTool);
          updateMsgFull(msgId, { content, type, data });
        } else if (status.status === 'denied') {
          clearInterval(approvalIntervalRef.current);
          approvalIntervalRef.current = null;
          setApprovalPolling(null);
          updateMsg(msgId, `🚫 **Denied** — Your request to \`${toolName}\` was denied by an admin.`);
        } else if (status.status === 'expired') {
          clearInterval(approvalIntervalRef.current);
          approvalIntervalRef.current = null;
          setApprovalPolling(null);
          const autoAction = status.timeout_action === 'approve' ? 'auto-approved' : 'auto-denied';
          updateMsg(msgId, `⏱ **Timed out** — The approval window expired and the request was ${autoAction}.`);
        } else if (status.status === 'approved' && status.error) {
          // Approved, but running it failed (Warden now reports this instead of "still executing")
          clearInterval(approvalIntervalRef.current);
          approvalIntervalRef.current = null;
          setApprovalPolling(null);
          updateMsg(msgId, `⚠️ **The approved request could not be completed**\n\n• ${status.error}`);
        }
        // pending / approved (executing) → keep polling
      } catch {
        // Network blip — keep polling silently
      }
    };

    approvalIntervalRef.current = setInterval(check, 5000);
    // Run once immediately too
    check();

    return () => {
      if (approvalIntervalRef.current) {
        clearInterval(approvalIntervalRef.current);
        approvalIntervalRef.current = null;
      }
    };
  }, [approvalPolling]);

  function addMsg(role, type, content, data = null) {
    setMessages(prev => [...prev, makeMsg(role, type, content, data)]);
  }

  function updateMsg(msgId, newContent) {
    setMessages(prev => prev.map(m => m.id === msgId ? { ...m, content: newContent } : m));
  }

  function updateMsgFull(msgId, updates) {
    setMessages(prev => prev.map(m => m.id === msgId ? { ...m, ...updates } : m));
  }

  // Flatten structured agent data into a scannable text string so the outbound
  // interceptor can check account numbers, IBANs, payee names, etc. for PII.
  function flattenForScan(type, content, data) {
    const parts = [content];
    if (!data) return parts.join(' ');
    const push = (...vals) => vals.forEach(v => v && parts.push(String(v)));
    if (type === 'accounts' && data.accounts) {
      data.accounts.forEach(a => push(a.name, a.accountName, a.accountNumber, a.iban, a.sortCode));
    } else if (type === 'transactions' && data.transactions) {
      data.transactions.forEach(t => push(t.description, t.merchant, t.payee, t.reference, t.counterpartyName));
    } else if (type === 'payments' && data.payments) {
      data.payments.forEach(p => push(p.payeeName, p.to, p.accountNumber, p.sortCode, p.reference, p.description));
    } else if (type === 'standing_orders' && data.orders) {
      data.orders.forEach(o => push(o.payeeName, o.beneficiary, o.accountNumber, o.reference));
    } else if (type === 'a2a_card') {
      // Same as MCP replies: scan the answer's data, not the call trace
      try { parts.push(JSON.stringify({ cards: data.cards, transactions: data.transactions })); } catch {}
    } else {
      try { parts.push(JSON.stringify(data)); } catch {}
    }
    return parts.filter(Boolean).join(' ');
  }

  const SCANNER_LABELS = {
    regex: 'Regex + Keyword', embedding: 'Embedding Scanner',
    presidio: 'Presidio PII', 'llama-guard': 'Llama Guard 3',
  };

  // Scan an agent response outbound through banking-chatbot before showing it.
  // For structured types the key fields are flattened to text for scanning;
  // if the scan is clean the card still renders normally.
  async function addAgentMsg(type, content, data = null) {
    const textToScan = type === 'text' ? content : flattenForScan(type, content, data);
    const scan = await scanMessage(textToScan, 'outbound', scanAgentName);

    if (scan.action === 'block') {
      addMsg('agent', 'text',
        `🚫 **Warden blocked this response**\n\n• **Reason:** ${scan.reason || 'policy violation'}`
      );
      return;
    }

    const scannerLabel = SCANNER_LABELS[scan.scanner] || scan.scanner || 'Unknown';
    const ruleSuffix   = scan.rule ? ` · Rule: ${scan.rule}` : '';

    if (type === 'text') {
      const safeContent = (scan.action === 'mask' && scan.text && scan.text !== content)
        ? scan.text : content;
      if (safeContent !== content) {
        addMsg('agent', 'text',
          `🛡 **Warden (outbound):** Response contained sensitive data and was masked.\n• **Scanner:** ${scannerLabel}${ruleSuffix}`
        );
      }
      addMsg('agent', 'text', safeContent, data);
    } else {
      // Structured card — masking individual fields isn't supported; warn if flagged
      if (scan.action === 'mask' || scan.flagged) {
        addMsg('agent', 'text',
          `🛡 **Warden (outbound):** Sensitive data detected in this response.\n• **Scanner:** ${scannerLabel}${ruleSuffix}`
        );
      }
      addMsg('agent', type, content, data);
    }
  }

  // Parse a stored MCP result (from an approval ticket) into { type, content, data }
  // for rich rendering, the same way a normal agent response would look.
  function parseMcpResult(rawResult, toolName) {
    try {
      const text = rawResult?.result?.content?.[0]?.text;
      if (!text) return { type: 'text', content: `✅ **Approved & executed** \`${toolName}\``, data: null };
      const parsed = JSON.parse(text);
      if (parsed?.error) return { type: 'text', content: `❌ **Execution error** — ${parsed.error}`, data: null };

      // Accounts list
      if (Array.isArray(parsed) && parsed.length && (parsed[0]?.account_number !== undefined || parsed[0]?.accountNumber !== undefined || parsed[0]?.balance !== undefined)) {
        return {
          type: 'accounts',
          content: `✅ **Approved & executed** — here are your accounts (${parsed.length}):`,
          data: { accounts: parsed },
        };
      }
      // Payments list
      if (Array.isArray(parsed) && parsed.length && (parsed[0]?.to_name !== undefined || parsed[0]?.toName !== undefined)) {
        return {
          type: 'payments',
          content: `✅ **Approved & executed** — here are your payments (${parsed.length}):`,
          data: { payments: parsed },
        };
      }
      // Transactions list
      if (Array.isArray(parsed) && parsed.length && (parsed[0]?.transaction_date !== undefined || parsed[0]?.bookingDateTime !== undefined || parsed[0]?.description !== undefined)) {
        return {
          type: 'transactions',
          content: `✅ **Approved & executed** — here are your transactions:`,
          data: { transactions: parsed },
        };
      }
      // Balance object
      if (!Array.isArray(parsed) && (parsed?.balance !== undefined || parsed?.available_balance !== undefined)) {
        const bal = parsed.balance ?? parsed.available_balance ?? 0;
        const cur = parsed.currency || 'USD';
        return { type: 'text', content: `✅ **Balance:** ${fmtCurrency(bal, cur)}`, data: null };
      }
      // Initiate / approve payment success
      if (!Array.isArray(parsed) && parsed?.id && (parsed?.status !== undefined)) {
        return { type: 'text', content: `✅ **Approved & executed** — \`${toolName}\` completed. Status: **${parsed.status}**`, data: null };
      }
      // Fallback
      return {
        type: 'text',
        content: `✅ **Approved & executed** — \`${toolName}\`\n\n\`\`\`\n${JSON.stringify(parsed, null, 2).slice(0, 500)}\n\`\`\``,
        data: null,
      };
    } catch {
      return { type: 'text', content: `✅ **Approved & executed** — \`${toolName}\``, data: null };
    }
  }

  async function send(text) {
    const trimmed = text.trim();
    if (!trimmed || loading) return;
    setInput('');
    addMsg('user', 'text', trimmed);
    setLoading(true);

    try {
      // ── Warden interceptor scan ──────────────────────────────
      const scan = await scanMessage(trimmed, 'inbound', scanAgentName);

      if (scan.action === 'block') {
        const scannerLabel = {
          regex: 'Regex + Keyword',
          embedding: 'Embedding Scanner',
          presidio: 'Presidio PII',
          'llama-guard': 'Llama Guard 3',
        }[scan.scanner] || scan.scanner || 'Unknown';
        const scoreStr = scan.score != null ? ` (confidence: ${(scan.score * 100).toFixed(0)}%)` : '';
        const ruleLine = scan.rule ? `\n• **Rule:** ${scan.rule}` : '';
        addMsg('agent', 'text',
          `🚫 **Message blocked by Warden**\n\nYour message was flagged by the security policy and could not be processed.\n\n• **Scanner:** ${scannerLabel}${scoreStr}${ruleLine}\n• **Reason:** ${scan.reason || 'policy violation'}`
        );
        return;
      }

      // Use the (possibly masked) text for intent processing
      const processText = (scan.action === 'mask' && scan.text && scan.text !== trimmed)
        ? scan.text
        : trimmed;

      if (scan.action === 'mask' && processText !== trimmed) {
        const maskScannerLabel = {
          regex: 'Regex + Keyword',
          embedding: 'Embedding Scanner',
          presidio: 'Presidio PII',
          'llama-guard': 'Llama Guard 3',
        }[scan.scanner] || scan.scanner || 'Unknown';
        const maskRuleLine = scan.rule ? ` · Rule: ${scan.rule}` : '';
        addMsg('agent', 'text',
          `🛡 **Warden:** Sensitive data detected and masked before processing.\n• **Scanner:** ${maskScannerLabel}${maskRuleLine}\n• **Masked:** ${processText.slice(0, 200)}`
        );
      }
      // ────────────────────────────────────────────────────────

      if (pendingAction) {
        await handlePending(processText);
      } else {
        await handleIntent(processText);
      }
    } catch (err) {
      if (err instanceof ApprovalPendingError) {
        // Show a persistent polling bubble
        const toolName = err.approvalMessage?.match(/`([^`]+)`/)?.[1] || 'tool call';
        const msgId = `${Date.now()}-approval`;
        const expiresIn = err.expiresAt
          ? Math.round((new Date(err.expiresAt.includes('Z') || err.expiresAt.includes('+') ? err.expiresAt : err.expiresAt + 'Z').getTime() - Date.now()) / 60000)
          : '?';
        setMessages(prev => [...prev, {
          id: msgId, role: 'agent', type: 'text',
          content: `⏳ **Awaiting Admin Approval**\n\nYour request has been queued for admin review. I'll update this message automatically every 5 seconds.\n\n• **Ticket:** \`${err.ticketId}\`\n• **Expires in:** ~${expiresIn} min\n• **On timeout:** ${err.timeoutAction === 'approve' ? 'auto-approve ✅' : 'auto-deny 🚫'}\n\nAn admin must approve in the Warden dashboard.`,
          data: null, ts: new Date(),
        }]);
        setApprovalPolling({ ticketId: err.ticketId, msgId, toolName });
      } else {
        addMsg('agent', 'text', `Sorry, something went wrong: ${err.message}`);
      }
    } finally {
      setLoading(false);
      inputRef.current?.focus();
    }
  }

  // ── Resolve account from user input (number or name) ──
  function resolveAccount(text, accounts) {
    const n = parseInt(text, 10);
    if (!isNaN(n) && n >= 1 && n <= accounts.length) return accounts[n - 1];
    const lower = text.toLowerCase();
    return accounts.find(a =>
      (a.name || a.accountName || a.nickname || '').toLowerCase().includes(lower)
    ) || null;
  }

  // ── Multi-step pending handlers ──
  async function handlePending(text) {
    const action = pendingAction;

    if (action.type === 'select_account' && action.purpose === 'balance') {
      const acc = resolveAccount(text, action.accounts);
      if (!acc) { await addAgentMsg('text', `I couldn't find that account. Type a number (1–${action.accounts.length}) or the account name.`); return; }
      setPendingAction(null);
      addMsg('agent', 'text', `Fetching balance for **${acc.name || acc.accountName || 'account'}**…`);
      const id = acc.id || acc.accountId;
      const res = await mcpBanking.getAccountBalance(id);
      const bal = res?.balance ?? res?.amount ?? acc.balance?.amount ?? acc.currentBalance ?? 0;
      const cur = res?.currency || acc.balance?.currency || acc.currency || 'USD';
      await addAgentMsg('text', `**Current balance:** ${fmtCurrency(bal, cur)}`);
      return;
    }

    if (action.type === 'select_account' && action.purpose === 'transactions') {
      const acc = resolveAccount(text, action.accounts);
      if (!acc) { await addAgentMsg('text', `I couldn't find that account. Type a number (1–${action.accounts.length}) or the account name.`); return; }
      setPendingAction(null);
      addMsg('agent', 'text', `Fetching transactions for **${acc.name || acc.accountName || 'account'}**…`);
      const id = acc.id || acc.accountId;
      const res = await mcpBanking.getTransactions(id, { limit: 20 });
      const txns = Array.isArray(res) ? res : (res?.transactions || res?.data || []);
      const cur = acc.balance?.currency || acc.currency || 'USD';
      await addAgentMsg('transactions', `Here are the latest transactions for **${acc.name || 'account'}**:`, { transactions: txns, currency: cur });
      return;
    }

    if (action.type === 'approve_confirm') {
      const yes = /^(y(es)?|ok(ay)?|sure|confirm|approve|do it)$/i.test(text.trim());
      const no  = /^(n(o)?|cancel|stop|don't|nope|skip)$/i.test(text.trim());
      if (yes) {
        setPendingAction(null);
        addMsg('agent', 'text', `Approving payment to **${action.to}**…`);
        await mcpBanking.approvePayment(action.paymentId);
        await addAgentMsg('text', `✅ Payment of ${action.amount} to **${action.to}** has been approved.`);
      } else if (no) {
        setPendingAction(null);
        await addAgentMsg('text', 'Approval cancelled. Let me know if there\'s anything else I can help with.');
      } else {
        await addAgentMsg('text', 'Please reply **yes** to approve or **no** to cancel.');
      }
      return;
    }

    if (action.type === 'payment_flow') {
      await handlePaymentStep(text, action);
      return;
    }

    // Fallback: treat as new intent
    setPendingAction(null);
    await handleIntent(text);
  }

  // ── Payment creation multi-step ──
  async function handlePaymentStep(text, action) {
    const step = action.step;
    const data = { ...action.data };

    if (step === 'from_account') {
      const acc = resolveAccount(text, action.accounts);
      if (!acc) {
        await addAgentMsg('text', `I couldn't find that account. Type a number (1–${action.accounts.length}) or the account name.`);
        return;
      }
      data.fromAccountId = acc.id || acc.accountId;
      data.fromAccountName = acc.name || acc.accountName || 'account';
      setPendingAction({ type: 'payment_flow', step: 'payee', data });
      await addAgentMsg('text', `Paying from **${data.fromAccountName}**. Who would you like to pay?`);
    } else if (step === 'payee') {
      data.payeeName = text;
      setPendingAction({ type: 'payment_flow', step: 'account', data });
      await addAgentMsg('text', `Got it. What's **${text}'s** account number?`);
    } else if (step === 'account') {
      data.accountNumber = text.replace(/\s/g, '');
      setPendingAction({ type: 'payment_flow', step: 'sortcode', data });
      await addAgentMsg('text', 'And the sort code? (e.g. `20-00-00`)');
    } else if (step === 'sortcode') {
      data.sortCode = text.replace(/[-\s]/g, '');
      setPendingAction({ type: 'payment_flow', step: 'amount', data });
      await addAgentMsg('text', 'How much would you like to send?');
    } else if (step === 'amount') {
      const amt = parseFloat(text.replace(/[£$,]/g, ''));
      if (isNaN(amt) || amt <= 0) { await addAgentMsg('text', 'Please enter a valid amount (e.g. `150` or `£150.00`).'); return; }
      data.amount = amt;
      setPendingAction({ type: 'payment_flow', step: 'reference', data });
      await addAgentMsg('text', 'Add a reference (or type `skip` to leave it blank):');
    } else if (step === 'reference') {
      data.reference = /^skip$/i.test(text) ? '' : text;
      setPendingAction({ type: 'payment_flow', step: 'confirm', data });
      await addAgentMsg('text',
        `Here's a summary of the payment:\n\n**From:** ${data.fromAccountName}\n**Payee:** ${data.payeeName}\n**Account:** ****${data.accountNumber.slice(-4)}\n**Sort code:** ${data.sortCode.replace(/(\d{2})(\d{2})(\d{2})/, '$1-$2-$3')}\n**Amount:** ${fmtCurrency(data.amount)}\n**Reference:** ${data.reference || '(none)'}\n\nShall I send this? (yes / no)`
      );
    } else if (step === 'confirm') {
      const yes = /^(y(es)?|ok(ay)?|sure|confirm|send|do it)$/i.test(text.trim());
      const no  = /^(n(o)?|cancel|stop|don't|nope|edit)$/i.test(text.trim());
      if (yes) {
        setPendingAction(null);
        addMsg('agent', 'text', 'Sending payment…');
        await mcpBanking.initiatePayment({
          fromAccountId: data.fromAccountId,
          toName: data.payeeName,
          toAccount: `${data.sortCode}${data.accountNumber}`,
          amount: data.amount,
          currency: 'USD',
          reference: data.reference,
        });
        await addAgentMsg('text', `✅ Payment of ${fmtCurrency(data.amount)} to **${data.payeeName}** has been submitted.`);
      } else if (no) {
        setPendingAction(null);
        await addAgentMsg('text', 'Payment cancelled. Let me know if you\'d like to try again.');
      } else {
        await addAgentMsg('text', 'Reply **yes** to send or **no** to cancel.');
      }
    }
  }

  // Shows an answer from the Credit Card Agent, whether it arrived directly or after an admin approved it.
  // Replies go through the same outbound chat scan as MCP replies (addAgentMsg).
  async function showA2aResult(r, skill) {
    const blob = JSON.stringify(r.data);
    const cards = r.data.find(d => d?.cards)?.cards;
    const transactions = r.data.find(d => d?.transactions)?.transactions;
    const trace = { outcome: 'ok', skill, taskId: r.taskId, state: r.state };
    if (skill === 'card-details') {
      await addAgentMsg('a2a_card', 'Here are your credit cards, answered by the **Credit Card Agent**:', { cards, redacted: blob.includes('REDACTED'), trace });
    } else if (skill === 'card-transactions') {
      await addAgentMsg('a2a_card', 'Recent credit card transactions, from the **Credit Card Agent**:', { transactions, trace });
    } else {
      await addAgentMsg('a2a_card', `✅ ${r.text}`, { trace });
    }
  }

  // ── A2A: delegate a credit card question to the Credit Card Agent via Warden ──
  async function askCardAgent(question, skill) {
    if (!(await isA2AConfigured())) {
      addMsg('agent', 'text',
        '🏦 **Credit Card Agent is not connected yet.**\n\nRun `node credit-card-agent/setup-warden.js` (with the card agent and Warden running), store the printed agent token in the Warden Credential Vault, then restart the banking backend so it picks up `banking-app/backend/.env.local`.');
      return;
    }
    addMsg('agent', 'text', skill === 'card-freeze'
      ? 'Asking the **Credit Card Agent** to freeze that card — over A2A, through Warden…'
      : 'Asking the **Credit Card Agent** — over A2A, through Warden…');
    try {
      const r = await askCreditCardAgent(question, skill);
      await showA2aResult(r, skill);
    } catch (err) {
      if (err instanceof A2AApprovalPendingError) {
        // An approval policy is holding the call: show a polling bubble (like MCP approvals); the result appears
        // here automatically once an admin approves it.
        const msgId = `${Date.now()}-a2a-approval`;
        const expiresIn = err.expiresAt ? Math.max(1, Math.round((new Date(err.expiresAt).getTime() - Date.now()) / 60000)) : '?';
        setMessages(prev => [...prev, {
          id: msgId, role: 'agent', type: 'text',
          content: `⏳ **Awaiting Admin Approval**\n\nYour request to the Credit Card Agent is held by a Warden approval policy. I'll update this message automatically every 5 seconds.\n\n• **Ticket:** \`${err.ticketId}\`\n• **Expires in:** ~${expiresIn} min\n• **On timeout:** ${err.timeoutAction === 'approve' ? 'auto-approve ✅' : 'auto-deny 🚫'}\n\nAn admin must approve in the Warden dashboard.`,
          data: null, ts: new Date(),
        }]);
        setApprovalPolling({ ticketId: err.ticketId, msgId, toolName: skill || 'Credit Card Agent request', kind: 'a2a', skill });
      } else if (err instanceof A2AError) {
        const denied = err.status === 403 || err.status === 401;
        addMsg('agent', 'a2a_card',
          denied ? `🚫 **Warden blocked this A2A call**\n\n• **Reason:** ${err.message}` : `⚠️ **The A2A call failed**\n\n• ${err.message}`,
          { trace: { outcome: denied ? 'denied' : 'error', skill } });
      } else {
        throw err;
      }
    }
  }

  // ── Agent selector: each agent only handles its own domain ──
  function switchAgent(nextKey) {
    if (nextKey === agentKey || loading) return;
    const next = AGENTS[nextKey];
    setAgentKey(nextKey);
    setPendingAction(null);
    addMsg('agent', 'text',
      `🔀 **Switched to the ${next.name}** · ${next.protocol}\n\n${next.blurb}. Your messages are still screened by Warden's chat scan first, whichever agent you choose.`);
  }

  // ── Intent dispatcher ──
  async function handleIntent(text) {
    const intent = detectIntent(text);

    // Route by the selected agent: a message for the other agent gets a pointer, not a call.
    if (!SHARED_INTENTS.has(intent)) {
      const isCard = A2A_INTENTS.has(intent);
      if (isCard && agentKey !== 'a2a') {
        await addAgentMsg('text', `That's a question for the **Credit Card Agent** (A2A). Switch agents with the selector at the top, then ask again.`);
        return;
      }
      if (!isCard && agentKey === 'a2a') {
        await addAgentMsg('text', `The **Credit Card Agent** only handles credit-card questions. For accounts, payments and transfers, switch to the **Banking Agent** (MCP) with the selector at the top.`);
        return;
      }
    }

    switch (intent) {
      case 'greet':
        await addAgentMsg('text', `Hello! Great to see you, **${userName}**! ${agentKey === 'a2a' ? 'What would you like to know about your credit cards?' : 'How can I help you with your banking today?'}`);
        return;

      case 'help':
        await addAgentMsg('text', agentKey === 'a2a' ? HELP_TEXT_A2A : HELP_TEXT);
        return;

      case 'list_accounts': {
        addMsg('agent', 'text', 'Fetching your accounts…');
        const res = await mcpBanking.getAccounts();
        const accounts = Array.isArray(res) ? res : (res?.accounts || res?.data || []);
        setCachedAccounts(accounts);
        await addAgentMsg('accounts', `You have **${accounts.length}** account${accounts.length !== 1 ? 's' : ''}:`, { accounts });
        return;
      }

      case 'balance': {
        const accounts = cachedAccounts || await (async () => {
          const r = await mcpBanking.getAccounts();
          const a = Array.isArray(r) ? r : (r?.accounts || r?.data || []);
          setCachedAccounts(a);
          return a;
        })();
        if (!accounts.length) { await addAgentMsg('text', 'No accounts found.'); return; }
        if (accounts.length === 1) {
          const acc = accounts[0];
          const id = acc.id || acc.accountId;
          const res = await mcpBanking.getAccountBalance(id);
          const bal = res?.balance ?? res?.amount ?? acc.balance?.amount ?? acc.currentBalance ?? 0;
          const cur = res?.currency || acc.balance?.currency || acc.currency || 'USD';
          await addAgentMsg('text', `**Current balance:** ${fmtCurrency(bal, cur)}`);
        } else {
          setPendingAction({ type: 'select_account', purpose: 'balance', accounts });
          await addAgentMsg('accounts', 'Which account would you like to check? Tap one or type its number:', { accounts, selectable: true, onSelectPurpose: 'balance' });
        }
        return;
      }

      case 'transactions': {
        const accounts = cachedAccounts || await (async () => {
          const r = await mcpBanking.getAccounts();
          const a = Array.isArray(r) ? r : (r?.accounts || r?.data || []);
          setCachedAccounts(a);
          return a;
        })();
        if (!accounts.length) { addMsg('agent', 'text', 'No accounts found.'); return; }
        if (accounts.length === 1) {
          const acc = accounts[0];
          const id = acc.id || acc.accountId;
          addMsg('agent', 'text', `Fetching transactions for **${acc.name || acc.accountName || 'account'}**…`);
          const res = await mcpBanking.getTransactions(id, { limit: 20 });
          const txns = Array.isArray(res) ? res : (res?.transactions || res?.data || []);
          const cur = acc.balance?.currency || acc.currency || 'USD';
          await addAgentMsg('transactions', `Here are the latest transactions:`, { transactions: txns, currency: cur });
        } else {
          setPendingAction({ type: 'select_account', purpose: 'transactions', accounts });
          await addAgentMsg('accounts', 'Which account\'s transactions? Tap one or type its number:', { accounts, selectable: true, onSelectPurpose: 'transactions' });
        }
        return;
      }

      case 'list_payments': {
        addMsg('agent', 'text', 'Fetching your payments…');
        const res = await mcpBanking.listPayments();
        const payments = Array.isArray(res) ? res : (res?.payments || res?.data || []);
        await addAgentMsg('payments', `Here are your payments (${payments.length} total):`, { payments });
        return;
      }

      case 'approve_payments': {
        addMsg('agent', 'text', 'Fetching pending payments…');
        const res = await mcpBanking.listPayments();
        const payments = (Array.isArray(res) ? res : (res?.payments || res?.data || [])).filter(p => (p.status || '').toLowerCase() === 'pending');
        if (!payments.length) {
          await addAgentMsg('text', 'No pending payments to approve right now.');
        } else {
          await addAgentMsg('payments', `You have **${payments.length}** pending payment${payments.length !== 1 ? 's' : ''}. Tap Approve on any:`, { payments, approvable: true });
        }
        return;
      }

      case 'standing_orders': {
        addMsg('agent', 'text', 'Fetching standing orders…');
        const res = await banking.getStandingOrders();
        const orders = Array.isArray(res) ? res : (res?.standingOrders || res?.data || []);
        await addAgentMsg('standing_orders', `You have **${orders.length}** standing order${orders.length !== 1 ? 's' : ''}:`, { orders });
        return;
      }

      case 'transfers': {
        addMsg('agent', 'text', 'Fetching external transfers…');
        const res = await banking.getExternalTransfers().catch(() => []);
        const transfers = Array.isArray(res) ? res : (res?.transfers || res?.data || []);
        await addAgentMsg('payments', `Here are your external transfers (${transfers.length} total):`, { payments: transfers });
        return;
      }

      case 'new_payment': {
        addMsg('agent', 'text', 'Let\'s create a new payment. First, which account would you like to pay from?');
        const payAccRes = await mcpBanking.getAccounts();
        const payAccounts = Array.isArray(payAccRes) ? payAccRes : (payAccRes?.accounts || payAccRes?.data || []);
        if (!payAccounts.length) { addMsg('agent', 'text', 'No accounts found to pay from.'); return; }
        setPendingAction({ type: 'payment_flow', step: 'from_account', data: {}, accounts: payAccounts });
        await addAgentMsg('accounts', 'Which account would you like to pay from? Tap or type the number:', { accounts: payAccounts, selectable: true });
        return;
      }

      case 'card_details':
        await askCardAgent(text, 'card-details');
        return;
      case 'card_transactions':
        await askCardAgent(text, 'card-transactions');
        return;
      case 'card_freeze':
        await askCardAgent(text, 'card-freeze');
        return;

      default:
        await addAgentMsg('text', agentKey === 'a2a'
          ? `I'm not sure how to help with that. Try asking about your **credit card details**, **card spending**, or type **help** for a full list.`
          : `I'm not sure how to help with that. Try asking about your **accounts**, **transactions**, **payments**, or **standing orders** — or type **help** for a full list.`);
    }
  }

  // ── Approve from PaymentList card ──
  function handleApproveClick(paymentId, to, amount) {
    setPendingAction({ type: 'approve_confirm', paymentId, to, amount });
    addMsg('agent', 'text', `Approve a payment of **${amount}** to **${to}**? (yes / no)`);
  }

  // ── Render a single message bubble ──
  function renderMessage(msg) {
    const isAgent = msg.role === 'agent';
    return (
      <div
        key={msg.id}
        className="agent-msg-row"
        style={{
          display: 'flex',
          flexDirection: isAgent ? 'row' : 'row-reverse',
          gap: 10,
          marginBottom: 16,
          alignItems: 'flex-end',
        }}
      >
        {/* Avatar */}
        {isAgent && (
          <div style={{ width: 34, height: 34, borderRadius: '50%', background: 'linear-gradient(135deg,#1d4ed8,#4f46e5)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 15, flexShrink: 0, boxShadow: '0 2px 8px rgba(59,130,246,0.4)' }}>
            🤖
          </div>
        )}

        {/* Bubble */}
        <div style={{
          maxWidth: '80%',
          background: isAgent ? 'linear-gradient(135deg,#1e3a6e,#243256)' : 'linear-gradient(135deg,#2563eb,#1d4ed8)',
          borderRadius: isAgent ? '4px 16px 16px 16px' : '16px 4px 16px 16px',
          padding: '12px 15px',
          color: '#ffffff',
          boxShadow: '0 2px 8px rgba(0,0,0,0.15)',
          position: 'relative',
        }}>
          {/* Main text */}
          {msg.content && <AgentText text={msg.content} />}

          {/* Rich data */}
          {msg.type === 'accounts' && msg.data?.accounts && (
            <AccountCards
              accounts={msg.data.accounts}
              selectable={msg.data.selectable}
              onSelect={(acct, num) => {
                if (
                  pendingAction?.type === 'select_account' ||
                  (pendingAction?.type === 'payment_flow' && pendingAction?.step === 'from_account')
                ) {
                  send(String(num));
                }
              }}
            />
          )}
          {msg.type === 'transactions' && msg.data?.transactions && (
            <TxnTable transactions={msg.data.transactions} currency={msg.data.currency} />
          )}
          {msg.type === 'payments' && msg.data?.payments && (
            <PaymentList payments={msg.data.payments} onApprove={msg.data.approvable ? handleApproveClick : undefined} />
          )}
          {msg.type === 'standing_orders' && msg.data?.orders && (
            <StandingOrderList orders={msg.data.orders} />
          )}
          {msg.type === 'a2a_card' && msg.data && (
            <>
              {msg.data.cards && <CreditCardTiles cards={msg.data.cards} redacted={msg.data.redacted} />}
              {msg.data.transactions && <CardTxnTable transactions={msg.data.transactions} />}
              {msg.data.trace && <A2AFlow trace={msg.data.trace} />}
            </>
          )}

          {/* Timestamp */}
          <div style={{ fontSize: 10, opacity: 0.45, marginTop: 6, textAlign: isAgent ? 'left' : 'right' }}>
            {fmtTime(msg.ts)}
          </div>
        </div>
      </div>
    );
  }

  function handleKeyDown(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      send(input);
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', overflow: 'hidden', background: 'var(--bg)' }}>

      {/* ── Header ── */}
      <div style={{
        padding: '16px 24px',
        background: 'var(--white)',
        borderBottom: '1px solid var(--border)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexShrink: 0,
        boxShadow: '0 1px 4px rgba(0,0,0,0.06)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ width: 40, height: 40, borderRadius: '50%', background: 'linear-gradient(135deg,#1d4ed8,#4f46e5)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 18 }}>
            🤖
          </div>
          <div>
            <div style={{ fontWeight: 700, fontSize: 15, color: 'var(--text-primary)' }}>SecureBank Assistant</div>
            <div style={{ fontSize: 11, color: 'var(--success)', display: 'flex', alignItems: 'center', gap: 4 }}>
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--success)', display: 'inline-block' }} />
              Online · Powered by Warden · {agent.protocol}
            </div>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--text-secondary)', fontWeight: 500 }}>
            Agent
            <select
              value={agentKey}
              onChange={e => switchAgent(e.target.value)}
              disabled={loading}
              aria-label="Select agent"
              style={{
                border: `1.5px solid ${agent.color}`, borderRadius: 8, padding: '6px 10px',
                fontSize: 13, fontWeight: 600, fontFamily: 'inherit', color: agent.color,
                background: 'var(--white)', cursor: loading ? 'not-allowed' : 'pointer', outline: 'none',
              }}
            >
              {Object.entries(AGENTS).map(([key, a]) => (
                <option key={key} value={key}>{a.name} · {a.protocol}</option>
              ))}
            </select>
          </label>
          <button
            onClick={() => { setMessages([welcomeMsg(agentKey)]); setPendingAction(null); setCachedAccounts(null); setApprovalPolling(null); }}
            style={{ background: 'none', border: '1px solid var(--border)', borderRadius: 7, padding: '6px 14px', fontSize: 12, cursor: 'pointer', color: 'var(--text-secondary)', fontFamily: 'inherit', fontWeight: 500 }}
          >
            New Chat
          </button>
        </div>
      </div>

      {/* ── Call flow for the selected agent ── */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', padding: '8px 24px', background: 'var(--bg)', borderBottom: '1px solid var(--border)', flexShrink: 0, fontSize: 11.5 }}>
        <span style={{ color: 'var(--text-secondary)', fontWeight: 600, marginRight: 2 }}>Call flow</span>
        <span style={{ color: 'var(--text-secondary)' }}>You</span>
        {agent.flow.map((step, i) => (
          <React.Fragment key={step}>
            <span style={{ color: 'var(--text-secondary)' }}>→</span>
            <span style={{
              padding: '2px 9px', borderRadius: 12, fontWeight: 600, whiteSpace: 'nowrap',
              background: i === 0 ? 'rgba(124,58,237,0.10)' : `${agent.color}1a`,
              color: i === 0 ? '#7c3aed' : agent.color,
              border: `1px solid ${i === 0 ? 'rgba(124,58,237,0.35)' : `${agent.color}55`}`,
            }}>{step}</span>
          </React.Fragment>
        ))}
        <span style={{ color: 'var(--text-secondary)', marginLeft: 4 }}>· the chat scan is shared by both agents</span>
      </div>

      {/* ── Messages area ── */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '24px 20px 8px', scrollBehavior: 'smooth' }}>
        <div style={{ maxWidth: 720, margin: '0 auto' }}>
          {messages.map(renderMessage)}

          {/* Typing indicator */}
          {loading && (
            <div style={{ display: 'flex', gap: 10, marginBottom: 16, alignItems: 'flex-end' }}>
              <div style={{ width: 34, height: 34, borderRadius: '50%', background: 'linear-gradient(135deg,#1d4ed8,#4f46e5)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 15, flexShrink: 0 }}>🤖</div>
              <div style={{ background: 'linear-gradient(135deg,#1e3a6e,#243256)', borderRadius: '4px 16px 16px 16px', padding: '14px 18px', display: 'flex', gap: 5, alignItems: 'center' }}>
                <span className="agent-dot" style={{ animationDelay: '0ms' }} />
                <span className="agent-dot" style={{ animationDelay: '160ms' }} />
                <span className="agent-dot" style={{ animationDelay: '320ms' }} />
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>
      </div>

      {/* ── Input area ── */}
      <div style={{ background: 'var(--white)', borderTop: '1px solid var(--border)', padding: '12px 20px 16px', flexShrink: 0 }}>
        <div style={{ maxWidth: 720, margin: '0 auto' }}>
          {/* Quick action chips */}
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 10 }}>
            {agent.chips.map((qa) => (
              <button
                key={qa.label}
                onClick={() => send(qa.text)}
                disabled={loading}
                style={{
                  display: 'flex', alignItems: 'center', gap: 4,
                  background: 'var(--bg)', border: '1px solid var(--border)',
                  borderRadius: 20, padding: '4px 12px',
                  fontSize: 12, cursor: loading ? 'not-allowed' : 'pointer',
                  color: 'var(--text-secondary)', fontFamily: 'inherit',
                  fontWeight: 500, transition: 'all 0.15s', whiteSpace: 'nowrap',
                  opacity: loading ? 0.5 : 1,
                }}
                onMouseEnter={e => { if (!loading) { e.currentTarget.style.background = '#eff4ff'; e.currentTarget.style.color = '#1d4ed8'; e.currentTarget.style.borderColor = '#93c5fd'; } }}
                onMouseLeave={e => { e.currentTarget.style.background = 'var(--bg)'; e.currentTarget.style.color = 'var(--text-secondary)'; e.currentTarget.style.borderColor = 'var(--border)'; }}
              >
                <span>{qa.icon}</span> {qa.label}
              </button>
            ))}
          </div>

          {/* Text input */}
          <div style={{ display: 'flex', gap: 10, alignItems: 'flex-end' }}>
            <textarea
              ref={inputRef}
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              disabled={loading}
              placeholder={pendingAction ? 'Type your reply…' : agentKey === 'a2a' ? 'Ask about your credit cards…' : 'Ask me anything about your accounts…'}
              rows={1}
              style={{
                flex: 1, resize: 'none', border: '1.5px solid var(--border)',
                borderRadius: 12, padding: '11px 14px', fontFamily: 'inherit',
                fontSize: 14, lineHeight: 1.5, outline: 'none',
                background: 'var(--white)', color: 'var(--text-primary)',
                transition: 'border-color 0.15s',
                minHeight: 44, maxHeight: 120, overflow: 'auto',
              }}
              onFocus={e => { e.target.style.borderColor = 'var(--accent)'; }}
              onBlur={e => { e.target.style.borderColor = 'var(--border)'; }}
            />
            <button
              onClick={() => send(input)}
              disabled={loading || !input.trim()}
              style={{
                width: 44, height: 44, borderRadius: 12, flexShrink: 0,
                background: loading || !input.trim() ? 'var(--border)' : 'var(--accent)',
                border: 'none', cursor: loading || !input.trim() ? 'not-allowed' : 'pointer',
                color: 'white', fontSize: 18, display: 'flex', alignItems: 'center',
                justifyContent: 'center', transition: 'background 0.15s',
              }}
            >
              {loading ? '⏳' : '➤'}
            </button>
          </div>
          <p style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 8, textAlign: 'center' }}>
            Press Enter to send · Shift+Enter for new line
          </p>
        </div>
      </div>
    </div>
  );
}
