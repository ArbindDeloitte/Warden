import React, { useState, useEffect, useRef } from 'react';
import { useOktaAuth } from '@okta/okta-react';
import { banking } from '../services/api.js';
import { mcpBanking, scanMessage } from '../services/mcpProxy.js';

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
        const to = pmt.creditorAccount?.name || pmt.toName || pmt.recipientName || 'Unknown';
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

// ── quick action chips ────────────────────────────────────────────────────────
const QUICK_ACTIONS = [
  { label: 'My Accounts', icon: '💳', text: 'Show my accounts' },
  { label: 'Balance', icon: '💰', text: 'Check my balance' },
  { label: 'Transactions', icon: '📋', text: 'Recent transactions' },
  { label: 'Payments', icon: '💸', text: 'List my payments' },
  { label: 'Standing Orders', icon: '🔄', text: 'Standing orders' },
  { label: 'New Payment', icon: '➕', text: 'New payment' },
];

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
• "New payment"`;

// ── initial message ───────────────────────────────────────────────────────────
function makeMsg(role, type, content, data = null) {
  return { id: `${Date.now()}-${Math.random()}`, role, type, content, data, ts: new Date() };
}

const WELCOME_MSG = makeMsg('agent', 'text',
  'Hi! I\'m your **SecureBank AI assistant**.\n\nI can help you check accounts, view transactions, manage payments, and more.\n\nWhat would you like to do today?'
);

// ── main component ────────────────────────────────────────────────────────────
export default function Agent() {
  const { authState } = useOktaAuth();
  const user = authState?.idToken?.claims || {};
  const userName = user.name || user.given_name || 'there';

  const [messages, setMessages] = useState([WELCOME_MSG]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [pendingAction, setPendingAction] = useState(null);
  const [cachedAccounts, setCachedAccounts] = useState(null);

  const messagesEndRef = useRef(null);
  const inputRef = useRef(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  function addMsg(role, type, content, data = null) {
    setMessages(prev => [...prev, makeMsg(role, type, content, data)]);
  }

  async function send(text) {
    const trimmed = text.trim();
    if (!trimmed || loading) return;
    setInput('');
    addMsg('user', 'text', trimmed);
    setLoading(true);

    try {
      // ── Warden interceptor scan ──────────────────────────────
      const scan = await scanMessage(trimmed, 'inbound');

      if (scan.action === 'block') {
        addMsg('agent', 'text',
          `🚫 **Message blocked by Warden**\n\nYour message was flagged by the security policy and could not be processed.\n_Reason: ${scan.reason || 'policy violation'}_`
        );
        return;
      }

      // Use the (possibly masked) text for intent processing
      const processText = (scan.action === 'mask' && scan.text && scan.text !== trimmed)
        ? scan.text
        : trimmed;

      if (scan.action === 'mask' && processText !== trimmed) {
        addMsg('agent', 'text',
          `🛡 **Warden:** Sensitive data detected in your message and masked before processing.\n_Masked: ${processText.slice(0, 200)}_`
        );
      }
      // ────────────────────────────────────────────────────────

      if (pendingAction) {
        await handlePending(processText);
      } else {
        await handleIntent(processText);
      }
    } catch (err) {
      addMsg('agent', 'text', `Sorry, something went wrong: ${err.message}`);
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
      if (!acc) { addMsg('agent', 'text', `I couldn't find that account. Type a number (1–${action.accounts.length}) or the account name.`); return; }
      setPendingAction(null);
      addMsg('agent', 'text', `Fetching balance for **${acc.name || acc.accountName || 'account'}**…`);
      const id = acc.id || acc.accountId;
      const res = await mcpBanking.getAccountBalance(id);
      const bal = res?.balance ?? res?.amount ?? acc.balance?.amount ?? acc.currentBalance ?? 0;
      const cur = res?.currency || acc.balance?.currency || acc.currency || 'USD';
      addMsg('agent', 'text', `**Current balance:** ${fmtCurrency(bal, cur)}`);
      return;
    }

    if (action.type === 'select_account' && action.purpose === 'transactions') {
      const acc = resolveAccount(text, action.accounts);
      if (!acc) { addMsg('agent', 'text', `I couldn't find that account. Type a number (1–${action.accounts.length}) or the account name.`); return; }
      setPendingAction(null);
      addMsg('agent', 'text', `Fetching transactions for **${acc.name || acc.accountName || 'account'}**…`);
      const id = acc.id || acc.accountId;
      const res = await mcpBanking.getTransactions(id, { limit: 20 });
      const txns = Array.isArray(res) ? res : (res?.transactions || res?.data || []);
      const cur = acc.balance?.currency || acc.currency || 'USD';
      addMsg('agent', 'transactions', `Here are the latest transactions for **${acc.name || 'account'}**:`, { transactions: txns, currency: cur });
      return;
    }

    if (action.type === 'approve_confirm') {
      const yes = /^(y(es)?|ok(ay)?|sure|confirm|approve|do it)$/i.test(text.trim());
      const no  = /^(n(o)?|cancel|stop|don't|nope|skip)$/i.test(text.trim());
      if (yes) {
        setPendingAction(null);
        addMsg('agent', 'text', `Approving payment to **${action.to}**…`);
        await mcpBanking.approvePayment(action.paymentId);
        addMsg('agent', 'text', `✅ Payment of ${action.amount} to **${action.to}** has been approved.`);
      } else if (no) {
        setPendingAction(null);
        addMsg('agent', 'text', 'Approval cancelled. Let me know if there\'s anything else I can help with.');
      } else {
        addMsg('agent', 'text', 'Please reply **yes** to approve or **no** to cancel.');
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
        addMsg('agent', 'text', `I couldn't find that account. Type a number (1–${action.accounts.length}) or the account name.`);
        return;
      }
      data.fromAccountId = acc.id || acc.accountId;
      data.fromAccountName = acc.name || acc.accountName || 'account';
      setPendingAction({ type: 'payment_flow', step: 'payee', data });
      addMsg('agent', 'text', `Paying from **${data.fromAccountName}**. Who would you like to pay?`);
    } else if (step === 'payee') {
      data.payeeName = text;
      setPendingAction({ type: 'payment_flow', step: 'account', data });
      addMsg('agent', 'text', `Got it. What's **${text}'s** account number?`);
    } else if (step === 'account') {
      data.accountNumber = text.replace(/\s/g, '');
      setPendingAction({ type: 'payment_flow', step: 'sortcode', data });
      addMsg('agent', 'text', 'And the sort code? (e.g. `20-00-00`)');
    } else if (step === 'sortcode') {
      data.sortCode = text.replace(/[-\s]/g, '');
      setPendingAction({ type: 'payment_flow', step: 'amount', data });
      addMsg('agent', 'text', 'How much would you like to send?');
    } else if (step === 'amount') {
      const amt = parseFloat(text.replace(/[£$,]/g, ''));
      if (isNaN(amt) || amt <= 0) { addMsg('agent', 'text', 'Please enter a valid amount (e.g. `150` or `£150.00`).'); return; }
      data.amount = amt;
      setPendingAction({ type: 'payment_flow', step: 'reference', data });
      addMsg('agent', 'text', 'Add a reference (or type `skip` to leave it blank):');
    } else if (step === 'reference') {
      data.reference = /^skip$/i.test(text) ? '' : text;
      setPendingAction({ type: 'payment_flow', step: 'confirm', data });
      addMsg('agent', 'text',
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
        addMsg('agent', 'text', `✅ Payment of ${fmtCurrency(data.amount)} to **${data.payeeName}** has been submitted.`);
      } else if (no) {
        setPendingAction(null);
        addMsg('agent', 'text', 'Payment cancelled. Let me know if you\'d like to try again.');
      } else {
        addMsg('agent', 'text', 'Reply **yes** to send or **no** to cancel.');
      }
    }
  }

  // ── Intent dispatcher ──
  async function handleIntent(text) {
    const intent = detectIntent(text);

    switch (intent) {
      case 'greet':
        addMsg('agent', 'text', `Hello! Great to see you, **${userName}**! How can I help you with your banking today?`);
        return;

      case 'help':
        addMsg('agent', 'text', HELP_TEXT);
        return;

      case 'list_accounts': {
        addMsg('agent', 'text', 'Fetching your accounts…');
        const res = await mcpBanking.getAccounts();
        const accounts = Array.isArray(res) ? res : (res?.accounts || res?.data || []);
        setCachedAccounts(accounts);
        addMsg('agent', 'accounts', `You have **${accounts.length}** account${accounts.length !== 1 ? 's' : ''}:`, { accounts });
        return;
      }

      case 'balance': {
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
          const res = await mcpBanking.getAccountBalance(id);
          const bal = res?.balance ?? res?.amount ?? acc.balance?.amount ?? acc.currentBalance ?? 0;
          const cur = res?.currency || acc.balance?.currency || acc.currency || 'USD';
          addMsg('agent', 'text', `**Current balance:** ${fmtCurrency(bal, cur)}`);
        } else {
          setPendingAction({ type: 'select_account', purpose: 'balance', accounts });
          addMsg('agent', 'accounts', 'Which account would you like to check? Tap one or type its number:', { accounts, selectable: true, onSelectPurpose: 'balance' });
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
          addMsg('agent', 'transactions', `Here are the latest transactions:`, { transactions: txns, currency: cur });
        } else {
          setPendingAction({ type: 'select_account', purpose: 'transactions', accounts });
          addMsg('agent', 'accounts', 'Which account\'s transactions? Tap one or type its number:', { accounts, selectable: true, onSelectPurpose: 'transactions' });
        }
        return;
      }

      case 'list_payments': {
        addMsg('agent', 'text', 'Fetching your payments…');
        const res = await mcpBanking.listPayments();
        const payments = Array.isArray(res) ? res : (res?.payments || res?.data || []);
        addMsg('agent', 'payments', `Here are your payments (${payments.length} total):`, { payments });
        return;
      }

      case 'approve_payments': {
        addMsg('agent', 'text', 'Fetching pending payments…');
        const res = await mcpBanking.listPayments();
        const payments = (Array.isArray(res) ? res : (res?.payments || res?.data || [])).filter(p => (p.status || '').toLowerCase() === 'pending');
        if (!payments.length) {
          addMsg('agent', 'text', 'No pending payments to approve right now.');
        } else {
          addMsg('agent', 'payments', `You have **${payments.length}** pending payment${payments.length !== 1 ? 's' : ''}. Tap Approve on any:`, { payments, approvable: true });
        }
        return;
      }

      case 'standing_orders': {
        addMsg('agent', 'text', 'Fetching standing orders…');
        const res = await banking.getStandingOrders();
        const orders = Array.isArray(res) ? res : (res?.standingOrders || res?.data || []);
        addMsg('agent', 'standing_orders', `You have **${orders.length}** standing order${orders.length !== 1 ? 's' : ''}:`, { orders });
        return;
      }

      case 'transfers': {
        addMsg('agent', 'text', 'Fetching external transfers…');
        const res = await banking.getExternalTransfers().catch(() => []);
        const transfers = Array.isArray(res) ? res : (res?.transfers || res?.data || []);
        addMsg('agent', 'payments', `Here are your external transfers (${transfers.length} total):`, { payments: transfers });
        return;
      }

      case 'new_payment': {
        addMsg('agent', 'text', 'Let\'s create a new payment. First, which account would you like to pay from?');
        const payAccRes = await mcpBanking.getAccounts();
        const payAccounts = Array.isArray(payAccRes) ? payAccRes : (payAccRes?.accounts || payAccRes?.data || []);
        if (!payAccounts.length) { addMsg('agent', 'text', 'No accounts found to pay from.'); return; }
        setPendingAction({ type: 'payment_flow', step: 'from_account', data: {}, accounts: payAccounts });
        addMsg('agent', 'accounts', 'Which account would you like to pay from? Tap or type the number:', { accounts: payAccounts, selectable: true });
        return;
      }

      default:
        addMsg('agent', 'text', `I'm not sure how to help with that. Try asking about your **accounts**, **transactions**, **payments**, or **standing orders** — or type **help** for a full list.`);
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
              Online · Powered by MCP Virtual Server
            </div>
          </div>
        </div>
        <button
          onClick={() => { setMessages([WELCOME_MSG]); setPendingAction(null); setCachedAccounts(null); }}
          style={{ background: 'none', border: '1px solid var(--border)', borderRadius: 7, padding: '6px 14px', fontSize: 12, cursor: 'pointer', color: 'var(--text-secondary)', fontFamily: 'inherit', fontWeight: 500 }}
        >
          New Chat
        </button>
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
            {QUICK_ACTIONS.map((qa) => (
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
              placeholder={pendingAction ? 'Type your reply…' : 'Ask me anything about your accounts…'}
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
