import React, { useState, useEffect } from 'react';
import { useOktaAuth } from '@okta/okta-react';
import { api } from '../services/api.js';

function fmtCurrency(amount, currency = 'USD') {
  return new Intl.NumberFormat('en-US', { style: 'currency', currency: currency || 'USD' }).format(Number(amount) || 0);
}

function fmtDate(str) {
  if (!str) return '—';
  return new Date(str).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

const ACCOUNT_TYPE_COLOR = {
  checking: { bg: '#eff6ff', color: '#1d4ed8', border: '#bfdbfe' },
  savings:  { bg: '#f0fdf4', color: '#16a34a', border: '#bbf7d0' },
  credit:   { bg: '#fff7ed', color: '#c2410c', border: '#fed7aa' },
};

export default function BankAdmin() {
  const { authState } = useOktaAuth();
  const currentSub = authState?.accessToken?.claims?.sub || authState?.idToken?.claims?.sub || '';

  const [users, setUsers]         = useState([]);
  const [loading, setLoading]     = useState(true);
  const [error, setError]         = useState(null);
  const [expandedUser, setExpandedUser] = useState(null);
  const [adjusting, setAdjusting] = useState(null); // { accountId, accountName, currency }
  const [form, setForm]           = useState({ amount: '', type: 'credit', description: '' });
  const [submitting, setSubmitting] = useState(false);
  const [toast, setToast]         = useState(null);
  const [search, setSearch]       = useState('');

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get('/admin/users');
      setUsers(res?.data || []);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  function showToast(msg, isError = false) {
    setToast({ msg, isError });
    setTimeout(() => setToast(null), 3500);
  }

  function openAdjust(account) {
    setAdjusting({ accountId: account.id, accountName: account.account_name, currency: account.currency });
    setForm({ amount: '', type: 'credit', description: '' });
  }

  function closeAdjust() {
    setAdjusting(null);
    setForm({ amount: '', type: 'credit', description: '' });
  }

  async function handleSubmit(e) {
    e.preventDefault();
    if (!form.amount || isNaN(parseFloat(form.amount)) || parseFloat(form.amount) <= 0) {
      showToast('Enter a valid positive amount.', true);
      return;
    }
    setSubmitting(true);
    try {
      const res = await api.post(`/admin/accounts/${adjusting.accountId}/adjust`, {
        amount: parseFloat(form.amount),
        type: form.type,
        description: form.description || undefined,
      });

      // Update the users list in place
      setUsers(prev => prev.map(u => ({
        ...u,
        accounts: u.accounts.map(a =>
          a.id === adjusting.accountId ? res.data : a
        ),
      })));

      showToast(`✓ ${form.type === 'credit' ? 'Added' : 'Withdrawn'} ${fmtCurrency(form.amount, adjusting.currency)} from ${adjusting.accountName}`);
      closeAdjust();
    } catch (e) {
      showToast(e.message, true);
    } finally {
      setSubmitting(false);
    }
  }

  const filtered = users.filter(u =>
    !search ||
    (u.name || '').toLowerCase().includes(search.toLowerCase()) ||
    (u.email || '').toLowerCase().includes(search.toLowerCase())
  );

  const totalAccounts = users.reduce((s, u) => s + (u.accounts?.length || 0), 0);
  const totalBalance  = users.reduce((s, u) =>
    s + (u.accounts || []).reduce((as, a) => as + (a.balance || 0), 0), 0);

  return (
    <div className="page">
      {/* ── Toast ── */}
      {toast && (
        <div style={{
          position: 'fixed', top: 20, right: 24, zIndex: 1000,
          background: toast.isError ? '#fef2f2' : '#f0fdf4',
          border: `1px solid ${toast.isError ? '#fca5a5' : '#bbf7d0'}`,
          color: toast.isError ? '#991b1b' : '#166534',
          padding: '12px 18px', borderRadius: 10, fontSize: 14,
          boxShadow: '0 4px 16px rgba(0,0,0,0.12)', maxWidth: 380,
          animation: 'agent-msg-in 0.2s ease-out',
        }}>
          {toast.msg}
        </div>
      )}

      {/* ── Header ── */}
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <span style={{ marginRight: 8 }}>🛡️</span>Bank Administration
          </h1>
          <p className="page-subtitle">Manage user accounts and adjust balances</p>
        </div>
        <button
          onClick={load}
          disabled={loading}
          style={{
            background: 'var(--accent)', color: '#fff', border: 'none',
            borderRadius: 8, padding: '9px 18px', cursor: loading ? 'not-allowed' : 'pointer',
            fontSize: 13, fontFamily: 'inherit', fontWeight: 600, opacity: loading ? 0.6 : 1,
          }}
        >
          {loading ? 'Refreshing…' : '↻ Refresh'}
        </button>
      </div>

      {/* ── Summary cards ── */}
      {!loading && !error && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 16, marginBottom: 24 }}>
          {[
            { label: 'Total Users',    value: users.length,    icon: '👥' },
            { label: 'Total Accounts', value: totalAccounts,   icon: '💳' },
            { label: 'Total Balances', value: fmtCurrency(totalBalance), icon: '💰' },
          ].map(c => (
            <div key={c.label} style={{
              background: 'var(--white)', border: '1px solid var(--border)',
              borderRadius: 12, padding: '18px 22px',
              display: 'flex', alignItems: 'center', gap: 16,
              boxShadow: '0 1px 4px rgba(0,0,0,0.06)',
            }}>
              <span style={{ fontSize: 28 }}>{c.icon}</span>
              <div>
                <div style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary)' }}>{c.value}</div>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>{c.label}</div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ── Search ── */}
      {!loading && !error && (
        <div style={{ marginBottom: 20 }}>
          <input
            type="text"
            placeholder="Search by name or email…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{
              width: '100%', maxWidth: 400,
              border: '1.5px solid var(--border)', borderRadius: 8,
              padding: '9px 14px', fontSize: 14, fontFamily: 'inherit',
              color: 'var(--text-primary)', background: 'var(--white)',
              outline: 'none',
            }}
            onFocus={e => { e.target.style.borderColor = 'var(--accent)'; }}
            onBlur={e => { e.target.style.borderColor = 'var(--border)'; }}
          />
        </div>
      )}

      {/* ── States ── */}
      {loading && (
        <div style={{ textAlign: 'center', padding: 60, color: 'var(--text-secondary)' }}>
          <div className="spinner" style={{ margin: '0 auto 16px' }} />
          Loading users…
        </div>
      )}

      {error && (
        <div style={{ background: '#fef2f2', border: '1px solid #fca5a5', borderRadius: 10, padding: '16px 20px', color: '#991b1b' }}>
          <strong>Error:</strong> {error}
          {error.toLowerCase().includes('admin') && (
            <p style={{ marginTop: 8, fontSize: 13 }}>
              Make sure your Okta access token includes the <code>bank-admin</code> group claim.
            </p>
          )}
        </div>
      )}

      {/* ── User list ── */}
      {!loading && !error && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {filtered.length === 0 && (
            <p style={{ color: 'var(--text-secondary)', textAlign: 'center', padding: 40 }}>
              No users found{search ? ` for "${search}"` : ''}.
            </p>
          )}

          {filtered.map(user => {
            const isOpen = expandedUser === user.id;
            const totalBal = (user.accounts || []).reduce((s, a) => s + (a.balance || 0), 0);

            return (
              <div key={user.id} className="card" style={{ overflow: 'hidden', padding: 0 }}>
                {/* User row */}
                <button
                  onClick={() => setExpandedUser(isOpen ? null : user.id)}
                  style={{
                    width: '100%', display: 'flex', alignItems: 'center',
                    gap: 14, padding: '16px 20px', background: 'none',
                    border: 'none', cursor: 'pointer', textAlign: 'left',
                    borderBottom: isOpen ? '1px solid var(--border)' : 'none',
                  }}
                >
                  {/* Avatar */}
                  {(() => {
                    const displayEmail = user.email || user.okta_sub || '';
                    const displayName  = user.name  || displayEmail.split('@')[0] || '?';
                    return (
                      <>
                        <div style={{
                          width: 42, height: 42, borderRadius: '50%', flexShrink: 0,
                          background: 'linear-gradient(135deg, var(--navy), var(--navy-light))',
                          display: 'flex', alignItems: 'center', justifyContent: 'center',
                          color: '#fff', fontWeight: 700, fontSize: 16,
                        }}>
                          {displayName[0].toUpperCase()}
                        </div>

                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ fontWeight: 600, fontSize: 14, color: 'var(--text-primary)' }}>
                            {displayName}
                          </div>
                          <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
                            {displayEmail} · {user.accounts?.length || 0} account{user.accounts?.length !== 1 ? 's' : ''} · Joined {fmtDate(user.created_at)}
                          </div>
                        </div>
                      </>
                    );
                  })()}

                  <div style={{ textAlign: 'right', flexShrink: 0 }}>
                    <div style={{ fontWeight: 700, fontSize: 15, color: 'var(--text-primary)' }}>
                      {fmtCurrency(totalBal)}
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>total balance</div>
                  </div>

                  <span style={{ fontSize: 12, color: 'var(--text-secondary)', marginLeft: 8, flexShrink: 0 }}>
                    {isOpen ? '▲' : '▼'}
                  </span>
                </button>

                {/* Accounts detail */}
                {isOpen && (
                  <div style={{ padding: '16px 20px', background: '#fafbfd' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                      {(user.accounts || []).map(acct => {
                        const colors = ACCOUNT_TYPE_COLOR[acct.account_type] || ACCOUNT_TYPE_COLOR.checking;
                        const isSelf = user.okta_sub === currentSub;
                        return (
                          <div
                            key={acct.id}
                            style={{
                              background: 'var(--white)', border: '1px solid var(--border)',
                              borderRadius: 10, padding: '14px 16px',
                              display: 'flex', alignItems: 'center', gap: 14,
                            }}
                          >
                            {/* Account type badge */}
                            <div style={{
                              flexShrink: 0, padding: '4px 10px', borderRadius: 20,
                              fontSize: 11, fontWeight: 600, textTransform: 'capitalize',
                              background: colors.bg, color: colors.color, border: `1px solid ${colors.border}`,
                            }}>
                              {acct.account_type}
                            </div>

                            <div style={{ flex: 1, minWidth: 0 }}>
                              <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-primary)' }}>
                                {acct.account_name}
                              </div>
                              <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
                                ****{(acct.account_number || '').slice(-4)}
                                {acct.sort_code ? ` · ${acct.sort_code}` : ''}
                                {acct.currency ? ` · ${acct.currency}` : ''}
                              </div>
                            </div>

                            <div style={{ textAlign: 'right', flexShrink: 0, minWidth: 120 }}>
                              <div style={{ fontWeight: 700, fontSize: 15, color: acct.balance < 0 ? '#dc2626' : 'var(--text-primary)' }}>
                                {fmtCurrency(acct.balance, acct.currency)}
                              </div>
                              <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                                avail. {fmtCurrency(acct.available_balance, acct.currency)}
                              </div>
                            </div>

                            {isSelf ? (
                              <div title="You cannot adjust your own balance" style={{
                                flexShrink: 0, padding: '7px 14px', fontSize: 12,
                                borderRadius: 7, border: '1px solid var(--border)',
                                color: 'var(--text-secondary)', background: '#f8fafc',
                                display: 'flex', alignItems: 'center', gap: 5,
                                fontWeight: 500, userSelect: 'none',
                              }}>
                                🔒 Your account
                              </div>
                            ) : (
                              <button
                                onClick={() => openAdjust(acct)}
                                style={{
                                  flexShrink: 0,
                                  background: 'var(--navy)', color: '#fff',
                                  border: 'none', borderRadius: 7,
                                  padding: '7px 14px', fontSize: 12,
                                  cursor: 'pointer', fontFamily: 'inherit', fontWeight: 600,
                                }}
                                onMouseEnter={e => { e.currentTarget.style.background = 'var(--accent)'; }}
                                onMouseLeave={e => { e.currentTarget.style.background = 'var(--navy)'; }}
                              >
                                Adjust Balance
                              </button>
                            )}
                          </div>
                        );
                      })}

                      {!user.accounts?.length && (
                        <p style={{ color: 'var(--text-secondary)', fontSize: 13, padding: '8px 0' }}>
                          No accounts for this user.
                        </p>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* ── Adjust Balance Modal ── */}
      {adjusting && (
        <div
          onClick={closeAdjust}
          style={{
            position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.45)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            zIndex: 900, padding: 16,
          }}
        >
          <div
            onClick={e => e.stopPropagation()}
            style={{
              background: '#fff', borderRadius: 14, padding: 28,
              width: '100%', maxWidth: 440,
              boxShadow: '0 20px 60px rgba(0,0,0,0.2)',
              animation: 'agent-msg-in 0.18s ease-out',
            }}
          >
            <h2 style={{ fontSize: 17, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
              Adjust Balance
            </h2>
            <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 22 }}>
              {adjusting.accountName}
            </p>

            <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              {/* Credit / Debit toggle */}
              <div>
                <label style={labelStyle}>Transaction type</label>
                <div style={{ display: 'flex', gap: 8 }}>
                  {[
                    { value: 'credit', label: '＋ Add funds',     activeColor: '#16a34a', activeBg: '#f0fdf4', activeBorder: '#86efac' },
                    { value: 'debit',  label: '－ Withdraw funds', activeColor: '#dc2626', activeBg: '#fef2f2', activeBorder: '#fca5a5' },
                  ].map(opt => (
                    <button
                      key={opt.value}
                      type="button"
                      onClick={() => setForm(f => ({ ...f, type: opt.value }))}
                      style={{
                        flex: 1, padding: '10px 0', borderRadius: 8, fontFamily: 'inherit',
                        fontSize: 13, fontWeight: 600, cursor: 'pointer',
                        border: `1.5px solid ${form.type === opt.value ? opt.activeBorder : 'var(--border)'}`,
                        background: form.type === opt.value ? opt.activeBg : 'var(--white)',
                        color: form.type === opt.value ? opt.activeColor : 'var(--text-secondary)',
                        transition: 'all 0.15s',
                      }}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Amount */}
              <div>
                <label style={labelStyle}>Amount ({adjusting.currency || 'USD'})</label>
                <div style={{ position: 'relative' }}>
                  <span style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-secondary)', fontSize: 14 }}>$</span>
                  <input
                    type="number"
                    min="0.01"
                    step="0.01"
                    placeholder="0.00"
                    value={form.amount}
                    onChange={e => setForm(f => ({ ...f, amount: e.target.value }))}
                    required
                    autoFocus
                    style={{ ...inputStyle, paddingLeft: 28 }}
                    onFocus={e => { e.target.style.borderColor = 'var(--accent)'; }}
                    onBlur={e => { e.target.style.borderColor = 'var(--border)'; }}
                  />
                </div>
              </div>

              {/* Description */}
              <div>
                <label style={labelStyle}>Reason <span style={{ fontWeight: 400, opacity: 0.6 }}>(optional)</span></label>
                <input
                  type="text"
                  placeholder="e.g. Bonus credit, Error correction…"
                  value={form.description}
                  onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                  style={inputStyle}
                  onFocus={e => { e.target.style.borderColor = 'var(--accent)'; }}
                  onBlur={e => { e.target.style.borderColor = 'var(--border)'; }}
                />
              </div>

              {/* Preview */}
              {form.amount && !isNaN(parseFloat(form.amount)) && (
                <div style={{
                  background: form.type === 'credit' ? '#f0fdf4' : '#fef2f2',
                  border: `1px solid ${form.type === 'credit' ? '#bbf7d0' : '#fca5a5'}`,
                  borderRadius: 8, padding: '10px 14px', fontSize: 13,
                  color: form.type === 'credit' ? '#166534' : '#991b1b',
                }}>
                  {form.type === 'credit' ? '＋' : '－'} {fmtCurrency(parseFloat(form.amount), adjusting.currency)} will be {form.type === 'credit' ? 'added to' : 'deducted from'} <strong>{adjusting.accountName}</strong>
                </div>
              )}

              <div style={{ display: 'flex', gap: 10, marginTop: 4 }}>
                <button
                  type="button"
                  onClick={closeAdjust}
                  style={{
                    flex: 1, padding: '10px 0', borderRadius: 8,
                    border: '1.5px solid var(--border)', background: 'var(--white)',
                    color: 'var(--text-secondary)', fontSize: 14,
                    cursor: 'pointer', fontFamily: 'inherit', fontWeight: 500,
                  }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  style={{
                    flex: 1, padding: '10px 0', borderRadius: 8,
                    border: 'none', fontSize: 14, fontFamily: 'inherit', fontWeight: 600,
                    cursor: submitting ? 'not-allowed' : 'pointer',
                    background: submitting ? 'var(--border)' : (form.type === 'credit' ? '#16a34a' : '#dc2626'),
                    color: submitting ? 'var(--text-secondary)' : '#fff',
                    transition: 'background 0.15s',
                  }}
                >
                  {submitting ? 'Processing…' : `Confirm ${form.type === 'credit' ? 'Credit' : 'Debit'}`}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

const labelStyle = {
  display: 'block', fontSize: 12, fontWeight: 600,
  color: 'var(--text-secondary)', marginBottom: 6,
  textTransform: 'uppercase', letterSpacing: '0.4px',
};

const inputStyle = {
  width: '100%', border: '1.5px solid var(--border)',
  borderRadius: 8, padding: '10px 12px', fontSize: 14,
  fontFamily: 'inherit', color: 'var(--text-primary)',
  background: 'var(--white)', outline: 'none',
  boxSizing: 'border-box', transition: 'border-color 0.15s',
};
