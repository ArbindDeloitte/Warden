import React, { useState, useEffect } from 'react';
import { banking } from '../services/api.js';

function formatCurrency(amount, currency = 'USD') {
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: currency || 'USD',
  }).format(amount || 0);
}

function formatDate(dateStr) {
  if (!dateStr) return '';
  const d = new Date(dateStr);
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

function Skeleton({ width = '100%', height = '20px', style = {} }) {
  return <div className="skeleton" style={{ width, height, ...style }} />;
}

const INITIAL_FORM = {
  fromAccountId: '',
  iban: '',
  recipientName: '',
  bankName: '',
  amount: '',
  currency: 'USD',
  reference: '',
};

export default function ExternalTransfers() {
  const [accounts, setAccounts] = useState([]);
  const [transfers, setTransfers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);
  const [formError, setFormError] = useState(null);
  const [success, setSuccess] = useState(null);
  const [form, setForm] = useState(INITIAL_FORM);

  useEffect(() => {
    fetchData();
  }, []);

  async function fetchData() {
    try {
      setLoading(true);
      setError(null);
      const [accts, txfrs] = await Promise.all([
        banking.getAccounts().catch(() => []),
        banking.getExternalTransfers().catch(() => []),
      ]);
      setAccounts(Array.isArray(accts) ? accts : (accts?.accounts || accts?.data || []));
      setTransfers(Array.isArray(txfrs) ? txfrs : (txfrs?.transfers || txfrs?.data || []));
    } catch (err) {
      setError(err.message || 'Failed to load transfers');
    } finally {
      setLoading(false);
    }
  }

  function handleChange(e) {
    setForm({ ...form, [e.target.name]: e.target.value });
  }

  function validateIBAN(iban) {
    // Basic IBAN format check (2 letters + 2 digits + up to 30 alphanumeric)
    return /^[A-Z]{2}\d{2}[A-Z0-9]{1,30}$/.test(iban.replace(/\s/g, '').toUpperCase());
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setFormError(null);
    setSuccess(null);

    if (!form.fromAccountId) return setFormError('Please select a source account');
    if (!form.iban.trim()) return setFormError('Please enter IBAN');
    if (!form.recipientName.trim()) return setFormError('Please enter recipient name');
    if (!form.amount || parseFloat(form.amount) <= 0)
      return setFormError('Amount must be greater than 0');

    try {
      setSubmitting(true);
      await banking.createExternalTransfer({
        fromAccountId: form.fromAccountId,
        iban: form.iban.replace(/\s/g, '').toUpperCase(),
        recipientName: form.recipientName,
        bankName: form.bankName || undefined,
        amount: { amount: parseFloat(form.amount), currency: form.currency },
        reference: form.reference,
      });
      setSuccess('External transfer initiated successfully!');
      setForm(INITIAL_FORM);
      await fetchData();
    } catch (err) {
      setFormError(err.message || 'Failed to initiate transfer');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">External Transfers</h1>
        <p className="page-subtitle">Send money to external bank accounts internationally</p>
      </div>

      {error && (
        <div className="alert alert-error">
          <span>⚠️ {error}</span>
        </div>
      )}

      {/* Transfer Form */}
      <section className="section">
        <h2 className="section-title">New External Transfer</h2>
        <div className="form-card">
          {success && (
            <div className="alert alert-success">
              <span>✅ {success}</span>
            </div>
          )}
          {formError && (
            <div className="alert alert-error">
              <span>⚠️ {formError}</span>
            </div>
          )}
          <form onSubmit={handleSubmit}>
            <div className="form-row">
              <div className="form-group">
                <label className="form-label">From Account *</label>
                <select
                  name="fromAccountId"
                  className="form-input"
                  value={form.fromAccountId}
                  onChange={handleChange}
                  required
                >
                  <option value="">Select account</option>
                  {accounts.map((a) => {
                    const acctId = a.id || a.accountId;
                    const name = a.name || a.accountName || a.nickname || 'Account';
                    const num = a.accountNumber || a.identification || '';
                    return (
                      <option key={acctId} value={acctId}>
                        {name} {num ? `(****${num.slice(-4)})` : ''}
                      </option>
                    );
                  })}
                </select>
              </div>
              <div className="form-group">
                <label className="form-label">Recipient IBAN *</label>
                <input
                  type="text"
                  name="iban"
                  className="form-input"
                  placeholder="e.g. GB29NWBK60161331926819"
                  value={form.iban}
                  onChange={handleChange}
                  required
                />
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label className="form-label">Recipient Name *</label>
                <input
                  type="text"
                  name="recipientName"
                  className="form-input"
                  placeholder="Full name or company name"
                  value={form.recipientName}
                  onChange={handleChange}
                  required
                />
              </div>
              <div className="form-group">
                <label className="form-label">Bank Name (optional)</label>
                <input
                  type="text"
                  name="bankName"
                  className="form-input"
                  placeholder="Recipient's bank name"
                  value={form.bankName}
                  onChange={handleChange}
                />
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label className="form-label">Amount *</label>
                <input
                  type="number"
                  name="amount"
                  className="form-input"
                  placeholder="0.00"
                  min="0.01"
                  step="0.01"
                  value={form.amount}
                  onChange={handleChange}
                  required
                />
              </div>
              <div className="form-group">
                <label className="form-label">Currency</label>
                <select
                  name="currency"
                  className="form-input"
                  value={form.currency}
                  onChange={handleChange}
                >
                  <option value="USD">USD</option>
                  <option value="EUR">EUR</option>
                  <option value="GBP">GBP</option>
                  <option value="CAD">CAD</option>
                  <option value="AUD">AUD</option>
                  <option value="CHF">CHF</option>
                  <option value="JPY">JPY</option>
                </select>
              </div>
              <div className="form-group">
                <label className="form-label">Reference</label>
                <input
                  type="text"
                  name="reference"
                  className="form-input"
                  placeholder="Transfer reference (optional)"
                  value={form.reference}
                  onChange={handleChange}
                />
              </div>
            </div>

            <div style={{ marginTop: '16px' }}>
              <button type="submit" className="btn btn-primary" disabled={submitting}>
                {submitting ? 'Processing...' : 'Send Transfer'}
              </button>
            </div>
          </form>
        </div>
      </section>

      {/* Recent Transfers */}
      <section className="section">
        <h2 className="section-title">Recent External Transfers</h2>
        {loading ? (
          <div>
            {[1, 2, 3].map((i) => (
              <Skeleton key={i} height="44px" style={{ marginBottom: '4px' }} />
            ))}
          </div>
        ) : transfers.length === 0 ? (
          <div className="empty-state">No external transfers found.</div>
        ) : (
          <div className="table-wrapper">
            <table className="table">
              <thead>
                <tr>
                  <th>Date</th>
                  <th>Recipient</th>
                  <th>IBAN</th>
                  <th>Reference</th>
                  <th>Status</th>
                  <th className="text-right">Amount</th>
                </tr>
              </thead>
              <tbody>
                {transfers.map((t, idx) => {
                  const id = t.transferId || t.id;
                  const date = t.createdAt || t.executionDateTime || t.date;
                  const recipientName = t.recipientName || t.creditorName || '';
                  const iban = t.iban || t.creditorAccount?.identification || '';
                  const ref = t.reference || '';
                  const status = t.status || 'pending';
                  const amount = t.amount?.amount || t.amount || 0;
                  const currency = t.amount?.currency || t.currency || 'USD';

                  return (
                    <tr key={id || idx}>
                      <td>{formatDate(date)}</td>
                      <td>{recipientName}</td>
                      <td style={{ fontFamily: 'monospace', fontSize: '0.85em' }}>
                        {iban ? `${iban.slice(0, 8)}...` : ''}
                      </td>
                      <td>{ref}</td>
                      <td>
                        <span className={`badge badge-${status.toLowerCase() === 'completed' ? 'completed' : status.toLowerCase() === 'rejected' || status.toLowerCase() === 'failed' ? 'rejected' : 'pending'}`}>
                          {status}
                        </span>
                      </td>
                      <td className="text-right">{formatCurrency(amount, currency)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
