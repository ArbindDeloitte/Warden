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

function statusBadgeClass(status) {
  const s = (status || '').toLowerCase();
  if (s === 'pending') return 'badge-pending';
  if (s === 'approved') return 'badge-approved';
  if (s === 'completed') return 'badge-completed';
  if (s === 'rejected' || s === 'failed') return 'badge-rejected';
  return 'badge-neutral';
}

function Skeleton({ width = '100%', height = '20px', style = {} }) {
  return <div className="skeleton" style={{ width, height, ...style }} />;
}

const INITIAL_FORM = {
  fromAccountId: '',
  toAccount: '',
  toName: '',
  amount: '',
  currency: 'USD',
  reference: '',
};

export default function Payments() {
  const [accounts, setAccounts] = useState([]);
  const [payments, setPayments] = useState([]);
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
      const [accts, pmts] = await Promise.all([
        banking.getAccounts().catch(() => []),
        banking.getPayments().catch(() => []),
      ]);
      setAccounts(Array.isArray(accts) ? accts : (accts?.accounts || accts?.data || []));
      setPayments(Array.isArray(pmts) ? pmts : (pmts?.payments || pmts?.data || []));
    } catch (err) {
      setError(err.message || 'Failed to load payments');
    } finally {
      setLoading(false);
    }
  }

  function handleChange(e) {
    setForm({ ...form, [e.target.name]: e.target.value });
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setFormError(null);
    setSuccess(null);

    if (!form.fromAccountId) return setFormError('Please select a source account');
    if (!form.toAccount.trim()) return setFormError('Please enter destination account');
    if (!form.toName.trim()) return setFormError('Please enter recipient name');
    if (!form.amount || parseFloat(form.amount) <= 0)
      return setFormError('Amount must be greater than 0');

    try {
      setSubmitting(true);
      await banking.createPayment({
        fromAccountId: form.fromAccountId,
        toAccount: form.toAccount,
        toName: form.toName,
        amount: { amount: parseFloat(form.amount), currency: form.currency },
        reference: form.reference,
      });
      setSuccess('Payment initiated successfully!');
      setForm(INITIAL_FORM);
      await fetchData();
    } catch (err) {
      setFormError(err.message || 'Failed to initiate payment');
    } finally {
      setSubmitting(false);
    }
  }

  async function handleApprove(paymentId) {
    try {
      await banking.approvePayment(paymentId);
      setSuccess('Payment approved!');
      await fetchData();
    } catch (err) {
      setError(err.message || 'Failed to approve payment');
    }
  }

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Payments</h1>
        <p className="page-subtitle">Initiate and manage your payments</p>
      </div>

      {error && (
        <div className="alert alert-error">
          <span>⚠️ {error}</span>
        </div>
      )}

      {/* Initiate Payment Form */}
      <section className="section">
        <h2 className="section-title">Initiate Payment</h2>
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
                <label className="form-label">To Account *</label>
                <input
                  type="text"
                  name="toAccount"
                  className="form-input"
                  placeholder="Account number or IBAN"
                  value={form.toAccount}
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
                  name="toName"
                  className="form-input"
                  placeholder="Recipient name"
                  value={form.toName}
                  onChange={handleChange}
                  required
                />
              </div>
              <div className="form-group">
                <label className="form-label">Reference</label>
                <input
                  type="text"
                  name="reference"
                  className="form-input"
                  placeholder="Payment reference (optional)"
                  value={form.reference}
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
                </select>
              </div>
            </div>
            <div style={{ marginTop: '16px' }}>
              <button type="submit" className="btn btn-primary" disabled={submitting}>
                {submitting ? 'Processing...' : 'Send Payment'}
              </button>
            </div>
          </form>
        </div>
      </section>

      {/* Payment History */}
      <section className="section">
        <h2 className="section-title">Payment History</h2>
        {loading ? (
          <div>
            {[1, 2, 3].map((i) => (
              <Skeleton key={i} height="44px" style={{ marginBottom: '4px' }} />
            ))}
          </div>
        ) : payments.length === 0 ? (
          <div className="empty-state">No payments found.</div>
        ) : (
          <div className="table-wrapper">
            <table className="table">
              <thead>
                <tr>
                  <th>Date</th>
                  <th>To</th>
                  <th className="table-col-hide-mobile">Reference</th>
                  <th>Status</th>
                  <th className="text-right">Amount</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {payments.map((pmt, idx) => {
                  const id = pmt.paymentId || pmt.id;
                  const date = pmt.initiated_at || pmt.createdAt || pmt.instructedDateTime || pmt.date;
                  const toName = pmt.to_name || pmt.creditorAccount?.name || pmt.toName || pmt.recipientName || '';
                  const amount = pmt.instructedAmount?.amount || pmt.amount?.amount || pmt.amount || 0;
                  const currency = pmt.instructedAmount?.currency || pmt.amount?.currency || pmt.currency || 'USD';
                  const status = pmt.status || 'pending';
                  const ref = pmt.reference || pmt.remittanceInfo || '';
                  const isPending = status.toLowerCase() === 'pending';

                  return (
                    <tr key={id || idx}>
                      <td>{formatDate(date)}</td>
                      <td>{toName}</td>
                      <td className="table-col-hide-mobile">{ref}</td>
                      <td>
                        <span className={`badge ${statusBadgeClass(status)}`}>
                          {status}
                        </span>
                      </td>
                      <td className="text-right">{formatCurrency(amount, currency)}</td>
                      <td>
                        {isPending && id && (
                          <button
                            className="btn btn-sm btn-primary"
                            onClick={() => handleApprove(id)}
                          >
                            Approve
                          </button>
                        )}
                      </td>
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
