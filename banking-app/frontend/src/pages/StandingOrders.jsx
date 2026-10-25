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
  toAccount: '',
  toName: '',
  amount: '',
  currency: 'USD',
  frequency: 'monthly',
  startDate: '',
  endDate: '',
  reference: '',
};

export default function StandingOrders() {
  const [accounts, setAccounts] = useState([]);
  const [standingOrders, setStandingOrders] = useState([]);
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
      const [accts, sos] = await Promise.all([
        banking.getAccounts().catch(() => []),
        banking.getStandingOrders().catch(() => []),
      ]);
      setAccounts(Array.isArray(accts) ? accts : (accts?.accounts || accts?.data || []));
      setStandingOrders(Array.isArray(sos) ? sos : (sos?.standingOrders || sos?.data || []));
    } catch (err) {
      setError(err.message || 'Failed to load standing orders');
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
    if (!form.startDate) return setFormError('Please select a start date');

    try {
      setSubmitting(true);
      await banking.createStandingOrder({
        fromAccountId: form.fromAccountId,
        toAccount: form.toAccount,
        toName: form.toName,
        amount: { amount: parseFloat(form.amount), currency: form.currency },
        frequency: form.frequency,
        startDate: form.startDate,
        endDate: form.endDate || undefined,
        reference: form.reference,
      });
      setSuccess('Standing order created successfully!');
      setForm(INITIAL_FORM);
      await fetchData();
    } catch (err) {
      setFormError(err.message || 'Failed to create standing order');
    } finally {
      setSubmitting(false);
    }
  }

  async function handlePauseResume(so) {
    const soId = so.standingOrderId || so.id;
    const newStatus = so.status?.toLowerCase() === 'active' ? 'paused' : 'active';
    try {
      await banking.updateStandingOrder(soId, { status: newStatus });
      setSuccess(`Standing order ${newStatus === 'active' ? 'resumed' : 'paused'}.`);
      await fetchData();
    } catch (err) {
      setError(err.message || 'Failed to update standing order');
    }
  }

  async function handleCancel(soId) {
    if (!window.confirm('Are you sure you want to cancel this standing order?')) return;
    try {
      await banking.cancelStandingOrder(soId);
      setSuccess('Standing order cancelled.');
      await fetchData();
    } catch (err) {
      setError(err.message || 'Failed to cancel standing order');
    }
  }

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Standing Orders</h1>
        <p className="page-subtitle">Set up and manage recurring payments</p>
      </div>

      {error && (
        <div className="alert alert-error">
          <span>⚠️ {error}</span>
        </div>
      )}

      {/* Create Form */}
      <section className="section">
        <h2 className="section-title">Create Standing Order</h2>
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
                </select>
              </div>
              <div className="form-group">
                <label className="form-label">Frequency *</label>
                <select
                  name="frequency"
                  className="form-input"
                  value={form.frequency}
                  onChange={handleChange}
                >
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly</option>
                  <option value="monthly">Monthly</option>
                  <option value="quarterly">Quarterly</option>
                </select>
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label className="form-label">Start Date *</label>
                <input
                  type="date"
                  name="startDate"
                  className="form-input"
                  value={form.startDate}
                  onChange={handleChange}
                  required
                />
              </div>
              <div className="form-group">
                <label className="form-label">End Date (optional)</label>
                <input
                  type="date"
                  name="endDate"
                  className="form-input"
                  value={form.endDate}
                  onChange={handleChange}
                />
              </div>
            </div>

            <div style={{ marginTop: '16px' }}>
              <button type="submit" className="btn btn-primary" disabled={submitting}>
                {submitting ? 'Creating...' : 'Create Standing Order'}
              </button>
            </div>
          </form>
        </div>
      </section>

      {/* Active Standing Orders */}
      <section className="section">
        <h2 className="section-title">Active Standing Orders</h2>
        {loading ? (
          <div>
            {[1, 2, 3].map((i) => (
              <Skeleton key={i} height="44px" style={{ marginBottom: '4px' }} />
            ))}
          </div>
        ) : standingOrders.length === 0 ? (
          <div className="empty-state">No standing orders found.</div>
        ) : (
          <div className="table-wrapper">
            <table className="table">
              <thead>
                <tr>
                  <th>To</th>
                  <th>Amount</th>
                  <th>Frequency</th>
                  <th>Next Payment</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {standingOrders.map((so, idx) => {
                  const soId = so.standingOrderId || so.id;
                  const toName = so.creditorAccount?.name || so.toName || so.recipientName || '';
                  const amount = so.firstPaymentAmount?.amount || so.amount?.amount || so.amount || 0;
                  const currency = so.firstPaymentAmount?.currency || so.amount?.currency || so.currency || 'USD';
                  const freq = so.frequency || so.paymentFrequency || '';
                  const nextPayment = so.nextPaymentDateTime || so.nextPaymentDate;
                  const status = so.status || 'active';
                  const isActive = status.toLowerCase() === 'active';

                  return (
                    <tr key={soId || idx}>
                      <td>{toName}</td>
                      <td>{formatCurrency(amount, currency)}</td>
                      <td style={{ textTransform: 'capitalize' }}>{freq}</td>
                      <td>{formatDate(nextPayment)}</td>
                      <td>
                        <span className={`badge ${isActive ? 'badge-completed' : 'badge-pending'}`}>
                          {status}
                        </span>
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: '8px' }}>
                          <button
                            className="btn btn-sm btn-outline"
                            onClick={() => handlePauseResume(so)}
                          >
                            {isActive ? 'Pause' : 'Resume'}
                          </button>
                          <button
                            className="btn btn-sm btn-danger"
                            onClick={() => handleCancel(soId)}
                          >
                            Cancel
                          </button>
                        </div>
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
