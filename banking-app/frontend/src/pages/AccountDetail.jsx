import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
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

const PAGE_SIZE = 10;

export default function AccountDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [account, setAccount] = useState(null);
  const [transactions, setTransactions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [txnLoading, setTxnLoading] = useState(false);
  const [error, setError] = useState(null);
  const [page, setPage] = useState(1);
  const [totalCount, setTotalCount] = useState(0);

  // Filters
  const [fromDate, setFromDate] = useState('');
  const [toDate, setToDate] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');

  useEffect(() => {
    async function fetchAccount() {
      try {
        setLoading(true);
        const res = await banking.getAccount(id);
        setAccount(res?.account || res?.data || res);
      } catch (err) {
        setError(err.message || 'Failed to load account details');
      } finally {
        setLoading(false);
      }
    }
    fetchAccount();
  }, [id]);

  useEffect(() => {
    fetchTransactions();
  }, [id, page, fromDate, toDate, typeFilter]);

  async function fetchTransactions() {
    try {
      setTxnLoading(true);
      const params = {
        page,
        limit: PAGE_SIZE,
      };
      if (fromDate) params.fromDate = fromDate;
      if (toDate) params.toDate = toDate;
      if (typeFilter !== 'all') params.type = typeFilter;

      const res = await banking.getTransactions(id, params);
      const txns = Array.isArray(res) ? res : (res?.transactions || res?.data || []);
      const total = res?.totalCount || res?.total || txns.length;
      setTransactions(txns);
      setTotalCount(total);
    } catch (err) {
      setError(err.message || 'Failed to load transactions');
    } finally {
      setTxnLoading(false);
    }
  }

  function handleFilter(e) {
    e.preventDefault();
    setPage(1);
    fetchTransactions();
  }

  const totalPages = Math.max(1, Math.ceil(totalCount / PAGE_SIZE));

  const currency = account?.currency || account?.balance?.currency || 'USD';
  const balance = account?.balance?.amount || account?.currentBalance || account?.balance || 0;
  const name = account?.name || account?.accountName || account?.nickname || 'Account';
  const type = account?.accountType || account?.type || 'Checking';
  const acctNum = account?.accountNumber || account?.identification || '';

  return (
    <div className="page">
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
          <button className="btn btn-outline" onClick={() => navigate('/accounts')}>
            ← Back
          </button>
          <h1 className="page-title" style={{ margin: 0 }}>Account Details</h1>
        </div>
      </div>

      {error && (
        <div className="alert alert-error">
          <span>⚠️ {error}</span>
        </div>
      )}

      {/* Account Info Card */}
      <div className="detail-card">
        {loading ? (
          <>
            <Skeleton height="24px" width="40%" />
            <Skeleton height="40px" width="50%" style={{ marginTop: '12px' }} />
            <Skeleton height="16px" width="30%" style={{ marginTop: '12px' }} />
          </>
        ) : account ? (
          <>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <div className="account-name" style={{ fontSize: '1.25rem' }}>{name}</div>
                <span className="badge badge-checking" style={{ marginTop: '4px' }}>{type}</span>
              </div>
              <div style={{ textAlign: 'right' }}>
                <div className="balance-label">Current Balance</div>
                <div style={{ fontSize: '2rem', fontWeight: '700', color: '#1a2744' }}>
                  {formatCurrency(balance, currency)}
                </div>
              </div>
            </div>
            <div style={{ marginTop: '16px', display: 'flex', gap: '32px', flexWrap: 'wrap' }}>
              {acctNum && (
                <div>
                  <div className="balance-label">Account Number</div>
                  <div>****{acctNum.slice(-4)}</div>
                </div>
              )}
              {account.sortCode && (
                <div>
                  <div className="balance-label">Sort Code</div>
                  <div>{account.sortCode}</div>
                </div>
              )}
              {(account.iban || account.IBAN) && (
                <div>
                  <div className="balance-label">IBAN</div>
                  <div>{account.iban || account.IBAN}</div>
                </div>
              )}
            </div>
          </>
        ) : null}
      </div>

      {/* Transaction Filters */}
      <section className="section">
        <h2 className="section-title">Transactions</h2>
        <form className="filter-form" onSubmit={handleFilter}>
          <div className="form-row">
            <div className="form-group">
              <label className="form-label">From Date</label>
              <input
                type="date"
                className="form-input"
                value={fromDate}
                onChange={(e) => setFromDate(e.target.value)}
              />
            </div>
            <div className="form-group">
              <label className="form-label">To Date</label>
              <input
                type="date"
                className="form-input"
                value={toDate}
                onChange={(e) => setToDate(e.target.value)}
              />
            </div>
            <div className="form-group">
              <label className="form-label">Type</label>
              <select
                className="form-input"
                value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value)}
              >
                <option value="all">All</option>
                <option value="debit">Debit</option>
                <option value="credit">Credit</option>
              </select>
            </div>
            <div className="form-group" style={{ alignSelf: 'flex-end' }}>
              <button type="submit" className="btn btn-primary">
                Filter
              </button>
            </div>
          </div>
        </form>

        {txnLoading ? (
          <div>
            {[1, 2, 3, 4, 5].map((i) => (
              <Skeleton key={i} height="44px" style={{ marginBottom: '4px' }} />
            ))}
          </div>
        ) : transactions.length === 0 ? (
          <div className="empty-state">No transactions found.</div>
        ) : (
          <>
            <div className="table-wrapper">
              <table className="table">
                <thead>
                  <tr>
                    <th>Date</th>
                    <th>Description</th>
                    <th className="table-col-hide-mobile">Merchant</th>
                    <th className="table-col-hide-mobile">Category</th>
                    <th className="text-right">Amount</th>
                  </tr>
                </thead>
                <tbody>
                  {transactions.map((txn, idx) => {
                    const date = txn.transaction_date || txn.valueDateTime || txn.bookingDateTime || txn.date;
                    const desc = txn.transactionInformation || txn.description || txn.narrative || 'Transaction';
                    const merchant = txn.merchant || txn.merchantName || txn.creditorName || '';
                    const category = txn.transactionCode || txn.category || '';
                    const amount = txn.amount?.amount || txn.amount || 0;
                    const cur = txn.amount?.currency || txn.currency || currency;
                    const creditDebit = txn.creditDebitIndicator || txn.type;
                    const isCredit = creditDebit === 'Credit' || creditDebit === 'CREDIT';
                    const sign = isCredit ? '+' : '-';
                    const absAmount = Math.abs(parseFloat(amount));

                    return (
                      <tr key={txn.transactionId || txn.id || idx}>
                        <td>{formatDate(date)}</td>
                        <td>{desc}</td>
                        <td className="table-col-hide-mobile">{merchant}</td>
                        <td className="table-col-hide-mobile">
                          {category && <span className="badge badge-neutral">{category}</span>}
                        </td>
                        <td className={`text-right amount ${isCredit ? 'amount-credit' : 'amount-debit'}`}>
                          {sign}{formatCurrency(absAmount, cur)}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            <div className="pagination">
              <button
                className="btn btn-outline"
                disabled={page <= 1}
                onClick={() => setPage((p) => p - 1)}
              >
                ← Prev
              </button>
              <span className="pagination-info">
                Page {page} of {totalPages}
              </span>
              <button
                className="btn btn-outline"
                disabled={page >= totalPages}
                onClick={() => setPage((p) => p + 1)}
              >
                Next →
              </button>
            </div>
          </>
        )}
      </section>
    </div>
  );
}
