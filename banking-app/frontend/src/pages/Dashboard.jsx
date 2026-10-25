import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useOktaAuth } from '@okta/okta-react';
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
  return (
    <div
      className="skeleton"
      style={{ width, height, ...style }}
    />
  );
}

function SummaryCard({ label, value, icon, loading }) {
  return (
    <div className="summary-card">
      <div className="summary-card-icon">{icon}</div>
      <div className="summary-card-body">
        <div className="summary-card-label">{label}</div>
        {loading ? (
          <Skeleton height="28px" width="120px" style={{ marginTop: '6px' }} />
        ) : (
          <div className="summary-card-value">{value}</div>
        )}
      </div>
    </div>
  );
}

export default function Dashboard() {
  const { authState } = useOktaAuth();
  const navigate = useNavigate();
  const [accounts, setAccounts] = useState([]);
  const [payments, setPayments] = useState([]);
  const [standingOrders, setStandingOrders] = useState([]);
  const [recentTxns, setRecentTxns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const user = authState?.idToken?.claims || {};
  const userName = user.name || user.given_name || 'there';

  useEffect(() => {
    async function fetchData() {
      try {
        setLoading(true);
        setError(null);

        const [accts, pmts, sos] = await Promise.all([
          banking.getAccounts().catch(() => []),
          banking.getPayments().catch(() => []),
          banking.getStandingOrders().catch(() => []),
        ]);

        const accountList = Array.isArray(accts) ? accts : (accts?.accounts || accts?.data || []);
        const paymentList = Array.isArray(pmts) ? pmts : (pmts?.payments || pmts?.data || []);
        const soList = Array.isArray(sos) ? sos : (sos?.standingOrders || sos?.data || []);

        setAccounts(accountList);
        setPayments(paymentList);
        setStandingOrders(soList);

        // Fetch recent transactions from first few accounts
        const txnPromises = accountList.slice(0, 3).map((acct) =>
          banking.getTransactions(acct.id || acct.accountId, { limit: 10 })
            .then((res) => {
              const txns = Array.isArray(res) ? res : (res?.transactions || res?.data || []);
              return txns.map((t) => ({
                ...t,
                accountName: acct.name || acct.accountName || acct.nickname || 'Account',
              }));
            })
            .catch(() => [])
        );

        const txnResults = await Promise.all(txnPromises);
        const allTxns = txnResults.flat().sort((a, b) => {
          const da = new Date(a.transaction_date || a.valueDateTime || a.bookingDateTime || a.date || 0);
          const db = new Date(b.transaction_date || b.valueDateTime || b.bookingDateTime || b.date || 0);
          return db - da;
        });
        setRecentTxns(allTxns.slice(0, 10));
      } catch (err) {
        setError(err.message || 'Failed to load dashboard data');
      } finally {
        setLoading(false);
      }
    }
    fetchData();
  }, []);

  const totalBalance = accounts.reduce((sum, a) => {
    const bal = a.balance?.amount || a.currentBalance || a.balance || 0;
    return sum + parseFloat(bal);
  }, 0);

  const activeAccountsCount = accounts.length;
  const pendingPaymentsCount = payments.filter(
    (p) => p.status === 'pending' || p.status === 'PENDING'
  ).length;
  const activeSoCount = standingOrders.filter(
    (so) => so.status === 'active' || so.status === 'ACTIVE'
  ).length;

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Welcome back, {userName} 👋</h1>
        <p className="page-subtitle">Here's an overview of your finances</p>
      </div>

      {error && (
        <div className="alert alert-error">
          <span>⚠️ {error}</span>
        </div>
      )}

      {/* Summary Cards */}
      <div className="summary-cards">
        <SummaryCard
          label="Total Balance"
          value={formatCurrency(totalBalance)}
          icon="💰"
          loading={loading}
        />
        <SummaryCard
          label="Active Accounts"
          value={activeAccountsCount}
          icon="💳"
          loading={loading}
        />
        <SummaryCard
          label="Pending Payments"
          value={pendingPaymentsCount}
          icon="⏳"
          loading={loading}
        />
        <SummaryCard
          label="Standing Orders"
          value={activeSoCount}
          icon="🔄"
          loading={loading}
        />
      </div>

      {/* Accounts Section */}
      <section className="section">
        <div className="section-header">
          <h2 className="section-title">My Accounts</h2>
          <button className="btn btn-outline" onClick={() => navigate('/accounts')}>
            View All
          </button>
        </div>
        {loading ? (
          <div className="account-cards-grid">
            {[1, 2, 3].map((i) => (
              <div key={i} className="account-card">
                <Skeleton height="20px" width="60%" />
                <Skeleton height="16px" width="40%" style={{ marginTop: '8px' }} />
                <Skeleton height="32px" width="80%" style={{ marginTop: '16px' }} />
              </div>
            ))}
          </div>
        ) : accounts.length === 0 ? (
          <div className="empty-state">No accounts found.</div>
        ) : (
          <div className="account-cards-grid">
            {accounts.map((acct) => {
              const acctId = acct.id || acct.accountId;
              const acctNum = acct.accountNumber || acct.identification || '';
              const masked = acctNum ? `****${acctNum.slice(-4)}` : '****';
              const balance = acct.balance?.amount || acct.currentBalance || acct.balance || 0;
              const currency = acct.balance?.currency || acct.currency || 'USD';
              const name = acct.name || acct.accountName || acct.nickname || 'Account';
              const type = acct.accountType || acct.type || 'Checking';
              return (
                <div
                  key={acctId}
                  className="account-card clickable"
                  onClick={() => navigate(`/accounts/${acctId}`)}
                >
                  <div className="account-card-top">
                    <div className="account-name">{name}</div>
                    <span className={`badge badge-${(type || '').toLowerCase().replace(/\s+/g, '-')}`}>
                      {type}
                    </span>
                  </div>
                  <div className="account-number">{masked}</div>
                  <div className="account-balance">{formatCurrency(balance, currency)}</div>
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* Recent Transactions */}
      <section className="section">
        <div className="section-header">
          <h2 className="section-title">Recent Transactions</h2>
        </div>
        {loading ? (
          <div className="table-skeleton">
            {[1, 2, 3, 4, 5].map((i) => (
              <Skeleton key={i} height="44px" style={{ marginBottom: '4px' }} />
            ))}
          </div>
        ) : recentTxns.length === 0 ? (
          <div className="empty-state">No recent transactions.</div>
        ) : (
          <div className="table-wrapper">
            <table className="table">
              <thead>
                <tr>
                  <th>Date</th>
                  <th>Description</th>
                  <th className="table-col-hide-mobile">Account</th>
                  <th className="table-col-hide-mobile">Category</th>
                  <th className="text-right">Amount</th>
                </tr>
              </thead>
              <tbody>
                {recentTxns.map((txn, idx) => {
                  const date = txn.transaction_date || txn.valueDateTime || txn.bookingDateTime || txn.date;
                  const desc = txn.transactionInformation || txn.description || txn.narrative || 'Transaction';
                  const amount = txn.amount?.amount || txn.amount || 0;
                  const currency = txn.amount?.currency || txn.currency || 'USD';
                  const creditDebit = txn.creditDebitIndicator || txn.type;
                  const isCredit = creditDebit === 'Credit' || creditDebit === 'CREDIT' || parseFloat(amount) > 0;
                  const category = txn.transactionCode || txn.category || '';
                  const sign = isCredit ? '+' : '-';
                  const absAmount = Math.abs(parseFloat(amount));

                  return (
                    <tr key={txn.transactionId || txn.id || idx}>
                      <td>{formatDate(date)}</td>
                      <td>{desc}</td>
                      <td className="table-col-hide-mobile">{txn.accountName}</td>
                      <td className="table-col-hide-mobile">
                        {category && (
                          <span className="badge badge-neutral">{category}</span>
                        )}
                      </td>
                      <td className={`text-right amount ${isCredit ? 'amount-credit' : 'amount-debit'}`}>
                        {sign}{formatCurrency(absAmount, currency)}
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
