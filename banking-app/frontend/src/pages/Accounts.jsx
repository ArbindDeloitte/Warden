import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { banking } from '../services/api.js';

function formatCurrency(amount, currency = 'USD') {
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: currency || 'USD',
  }).format(amount || 0);
}

function Skeleton({ width = '100%', height = '20px', style = {} }) {
  return <div className="skeleton" style={{ width, height, ...style }} />;
}

function accountTypeBadge(type) {
  const t = (type || '').toLowerCase();
  if (t.includes('saving')) return 'badge-savings';
  if (t.includes('credit')) return 'badge-credit';
  if (t.includes('loan') || t.includes('mortgage')) return 'badge-loan';
  return 'badge-checking';
}

export default function Accounts() {
  const navigate = useNavigate();
  const [accounts, setAccounts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    async function fetchAccounts() {
      try {
        setLoading(true);
        setError(null);
        const res = await banking.getAccounts();
        const list = Array.isArray(res) ? res : (res?.accounts || res?.data || []);
        setAccounts(list);
      } catch (err) {
        setError(err.message || 'Failed to load accounts');
      } finally {
        setLoading(false);
      }
    }
    fetchAccounts();
  }, []);

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">My Accounts</h1>
        <p className="page-subtitle">Manage and view all your accounts</p>
      </div>

      {error && (
        <div className="alert alert-error">
          <span>⚠️ {error}</span>
        </div>
      )}

      {loading ? (
        <div className="account-cards-grid">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="account-card-full">
              <Skeleton height="20px" width="60%" />
              <Skeleton height="16px" width="40%" style={{ marginTop: '8px' }} />
              <Skeleton height="32px" width="70%" style={{ marginTop: '16px' }} />
              <Skeleton height="16px" width="55%" style={{ marginTop: '12px' }} />
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
            const availableBalance = acct.availableBalance?.amount || acct.availableBalance || balance;
            const currency = acct.balance?.currency || acct.currency || 'USD';
            const name = acct.name || acct.accountName || acct.nickname || 'Account';
            const type = acct.accountType || acct.type || 'Checking';
            const sortCode = acct.sortCode || acct.routingNumber || '';
            const iban = acct.iban || acct.IBAN || '';

            return (
              <div
                key={acctId}
                className="account-card-full clickable"
                onClick={() => navigate(`/accounts/${acctId}`)}
              >
                <div className="account-card-header">
                  <div>
                    <div className="account-name">{name}</div>
                    <span className={`badge ${accountTypeBadge(type)}`}>{type}</span>
                  </div>
                  <div className="account-arrow">›</div>
                </div>

                <div className="account-number-row">
                  <span className="account-number-label">Account No.</span>
                  <span className="account-number">{masked}</span>
                </div>

                {sortCode && (
                  <div className="account-number-row">
                    <span className="account-number-label">Sort Code</span>
                    <span className="account-number">{sortCode}</span>
                  </div>
                )}

                {iban && (
                  <div className="account-number-row">
                    <span className="account-number-label">IBAN</span>
                    <span className="account-number">{iban}</span>
                  </div>
                )}

                <div className="account-balances">
                  <div className="balance-item">
                    <div className="balance-label">Current Balance</div>
                    <div className="balance-amount">{formatCurrency(balance, currency)}</div>
                  </div>
                  <div className="balance-item">
                    <div className="balance-label">Available Balance</div>
                    <div className="balance-amount balance-available">
                      {formatCurrency(availableBalance, currency)}
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
