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

function StatementModal({ statement, onClose }) {
  if (!statement) return null;
  const currency = statement.totalValue?.currency || statement.currency || 'USD';

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h3 className="modal-title">Statement Details</h3>
          <button className="modal-close" onClick={onClose}>✕</button>
        </div>
        <div className="modal-body">
          <div className="statement-detail-grid">
            <div className="statement-detail-item">
              <div className="detail-label">Period</div>
              <div className="detail-value">
                {formatDate(statement.startDateTime || statement.fromDate)} –{' '}
                {formatDate(statement.endDateTime || statement.toDate)}
              </div>
            </div>
            <div className="statement-detail-item">
              <div className="detail-label">Statement ID</div>
              <div className="detail-value">{statement.statementId || statement.id || '—'}</div>
            </div>
            <div className="statement-detail-item">
              <div className="detail-label">Opening Balance</div>
              <div className="detail-value">
                {formatCurrency(
                  statement.statementAmount?.find((a) => a.creditDebitIndicator === 'Credit')?.amount ||
                    statement.openingBalance?.amount ||
                    statement.openingBalance ||
                    0,
                  currency
                )}
              </div>
            </div>
            <div className="statement-detail-item">
              <div className="detail-label">Closing Balance</div>
              <div className="detail-value">
                {formatCurrency(
                  statement.statementAmount?.find((a) => a.type === 'ClosingBooked')?.amount ||
                    statement.closingBalance?.amount ||
                    statement.closingBalance ||
                    0,
                  currency
                )}
              </div>
            </div>
            <div className="statement-detail-item">
              <div className="detail-label">Total Credits</div>
              <div className="detail-value amount-credit">
                {formatCurrency(
                  statement.totalCredits?.amount || statement.totalCredits || 0,
                  currency
                )}
              </div>
            </div>
            <div className="statement-detail-item">
              <div className="detail-label">Total Debits</div>
              <div className="detail-value amount-debit">
                {formatCurrency(
                  statement.totalDebits?.amount || statement.totalDebits || 0,
                  currency
                )}
              </div>
            </div>
          </div>
        </div>
        <div className="modal-footer">
          <button className="btn btn-outline" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

export default function Statements() {
  const [accounts, setAccounts] = useState([]);
  const [statementsByAccount, setStatementsByAccount] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedStatement, setSelectedStatement] = useState(null);

  useEffect(() => {
    fetchData();
  }, []);

  async function fetchData() {
    try {
      setLoading(true);
      setError(null);
      const accts = await banking.getAccounts().catch(() => []);
      const accountList = Array.isArray(accts) ? accts : (accts?.accounts || accts?.data || []);
      setAccounts(accountList);

      const stmtPromises = accountList.map(async (acct) => {
        const acctId = acct.id || acct.accountId;
        try {
          const res = await banking.getStatements(acctId);
          const stmts = Array.isArray(res) ? res : (res?.statements || res?.data || []);
          return { acctId, stmts };
        } catch {
          return { acctId, stmts: [] };
        }
      });

      const results = await Promise.all(stmtPromises);
      const byAccount = {};
      results.forEach(({ acctId, stmts }) => {
        byAccount[acctId] = stmts;
      });
      setStatementsByAccount(byAccount);
    } catch (err) {
      setError(err.message || 'Failed to load statements');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Statements</h1>
        <p className="page-subtitle">View and download your account statements</p>
      </div>

      {error && (
        <div className="alert alert-error">
          <span>⚠️ {error}</span>
        </div>
      )}

      {loading ? (
        <div>
          {[1, 2].map((i) => (
            <div key={i} className="section">
              <Skeleton height="24px" width="200px" />
              <div style={{ marginTop: '12px' }}>
                {[1, 2, 3].map((j) => (
                  <Skeleton key={j} height="44px" style={{ marginBottom: '4px' }} />
                ))}
              </div>
            </div>
          ))}
        </div>
      ) : accounts.length === 0 ? (
        <div className="empty-state">No accounts found.</div>
      ) : (
        accounts.map((acct) => {
          const acctId = acct.id || acct.accountId;
          const name = acct.name || acct.accountName || acct.nickname || 'Account';
          const num = acct.accountNumber || acct.identification || '';
          const statements = statementsByAccount[acctId] || [];

          return (
            <section key={acctId} className="section">
              <div className="section-header">
                <h2 className="section-title">
                  {name} {num ? `(****${num.slice(-4)})` : ''}
                </h2>
                <span className="badge badge-neutral">{statements.length} statement{statements.length !== 1 ? 's' : ''}</span>
              </div>

              {statements.length === 0 ? (
                <div className="empty-state">No statements available for this account.</div>
              ) : (
                <div className="table-wrapper">
                  <table className="table">
                    <thead>
                      <tr>
                        <th>Period</th>
                        <th>Opening Balance</th>
                        <th>Closing Balance</th>
                        <th className="amount-credit">Total Credits</th>
                        <th className="amount-debit">Total Debits</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {statements.map((stmt, idx) => {
                        const stmtId = stmt.statementId || stmt.id || idx;
                        const currency = stmt.currency || 'USD';
                        const openBal = stmt.openingBalance?.amount || stmt.openingBalance || 0;
                        const closeBal = stmt.closingBalance?.amount || stmt.closingBalance || 0;
                        const totalCredits = stmt.totalCredits?.amount || stmt.totalCredits || 0;
                        const totalDebits = stmt.totalDebits?.amount || stmt.totalDebits || 0;
                        const from = stmt.startDateTime || stmt.fromDate;
                        const to = stmt.endDateTime || stmt.toDate;

                        return (
                          <tr key={stmtId}>
                            <td>
                              {formatDate(from)} – {formatDate(to)}
                            </td>
                            <td>{formatCurrency(openBal, currency)}</td>
                            <td>{formatCurrency(closeBal, currency)}</td>
                            <td className="amount-credit">{formatCurrency(totalCredits, currency)}</td>
                            <td className="amount-debit">{formatCurrency(totalDebits, currency)}</td>
                            <td>
                              <button
                                className="btn btn-sm btn-outline"
                                onClick={() => setSelectedStatement({ ...stmt, currency })}
                              >
                                📄 View
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          );
        })
      )}

      {selectedStatement && (
        <StatementModal
          statement={selectedStatement}
          onClose={() => setSelectedStatement(null)}
        />
      )}
    </div>
  );
}
