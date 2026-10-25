/**
 * banking.js — Pure business-logic functions for the banking application.
 *
 * No HTTP / Express here.  All functions accept (db, userId, ...) and return
 * plain objects / arrays.  They are called by both REST routes and MCP tools.
 *
 * Uses node:sqlite (DatabaseSync) which is synchronous — no async/await needed.
 */
import { v4 as uuidv4 } from 'uuid';

// ─────────────────────────────────────────────────────────────────────────────
// Accounts
// ─────────────────────────────────────────────────────────────────────────────

export function getUserAccounts(db, userId) {
  return db
    .prepare("SELECT * FROM accounts WHERE user_id = ? AND status != 'closed' ORDER BY created_at ASC")
    .all(userId);
}

export function getAccountById(db, userId, accountId) {
  return (
    db.prepare('SELECT * FROM accounts WHERE id = ? AND user_id = ?').get(accountId, userId) ?? null
  );
}

export function getAccountBalance(db, userId, accountId) {
  const account = db
    .prepare('SELECT balance, available_balance, currency FROM accounts WHERE id = ? AND user_id = ?')
    .get(accountId, userId);

  if (!account) return null;

  return {
    balance: account.balance,
    availableBalance: account.available_balance,
    currency: account.currency,
  };
}

export function getAccountTransactions(db, userId, accountId, { limit = 50, offset = 0, from, to } = {}) {
  // Verify ownership
  const account = db
    .prepare('SELECT id FROM accounts WHERE id = ? AND user_id = ?')
    .get(accountId, userId);
  if (!account) return null;

  let query = 'SELECT * FROM transactions WHERE account_id = ?';
  const params = [accountId];

  if (from) { query += ' AND transaction_date >= ?'; params.push(from); }
  if (to)   { query += ' AND transaction_date <= ?'; params.push(to); }

  query += ' ORDER BY transaction_date DESC, created_at DESC LIMIT ? OFFSET ?';
  params.push(Number(limit), Number(offset));

  return db.prepare(query).all(...params);
}

export function getAccountStatements(db, userId, accountId) {
  const account = db
    .prepare('SELECT id FROM accounts WHERE id = ? AND user_id = ?')
    .get(accountId, userId);
  if (!account) return null;

  return db
    .prepare('SELECT * FROM statements WHERE account_id = ? ORDER BY period_end DESC')
    .all(accountId);
}

// ─────────────────────────────────────────────────────────────────────────────
// Payments
// ─────────────────────────────────────────────────────────────────────────────

export function getUserPayments(db, userId) {
  return db
    .prepare('SELECT * FROM payments WHERE user_id = ? ORDER BY initiated_at DESC')
    .all(userId);
}

export function createPayment(db, userId, { fromAccountId, toAccount, toName, amount, currency = 'USD', reference }) {
  const account = db
    .prepare("SELECT * FROM accounts WHERE id = ? AND user_id = ? AND status = 'active'")
    .get(fromAccountId, userId);
  if (!account) throw new Error('Source account not found or not active');
  if (amount <= 0) throw new Error('Amount must be greater than zero');
  if (account.available_balance < amount) throw new Error('Insufficient available balance');

  const id = uuidv4();
  db.prepare(`
    INSERT INTO payments (id, user_id, from_account_id, to_account, to_name, amount, currency, reference, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')
  `).run(id, userId, fromAccountId, toAccount, toName, amount, currency, reference ?? null);

  return db.prepare('SELECT * FROM payments WHERE id = ?').get(id);
}

export function approvePayment(db, userId, paymentId) {
  const payment = db
    .prepare('SELECT * FROM payments WHERE id = ? AND user_id = ?')
    .get(paymentId, userId);
  if (!payment) throw new Error('Payment not found');
  if (payment.status !== 'pending') throw new Error(`Payment cannot be approved. Current status: ${payment.status}`);

  const account = db.prepare('SELECT * FROM accounts WHERE id = ?').get(payment.from_account_id);
  if (!account || account.available_balance < payment.amount) throw new Error('Insufficient available balance');

  const now = new Date().toISOString();
  const today = now.split('T')[0];

  db.exec('BEGIN');
  try {
    db.prepare(`
      UPDATE payments SET status = 'approved', approved_at = ?, completed_at = ? WHERE id = ?
    `).run(now, now, paymentId);

    db.prepare(`
      UPDATE accounts SET balance = balance - ?, available_balance = available_balance - ? WHERE id = ?
    `).run(payment.amount, payment.amount, payment.from_account_id);

    db.prepare(`
      INSERT INTO transactions (id, account_id, amount, currency, type, category, description, status, reference, transaction_date)
      VALUES (?, ?, ?, ?, 'debit', 'payment', ?, 'completed', ?, ?)
    `).run(
      uuidv4(), payment.from_account_id, payment.amount, payment.currency,
      `Payment to ${payment.to_name}`, payment.reference ?? null, today
    );
    db.exec('COMMIT');
  } catch (e) {
    db.exec('ROLLBACK');
    throw e;
  }
  return db.prepare('SELECT * FROM payments WHERE id = ?').get(paymentId);
}

// ─────────────────────────────────────────────────────────────────────────────
// Standing Orders
// ─────────────────────────────────────────────────────────────────────────────

export function getUserStandingOrders(db, userId) {
  return db
    .prepare('SELECT * FROM standing_orders WHERE user_id = ? ORDER BY created_at DESC')
    .all(userId);
}

export function createStandingOrder(db, userId, {
  fromAccountId, toAccount, toName, amount, currency = 'USD',
  frequency, startDate, endDate, reference,
}) {
  const account = db
    .prepare("SELECT * FROM accounts WHERE id = ? AND user_id = ? AND status = 'active'")
    .get(fromAccountId, userId);
  if (!account) throw new Error('Source account not found or not active');
  if (amount <= 0) throw new Error('Amount must be greater than zero');

  const validFrequencies = ['daily', 'weekly', 'monthly', 'quarterly'];
  if (!validFrequencies.includes(frequency)) {
    throw new Error(`Invalid frequency. Must be one of: ${validFrequencies.join(', ')}`);
  }

  const id = uuidv4();
  db.prepare(`
    INSERT INTO standing_orders
      (id, user_id, from_account_id, to_account, to_name, amount, currency, frequency, start_date, end_date, next_payment_date, reference, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
  `).run(
    id, userId, fromAccountId, toAccount, toName, amount, currency,
    frequency, startDate, endDate ?? null, startDate, reference ?? null
  );

  return db.prepare('SELECT * FROM standing_orders WHERE id = ?').get(id);
}

export function updateStandingOrder(db, userId, orderId, updates) {
  const order = db
    .prepare('SELECT * FROM standing_orders WHERE id = ? AND user_id = ?')
    .get(orderId, userId);
  if (!order) throw new Error('Standing order not found');
  if (order.status === 'cancelled') throw new Error('Cannot update a cancelled standing order');

  // Map camelCase → snake_case for allowed columns
  const colMap = { amount: 'amount', frequency: 'frequency', endDate: 'end_date', reference: 'reference', status: 'status' };
  const setClauses = [];
  const values = [];

  for (const [key, value] of Object.entries(updates)) {
    const col = colMap[key];
    if (col) { setClauses.push(`${col} = ?`); values.push(value); }
  }

  if (setClauses.length === 0) throw new Error('No valid fields to update');

  values.push(orderId);
  db.prepare(`UPDATE standing_orders SET ${setClauses.join(', ')} WHERE id = ?`).run(...values);

  return db.prepare('SELECT * FROM standing_orders WHERE id = ?').get(orderId);
}

export function cancelStandingOrder(db, userId, orderId) {
  const order = db
    .prepare('SELECT * FROM standing_orders WHERE id = ? AND user_id = ?')
    .get(orderId, userId);
  if (!order) throw new Error('Standing order not found');
  if (order.status === 'cancelled') throw new Error('Standing order is already cancelled');

  db.prepare("UPDATE standing_orders SET status = 'cancelled' WHERE id = ?").run(orderId);
  return db.prepare('SELECT * FROM standing_orders WHERE id = ?').get(orderId);
}

// ─────────────────────────────────────────────────────────────────────────────
// External Transfers
// ─────────────────────────────────────────────────────────────────────────────

export function createExternalTransfer(db, userId, {
  fromAccountId, toIban, toName, toBank, amount, currency = 'USD', reference,
}) {
  const account = db
    .prepare("SELECT * FROM accounts WHERE id = ? AND user_id = ? AND status = 'active'")
    .get(fromAccountId, userId);
  if (!account) throw new Error('Source account not found or not active');
  if (amount <= 0) throw new Error('Amount must be greater than zero');
  if (account.available_balance < amount) throw new Error('Insufficient available balance');

  // Basic IBAN format check (letters + digits, 15-34 chars)
  const cleanIban = toIban.replace(/\s/g, '');
  const ibanRegex = /^[A-Z]{2}\d{2}[A-Z0-9]{1,30}$/;
  if (!ibanRegex.test(cleanIban)) throw new Error('Invalid IBAN format');

  const id = uuidv4();
  const today = new Date().toISOString().split('T')[0];

  db.exec('BEGIN');
  try {
    db.prepare(`
      INSERT INTO external_transfers
        (id, user_id, from_account_id, to_iban, to_name, to_bank, amount, currency, reference, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'processing')
    `).run(id, userId, fromAccountId, cleanIban, toName, toBank ?? null, amount, currency, reference ?? null);

    db.prepare(`
      UPDATE accounts SET balance = balance - ?, available_balance = available_balance - ? WHERE id = ?
    `).run(amount, amount, fromAccountId);

    db.prepare(`
      INSERT INTO transactions (id, account_id, amount, currency, type, category, description, status, reference, transaction_date)
      VALUES (?, ?, ?, ?, 'debit', 'transfer', ?, 'completed', ?, ?)
    `).run(
      uuidv4(), fromAccountId, amount, currency,
      `International Transfer to ${toName} (${cleanIban})`, reference ?? null, today
    );
    db.exec('COMMIT');
  } catch (e) {
    db.exec('ROLLBACK');
    throw e;
  }
  return db.prepare('SELECT * FROM external_transfers WHERE id = ?').get(id);
}
