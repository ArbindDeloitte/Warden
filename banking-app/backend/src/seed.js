/**
 * seed.js — Populates the database with realistic demo data.
 * Only runs when the users table is empty (idempotent).
 */
import { v4 as uuidv4 } from 'uuid';

export function seedDatabase(db) {
  const existingUsers = db.prepare('SELECT COUNT(*) as count FROM users').get();
  if (existingUsers.count > 0) {
    console.log('Database already seeded, skipping...');
    return;
  }

  console.log('Seeding database with demo data...');

  // ── Demo user ───────────────────────────────────────────────────────────────
  const userResult = db
    .prepare("INSERT INTO users (okta_sub, email, name) VALUES (?, ?, ?)")
    .run('demo-user-seed', 'demo@bankingapp.com', 'Alex Johnson');

  // node:sqlite returns lastInsertRowid as BigInt
  const userId = Number(userResult.lastInsertRowid);

  // ── Accounts ────────────────────────────────────────────────────────────────
  const checkingId = uuidv4();
  const savingsId  = uuidv4();
  const creditId   = uuidv4();

  const insertAccount = db.prepare(`
    INSERT INTO accounts (id, user_id, account_number, account_name, account_type, currency, balance, available_balance, sort_code, iban, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  insertAccount.run(checkingId, userId, '4021567890', 'Primary Checking', 'checking', 'USD',
    5842.75, 5342.75, '021000021', 'US12BANK00210004021567890', 'active');

  insertAccount.run(savingsId, userId, '4021567891', 'High-Yield Savings', 'savings', 'USD',
    24350.00, 24350.00, '021000021', 'US12BANK00210004021567891', 'active');

  insertAccount.run(creditId, userId, '5510234567', 'Platinum Credit Card', 'credit', 'USD',
    -1250.80, 8749.20, null, null, 'active');

  // ── Helper ──────────────────────────────────────────────────────────────────
  function daysAgo(n) {
    const d = new Date();
    d.setDate(d.getDate() - n);
    return d.toISOString().split('T')[0];
  }

  // ── Transactions (30 total, spread across 90 days) ──────────────────────────
  const txData = [
    // Checking — income
    { accountId: checkingId, amount: 3500.00, type: 'credit', category: 'income',        description: 'Payroll Deposit - Acme Corp',         merchant: 'Acme Corp',         days: 2  },
    { accountId: checkingId, amount: 3500.00, type: 'credit', category: 'income',        description: 'Payroll Deposit - Acme Corp',         merchant: 'Acme Corp',         days: 17 },
    { accountId: checkingId, amount: 3500.00, type: 'credit', category: 'income',        description: 'Payroll Deposit - Acme Corp',         merchant: 'Acme Corp',         days: 32 },
    // Checking — expenses
    { accountId: checkingId, amount: 89.99,  type: 'debit',  category: 'groceries',     description: 'Whole Foods Market',                  merchant: 'Whole Foods',       days: 3  },
    { accountId: checkingId, amount: 15.99,  type: 'debit',  category: 'entertainment', description: 'Netflix Monthly Subscription',         merchant: 'Netflix',           days: 5  },
    { accountId: checkingId, amount: 120.45, type: 'debit',  category: 'shopping',      description: 'Amazon.com Order #112-4567890',        merchant: 'Amazon',            days: 6  },
    { accountId: checkingId, amount: 45.20,  type: 'debit',  category: 'fuel',          description: 'Shell Gas Station',                   merchant: 'Shell Gas',         days: 8  },
    { accountId: checkingId, amount: 7.50,   type: 'debit',  category: 'food',          description: 'Starbucks Coffee',                    merchant: 'Starbucks',         days: 9  },
    { accountId: checkingId, amount: 1200.00,type: 'debit',  category: 'housing',       description: 'Rent Payment - Oak Apartments',        merchant: 'Oak Apartments',    days: 10 },
    { accountId: checkingId, amount: 234.56, type: 'debit',  category: 'utilities',     description: 'Electricity Bill - ConEdison',         merchant: 'ConEdison',         days: 18 },
    { accountId: checkingId, amount: 67.30,  type: 'debit',  category: 'groceries',     description: "Trader Joe's",                        merchant: "Trader Joe's",      days: 20 },
    { accountId: checkingId, amount: 500.00, type: 'debit',  category: 'transfer',      description: 'Transfer to Savings',                  merchant: null,                days: 22 },
    { accountId: checkingId, amount: 12.99,  type: 'debit',  category: 'entertainment', description: 'Spotify Premium',                      merchant: 'Spotify',           days: 25 },
    { accountId: checkingId, amount: 89.00,  type: 'debit',  category: 'dining',        description: 'The Capital Grille',                   merchant: 'The Capital Grille',days: 28 },
    { accountId: checkingId, amount: 275.00, type: 'debit',  category: 'insurance',     description: 'State Farm Auto Insurance',            merchant: 'State Farm',        days: 35 },
    { accountId: checkingId, amount: 55.00,  type: 'debit',  category: 'health',        description: 'CVS Pharmacy',                         merchant: 'CVS Pharmacy',      days: 38 },
    { accountId: checkingId, amount: 44.75,  type: 'debit',  category: 'fuel',          description: 'BP Gas Station',                       merchant: 'BP Gas',            days: 40 },
    { accountId: checkingId, amount: 1200.00,type: 'debit',  category: 'housing',       description: 'Rent Payment - Oak Apartments',        merchant: 'Oak Apartments',    days: 40 },
    { accountId: checkingId, amount: 350.00, type: 'debit',  category: 'shopping',      description: 'Best Buy Electronics',                 merchant: 'Best Buy',          days: 45 },
    { accountId: checkingId, amount: 32.40,  type: 'debit',  category: 'dining',        description: 'Chipotle Mexican Grill',               merchant: 'Chipotle',          days: 52 },
    // Savings — credits
    { accountId: savingsId,  amount: 500.00, type: 'credit', category: 'transfer',      description: 'Transfer from Checking',               merchant: null,                days: 22 },
    { accountId: savingsId,  amount: 1000.00,type: 'credit', category: 'transfer',      description: 'Monthly Savings Transfer',             merchant: null,                days: 30 },
    { accountId: savingsId,  amount: 85.40,  type: 'credit', category: 'interest',      description: 'Monthly Interest Credit',              merchant: 'Chase Bank',        days: 31 },
    { accountId: savingsId,  amount: 1000.00,type: 'credit', category: 'transfer',      description: 'Monthly Savings Transfer',             merchant: null,                days: 60 },
    { accountId: savingsId,  amount: 82.15,  type: 'credit', category: 'interest',      description: 'Monthly Interest Credit',              merchant: 'Chase Bank',        days: 61 },
    // Credit card
    { accountId: creditId,   amount: 320.00, type: 'debit',  category: 'travel',        description: 'Delta Airlines Flight Booking',        merchant: 'Delta Airlines',    days: 4  },
    { accountId: creditId,   amount: 145.60, type: 'debit',  category: 'dining',        description: 'Cheesecake Factory',                   merchant: 'Cheesecake Factory',days: 7  },
    { accountId: creditId,   amount: 78.90,  type: 'debit',  category: 'shopping',      description: 'Target Store Purchase',                merchant: 'Target',            days: 12 },
    { accountId: creditId,   amount: 500.00, type: 'credit', category: 'payment',       description: 'Credit Card Payment',                  merchant: null,                days: 15 },
    { accountId: creditId,   amount: 95.00,  type: 'debit',  category: 'health',        description: 'Gym Membership - Planet Fitness',      merchant: 'Planet Fitness',    days: 19 },
  ];

  const txInsert = db.prepare(`
    INSERT INTO transactions (id, account_id, amount, currency, type, category, description, merchant, status, reference, transaction_date)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'completed', ?, ?)
  `);

  db.exec('BEGIN');
  try {
    for (const tx of txData) {
      txInsert.run(
        uuidv4(), tx.accountId, tx.amount, 'USD', tx.type, tx.category,
        tx.description, tx.merchant ?? null,
        `REF-${Math.random().toString(36).substring(2, 11).toUpperCase()}`,
        daysAgo(tx.days)
      );
    }
    db.exec('COMMIT');
  } catch (e) {
    db.exec('ROLLBACK');
    throw e;
  }

  // ── Payments ────────────────────────────────────────────────────────────────
  const pyInsert = db.prepare(`
    INSERT INTO payments (id, user_id, from_account_id, to_account, to_name, amount, currency, reference, status, initiated_at, approved_at, completed_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  pyInsert.run(uuidv4(), userId, checkingId, '1234567890', 'Jane Smith',      250.00, 'USD', 'Rent share April',  'completed', daysAgo(14)+'T10:30:00Z', daysAgo(14)+'T10:31:00Z', daysAgo(14)+'T10:32:00Z');
  pyInsert.run(uuidv4(), userId, checkingId, '9876543210', 'Bob Williams',     75.50, 'USD', 'Dinner split',      'approved',  daysAgo(3)+'T18:00:00Z',  daysAgo(3)+'T18:05:00Z',  null);
  pyInsert.run(uuidv4(), userId, savingsId,  '5551234567', 'Sarah Connor',   1500.00, 'USD', 'Freelance payment', 'pending',   daysAgo(1)+'T09:00:00Z',  null,                      null);

  // ── Standing Orders ─────────────────────────────────────────────────────────
  const soInsert = db.prepare(`
    INSERT INTO standing_orders (id, user_id, from_account_id, to_account, to_name, amount, currency, frequency, start_date, end_date, next_payment_date, reference, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  soInsert.run(uuidv4(), userId, checkingId, '3334445556', 'Savings Account Transfer',
    500.00, 'USD', 'monthly', daysAgo(90), null, daysAgo(-30), 'Monthly savings', 'active');

  soInsert.run(uuidv4(), userId, checkingId, '7778889990', 'Electric Bill Auto-Pay',
    120.00, 'USD', 'monthly', daysAgo(60), null, daysAgo(-15), 'ConEdison bill', 'active');

  // ── Statements ──────────────────────────────────────────────────────────────
  const stmtInsert = db.prepare(`
    INSERT INTO statements (id, account_id, period_start, period_end, opening_balance, closing_balance, total_credits, total_debits)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  stmtInsert.run(uuidv4(), checkingId, daysAgo(90), daysAgo(60), 4200.00, 5100.00, 3500.00, 2600.00);
  stmtInsert.run(uuidv4(), checkingId, daysAgo(60), daysAgo(30), 5100.00, 4850.00, 3500.00, 3750.00);
  stmtInsert.run(uuidv4(), checkingId, daysAgo(30), daysAgo(0),  4850.00, 5842.75, 3585.40, 2592.65);

  console.log('Database seeded successfully with demo data.');
}
