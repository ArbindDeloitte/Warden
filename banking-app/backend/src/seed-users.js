/**
 * seed-users.js — Seeds realistic data for specific Okta users.
 * Run once: node src/seed-users.js
 * Safe to re-run: skips any user who already has accounts.
 */
import 'dotenv/config';
import { v4 as uuidv4 } from 'uuid';
import { initDatabase, getDb } from './db.js';

function daysAgo(n) {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return d.toISOString().split('T')[0];
}

function daysFromNow(n) {
  const d = new Date();
  d.setDate(d.getDate() + n);
  return d.toISOString().split('T')[0];
}

function seedUser(db, { oktaSub, email, name, accounts, payments, standingOrders, transfers }) {
  // Get or create the user record
  let user = db.prepare('SELECT * FROM users WHERE okta_sub = ?').get(oktaSub);
  if (!user) {
    const r = db.prepare('INSERT INTO users (okta_sub, email, name) VALUES (?, ?, ?)')
      .run(oktaSub, email, name);
    user = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(r.lastInsertRowid));
    console.log(`  Created user: ${email}`);
  } else {
    console.log(`  Found existing user: ${email} (id=${user.id})`);
  }

  // Skip if already has accounts
  const existing = db.prepare('SELECT COUNT(*) as c FROM accounts WHERE user_id = ?').get(user.id);
  if (existing.c > 0) {
    console.log(`  → Already has ${existing.c} account(s), skipping.`);
    return;
  }

  const insertAccount = db.prepare(`
    INSERT INTO accounts (id, user_id, account_number, account_name, account_type, currency, balance, available_balance, sort_code, iban, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const insertTx = db.prepare(`
    INSERT INTO transactions (id, account_id, amount, currency, type, category, description, merchant, status, reference, transaction_date)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'completed', ?, ?)
  `);
  const insertPayment = db.prepare(`
    INSERT INTO payments (id, user_id, from_account_id, to_account, to_name, amount, currency, reference, status, initiated_at, approved_at, completed_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const insertSO = db.prepare(`
    INSERT INTO standing_orders (id, user_id, from_account_id, to_account, to_name, amount, currency, frequency, start_date, end_date, next_payment_date, reference, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const insertTransfer = db.prepare(`
    INSERT INTO external_transfers (id, user_id, from_account_id, to_iban, to_name, to_bank, amount, currency, reference, status, created_at, completed_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const insertStmt = db.prepare(`
    INSERT INTO statements (id, account_id, period_start, period_end, opening_balance, closing_balance, total_credits, total_debits)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const acctIds = {};
  db.exec('BEGIN');
  try {
    // Accounts
    for (const acct of accounts) {
      const id = uuidv4();
      acctIds[acct.key] = id;
      insertAccount.run(id, user.id, acct.number, acct.name, acct.type, acct.currency || 'USD',
        acct.balance, acct.availableBalance, acct.sortCode || null, acct.iban || null, 'active');

      // Statements
      if (acct.statements) {
        for (const s of acct.statements) {
          insertStmt.run(uuidv4(), id, daysAgo(s.fromDays), daysAgo(s.toDays),
            s.openBal, s.closeBal, s.credits, s.debits);
        }
      }

      // Transactions
      if (acct.transactions) {
        for (const tx of acct.transactions) {
          insertTx.run(
            uuidv4(), id, tx.amount, tx.currency || 'USD', tx.type,
            tx.category, tx.description, tx.merchant || null,
            `REF-${Math.random().toString(36).substring(2, 11).toUpperCase()}`,
            daysAgo(tx.days)
          );
        }
      }
    }

    // Payments
    for (const p of (payments || [])) {
      insertPayment.run(
        uuidv4(), user.id, acctIds[p.fromKey],
        p.toAccount, p.toName, p.amount, p.currency || 'USD', p.reference,
        p.status,
        daysAgo(p.daysAgo) + 'T' + (p.time || '10:00:00') + 'Z',
        p.status !== 'pending' ? daysAgo(p.daysAgo) + 'T' + (p.time || '10:05:00') + 'Z' : null,
        p.status === 'completed' ? daysAgo(p.daysAgo) + 'T' + (p.time || '10:10:00') + 'Z' : null
      );
    }

    // Standing orders
    for (const so of (standingOrders || [])) {
      insertSO.run(
        uuidv4(), user.id, acctIds[so.fromKey],
        so.toAccount, so.toName, so.amount, so.currency || 'USD',
        so.frequency, daysAgo(so.startDaysAgo), so.endDate || null,
        daysFromNow(so.nextDaysFromNow || 15), so.reference, so.status || 'active'
      );
    }

    // External transfers
    for (const t of (transfers || [])) {
      insertTransfer.run(
        uuidv4(), user.id, acctIds[t.fromKey],
        t.toIban, t.toName, t.toBank || null, t.amount, t.currency || 'USD',
        t.reference, t.status || 'completed',
        daysAgo(t.daysAgo) + 'T12:00:00Z',
        t.status === 'completed' ? daysAgo(t.daysAgo - 1) + 'T14:00:00Z' : null
      );
    }

    db.exec('COMMIT');
    console.log(`  ✓ Seeded accounts + data for ${email}`);
  } catch (e) {
    db.exec('ROLLBACK');
    throw e;
  }
}

// ── User definitions ──────────────────────────────────────────────────────────

const ARBMISHRA = {
  oktaSub: 'arbmishra@deloitte.com',
  email:   'arbmishra@deloitte.com',
  name:    'Arbind Mishra',
  accounts: [
    {
      key: 'checking', number: '8821001001', name: 'Deloitte Payroll Checking',
      type: 'checking', balance: 12480.55, availableBalance: 11980.55,
      sortCode: '026009593', iban: 'US64SVBK00210002882100100',
      statements: [
        { fromDays: 90, toDays: 60, openBal: 9200.00, closeBal: 10800.00, credits: 7000.00, debits: 5400.00 },
        { fromDays: 60, toDays: 30, openBal: 10800.00, closeBal: 11200.00, credits: 7200.00, debits: 6800.00 },
        { fromDays: 30, toDays: 0,  openBal: 11200.00, closeBal: 12480.55, credits: 7350.00, debits: 6069.45 },
      ],
      transactions: [
        { amount: 7000.00, type: 'credit', category: 'income',        description: 'Deloitte Salary — October',       merchant: 'Deloitte',            days: 1  },
        { amount: 7000.00, type: 'credit', category: 'income',        description: 'Deloitte Salary — September',     merchant: 'Deloitte',            days: 16 },
        { amount: 7000.00, type: 'credit', category: 'income',        description: 'Deloitte Salary — August',        merchant: 'Deloitte',            days: 46 },
        { amount: 2500.00, type: 'debit',  category: 'housing',       description: 'Mortgage — First National Bank',  merchant: 'First National',      days: 3  },
        { amount: 350.00,  type: 'debit',  category: 'transfer',      description: 'Transfer to High-Yield Savings',  merchant: null,                  days: 4  },
        { amount: 189.99,  type: 'debit',  category: 'shopping',      description: 'Amazon Order #D48-2291044',       merchant: 'Amazon',              days: 5  },
        { amount: 12.99,   type: 'debit',  category: 'entertainment', description: 'Netflix Monthly',                  merchant: 'Netflix',             days: 6  },
        { amount: 15.99,   type: 'debit',  category: 'entertainment', description: 'Spotify Premium',                  merchant: 'Spotify',             days: 6  },
        { amount: 72.40,   type: 'debit',  category: 'groceries',     description: 'Whole Foods Market',               merchant: 'Whole Foods',         days: 7  },
        { amount: 340.00,  type: 'debit',  category: 'utilities',     description: 'PG&E Electricity & Gas',           merchant: 'PG&E',                days: 8  },
        { amount: 55.00,   type: 'debit',  category: 'dining',        description: 'Nobu Restaurant',                  merchant: 'Nobu',                days: 9  },
        { amount: 18.50,   type: 'debit',  category: 'food',          description: 'Starbucks',                        merchant: 'Starbucks',           days: 10 },
        { amount: 490.00,  type: 'debit',  category: 'insurance',     description: 'Geico Auto Insurance',             merchant: 'Geico',               days: 12 },
        { amount: 38.00,   type: 'debit',  category: 'fuel',          description: 'Chevron Gas Station',              merchant: 'Chevron',             days: 14 },
        { amount: 85.00,   type: 'debit',  category: 'health',        description: 'CVS Pharmacy — Prescription',      merchant: 'CVS Pharmacy',        days: 15 },
        { amount: 2500.00, type: 'debit',  category: 'housing',       description: 'Mortgage — First National Bank',  merchant: 'First National',      days: 33 },
        { amount: 350.00,  type: 'debit',  category: 'transfer',      description: 'Transfer to High-Yield Savings',  merchant: null,                  days: 34 },
        { amount: 234.00,  type: 'debit',  category: 'shopping',      description: 'Best Buy — MacBook Accessories',  merchant: 'Best Buy',            days: 37 },
        { amount: 22.00,   type: 'debit',  category: 'food',          description: 'Chipotle',                         merchant: 'Chipotle',            days: 40 },
        { amount: 120.00,  type: 'debit',  category: 'dining',        description: 'Nobu Restaurant — Team Dinner',   merchant: 'Nobu',                days: 45 },
      ],
    },
    {
      key: 'savings', number: '8821001002', name: 'High-Yield Savings',
      type: 'savings', balance: 52750.00, availableBalance: 52750.00,
      sortCode: '026009593', iban: 'US64SVBK00210002882100102',
      statements: [
        { fromDays: 90, toDays: 60, openBal: 48000.00, closeBal: 49500.00, credits: 1720.00, debits: 220.00 },
        { fromDays: 60, toDays: 30, openBal: 49500.00, closeBal: 51100.00, credits: 1750.00, debits: 150.00 },
        { fromDays: 30, toDays: 0,  openBal: 51100.00, closeBal: 52750.00, credits: 1760.00, debits: 110.00 },
      ],
      transactions: [
        { amount: 350.00, type: 'credit', category: 'transfer',  description: 'Transfer from Payroll Checking', merchant: null,        days: 4  },
        { amount: 186.20, type: 'credit', category: 'interest',  description: 'Monthly Interest — 4.35% APY',   merchant: 'SecureBank',days: 5  },
        { amount: 350.00, type: 'credit', category: 'transfer',  description: 'Transfer from Payroll Checking', merchant: null,        days: 34 },
        { amount: 184.90, type: 'credit', category: 'interest',  description: 'Monthly Interest — 4.35% APY',   merchant: 'SecureBank',days: 35 },
        { amount: 350.00, type: 'credit', category: 'transfer',  description: 'Transfer from Payroll Checking', merchant: null,        days: 65 },
        { amount: 183.60, type: 'credit', category: 'interest',  description: 'Monthly Interest — 4.35% APY',   merchant: 'SecureBank',days: 66 },
      ],
    },
    {
      key: 'credit', number: '5521009900', name: 'Deloitte Platinum Visa',
      type: 'credit', balance: -4210.80, availableBalance: 20789.20,
      transactions: [
        { amount: 1850.00, type: 'debit',  category: 'travel',        description: 'United Airlines — NYC→SFO Round Trip', merchant: 'United Airlines',   days: 2  },
        { amount: 320.00,  type: 'debit',  category: 'travel',        description: 'Marriott Bonvoy — 2 nights SF',          merchant: 'Marriott',          days: 3  },
        { amount: 65.40,   type: 'debit',  category: 'dining',        description: 'Bix Restaurant San Francisco',           merchant: 'Bix Restaurant',    days: 4  },
        { amount: 145.80,  type: 'debit',  category: 'shopping',      description: 'Apple Store — AirPods Pro',              merchant: 'Apple Store',       days: 6  },
        { amount: 38.50,   type: 'debit',  category: 'dining',        description: 'Blue Bottle Coffee',                     merchant: 'Blue Bottle',       days: 7  },
        { amount: 2000.00, type: 'credit', category: 'payment',       description: 'Credit Card Payment — Thank You',        merchant: null,                days: 10 },
        { amount: 290.00,  type: 'debit',  category: 'shopping',      description: 'Nordstrom — Business Attire',            merchant: 'Nordstrom',         days: 18 },
        { amount: 49.99,   type: 'debit',  category: 'entertainment', description: 'Adobe Creative Cloud',                   merchant: 'Adobe',             days: 22 },
        { amount: 178.00,  type: 'debit',  category: 'dining',        description: 'Eleven Madison Park — Client Dinner',   merchant: 'Eleven Madison',    days: 28 },
        { amount: 1500.00, type: 'credit', category: 'payment',       description: 'Credit Card Payment — Thank You',        merchant: null,                days: 40 },
      ],
    },
  ],
  payments: [
    { fromKey: 'checking', toAccount: '2340011122', toName: 'Sarah Mishra',        amount: 1200.00, reference: 'Monthly household transfer', status: 'completed', daysAgo: 5,  time: '09:30:00' },
    { fromKey: 'checking', toAccount: '7788990011', toName: 'Oak Street Properties',amount: 2500.00, reference: 'October rent',               status: 'completed', daysAgo: 3,  time: '08:00:00' },
    { fromKey: 'credit',   toAccount: '0000001234', toName: 'Visa Credit Services', amount: 2000.00, reference: 'CC min payment Oct',         status: 'completed', daysAgo: 10, time: '11:00:00' },
    { fromKey: 'checking', toAccount: '3312445566', toName: 'Ravi Kumar',           amount: 450.00,  reference: 'Conference travel split',    status: 'approved',  daysAgo: 1,  time: '14:00:00' },
    { fromKey: 'savings',  toAccount: '9988776655', toName: 'Investment Portfolio', amount: 5000.00, reference: 'Q4 investment contribution', status: 'pending',   daysAgo: 0,  time: '10:00:00' },
  ],
  standingOrders: [
    { fromKey: 'checking', toAccount: '3334445556', toName: 'High-Yield Savings',    amount: 350.00,  frequency: 'monthly',  startDaysAgo: 180, nextDaysFromNow: 28, reference: 'Auto savings transfer' },
    { fromKey: 'checking', toAccount: '8899001122', toName: 'First National Mortgage',amount: 2500.00, frequency: 'monthly',  startDaysAgo: 365, nextDaysFromNow: 26, reference: 'Mortgage payment Oct' },
    { fromKey: 'checking', toAccount: '5566778899', toName: 'Planet Fitness',         amount: 24.99,   frequency: 'monthly',  startDaysAgo: 90,  nextDaysFromNow: 20, reference: 'Gym membership' },
    { fromKey: 'checking', toAccount: '2244668800', toName: 'Deloitte 401k',          amount: 700.00,  frequency: 'monthly',  startDaysAgo: 365, nextDaysFromNow: 15, reference: 'Retirement contribution' },
  ],
  transfers: [
    { fromKey: 'savings', toIban: 'GB29NWBK60161331926819', toName: 'HSBC London Account',   toBank: 'HSBC UK',      amount: 3500.00, currency: 'USD', reference: 'London project expenses Q3', status: 'completed', daysAgo: 45 },
    { fromKey: 'savings', toIban: 'DE89370400440532013000', toName: 'Deutsche Bank Frankfurt', toBank: 'Deutsche Bank',amount: 2000.00, currency: 'USD', reference: 'Conference registration',    status: 'completed', daysAgo: 20 },
    { fromKey: 'checking',toIban: 'IN60HDFC0000001234567890',toName: 'HDFC Bank India',      toBank: 'HDFC Bank',    amount: 1500.00, currency: 'USD', reference: 'Family support October',     status: 'processing',daysAgo: 2  },
  ],
};

const ARBTEST = {
  oktaSub: 'arbtest@deloitte.com',
  email:   'arbtest@deloitte.com',
  name:    'Arbind Test',
  accounts: [
    {
      key: 'checking', number: '9910002001', name: 'Primary Checking',
      type: 'checking', balance: 4285.30, availableBalance: 3785.30,
      sortCode: '026009593', iban: 'US64SVBK00210009910002001',
      statements: [
        { fromDays: 90, toDays: 60, openBal: 2800.00, closeBal: 3500.00, credits: 3800.00, debits: 3100.00 },
        { fromDays: 60, toDays: 30, openBal: 3500.00, closeBal: 3900.00, credits: 3800.00, debits: 3400.00 },
        { fromDays: 30, toDays: 0,  openBal: 3900.00, closeBal: 4285.30, credits: 3850.00, debits: 3464.70 },
      ],
      transactions: [
        { amount: 3800.00, type: 'credit', category: 'income',        description: 'Deloitte Salary — October',       merchant: 'Deloitte',      days: 1  },
        { amount: 1100.00, type: 'debit',  category: 'housing',       description: 'Apartment Rent — Harbor View',    merchant: 'Harbor View',   days: 2  },
        { amount: 250.00,  type: 'debit',  category: 'transfer',      description: 'Transfer to Savings',             merchant: null,            days: 3  },
        { amount: 67.80,   type: 'debit',  category: 'groceries',     description: 'Trader Joe\'s',                   merchant: 'Trader Joe\'s', days: 4  },
        { amount: 15.99,   type: 'debit',  category: 'entertainment', description: 'Netflix',                         merchant: 'Netflix',       days: 5  },
        { amount: 9.99,    type: 'debit',  category: 'entertainment', description: 'Spotify',                         merchant: 'Spotify',       days: 5  },
        { amount: 42.00,   type: 'debit',  category: 'fuel',          description: 'BP Gas Station',                  merchant: 'BP Gas',        days: 7  },
        { amount: 28.50,   type: 'debit',  category: 'dining',        description: 'Chipotle',                        merchant: 'Chipotle',      days: 8  },
        { amount: 165.00,  type: 'debit',  category: 'utilities',     description: 'ConEdison Electric Bill',         merchant: 'ConEdison',     days: 9  },
        { amount: 55.00,   type: 'debit',  category: 'health',        description: 'Walgreens Pharmacy',              merchant: 'Walgreens',     days: 11 },
        { amount: 3800.00, type: 'credit', category: 'income',        description: 'Deloitte Salary — September',    merchant: 'Deloitte',      days: 16 },
        { amount: 1100.00, type: 'debit',  category: 'housing',       description: 'Apartment Rent — Harbor View',   merchant: 'Harbor View',   days: 17 },
        { amount: 250.00,  type: 'debit',  category: 'transfer',      description: 'Transfer to Savings',             merchant: null,            days: 18 },
        { amount: 89.99,   type: 'debit',  category: 'shopping',      description: 'Amazon Order',                    merchant: 'Amazon',        days: 20 },
        { amount: 18.00,   type: 'debit',  category: 'food',          description: 'Starbucks',                       merchant: 'Starbucks',     days: 22 },
        { amount: 75.00,   type: 'debit',  category: 'dining',        description: 'The Cheesecake Factory',          merchant: 'Cheesecake Factory', days: 25 },
        { amount: 3800.00, type: 'credit', category: 'income',        description: 'Deloitte Salary — August',       merchant: 'Deloitte',      days: 46 },
        { amount: 1100.00, type: 'debit',  category: 'housing',       description: 'Apartment Rent — Harbor View',   merchant: 'Harbor View',   days: 47 },
      ],
    },
    {
      key: 'savings', number: '9910002002', name: 'Emergency Fund Savings',
      type: 'savings', balance: 9850.00, availableBalance: 9850.00,
      sortCode: '026009593', iban: 'US64SVBK00210009910002002',
      statements: [
        { fromDays: 90, toDays: 60, openBal: 8500.00, closeBal: 8870.00, credits: 550.00, debits: 180.00 },
        { fromDays: 60, toDays: 30, openBal: 8870.00, closeBal: 9340.00, credits: 500.00, debits: 30.00 },
        { fromDays: 30, toDays: 0,  openBal: 9340.00, closeBal: 9850.00, credits: 510.00, debits: 0.00 },
      ],
      transactions: [
        { amount: 250.00, type: 'credit', category: 'transfer',  description: 'Transfer from Checking',         merchant: null,         days: 3  },
        { amount: 28.40,  type: 'credit', category: 'interest',  description: 'Monthly Interest — 3.50% APY',   merchant: 'SecureBank', days: 5  },
        { amount: 250.00, type: 'credit', category: 'transfer',  description: 'Transfer from Checking',         merchant: null,         days: 18 },
        { amount: 27.90,  type: 'credit', category: 'interest',  description: 'Monthly Interest — 3.50% APY',   merchant: 'SecureBank', days: 35 },
        { amount: 250.00, type: 'credit', category: 'transfer',  description: 'Transfer from Checking',         merchant: null,         days: 48 },
        { amount: 27.10,  type: 'credit', category: 'interest',  description: 'Monthly Interest — 3.50% APY',   merchant: 'SecureBank', days: 65 },
      ],
    },
    {
      key: 'credit', number: '5599001234', name: 'Visa Cashback Card',
      type: 'credit', balance: -1340.60, availableBalance: 8659.40,
      transactions: [
        { amount: 320.00, type: 'debit',  category: 'travel',   description: 'Airbnb — Weekend Getaway',   merchant: 'Airbnb',      days: 3  },
        { amount: 78.90,  type: 'debit',  category: 'shopping', description: 'Target',                      merchant: 'Target',      days: 5  },
        { amount: 42.50,  type: 'debit',  category: 'dining',   description: 'Olive Garden',                merchant: 'Olive Garden',days: 8  },
        { amount: 199.00, type: 'debit',  category: 'shopping', description: 'Zara Clothing',               merchant: 'Zara',        days: 12 },
        { amount: 700.00, type: 'credit', category: 'payment',  description: 'Credit Card Payment',         merchant: null,          days: 15 },
        { amount: 95.20,  type: 'debit',  category: 'shopping', description: 'Amazon Order',                merchant: 'Amazon',      days: 20 },
        { amount: 55.00,  type: 'debit',  category: 'health',   description: 'Planet Fitness Membership',   merchant: 'Planet Fitness', days: 22 },
        { amount: 350.00, type: 'debit',  category: 'travel',   description: 'Southwest Airlines Ticket',   merchant: 'Southwest',   days: 30 },
        { amount: 600.00, type: 'credit', category: 'payment',  description: 'Credit Card Payment',         merchant: null,          days: 40 },
      ],
    },
  ],
  payments: [
    { fromKey: 'checking', toAccount: '1122334455', toName: 'Mike Chen',           amount: 85.00,  reference: 'Lunch split last week',     status: 'completed', daysAgo: 4,  time: '13:00:00' },
    { fromKey: 'checking', toAccount: '5544332211', toName: 'Harbor View Mgmt',   amount: 1100.00,reference: 'November rent',              status: 'pending',   daysAgo: 0,  time: '09:00:00' },
    { fromKey: 'credit',   toAccount: '0000005678', toName: 'Visa Card Services', amount: 700.00, reference: 'Credit card payment Oct',    status: 'completed', daysAgo: 15, time: '10:00:00' },
    { fromKey: 'checking', toAccount: '6677889900', toName: 'Priya Singh',        amount: 200.00, reference: 'Team outing share',          status: 'approved',  daysAgo: 2,  time: '16:00:00' },
  ],
  standingOrders: [
    { fromKey: 'checking', toAccount: '3334445556', toName: 'Emergency Fund Savings', amount: 250.00, frequency: 'monthly', startDaysAgo: 120, nextDaysFromNow: 25, reference: 'Monthly savings' },
    { fromKey: 'checking', toAccount: '8877665544', toName: 'Harbor View Mgmt',       amount: 1100.00,frequency: 'monthly', startDaysAgo: 180, nextDaysFromNow: 22, reference: 'Rent auto-pay' },
    { fromKey: 'checking', toAccount: '2255447788', toName: 'Planet Fitness',         amount: 24.99,  frequency: 'monthly', startDaysAgo: 60,  nextDaysFromNow: 18, reference: 'Gym membership' },
  ],
  transfers: [
    { fromKey: 'savings', toIban: 'IN60HDFC0000009876543210', toName: 'HDFC Bank India', toBank: 'HDFC Bank', amount: 1000.00, currency: 'USD', reference: 'Family remittance September', status: 'completed', daysAgo: 30 },
    { fromKey: 'savings', toIban: 'IN60HDFC0000009876543210', toName: 'HDFC Bank India', toBank: 'HDFC Bank', amount: 1000.00, currency: 'USD', reference: 'Family remittance October',   status: 'processing',daysAgo: 2  },
  ],
};

// ── Run ───────────────────────────────────────────────────────────────────────
initDatabase();
const db = getDb();

console.log('\nSeeding users...\n');
seedUser(db, ARBMISHRA);
console.log();
seedUser(db, ARBTEST);
console.log('\nDone.\n');
