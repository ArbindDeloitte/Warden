import { Router } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { verifyToken, requireGroup } from '../middleware/auth.js';
import { getDb } from '../db.js';

const router = Router();

const IS_ADMIN = [verifyToken, requireGroup('bank-admin')];

// GET /api/admin/users — all users with their accounts
router.get('/users', ...IS_ADMIN, (req, res) => {
  try {
    const db = getDb();
    const users = db.prepare(
      'SELECT id, okta_sub, email, name, created_at FROM users ORDER BY created_at DESC'
    ).all();

    const data = users.map(user => {
      const accounts = db.prepare(
        'SELECT * FROM accounts WHERE user_id = ? ORDER BY created_at ASC'
      ).all(user.id);
      return { ...user, accounts };
    });

    return res.json({ success: true, data });
  } catch (err) {
    console.error('GET /admin/users error:', err);
    return res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// POST /api/admin/accounts/:accountId/adjust — credit or debit a balance
router.post('/accounts/:accountId/adjust', ...IS_ADMIN, (req, res) => {
  try {
    const { amount, type, description } = req.body;

    if (!amount || !type || !['credit', 'debit'].includes(type)) {
      return res.status(400).json({
        success: false,
        error: 'Required: amount (number), type ("credit" | "debit")',
      });
    }

    const parsed = parseFloat(amount);
    if (isNaN(parsed) || parsed <= 0) {
      return res.status(400).json({ success: false, error: 'Amount must be a positive number' });
    }

    const db = getDb();
    const account = db.prepare('SELECT * FROM accounts WHERE id = ?').get(req.params.accountId);
    if (!account) {
      return res.status(404).json({ success: false, error: 'Account not found' });
    }

    // Prevent admins from adjusting their own accounts
    const accountOwner = db.prepare('SELECT okta_sub FROM users WHERE id = ?').get(account.user_id);
    if (accountOwner && accountOwner.okta_sub === req.user.sub) {
      return res.status(403).json({
        success: false,
        error: 'Admins cannot adjust their own account balances.',
      });
    }

    const delta = type === 'credit' ? parsed : -parsed;
    const newBalance          = Math.round((account.balance + delta) * 100) / 100;
    const newAvailableBalance = Math.round((account.available_balance + delta) * 100) / 100;

    db.prepare(
      'UPDATE accounts SET balance = ?, available_balance = ? WHERE id = ?'
    ).run(newBalance, newAvailableBalance, account.id);

    // Audit transaction
    db.prepare(`
      INSERT INTO transactions
        (id, account_id, amount, currency, type, category, description, merchant, status, reference, transaction_date)
      VALUES (?, ?, ?, ?, ?, 'admin_adjustment', ?, 'Bank Admin', 'completed', ?, date('now'))
    `).run(
      uuidv4(),
      account.id,
      parsed,
      account.currency || 'USD',
      type,
      description || `Admin ${type} adjustment`,
      `ADM-${Math.random().toString(36).substring(2, 9).toUpperCase()}`
    );

    const updated = db.prepare('SELECT * FROM accounts WHERE id = ?').get(account.id);
    return res.json({ success: true, data: updated });
  } catch (err) {
    console.error('POST /admin/accounts/:id/adjust error:', err);
    return res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

export default router;
