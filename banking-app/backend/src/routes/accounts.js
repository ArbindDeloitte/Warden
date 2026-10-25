import { Router } from 'express';
import { verifyToken, requireScope } from '../middleware/auth.js';
import { getOrCreateUser, getDb } from '../db.js';
import {
  getUserAccounts,
  getAccountById,
  getAccountBalance,
  getAccountTransactions,
  getAccountStatements,
} from '../services/banking.js';

const router = Router();

// GET /api/accounts - List all accounts for the authenticated user
router.get(
  '/',
  verifyToken,
  requireScope('accounts:read'),
  async (req, res) => {
    try {
      const db = getDb();
      const user = getOrCreateUser(db, req.user.sub, req.user.email, req.user.name);
      const accounts = getUserAccounts(db, user.id);

      return res.json({ success: true, data: accounts });
    } catch (err) {
      console.error('GET /accounts error:', err);
      return res.status(500).json({ success: false, error: 'Internal server error' });
    }
  }
);

// GET /api/accounts/:id - Get a single account
router.get(
  '/:id',
  verifyToken,
  requireScope('accounts:read'),
  async (req, res) => {
    try {
      const db = getDb();
      const user = getOrCreateUser(db, req.user.sub, req.user.email, req.user.name);
      const account = getAccountById(db, user.id, req.params.id);

      if (!account) {
        return res.status(404).json({ success: false, error: 'Account not found' });
      }

      return res.json({ success: true, data: account });
    } catch (err) {
      console.error('GET /accounts/:id error:', err);
      return res.status(500).json({ success: false, error: 'Internal server error' });
    }
  }
);

// GET /api/accounts/:id/balance - Get account balance
router.get(
  '/:id/balance',
  verifyToken,
  requireScope('accounts:balance:read'),
  async (req, res) => {
    try {
      const db = getDb();
      const user = getOrCreateUser(db, req.user.sub, req.user.email, req.user.name);
      const balance = getAccountBalance(db, user.id, req.params.id);

      if (!balance) {
        return res.status(404).json({ success: false, error: 'Account not found' });
      }

      return res.json({ success: true, data: balance });
    } catch (err) {
      console.error('GET /accounts/:id/balance error:', err);
      return res.status(500).json({ success: false, error: 'Internal server error' });
    }
  }
);

// GET /api/accounts/:id/transactions - Get account transactions
router.get(
  '/:id/transactions',
  verifyToken,
  requireScope('accounts:transactions:read'),
  async (req, res) => {
    try {
      const db = getDb();
      const user = getOrCreateUser(db, req.user.sub, req.user.email, req.user.name);
      const { limit = 50, offset = 0, from, to } = req.query;

      const transactions = getAccountTransactions(db, user.id, req.params.id, {
        limit: parseInt(limit, 10),
        offset: parseInt(offset, 10),
        from,
        to,
      });

      if (transactions === null) {
        return res.status(404).json({ success: false, error: 'Account not found' });
      }

      return res.json({ success: true, data: transactions });
    } catch (err) {
      console.error('GET /accounts/:id/transactions error:', err);
      return res.status(500).json({ success: false, error: 'Internal server error' });
    }
  }
);

// GET /api/accounts/:id/statements - Get account statements
router.get(
  '/:id/statements',
  verifyToken,
  requireScope('accounts:statements:read'),
  async (req, res) => {
    try {
      const db = getDb();
      const user = getOrCreateUser(db, req.user.sub, req.user.email, req.user.name);
      const statements = getAccountStatements(db, user.id, req.params.id);

      if (statements === null) {
        return res.status(404).json({ success: false, error: 'Account not found' });
      }

      return res.json({ success: true, data: statements });
    } catch (err) {
      console.error('GET /accounts/:id/statements error:', err);
      return res.status(500).json({ success: false, error: 'Internal server error' });
    }
  }
);

export default router;
