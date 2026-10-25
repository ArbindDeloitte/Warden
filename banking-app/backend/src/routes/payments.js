import { Router } from 'express';
import { verifyToken, requireScope } from '../middleware/auth.js';
import { getOrCreateUser, getDb } from '../db.js';
import {
  getUserPayments,
  createPayment,
  approvePayment,
} from '../services/banking.js';

const router = Router();

// GET /api/payments - List all payments for the authenticated user
router.get(
  '/',
  verifyToken,
  requireScope('payments:read'),
  async (req, res) => {
    try {
      const db = getDb();
      const user = getOrCreateUser(db, req.user.sub, req.user.email, req.user.name);
      const payments = getUserPayments(db, user.id);

      return res.json({ success: true, data: payments });
    } catch (err) {
      console.error('GET /payments error:', err);
      return res.status(500).json({ success: false, error: 'Internal server error' });
    }
  }
);

// POST /api/payments - Initiate a new payment
router.post(
  '/',
  verifyToken,
  requireScope('payments:initiate'),
  async (req, res) => {
    try {
      const db = getDb();
      const user = getOrCreateUser(db, req.user.sub, req.user.email, req.user.name);

      const { fromAccountId, toAccount, toName, amount, currency, reference } = req.body;

      if (!fromAccountId || !toAccount || !toName || !amount) {
        return res.status(400).json({
          success: false,
          error: 'Missing required fields: fromAccountId, toAccount, toName, amount',
        });
      }

      if (typeof amount !== 'number' || amount <= 0) {
        return res.status(400).json({
          success: false,
          error: 'amount must be a positive number',
        });
      }

      const payment = createPayment(db, user.id, {
        fromAccountId,
        toAccount,
        toName,
        amount,
        currency,
        reference,
      });

      return res.status(201).json({ success: true, data: payment });
    } catch (err) {
      console.error('POST /payments error:', err);
      if (err.message.includes('not found') || err.message.includes('Insufficient')) {
        return res.status(400).json({ success: false, error: err.message });
      }
      return res.status(500).json({ success: false, error: 'Internal server error' });
    }
  }
);

// PUT /api/payments/:id/approve - Approve a pending payment
router.put(
  '/:id/approve',
  verifyToken,
  requireScope('payments:approve'),
  async (req, res) => {
    try {
      const db = getDb();
      const user = getOrCreateUser(db, req.user.sub, req.user.email, req.user.name);
      const payment = approvePayment(db, user.id, req.params.id);

      return res.json({ success: true, data: payment });
    } catch (err) {
      console.error('PUT /payments/:id/approve error:', err);
      if (err.message.includes('not found') || err.message.includes('cannot be approved') || err.message.includes('Insufficient')) {
        return res.status(400).json({ success: false, error: err.message });
      }
      return res.status(500).json({ success: false, error: 'Internal server error' });
    }
  }
);

export default router;
