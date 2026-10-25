import { Router } from 'express';
import { verifyToken, requireScope } from '../middleware/auth.js';
import { getOrCreateUser, getDb } from '../db.js';
import {
  getUserStandingOrders,
  createStandingOrder,
  updateStandingOrder,
  cancelStandingOrder,
} from '../services/banking.js';

const router = Router();

// GET /api/standing-orders - List all standing orders for the authenticated user
router.get(
  '/',
  verifyToken,
  requireScope('standing-orders:manage'),
  async (req, res) => {
    try {
      const db = getDb();
      const user = getOrCreateUser(db, req.user.sub, req.user.email, req.user.name);
      const orders = getUserStandingOrders(db, user.id);

      return res.json({ success: true, data: orders });
    } catch (err) {
      console.error('GET /standing-orders error:', err);
      return res.status(500).json({ success: false, error: 'Internal server error' });
    }
  }
);

// POST /api/standing-orders - Create a new standing order
router.post(
  '/',
  verifyToken,
  requireScope('standing-orders:manage'),
  async (req, res) => {
    try {
      const db = getDb();
      const user = getOrCreateUser(db, req.user.sub, req.user.email, req.user.name);

      const {
        fromAccountId, toAccount, toName, amount, currency,
        frequency, startDate, endDate, reference,
      } = req.body;

      if (!fromAccountId || !toAccount || !toName || !amount || !frequency || !startDate) {
        return res.status(400).json({
          success: false,
          error: 'Missing required fields: fromAccountId, toAccount, toName, amount, frequency, startDate',
        });
      }

      if (typeof amount !== 'number' || amount <= 0) {
        return res.status(400).json({
          success: false,
          error: 'amount must be a positive number',
        });
      }

      const order = createStandingOrder(db, user.id, {
        fromAccountId, toAccount, toName, amount, currency,
        frequency, startDate, endDate, reference,
      });

      return res.status(201).json({ success: true, data: order });
    } catch (err) {
      console.error('POST /standing-orders error:', err);
      if (err.message.includes('not found') || err.message.includes('Invalid') || err.message.includes('must be')) {
        return res.status(400).json({ success: false, error: err.message });
      }
      return res.status(500).json({ success: false, error: 'Internal server error' });
    }
  }
);

// PUT /api/standing-orders/:id - Update a standing order
router.put(
  '/:id',
  verifyToken,
  requireScope('standing-orders:manage'),
  async (req, res) => {
    try {
      const db = getDb();
      const user = getOrCreateUser(db, req.user.sub, req.user.email, req.user.name);
      const order = updateStandingOrder(db, user.id, req.params.id, req.body);

      return res.json({ success: true, data: order });
    } catch (err) {
      console.error('PUT /standing-orders/:id error:', err);
      if (err.message.includes('not found') || err.message.includes('Cannot update') || err.message.includes('No valid')) {
        return res.status(400).json({ success: false, error: err.message });
      }
      return res.status(500).json({ success: false, error: 'Internal server error' });
    }
  }
);

// DELETE /api/standing-orders/:id - Cancel a standing order
router.delete(
  '/:id',
  verifyToken,
  requireScope('standing-orders:manage'),
  async (req, res) => {
    try {
      const db = getDb();
      const user = getOrCreateUser(db, req.user.sub, req.user.email, req.user.name);
      const order = cancelStandingOrder(db, user.id, req.params.id);

      return res.json({ success: true, data: order });
    } catch (err) {
      console.error('DELETE /standing-orders/:id error:', err);
      if (err.message.includes('not found') || err.message.includes('already cancelled')) {
        return res.status(400).json({ success: false, error: err.message });
      }
      return res.status(500).json({ success: false, error: 'Internal server error' });
    }
  }
);

export default router;
