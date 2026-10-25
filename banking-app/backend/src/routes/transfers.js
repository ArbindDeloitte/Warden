import { Router } from 'express';
import { verifyToken, requireScope } from '../middleware/auth.js';
import { getOrCreateUser, getDb } from '../db.js';
import { createExternalTransfer } from '../services/banking.js';

const router = Router();

// POST /api/transfers/external - Create an external (IBAN) transfer
router.post(
  '/external',
  verifyToken,
  requireScope('transfers:external:create'),
  async (req, res) => {
    try {
      const db = getDb();
      const user = getOrCreateUser(db, req.user.sub, req.user.email, req.user.name);

      const { fromAccountId, toIban, toName, toBank, amount, currency, reference } = req.body;

      if (!fromAccountId || !toIban || !toName || !amount) {
        return res.status(400).json({
          success: false,
          error: 'Missing required fields: fromAccountId, toIban, toName, amount',
        });
      }

      if (typeof amount !== 'number' || amount <= 0) {
        return res.status(400).json({
          success: false,
          error: 'amount must be a positive number',
        });
      }

      const transfer = createExternalTransfer(db, user.id, {
        fromAccountId,
        toIban,
        toName,
        toBank,
        amount,
        currency,
        reference,
      });

      return res.status(201).json({ success: true, data: transfer });
    } catch (err) {
      console.error('POST /transfers/external error:', err);
      if (
        err.message.includes('not found') ||
        err.message.includes('Insufficient') ||
        err.message.includes('Invalid IBAN')
      ) {
        return res.status(400).json({ success: false, error: err.message });
      }
      return res.status(500).json({ success: false, error: 'Internal server error' });
    }
  }
);

export default router;
