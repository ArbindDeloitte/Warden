import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import {
  getUserAccounts,
  getAccountBalance,
  getAccountTransactions,
  getAccountStatements,
  createPayment,
  approvePayment,
  getUserPayments,
  createStandingOrder,
  updateStandingOrder,
  cancelStandingOrder,
  getUserStandingOrders,
  createExternalTransfer,
} from '../services/banking.js';

/**
 * Creates a new McpServer instance with all banking tools registered.
 * The userId and db are bound into each handler's closure so that
 * every request operates on the authenticated user's data.
 */
export function createMcpServer(userId, db) {
  const server = new McpServer({
    name: 'banking-mcp-server',
    version: '1.0.0',
  });

  // ─── Tool: get_accounts ───────────────────────────────────────────────────
  server.tool(
    'get_accounts',
    'Get all bank accounts for the authenticated user',
    {},
    async () => {
      try {
        const accounts = getUserAccounts(db, userId);
        return {
          content: [{ type: 'text', text: JSON.stringify(accounts, null, 2) }],
        };
      } catch (err) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: err.message }, null, 2) }],
          isError: true,
        };
      }
    }
  );

  // ─── Tool: get_account_balance ────────────────────────────────────────────
  server.tool(
    'get_account_balance',
    'Get the current balance for a specific account',
    { accountId: z.string().describe('The account ID to get the balance for') },
    async ({ accountId }) => {
      try {
        const balance = getAccountBalance(db, userId, accountId);
        if (!balance) {
          return {
            content: [{ type: 'text', text: JSON.stringify({ error: 'Account not found' }, null, 2) }],
            isError: true,
          };
        }
        return {
          content: [{ type: 'text', text: JSON.stringify(balance, null, 2) }],
        };
      } catch (err) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: err.message }, null, 2) }],
          isError: true,
        };
      }
    }
  );

  // ─── Tool: get_transactions ───────────────────────────────────────────────
  server.tool(
    'get_transactions',
    'Get transactions for a specific account, optionally filtered by date range',
    {
      accountId: z.string().describe('The account ID'),
      limit: z.number().optional().describe('Maximum number of transactions to return (default: 50)'),
      from: z.string().optional().describe('Start date filter in YYYY-MM-DD format'),
      to: z.string().optional().describe('End date filter in YYYY-MM-DD format'),
    },
    async ({ accountId, limit, from, to }) => {
      try {
        const transactions = getAccountTransactions(db, userId, accountId, { limit, from, to });
        if (transactions === null) {
          return {
            content: [{ type: 'text', text: JSON.stringify({ error: 'Account not found' }, null, 2) }],
            isError: true,
          };
        }
        return {
          content: [{ type: 'text', text: JSON.stringify(transactions, null, 2) }],
        };
      } catch (err) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: err.message }, null, 2) }],
          isError: true,
        };
      }
    }
  );

  // ─── Tool: get_statements ─────────────────────────────────────────────────
  server.tool(
    'get_statements',
    'Get bank statements for a specific account',
    { accountId: z.string().describe('The account ID to get statements for') },
    async ({ accountId }) => {
      try {
        const statements = getAccountStatements(db, userId, accountId);
        if (statements === null) {
          return {
            content: [{ type: 'text', text: JSON.stringify({ error: 'Account not found' }, null, 2) }],
            isError: true,
          };
        }
        return {
          content: [{ type: 'text', text: JSON.stringify(statements, null, 2) }],
        };
      } catch (err) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: err.message }, null, 2) }],
          isError: true,
        };
      }
    }
  );

  // ─── Tool: initiate_payment ───────────────────────────────────────────────
  server.tool(
    'initiate_payment',
    'Initiate a new payment from one of the user\'s accounts to another account',
    {
      fromAccountId: z.string().describe('Source account ID'),
      toAccount: z.string().describe('Destination account number'),
      toName: z.string().describe('Name of the payment recipient'),
      amount: z.number().positive().describe('Payment amount'),
      currency: z.string().optional().describe('Currency code (default: USD)'),
      reference: z.string().optional().describe('Payment reference or description'),
    },
    async ({ fromAccountId, toAccount, toName, amount, currency, reference }) => {
      try {
        const payment = createPayment(db, userId, { fromAccountId, toAccount, toName, amount, currency, reference });
        return {
          content: [{ type: 'text', text: JSON.stringify(payment, null, 2) }],
        };
      } catch (err) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: err.message }, null, 2) }],
          isError: true,
        };
      }
    }
  );

  // ─── Tool: approve_payment ────────────────────────────────────────────────
  server.tool(
    'approve_payment',
    'Approve a pending payment',
    { paymentId: z.string().describe('The ID of the payment to approve') },
    async ({ paymentId }) => {
      try {
        const payment = approvePayment(db, userId, paymentId);
        return {
          content: [{ type: 'text', text: JSON.stringify(payment, null, 2) }],
        };
      } catch (err) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: err.message }, null, 2) }],
          isError: true,
        };
      }
    }
  );

  // ─── Tool: list_payments ──────────────────────────────────────────────────
  server.tool(
    'list_payments',
    'List all payments for the authenticated user',
    {},
    async () => {
      try {
        const payments = getUserPayments(db, userId);
        return {
          content: [{ type: 'text', text: JSON.stringify(payments, null, 2) }],
        };
      } catch (err) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: err.message }, null, 2) }],
          isError: true,
        };
      }
    }
  );

  // ─── Tool: create_standing_order ─────────────────────────────────────────
  server.tool(
    'create_standing_order',
    'Create a recurring standing order for automatic payments',
    {
      fromAccountId: z.string().describe('Source account ID'),
      toAccount: z.string().describe('Destination account number'),
      toName: z.string().describe('Name of the recipient'),
      amount: z.number().positive().describe('Payment amount per occurrence'),
      currency: z.string().optional().describe('Currency code (default: USD)'),
      frequency: z.enum(['daily', 'weekly', 'monthly', 'quarterly']).describe('Payment frequency'),
      startDate: z.string().describe('Start date in YYYY-MM-DD format'),
      endDate: z.string().optional().describe('End date in YYYY-MM-DD format (optional)'),
      reference: z.string().optional().describe('Payment reference'),
    },
    async ({ fromAccountId, toAccount, toName, amount, currency, frequency, startDate, endDate, reference }) => {
      try {
        const order = createStandingOrder(db, userId, {
          fromAccountId, toAccount, toName, amount, currency, frequency, startDate, endDate, reference,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify(order, null, 2) }],
        };
      } catch (err) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: err.message }, null, 2) }],
          isError: true,
        };
      }
    }
  );

  // ─── Tool: manage_standing_order ─────────────────────────────────────────
  server.tool(
    'manage_standing_order',
    'Update, cancel, pause, or resume a standing order',
    {
      action: z.enum(['update', 'cancel', 'pause', 'resume']).describe('Action to perform'),
      orderId: z.string().describe('The standing order ID'),
      amount: z.number().positive().optional().describe('New amount (for update action)'),
      frequency: z.string().optional().describe('New frequency (for update action)'),
    },
    async ({ action, orderId, amount, frequency }) => {
      try {
        let result;

        if (action === 'cancel') {
          result = cancelStandingOrder(db, userId, orderId);
        } else if (action === 'pause') {
          result = updateStandingOrder(db, userId, orderId, { status: 'paused' });
        } else if (action === 'resume') {
          result = updateStandingOrder(db, userId, orderId, { status: 'active' });
        } else if (action === 'update') {
          const updates = {};
          if (amount !== undefined) updates.amount = amount;
          if (frequency !== undefined) updates.frequency = frequency;

          if (Object.keys(updates).length === 0) {
            return {
              content: [{ type: 'text', text: JSON.stringify({ error: 'No fields provided to update' }, null, 2) }],
              isError: true,
            };
          }
          result = updateStandingOrder(db, userId, orderId, updates);
        }

        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      } catch (err) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: err.message }, null, 2) }],
          isError: true,
        };
      }
    }
  );

  // ─── Tool: create_external_transfer ──────────────────────────────────────
  server.tool(
    'create_external_transfer',
    'Create an international transfer to an IBAN account',
    {
      fromAccountId: z.string().describe('Source account ID'),
      toIban: z.string().describe('Destination IBAN'),
      toName: z.string().describe('Name of the recipient'),
      toBank: z.string().optional().describe('Recipient bank name'),
      amount: z.number().positive().describe('Transfer amount'),
      currency: z.string().optional().describe('Currency code (default: USD)'),
      reference: z.string().optional().describe('Transfer reference'),
    },
    async ({ fromAccountId, toIban, toName, toBank, amount, currency, reference }) => {
      try {
        const transfer = createExternalTransfer(db, userId, {
          fromAccountId, toIban, toName, toBank, amount, currency, reference,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify(transfer, null, 2) }],
        };
      } catch (err) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: err.message }, null, 2) }],
          isError: true,
        };
      }
    }
  );

  return server;
}
