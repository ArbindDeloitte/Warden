const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001/api';

let _oktaAuth = null;

export function setOktaAuth(auth) {
  _oktaAuth = auth;
}

export async function getToken() {
  if (!_oktaAuth) return null;
  try {
    return await _oktaAuth.getAccessToken();
  } catch (e) {
    console.error('Failed to get access token', e);
    return null;
  }
}

async function request(method, path, body) {
  const token = await getToken();
  const headers = {
    'Content-Type': 'application/json',
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const options = { method, headers };
  if (body !== undefined) {
    options.body = JSON.stringify(body);
  }

  const url = `${BASE_URL}${path}`;
  const response = await fetch(url, options);

  if (!response.ok) {
    let errorMessage = `HTTP ${response.status}: ${response.statusText}`;
    try {
      const errData = await response.json();
      errorMessage = errData.message || errData.error || errorMessage;
    } catch (_) {}
    throw new Error(errorMessage);
  }

  const contentType = response.headers.get('content-type');
  if (contentType && contentType.includes('application/json')) {
    return response.json();
  }
  return response.text();
}

export const api = {
  get: (path) => request('GET', path),
  post: (path, body) => request('POST', path, body),
  put: (path, body) => request('PUT', path, body),
  delete: (path) => request('DELETE', path),
};

export const banking = {
  getAccounts: () => api.get('/accounts'),
  getAccount: (id) => api.get(`/accounts/${id}`),
  getBalance: (id) => api.get(`/accounts/${id}/balance`),
  getTransactions: (id, params) =>
    api.get(`/accounts/${id}/transactions?${new URLSearchParams(params || {})}`),
  getStatements: (id) => api.get(`/accounts/${id}/statements`),
  getPayments: () => api.get('/payments'),
  createPayment: (data) => api.post('/payments', data),
  approvePayment: (id) => api.put(`/payments/${id}/approve`),
  getStandingOrders: () => api.get('/standing-orders'),
  createStandingOrder: (data) => api.post('/standing-orders', data),
  updateStandingOrder: (id, data) => api.put(`/standing-orders/${id}`, data),
  cancelStandingOrder: (id) => api.delete(`/standing-orders/${id}`),
  createExternalTransfer: (data) => api.post('/transfers/external', data),
  getExternalTransfers: () => api.get('/transfers/external'),
};
