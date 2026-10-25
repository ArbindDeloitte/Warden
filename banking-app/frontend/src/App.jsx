import React, { useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Security, LoginCallback, useOktaAuth } from '@okta/okta-react';
import { OktaAuth } from '@okta/okta-auth-js';
import { oktaConfig } from './oktaConfig.js';
import { setOktaAuth } from './services/api.js';
import Layout from './components/Layout.jsx';
import Dashboard from './pages/Dashboard.jsx';
import Accounts from './pages/Accounts.jsx';
import AccountDetail from './pages/AccountDetail.jsx';
import Payments from './pages/Payments.jsx';
import StandingOrders from './pages/StandingOrders.jsx';
import ExternalTransfers from './pages/ExternalTransfers.jsx';
import Statements from './pages/Statements.jsx';
import DevTools from './pages/DevTools.jsx';
import Agent from './pages/Agent.jsx';
import BankAdmin from './pages/BankAdmin.jsx';

const oktaAuth = new OktaAuth(oktaConfig);
setOktaAuth(oktaAuth);

function RequireAuth({ children }) {
  const { authState, oktaAuth } = useOktaAuth();

  useEffect(() => {
    if (authState && !authState.isAuthenticated) {
      oktaAuth.signInWithRedirect();
    }
  }, [authState, oktaAuth]);

  if (!authState) {
    return (
      <div className="loading-fullscreen">
        <div className="spinner"></div>
        <p>Loading...</p>
      </div>
    );
  }

  if (!authState.isAuthenticated) {
    return (
      <div className="loading-fullscreen">
        <div className="spinner"></div>
        <p>Redirecting to login...</p>
      </div>
    );
  }

  return children;
}

function AppRoutes() {
  return (
    <Routes>
      <Route path="/login/callback" element={<LoginCallback />} />
      <Route
        path="/*"
        element={
          <RequireAuth>
            <Layout>
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/accounts" element={<Accounts />} />
                <Route path="/accounts/:id" element={<AccountDetail />} />
                <Route path="/payments" element={<Payments />} />
                <Route path="/standing-orders" element={<StandingOrders />} />
                <Route path="/transfers" element={<ExternalTransfers />} />
                <Route path="/statements" element={<Statements />} />
                <Route path="/dev-tools" element={<DevTools />} />
                <Route path="/agent" element={<Agent />} />
                <Route path="/bank-admin" element={<BankAdmin />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </Layout>
          </RequireAuth>
        }
      />
    </Routes>
  );
}

function App() {
  const restoreOriginalUri = async (_oktaAuth, originalUri) => {
    window.location.replace(originalUri || '/');
  };

  return (
    <BrowserRouter>
      <Security oktaAuth={oktaAuth} restoreOriginalUri={restoreOriginalUri}>
        <AppRoutes />
      </Security>
    </BrowserRouter>
  );
}

export default App;
