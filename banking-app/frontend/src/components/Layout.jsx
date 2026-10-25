import React, { useState } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { useOktaAuth } from '@okta/okta-react';

const BASE_NAV = [
  { path: '/', label: 'Dashboard', icon: '🏠', exact: true },
  { path: '/agent', label: 'AI Agent', icon: '🤖' },
  { path: '/accounts', label: 'Accounts', icon: '💳' },
  { path: '/payments', label: 'Payments', icon: '💸' },
  { path: '/standing-orders', label: 'Standing Orders', icon: '🔄' },
  { path: '/transfers', label: 'Transfers', icon: '🌐' },
  { path: '/statements', label: 'Statements', icon: '📄' },
  { path: '/dev-tools', label: 'Dev Tools', icon: '🔧' },
];

const ADMIN_NAV = { path: '/bank-admin', label: 'Bank Admin', icon: '🛡️', adminOnly: true };

export default function Layout({ children }) {
  const { oktaAuth, authState } = useOktaAuth();
  const navigate = useNavigate();
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const user = authState?.idToken?.claims || {};
  const userName = user.name || user.email || 'User';
  const userEmail = user.email || '';

  const groups = authState?.accessToken?.claims?.groups || [];
  const isAdmin = groups.includes('bank-admin');
  const navItems = isAdmin ? [...BASE_NAV, ADMIN_NAV] : BASE_NAV;

  const handleSignOut = async () => {
    await oktaAuth.signOut();
  };

  return (
    <div className="layout">
      {/* Mobile hamburger */}
      <button
        className="hamburger"
        onClick={() => setSidebarOpen(!sidebarOpen)}
        aria-label="Toggle menu"
      >
        ☰
      </button>

      {/* Overlay for mobile */}
      {sidebarOpen && (
        <div
          className="sidebar-overlay"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside className={`sidebar ${sidebarOpen ? 'sidebar-open' : ''}`}>
        <div className="sidebar-logo">
          <span className="logo-icon">🏦</span>
          <span className="logo-text">SecureBank</span>
        </div>

        <nav className="sidebar-nav">
          {navItems.map((item) => (
            <React.Fragment key={item.path}>
              {item.adminOnly && (
                <div style={{ margin: '8px 12px 4px', borderTop: '1px solid rgba(255,255,255,0.1)' }} />
              )}
              <NavLink
                to={item.path}
                end={item.exact}
                className={({ isActive }) =>
                  `nav-link ${isActive ? 'nav-link-active' : ''} ${item.adminOnly ? 'nav-link-admin' : ''}`
                }
                onClick={() => setSidebarOpen(false)}
              >
                <span className="nav-icon">{item.icon}</span>
                <span className="nav-label">{item.label}</span>
              </NavLink>
            </React.Fragment>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="user-info">
            <div className="user-avatar">
              {userName.charAt(0).toUpperCase()}
            </div>
            <div className="user-details">
              <div className="user-name">{userName}</div>
              {userEmail && <div className="user-email">{userEmail}</div>}
            </div>
          </div>
          <button className="sign-out-btn" onClick={handleSignOut}>
            Sign Out
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="main-content">
        {children}
      </main>
    </div>
  );
}
