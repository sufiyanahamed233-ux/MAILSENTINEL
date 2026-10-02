/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { ForensicProvider, useForensics } from './context/ForensicContext';
import { Sidebar } from './components/layout/Sidebar';
import { TopBar } from './components/layout/TopBar';
import { LoginPage } from './components/auth/LoginPage';
import { DashboardPage } from './pages/DashboardPage';
import { InvestigationsPage } from './pages/InvestigationsPage';
import { AnalyzeEmailPage } from './pages/AnalyzeEmailPage';
import { WorkspacePage } from './pages/WorkspacePage';
import { ThreatIntelPage } from './pages/ThreatIntelPage';
import { EvidencePage } from './pages/EvidencePage';
import { ReportsPage } from './pages/ReportsPage';
import { SettingsPage } from './pages/SettingsPage';

function MainAppShell() {
  const { currentView, isAuthenticated } = useForensics();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  if (!isAuthenticated) {
    return <LoginPage />;
  }

  const renderActiveView = () => {
    switch (currentView) {
      case 'dashboard':
        return <DashboardPage />;
      case 'investigations':
        return <InvestigationsPage />;
      case 'analyze':
        return <AnalyzeEmailPage />;
      case 'workspace':
        return <WorkspacePage />;
      case 'threat-intel':
        return <ThreatIntelPage />;
      case 'evidence':
        return <EvidencePage />;
      case 'reports':
        return <ReportsPage />;
      case 'settings':
        return <SettingsPage />;
      default:
        return <DashboardPage />;
    }
  };

  return (
    <div className="min-h-screen bg-[#080c14] text-slate-100 flex flex-col font-sans">
      {/* Persistent Sidebar */}
      <Sidebar mobileOpen={mobileMenuOpen} setMobileOpen={setMobileMenuOpen} />

      {/* Main Content Area */}
      <div className="lg:pl-64 flex flex-col flex-1 min-h-screen">
        <TopBar onToggleMobileMenu={() => setMobileMenuOpen(!mobileMenuOpen)} />

        <main className="flex-1 p-4 sm:p-6 max-w-7xl w-full mx-auto">
          {renderActiveView()}
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <ForensicProvider>
      <MainAppShell />
    </ForensicProvider>
  );
}
