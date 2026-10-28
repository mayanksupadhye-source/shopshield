'use client';

import React, { useState, useEffect } from 'react';
import { AnalysisResult, SignalCategory, RiskLevel } from '@/types/analyzer';

const SAMPLE_URLS = [
  { label: 'Example Domain (Reference)', url: 'https://example.com' },
  { label: 'Unencrypted HTTP test', url: 'http://example.com' },
  { label: 'Suspicious path test', url: 'https://example.com/cheap-deals-free-gift' }
];

export default function DashboardPage() {
  const [urlInput, setUrlInput] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [errorInfo, setErrorInfo] = useState<{ message: string; recommendation?: string } | null>(null);
  const [activeTab, setActiveTab] = useState<'all' | SignalCategory>('all');
  const [history, setHistory] = useState<AnalysisResult[]>([]);

  // Load history from localStorage
  useEffect(() => {
    try {
      const stored = localStorage.getItem('shopshield_scans');
      if (stored) {
        const parsed = JSON.parse(stored);
        if (Array.isArray(parsed)) {
          setHistory(parsed);
        }
      }
    } catch {
      // Local storage unavailable or disabled
    }
  }, []);

  const saveToHistory = (newResult: AnalysisResult) => {
    setHistory(prev => {
      const filtered = prev.filter(item => item.normalizedUrl !== newResult.normalizedUrl);
      const updated = [newResult, ...filtered].slice(0, 15);
      try {
        localStorage.setItem('shopshield_scans', JSON.stringify(updated));
      } catch {
        // ignore
      }
      return updated;
    });
  };

  const clearHistory = () => {
    setHistory([]);
    try {
      localStorage.removeItem('shopshield_scans');
    } catch {
      // ignore
    }
  };

  const handleScan = async (targetUrl: string) => {
    const trimmed = targetUrl.trim();
    if (!trimmed) return;

    setIsAnalyzing(true);
    setErrorInfo(null);
    setResult(null);

    try {
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: trimmed })
      });

      const data = await res.json();

      if (!res.ok) {
        setErrorInfo({
          message: data.error || 'Website analysis failed.',
          recommendation: data.recommendation || 'Please check the address and try again.'
        });
      } else {
        setResult(data as AnalysisResult);
        saveToHistory(data as AnalysisResult);
      }
    } catch (err: unknown) {
      const error = err as Error;
      setErrorInfo({
        message: 'Could not connect to analysis service.',
        recommendation: error.message || 'Please check your connection and try again.'
      });
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    handleScan(urlInput);
  };

  // Stats calculation
  const highRiskCount = history.filter(
    h => h.riskLevel === 'HIGH_RISK' || h.riskLevel === 'CRITICAL'
  ).length;

  const getRiskBadgeClass = (level: RiskLevel) => {
    switch (level) {
      case 'LOW_RISK':
        return 'risk-low';
      case 'MODERATE_RISK':
        return 'risk-moderate';
      case 'HIGH_RISK':
        return 'risk-high';
      case 'CRITICAL':
        return 'risk-critical';
      default:
        return 'risk-unable';
    }
  };

  const getRiskLabel = (level: RiskLevel) => {
    switch (level) {
      case 'LOW_RISK':
        return 'Low Risk';
      case 'MODERATE_RISK':
        return 'Moderate Risk';
      case 'HIGH_RISK':
        return 'High Risk';
      case 'CRITICAL':
        return 'Critical / Strong Warning';
      default:
        return 'Unable to Assess';
    }
  };

  const filteredSignals = result
    ? activeTab === 'all'
      ? result.signals
      : result.signals.filter(s => s.category === activeTab)
    : [];

  return (
    <div className="layout">
      {/* Sidebar Navigation */}
      <aside>
        <div className="brand">
          <div className="brand-icon">🛡</div>
          <span>ShopShield</span>
        </div>
        <div className="side-label">Workspace</div>
        <nav>
          <a className="active" href="#dashboard">
            ▦ <span>Dashboard</span>
          </a>
          <a href="#scanner">
            ⌕ <span>URL Scanner</span>
          </a>
          <a href="#signals">
            ◈ <span>Safety Signals</span>
          </a>
          <a href="#history">
            ◷ <span>Scan History</span>
          </a>
        </nav>
        <div className="side-bottom">
          <strong>Scam Intelligence</strong>
          Inspect online merchants before entering credit card information or completing purchases.
        </div>
      </aside>

      {/* Main Content Area */}
      <main id="dashboard">
        <div className="topbar">
          <div>
            <div className="eyebrow">Cyber security workspace</div>
            <h1>Shopping Scam Intelligence</h1>
            <p className="welcome">
              Evidence-based risk analysis for online shopping websites.
            </p>
          </div>
          <div className="top-right">
            <div className="status-pill">● System Online</div>
            <div className="avatar">SS</div>
          </div>
        </div>

        {/* Overview Stats */}
        <section className="stats" aria-label="Dashboard summary">
          <div className="stat">
            <div>
              <div className="stat-label">Total scans logged</div>
              <div className="stat-value">{history.length}</div>
              <div className="stat-note">Stored in local workspace</div>
            </div>
            <div className="stat-icon">⌕</div>
          </div>
          <div className="stat">
            <div>
              <div className="stat-label">High-risk & critical flags</div>
              <div className="stat-value">{highRiskCount}</div>
              <div className="stat-note">Observed scam/threat patterns</div>
            </div>
            <div className="stat-icon">⚠</div>
          </div>
          <div className="stat">
            <div>
              <div className="stat-label">Analysis Pipeline</div>
              <div className="stat-value" style={{ fontSize: '21px' }}>
                Active
              </div>
              <div className="stat-note">DNS, TLS, Content & RDAP live</div>
            </div>
            <div className="stat-icon">✓</div>
          </div>
        </section>

        {/* Content Grid */}
        <section className="content-grid">
          {/* Left Column: Scanner Form & Results */}
          <div className="card" id="scanner">
            <div className="card-heading">
              <div>
                <h2>Analyze a website</h2>
                <p className="sub">
                  Enter a shopping website URL to inspect real server, domain, policy, and payment signals.
                </p>
              </div>
              <span className="tiny-tag">LIVE INVESTIGATION</span>
            </div>

            <form onSubmit={handleSubmit}>
              <label htmlFor="urlInput">Shopping website address</label>
              <div className="url-wrap">
                <input
                  id="urlInput"
                  type="text"
                  placeholder="https://shop-example.com"
                  value={urlInput}
                  onChange={e => setUrlInput(e.target.value)}
                  disabled={isAnalyzing}
                  required
                />
                <button className="primary" type="submit" disabled={isAnalyzing}>
                  {isAnalyzing ? (
                    <>
                      <span className="spinner"></span>
                      <span>Analyzing...</span>
                    </>
                  ) : (
                    <span>Analyze Website →</span>
                  )}
                </button>
              </div>

              <div className="helper">
                Try a sample:{' '}
                {SAMPLE_URLS.map((sample, idx) => (
                  <React.Fragment key={sample.url}>
                    {idx > 0 && ' · '}
                    <button
                      type="button"
                      className="sample-btn"
                      onClick={() => {
                        setUrlInput(sample.url);
                        handleScan(sample.url);
                      }}
                    >
                      {sample.label}
                    </button>
                  </React.Fragment>
                ))}
              </div>
            </form>

            <div className="divider"></div>

            {/* Error Message Display */}
            {errorInfo && (
              <div className="result-box" style={{ borderLeft: '4px solid #d94355', marginBottom: '20px' }}>
                <span className="risk-badge risk-high" style={{ marginBottom: '8px' }}>
                  Analysis Blocked / Error
                </span>
                <p style={{ margin: '8px 0 4px', fontWeight: 600, fontSize: '13px' }}>
                  {errorInfo.message}
                </p>
                {errorInfo.recommendation && (
                  <p className="sub" style={{ margin: 0 }}>
                    {errorInfo.recommendation}
                  </p>
                )}
              </div>
            )}

            {/* Loading Indicator */}
            {isAnalyzing && (
              <div className="result-placeholder">
                <div className="placeholder-icon">
                  <span className="spinner" style={{ width: '24px', height: '24px', borderColor: 'rgba(49,92,245,0.2)', borderTopColor: '#315cf5' }}></span>
                </div>
                <strong>Performing deep analysis...</strong>
                <p>
                  Tracing redirects, verifying DNS, inspecting TLS certificates, checking RDAP registration, and scanning HTML for consumer policies.
                </p>
              </div>
            )}

            {/* Empty State */}
            {!isAnalyzing && !result && !errorInfo && (
              <div className="result-placeholder">
                <div className="placeholder-icon">🔎</div>
                <strong>Ready to investigate</strong>
                <p>
                  Submit a website URL above to inspect observable risk signals and view verifiable evidence.
                </p>
              </div>
            )}

            {/* Full Analysis Result */}
            {!isAnalyzing && result && (
              <div className="result-box">
                {/* Result Header */}
                <div className="result-top">
                  <div style={{ minWidth: 0, flex: 1 }}>
                    <div style={{ fontSize: '11px', color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                      Analyzed Target
                    </div>
                    <strong style={{ fontSize: '15px', overflowWrap: 'anywhere', color: '#17233c' }}>
                      {result.domain.hostname}
                    </strong>
                    <div style={{ fontSize: '11px', color: 'var(--muted)', marginTop: '2px', overflowWrap: 'anywhere' }}>
                      {result.normalizedUrl}
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <span className={`risk-badge ${getRiskBadgeClass(result.riskLevel)}`}>
                      {getRiskLabel(result.riskLevel)}
                    </span>
                    <span
                      className="confidence-pill"
                      title={result.confidenceReason}
                    >
                      Confidence: {result.confidence.toUpperCase()}
                    </span>
                  </div>
                </div>

                {/* Human-readable Summary */}
                <div className="summary-card">
                  <strong style={{ display: 'block', marginBottom: '4px', color: '#17233c' }}>
                    Assessment Summary
                  </strong>
                  <span>{result.summary}</span>
                  <div style={{ fontSize: '11px', color: 'var(--muted)', marginTop: '6px' }}>
                    {result.confidenceReason}
                  </div>
                </div>

                {/* Recommendations */}
                <div className="recommend-card">
                  <strong>Recommended Next Steps Before Purchasing:</strong>
                  <ul>
                    {result.recommendations.map((rec, i) => (
                      <li key={i}>{rec}</li>
                    ))}
                  </ul>
                </div>

                {/* Evidence Section */}
                <div className="evidence-section">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                    <h3 style={{ fontSize: '14px', margin: 0 }}>Observable Evidence</h3>
                    <span style={{ fontSize: '11px', color: 'var(--muted)' }}>
                      {filteredSignals.length} signal{filteredSignals.length === 1 ? '' : 's'}
                    </span>
                  </div>

                  {/* Category Tabs */}
                  <div className="category-tabs">
                    {(
                      [
                        { id: 'all', label: 'All Signals' },
                        { id: 'domain', label: 'Domain & Identity' },
                        { id: 'connection', label: 'Connection / TLS' },
                        { id: 'website', label: 'Website & Policies' },
                        { id: 'shopping', label: 'Shopping & Payments' },
                        { id: 'reputation', label: 'Reputation' }
                      ] as const
                    ).map(tab => (
                      <button
                        key={tab.id}
                        type="button"
                        className={`tab-btn ${activeTab === tab.id ? 'active' : ''}`}
                        onClick={() => setActiveTab(tab.id)}
                      >
                        {tab.label}
                      </button>
                    ))}
                  </div>

                  {/* Signal Cards */}
                  <div className="signal-cards-grid">
                    {filteredSignals.map(sig => {
                      const iconMap: Record<string, string> = {
                        verified: '✓',
                        warning: '⚠',
                        critical: '✕',
                        unavailable: '—',
                        not_detected: '○',
                        neutral: '•'
                      };
                      return (
                        <div key={sig.id} className="signal-item">
                          <div className={`signal-status-icon ${sig.status}`}>
                            {iconMap[sig.status] || '•'}
                          </div>
                          <div className="signal-body">
                            <div className="signal-title-row">
                              <span className="signal-title">{sig.title}</span>
                              <span
                                style={{
                                  fontSize: '10px',
                                  textTransform: 'uppercase',
                                  fontWeight: 800,
                                  color: sig.severity === 'critical' ? '#d94355' : sig.severity === 'high' ? '#b42336' : sig.severity === 'medium' ? '#c47a13' : '#15966a'
                                }}
                              >
                                {sig.severity}
                              </span>
                            </div>
                            <div className="signal-evidence">{sig.evidence}</div>
                            <div className="signal-explanation">{sig.explanation}</div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Expandable Technical Details */}
                <details className="tech-details">
                  <summary>View Technical Network & Protocol Details</summary>
                  <div className="tech-content">
                    <div className="tech-grid">
                      <div className="tech-item">
                        <strong>Resolved IP Addresses</strong>
                        <span>
                          {result.domain.resolvedIps.length
                            ? result.domain.resolvedIps.join(', ')
                            : 'None resolved'}
                        </span>
                      </div>
                      <div className="tech-item">
                        <strong>DNS Mail Servers (MX)</strong>
                        <span>
                          {result.domain.hasMxRecords
                            ? result.domain.mxRecords.join(', ')
                            : 'No MX records found'}
                        </span>
                      </div>
                      <div className="tech-item">
                        <strong>TLS Certificate Issuer</strong>
                        <span>{result.connection.tlsIssuer || 'None / Not available'}</span>
                      </div>
                      <div className="tech-item">
                        <strong>Certificate Valid Until</strong>
                        <span>
                          {result.connection.tlsValidTo
                            ? new Date(result.connection.tlsValidTo).toLocaleDateString()
                            : 'N/A'}{' '}
                          {result.connection.tlsDaysRemaining !== null
                            ? `(${result.connection.tlsDaysRemaining} days remaining)`
                            : ''}
                        </span>
                      </div>
                      <div className="tech-item">
                        <strong>Domain Registration Age</strong>
                        <span>
                          {result.domain.domainAgeDays !== null
                            ? `${result.domain.domainAgeDays} days (Registered ${new Date(result.domain.registrationDate!).toLocaleDateString()})`
                            : 'Unavailable from RDAP'}
                        </span>
                      </div>
                      <div className="tech-item">
                        <strong>Redirect Chain</strong>
                        <span>
                          {result.connection.redirectCount === 0
                            ? 'Direct connection (0 redirects)'
                            : `${result.connection.redirectCount} hops to ${result.connection.finalDomain}`}
                        </span>
                      </div>
                      <div className="tech-item">
                        <strong>HTTP Response Status</strong>
                        <span>
                          {result.content.statusCode
                            ? `${result.content.statusCode} (${result.content.htmlSizeBytes} bytes)`
                            : 'Not reachable'}
                        </span>
                      </div>
                      <div className="tech-item">
                        <strong>Internal Indicator Score</strong>
                        <span>
                          {result.internalRiskScore} / 100 (Internal heuristic indicator)
                        </span>
                      </div>
                    </div>
                  </div>
                </details>
              </div>
            )}
          </div>

          {/* Right Column: Signals Overview & Scan History */}
          <div className="right-stack">
            {/* Safety Signals Info Card */}
            <div className="card" id="signals">
              <div className="card-heading">
                <div>
                  <h2>Observed Signal Types</h2>
                  <p className="sub">Real data verified by server pipeline</p>
                </div>
                <span className="tiny-tag">6 DOMAINS</span>
              </div>
              <div className="signal-list">
                <div className="signal">
                  <div className="signal-icon">🌐</div>
                  <div>
                    <strong>Domain & RDAP History</strong>
                    <p>Queries official registry data for true domain registration age and active MX mail servers.</p>
                  </div>
                </div>
                <div className="signal">
                  <div className="signal-icon">🔒</div>
                  <div>
                    <strong>TLS Certificate & Handshake</strong>
                    <p>Connects via TLS to inspect certificate issuer, validity period, and hostname matching.</p>
                  </div>
                </div>
                <div className="signal">
                  <div className="signal-icon">🔗</div>
                  <div>
                    <strong>Redirect & Domain Tracing</strong>
                    <p>Follows HTTP redirects safely to detect deceptive off-domain checkout switches.</p>
                  </div>
                </div>
                <div className="signal">
                  <div className="signal-icon">📜</div>
                  <div>
                    <strong>Consumer Policies & Contact</strong>
                    <p>Inspects HTML for refund/return policies, physical addresses, support emails, and phone numbers.</p>
                  </div>
                </div>
                <div className="signal">
                  <div className="signal-icon">💳</div>
                  <div>
                    <strong>Payment & Pressure Signals</strong>
                    <p>Flags untraceable payment demands (wire, crypto, gift cards) and extreme 90%+ discount lures.</p>
                  </div>
                </div>
                <div className="signal">
                  <div className="signal-icon">🛡</div>
                  <div>
                    <strong>Threat Intelligence</strong>
                    <p>Optional integration with Google Safe Browsing and VirusTotal reputation databases.</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Scan History Card */}
            <div className="card" id="history">
              <div className="card-heading">
                <div>
                  <h2>Recent Scans</h2>
                  <p className="sub">Saved in local browser storage</p>
                </div>
                <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                  <span className="tiny-tag" id="historyCount">
                    {history.length} ITEM{history.length === 1 ? '' : 'S'}
                  </span>
                  {history.length > 0 && (
                    <button
                      type="button"
                      className="history-clear-btn"
                      onClick={clearHistory}
                      title="Clear history"
                    >
                      Clear
                    </button>
                  )}
                </div>
              </div>

              {history.length === 0 ? (
                <div className="history-empty">Your scan history will appear here.</div>
              ) : (
                <div className="history-list">
                  {history.slice(0, 8).map(item => (
                    <div key={item.id} className="history-item">
                      <div style={{ minWidth: 0 }}>
                        <div className="history-url">{item.domain.hostname}</div>
                        <div className="history-meta">
                          <span
                            style={{
                              fontWeight: 700,
                              color:
                                item.riskLevel === 'CRITICAL'
                                  ? '#d94355'
                                  : item.riskLevel === 'HIGH_RISK'
                                  ? '#b42336'
                                  : item.riskLevel === 'MODERATE_RISK'
                                  ? '#c47a13'
                                  : '#15966a'
                            }}
                          >
                            {getRiskLabel(item.riskLevel)}
                          </span>
                          <span>·</span>
                          <span>{new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                        </div>
                      </div>
                      <button
                        type="button"
                        onClick={() => {
                          setResult(item);
                          setUrlInput(item.originalUrl);
                          setErrorInfo(null);
                        }}
                      >
                        View
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </section>

        <footer>
          ShopShield is a website risk and shopping scam intelligence system. Analysis is based on observable network, domain, and content signals. A low-risk assessment does not guarantee merchant legitimacy, and warning indicators do not constitute legal proof of fraud. Always exercise due diligence before purchasing online.
        </footer>
      </main>
    </div>
  );
}
