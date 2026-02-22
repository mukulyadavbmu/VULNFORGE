import React, { useEffect, useState } from 'react';
import {
  createScan,
  executeActionApi,
  getScan,
  listScans,
  planScan,
  ScanSessionDto,
  ScanSummary,
  setAuthHeaders,
} from './api';

export const App: React.FC = () => {
  const [targetUrl, setTargetUrl] = useState('');
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [selectedScan, setSelectedScan] = useState<ScanSessionDto | null>(null);
  const [loadingScan, setLoadingScan] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [authCookieA, setAuthCookieA] = useState('');
  const [authCookieB, setAuthCookieB] = useState('');

  const loadScans = async () => {
    try {
      const data = await listScans();
      setScans(data);
    } catch (err) {
      setMessage(String(err));
    }
  };

  const loadScanDetails = async (id: string) => {
    setLoadingScan(true);
    try {
      const data = await getScan(id);
      setSelectedScan(data);
    } catch (err) {
      setMessage(String(err));
    } finally {
      setLoadingScan(false);
    }
  };

  useEffect(() => {
    void loadScans();
  }, []);

  useEffect(() => {
    if (selectedScanId) {
      void loadScanDetails(selectedScanId);
    }
  }, [selectedScanId]);

  const handleCreateScan = async () => {
    setMessage(null);
    try {
      const { scanId } = await createScan(targetUrl);
      setTargetUrl('');
      await loadScans();
      setSelectedScanId(scanId);
    } catch (err) {
      setMessage(String(err));
    }
  };

  const handlePlan = async () => {
    if (!selectedScanId) return;
    setMessage(null);
    try {
      await planScan(selectedScanId);
      await loadScanDetails(selectedScanId);
    } catch (err) {
      setMessage(String(err));
    }
  };

  const handleExecute = async (actionId: string) => {
    if (!selectedScanId) return;
    setMessage(null);
    try {
      await executeActionApi(selectedScanId, actionId);
      await loadScanDetails(selectedScanId);
    } catch (err) {
      setMessage(String(err));
    }
  };

  const handleSetAuth = async () => {
    if (!selectedScanId) return;
    setMessage(null);
    try {
      if (authCookieA.trim()) {
        await setAuthHeaders(selectedScanId, 'userA', {
          Cookie: authCookieA.trim(),
        });
      }
      if (authCookieB.trim()) {
        await setAuthHeaders(selectedScanId, 'userB', {
          Cookie: authCookieB.trim(),
        });
      }
      setMessage('Auth headers updated for userA/userB.');
    } catch (err) {
      setMessage(String(err));
    }
  };

  const nodesArray = selectedScan
    ? Object.values(selectedScan.attackNodes || {})
    : [];

  return (
    <div className="app">
      <header className="header">
        <h1>VulnForge</h1>
        <p>AI-guided web attack surface explorer & access control tester.</p>
      </header>

      {message && <div className="message">{message}</div>}

      <section className="panel">
        <h2>Start New Scan</h2>
        <div className="row">
          <input
            type="text"
            placeholder="https://target-app.example.com"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
          />
          <button onClick={handleCreateScan} disabled={!targetUrl}>
            Start Scan
          </button>
        </div>
        <p className="hint">
          The crawler will explore as guest. Use the Auth panel below to add
          sessions for userA/userB to enable BAC/BOLA tests.
        </p>
      </section>

      <section className="layout">
        <div className="sidebar">
          <h2>Scans</h2>
          <button onClick={loadScans}>Refresh</button>
          <ul className="scan-list">
            {scans.map((s) => (
              <li
                key={s.id}
                className={
                  s.id === selectedScanId ? 'scan-item active' : 'scan-item'
                }
                onClick={() => setSelectedScanId(s.id)}
              >
                <div className="scan-url">{s.targetUrl}</div>
                <div className="scan-meta">
                  <span>{s.status}</span>
                  <span>{s.findingCount} findings</span>
                </div>
              </li>
            ))}
          </ul>
        </div>

        <div className="content">
          {!selectedScan && <p>Select a scan to see details.</p>}
          {selectedScan && (
            <>
              <div className="scan-header">
                <h2>Scan Details</h2>
                <div>
                  <strong>Target:</strong> {selectedScan.targetUrl}
                </div>
                <div>
                  <strong>Status:</strong> {selectedScan.status}
                </div>
                <button onClick={handlePlan} disabled={loadingScan}>
                  AI Plan Next Steps
                </button>
              </div>

              <div className="panels-grid">
                <div className="panel">
                  <h3>Auth Sessions</h3>
                  <label>
                    userA Cookie header
                    <input
                      type="text"
                      placeholder="session=..."
                      value={authCookieA}
                      onChange={(e) => setAuthCookieA(e.target.value)}
                    />
                  </label>
                  <label>
                    userB Cookie header
                    <input
                      type="text"
                      placeholder="session=..."
                      value={authCookieB}
                      onChange={(e) => setAuthCookieB(e.target.value)}
                    />
                  </label>
                  <button onClick={handleSetAuth}>Save Auth Headers</button>
                  <p className="hint">
                    Log in as different users in your browser, copy cookies, and
                    paste here to enable BAC/BOLA testing.
                  </p>
                </div>

                <div className="panel">
                  <h3>Attack Surface Map</h3>
                  <div className="nodes-list">
                    {nodesArray.map((n: any) => (
                      <div key={n.id} className="node-item">
                        <div>
                          <strong>{n.type.toUpperCase()}</strong>{' '}
                          <span className="pill">{n.authContext}</span>
                        </div>
                        <div className="url">{n.url}</div>
                        {n.tags?.length ? (
                          <div className="tags">
                            {n.tags.map((t: string) => (
                              <span key={t} className="pill pill-tag">
                                {t}
                              </span>
                            ))}
                          </div>
                        ) : null}
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <div className="panels-grid">
                <div className="panel">
                  <h3>AI Decisions (Attacker Brain)</h3>
                  {!selectedScan.actions?.length && (
                    <p>No AI actions yet. Click &ldquo;AI Plan Next Steps&rdquo;.</p>
                  )}
                  <ul className="actions-list">
                    {selectedScan.actions?.map((a: any) => (
                      <li key={a.id} className="action-item">
                        <div className="action-header">
                          <span className="pill">{a.actionType}</span>
                          <span className="pill">
                            Risk: {a.riskScore ?? 'n/a'}
                          </span>
                          <button onClick={() => handleExecute(a.id)}>
                            Execute
                          </button>
                        </div>
                        <div className="action-expl">
                          <strong>Reasoning:</strong> {a.explanation}
                        </div>
                        {a.expectedSignal && (
                          <div className="action-expl">
                            <strong>Expected signal:</strong> {a.expectedSignal}
                          </div>
                        )}
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="panel">
                  <h3>Findings</h3>
                  {!selectedScan.findings?.length && (
                    <p>No findings yet. Execute AI actions to run tests.</p>
                  )}
                  <ul className="findings-list">
                    {selectedScan.findings?.map((f: any) => (
                      <li key={f.id} className="finding-item">
                        <div className="finding-header">
                          <span className="pill">{f.type}</span>
                          <span className={`pill severity-${f.severity}`}>
                            {f.severity}
                          </span>
                        </div>
                        <div className="url">{f.url}</div>
                        <div className="evidence">
                          <strong>Evidence:</strong> {f.evidence}
                        </div>
                        {f.aiExplanation && (
                          <div className="evidence">
                            <strong>AI rationale:</strong> {f.aiExplanation}
                          </div>
                        )}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </>
          )}
        </div>
      </section>
    </div>
  );
};

