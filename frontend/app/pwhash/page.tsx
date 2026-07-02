"use client";

import { useEffect, useState } from "react";
import Topbar from "@/components/Topbar";
import Sidebar, { SidebarItem } from "@/components/Sidebar";
import { useToast } from "@/components/Toast";

// See page_codesign.tsx for why this exists — bypasses next.config.js's
// rewrite proxy entirely when NEXT_PUBLIC_API_URL is set; no-op otherwise.
const API_BASE = process.env.NEXT_PUBLIC_API_URL || "";
const api = (path: string) => `${API_BASE}${path}`;

// frontend/app/pwhash/page.tsx
// Backend: password_hashing/api.py mounted at /pwhash
// Platform tabs are driven by GET /pwhash/platforms — the registry in
// password_hashing/platforms.py — so a newly-registered platform (a new
// Linux variant, a new network OS, whatever) appears here with zero
// frontend changes.

const NAV: SidebarItem[] = [
  { key: "scan", label: "Scan", icon: "scan", section: "Audit" },
  { key: "harden", label: "Hardening Plans", icon: "harden", section: "Audit" },
  { key: "history", label: "Scan History", icon: "history", section: "Audit" },
];

const RISK_CLASS: Record<string, string> = {
  critical: "pill-red", high: "pill-red", medium: "pill-muted", low: "pill-green", best: "pill-green",
};
// "medium" gets an inline amber override since there's no confirmed pill-amber
// class in this codebase — everything else reuses pill-red/green/muted.
const RISK_STYLE: Record<string, Record<string, string>> = {
  medium: { color: "#9a6a1a", borderColor: "#9a6a1a" },
};

export default function PasswordHashingPage() {
  const { toast, Toast } = useToast();
  const [page, setPage] = useState("scan");

  const [platformList, setPlatformList] = useState<any[] | null>(null);
  const [platform, setPlatform] = useState<string>("linux");
  const [text, setText] = useState("");
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<any>(null);

  const [hardenPlatform, setHardenPlatform] = useState("linux");
  const [plan, setPlan] = useState<any>(null);
  const [loadingPlan, setLoadingPlan] = useState(false);

  const [history, setHistory] = useState<any[] | null>(null);
  const [historyLoading, setHistoryLoading] = useState(false);

  useEffect(() => {
    fetch(api("/pwhash/platforms")).then((r) => r.json()).then((list) => {
      setPlatformList(list);
      if (list.length && !list.find((p: any) => p.id === platform)) setPlatform(list[0].id);
    }).catch(() => {});
  }, []);

  const currentPlatform = platformList?.find((p) => p.id === platform);

  async function runScan() {
    if (!text.trim()) { toast("Paste some content to scan first.", "error"); return; }
    setScanning(true); setResult(null);
    try {
      const res = await fetch(api(`/pwhash/scan/${platform}`), {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
      });
      if (!res.ok) throw new Error((await res.json()).detail || res.statusText);
      setResult(await res.json());
    } catch (e: any) {
      toast("Scan failed: " + e.message, "error");
    } finally { setScanning(false); }
  }

  async function loadPlan() {
    setLoadingPlan(true); setPlan(null);
    try {
      const res = await fetch(api(`/pwhash/harden/${hardenPlatform}`));
      setPlan(await res.json());
    } catch (e: any) {
      toast("Failed to load plan: " + e.message, "error");
    } finally { setLoadingPlan(false); }
  }

  async function loadHistory() {
    setHistoryLoading(true);
    try {
      const res = await fetch(api("/pwhash/scans?limit=50"));
      setHistory(await res.json());
    } finally { setHistoryLoading(false); }
  }

  function selectPage(key: string) {
    setPage(key);
    if (key === "history") loadHistory();
  }

  const totalCritHigh = result ? (result.by_risk?.critical || 0) + (result.by_risk?.high || 0) : 0;

  return (
    <div className="shell">
      <Topbar
        tag="Password Hashing"
        links={[{ href: "/", label: "Home" }, { href: "/ssh", label: "SSH" }, { href: "/codesign", label: "Code Signing" }, { href: "/docs", label: "API", external: true }]}
      />
      <Sidebar items={NAV} active={page} onSelect={selectPage} />

      <main className="main">
        {page === "scan" && (
          <div>
            <div style={{ marginBottom: 20 }}>
              <h1 style={{ fontFamily: "var(--serif)", fontSize: 22, fontWeight: 600, marginBottom: 4 }}>Password Hash Audit</h1>
              <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>
                Classifies the hashing scheme protecting each credential and flags weak/legacy algorithms.
                Cryptiq never sees plaintext passwords and cannot rehash existing credentials — see
                Hardening Plans for how to roll the algorithm forward. Platforms below are pulled live
                from the backend registry — adding a new one needs no frontend change.
              </div>
            </div>

            <div className="btn-row" style={{ marginBottom: 16, flexWrap: "wrap" }}>
              {(platformList || []).map((p) => (
                <button
                  key={p.id}
                  className={`btn ${platform === p.id ? "btn-primary" : "btn-ghost"} btn-sm`}
                  onClick={() => { setPlatform(p.id); setResult(null); setText(""); }}
                  title={p.description}
                >
                  {p.label}
                </button>
              ))}
              {!platformList && <span style={{ fontSize: 13, color: "var(--ink-faint)" }}>Loading platforms…</span>}
            </div>

            <div className="field">
              <label>Paste content {currentPlatform ? `(${currentPlatform.label})` : ""}</label>
              <textarea
                rows={8} value={text} onChange={(e) => setText(e.target.value)}
                placeholder={currentPlatform?.placeholder || "paste config or hash values here"}
                style={{ fontFamily: "var(--mono)", fontSize: 12, width: "100%" }}
              />
            </div>

            <div className="btn-row" style={{ marginTop: 12 }}>
              <button className="btn btn-primary" disabled={scanning} onClick={runScan}>{scanning ? <span className="spinner" /> : null} Scan</button>
            </div>

            {result && (
              <>
                <div className="stat-grid" style={{ marginTop: 24 }}>
                  <div className="stat-card"><div className="stat-label">Findings</div><div className="stat-value">{result.total_findings}</div></div>
                  <div className="stat-card"><div className="stat-label">Critical / High</div><div className="stat-value" style={{ color: totalCritHigh ? "#b8391a" : undefined }}>{totalCritHigh}</div></div>
                  <div className="stat-card"><div className="stat-label">Best Practice</div><div className="stat-value" style={{ color: "#0d7d89" }}>{result.by_risk?.best || 0}</div></div>
                </div>

                {!result.findings.length ? (
                  <div className="empty" style={{ marginTop: 20 }}><div className="empty-icon">✅</div><div className="empty-title">No classifiable hashes found in the pasted text.</div></div>
                ) : (
                  <div className="table-wrap" style={{ marginTop: 20 }}>
                    <table className="data-table">
                      <thead><tr><th>Identifier</th><th>Algorithm</th><th>Risk</th><th>Reason</th><th>Recommendation</th></tr></thead>
                      <tbody>
                        {result.findings.map((f: any, i: number) => (
                          <tr key={i}>
                            <td style={{ fontFamily: "var(--mono)" }}>{f.identifier}</td>
                            <td style={{ fontFamily: "var(--mono)" }}>{f.algorithm}</td>
                            <td><span className={`pill ${RISK_CLASS[f.risk] || "pill-muted"}`} style={RISK_STYLE[f.risk] || {}}>{f.risk}</span></td>
                            <td style={{ fontSize: 12, color: "var(--ink-faint)" }}>{f.reason}</td>
                            <td style={{ fontSize: 12 }}>{f.recommendation}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            )}
          </div>
        )}

        {page === "harden" && (
          <div>
            <div style={{ marginBottom: 20 }}>
              <h1 style={{ fontFamily: "var(--serif)", fontSize: 22, fontWeight: 600, marginBottom: 4 }}>Hardening Plans</h1>
              <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>
                Concrete commands to roll the default hashing algorithm forward. Nothing here is executed automatically — copy, review, and run.
              </div>
            </div>

            <div className="field-row" style={{ alignItems: "flex-end" }}>
              <div className="field" style={{ maxWidth: 260 }}>
                <label>Platform</label>
                <select value={hardenPlatform} onChange={(e) => setHardenPlatform(e.target.value)}>
                  <option value="linux">Linux</option>
                  <option value="macos">macOS</option>
                  <option value="windows">Windows</option>
                  <option value="network_cisco_ios">Cisco IOS</option>
                  <option value="network_panos">Palo Alto PAN-OS</option>
                </select>
              </div>
              <button className="btn btn-primary" disabled={loadingPlan} onClick={loadPlan}>{loadingPlan ? <span className="spinner" /> : null} Get Plan</button>
            </div>

            {plan && (
              <div style={{ marginTop: 20 }}>
                <div className="notice notice-info">{plan.summary}</div>
                <div className="section-label" style={{ marginTop: 16 }}>Commands</div>
                <pre className="cmd-block">{plan.commands.join("\n")}</pre>
                {!!plan.notes?.length && (
                  <>
                    <div className="section-label" style={{ marginTop: 16 }}>Notes</div>
                    <ul>{plan.notes.map((n: string, i: number) => <li key={i} style={{ fontSize: 13, marginBottom: 6 }}>{n}</li>)}</ul>
                  </>
                )}
              </div>
            )}
          </div>
        )}

        {page === "history" && (
          <div>
            <div style={{ marginBottom: 28 }}>
              <h1 style={{ fontFamily: "var(--serif)", fontSize: 22, fontWeight: 600, marginBottom: 4 }}>Scan History</h1>
              <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>Only classification metadata is stored — never raw hash material.</div>
            </div>
            <div className="btn-row" style={{ marginBottom: 20 }}><button className="btn btn-ghost" onClick={loadHistory}>Refresh</button></div>
            {historyLoading || history === null ? <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>Loading…</div> :
              !history.length ? <div className="empty"><div className="empty-icon">🔑</div><div className="empty-title">No scans yet.</div></div> : (
                <div className="table-wrap">
                  <table className="data-table">
                    <thead><tr><th>Platform</th><th>Source</th><th>Findings</th><th>By Risk</th><th>When</th></tr></thead>
                    <tbody>
                      {history.map((h, i) => (
                        <tr key={i}>
                          <td><span className="pill pill-muted">{h.platform}</span></td>
                          <td style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{h.source}</td>
                          <td>{h.total_findings}</td>
                          <td style={{ fontSize: 12 }}>{Object.entries(h.by_risk).map(([k, v]) => `${k}:${v}`).join(", ")}</td>
                          <td style={{ fontSize: 12, color: "var(--ink-faint)" }}>{h.scanned_at}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
          </div>
        )}
      </main>

      <Toast />
    </div>
  );
}