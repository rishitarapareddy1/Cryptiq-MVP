"use client";

import { useState } from "react";
import Topbar from "@/components/Topbar";
import { useToast } from "@/components/Toast";

export default function ALBPage() {
  const { toast, Toast } = useToast();
  const [page, setPage] = useState<"listeners" | "audit">("listeners");

  const [region, setRegion] = useState("us-east-1");
  const [discovering, setDiscovering] = useState(false);
  const [listeners, setListeners] = useState<any[] | null>(null);
  const [discoverErr, setDiscoverErr] = useState("");

  const [modalOpen, setModalOpen] = useState(false);
  const [current, setCurrent] = useState<any>(null);
  const [ghRepo, setGhRepo] = useState("");
  const [tfRepo, setTfRepo] = useState("");
  const [diff, setDiff] = useState<string | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const [lastDryRun, setLastDryRun] = useState<any>(null);
  const [openingPR, setOpeningPR] = useState(false);
  const [prUrl, setPrUrl] = useState("");

  const [audit, setAudit] = useState<any[] | null>(null);
  const [auditLoading, setAuditLoading] = useState(false);

  async function loadListeners() {
    setDiscovering(true); setDiscoverErr(""); setListeners(null);
    try {
      const res = await fetch(`/aws/alb-listeners?region=${encodeURIComponent(region || "us-east-1")}`);
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      setListeners(data.listeners || []);
    } catch (e: any) {
      setDiscoverErr("Discovery failed: " + e.message);
    } finally { setDiscovering(false); }
  }

  function openMigrateModal(listener: any) {
    setCurrent(listener); setDiff(null); setLastDryRun(null); setPrUrl(""); setModalOpen(true);
  }

  async function previewDiff() {
    if (!current) return;
    if (!ghRepo.trim() || !tfRepo.trim()) { toast("Enter GitHub repo and Terraform path.", "error"); return; }
    setPreviewing(true);
    try {
      const res = await fetch("/migrate/alb-tls", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ listener_arn: current.listener_arn, tf_repo: tfRepo, gh_repo: ghRepo, dry_run: true }),
      });
      const data = await res.json();
      if (data.status === "dry_run" && data.diff) {
        setLastDryRun(data);
        setDiff(data.diff);
      } else {
        setDiff(JSON.stringify(data, null, 2));
      }
    } catch (e: any) {
      setDiff("Error: " + e.message);
    } finally { setPreviewing(false); }
  }

  async function openPR() {
    if (!current || !lastDryRun) return;
    if (!window.confirm("Open a real migration PR in GitHub now? Cryptiq will NOT merge it.")) return;
    setOpeningPR(true);
    try {
      const res = await fetch("/migrate/alb-tls", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ listener_arn: current.listener_arn, tf_repo: tfRepo, gh_repo: ghRepo, dry_run: false }),
      });
      const data = await res.json();
      if (data.pr_url) setPrUrl(data.pr_url);
      else alert("Unexpected response: " + JSON.stringify(data));
    } catch (e: any) {
      alert("Error: " + e.message);
    } finally { setOpeningPR(false); }
  }

  async function loadAudit() {
    setAuditLoading(true); setAudit(null);
    try {
      const res = await fetch("/audit-log?limit=200");
      const data = await res.json();
      setAudit((data.entries || []).slice().reverse());
    } catch (e: any) {
      toast("Failed to load audit log: " + e.message, "error");
      setAudit([]);
    } finally { setAuditLoading(false); }
  }

  function selectPage(p: "listeners" | "audit") {
    setPage(p);
    if (p === "audit") loadAudit();
  }

  const vuln = listeners ? listeners.filter((l) => !l.is_post_quantum).length : 0;
  const pq = listeners ? listeners.length - vuln : 0;

  return (
    <div className="shell">
      <Topbar tag="ALB Dashboard" links={[{ href: "/", label: "Home" }, { href: "/tls", label: "TLS" }, { href: "/ssh", label: "SSH" }, { href: "/docs", label: "API", external: true }]} />

      <nav className="sidebar">
        <div className="nav-section">Views</div>
        <div className={`nav-item${page === "listeners" ? " active" : ""}`} onClick={() => selectPage("listeners")}>
          <svg width="15" height="15" fill="none" stroke="currentColor" strokeWidth={1.8} viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2" /><path d="M8 21h8M12 17v4" /></svg>
          ALB Listeners
        </div>
        <div className={`nav-item${page === "audit" ? " active" : ""}`} onClick={() => selectPage("audit")}>
          <svg width="15" height="15" fill="none" stroke="currentColor" strokeWidth={1.8} viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /><line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" /></svg>
          Audit Log
        </div>
      </nav>

      <main className="main">
        {page === "listeners" && (
          <div>
            <div style={{ marginBottom: 28 }}>
              <h1 style={{ fontFamily: "var(--serif)", fontSize: 22, fontWeight: 600, marginBottom: 4 }}>ALB / NLB TLS Listeners</h1>
              <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>Read-only discovery. Red rows need migration. Click &quot;Open migration PR&quot; to propose the change.</div>
            </div>

            <div className="field-row" style={{ alignItems: "flex-end" }}>
              <div className="field" style={{ maxWidth: 220 }}><label>AWS Region</label><input type="text" value={region} onChange={(e) => setRegion(e.target.value)} placeholder="us-east-1" /></div>
              <button className="btn btn-primary" disabled={discovering} onClick={loadListeners}>{discovering ? <span className="spinner" /> : null} Discover Listeners</button>
            </div>

            {listeners && !!listeners.length && (
              <div className="stat-grid" style={{ marginTop: 24 }}>
                <div className="stat-card"><div className="stat-label">Total Listeners</div><div className="stat-value">{listeners.length}</div></div>
                <div className="stat-card"><div className="stat-label">Needs Migration</div><div className="stat-value" style={{ color: "#b8391a" }}>{vuln}</div></div>
                <div className="stat-card"><div className="stat-label">PQ Ready</div><div className="stat-value" style={{ color: "#0d7d89" }}>{pq}</div></div>
              </div>
            )}

            {discoverErr && <div className="notice notice-warn" style={{ marginTop: 20 }}>{discoverErr}</div>}

            {listeners && !listeners.length && !discoverErr && (
              <div className="empty"><div className="empty-icon">🔍</div><div className="empty-title">No HTTPS/TLS listeners found in this region.</div></div>
            )}

            {listeners && !!listeners.length && (
              <div className="table-wrap" style={{ marginTop: 20 }}>
                <table className="data-table">
                  <thead><tr><th>Load Balancer</th><th>Port / Proto</th><th>Policy</th><th>Environment</th><th>PQ Status</th><th>Actions</th></tr></thead>
                  <tbody>
                    {listeners.map((l, i) => (
                      <tr key={i}>
                        <td style={{ fontFamily: "var(--mono)" }}>{l.lb_name}</td>
                        <td style={{ fontFamily: "var(--mono)" }}>{l.port} / {l.protocol}</td>
                        <td style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--ink-faint)" }}>{l.ssl_policy_name}</td>
                        <td><span className={`pill ${l.environment === "prod" ? "pill-red" : "pill-muted"}`}>{l.environment || "untagged"}</span></td>
                        <td><span className={`pill ${l.is_post_quantum ? "pill-green" : "pill-red"}`}>{l.is_post_quantum ? "PQ Ready" : "Needs Migration"}</span></td>
                        <td>
                          {l.is_post_quantum
                            ? <span style={{ color: "var(--ink-faint)", fontSize: 12 }}>PQ Ready</span>
                            : <button className="btn btn-danger btn-sm" onClick={() => openMigrateModal(l)}>Open Migration PR</button>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {page === "audit" && (
          <div>
            <div style={{ marginBottom: 28 }}>
              <h1 style={{ fontFamily: "var(--serif)", fontSize: 22, fontWeight: 600, marginBottom: 4 }}>Audit Log</h1>
              <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>Append-only record of every Cryptiq action. Never modified.</div>
            </div>
            <div className="btn-row" style={{ marginBottom: 20 }}><button className="btn btn-ghost" onClick={loadAudit}>Refresh</button></div>
            {auditLoading || audit === null ? <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>Loading…</div> :
              !audit.length ? <div className="empty"><div className="empty-icon">📋</div><div className="empty-title">No audit entries yet. Run a scan or migration.</div></div> : (
                <div>
                  {audit.map((e, i) => (
                    <div key={i} style={{ borderBottom: "1px solid var(--line)", padding: "10px 0", fontSize: 12, fontFamily: "var(--mono)" }}>
                      <span style={{ color: "var(--ink-faint)" }}>{e.timestamp}</span> · <span style={{ color: "var(--blue-deep, var(--blue))" }}>{e.action}</span> → <span style={{ color: e.outcome === "success" ? "#0d7d89" : e.outcome === "dry_run" ? "var(--blue-deep, var(--blue))" : "#b8391a" }}>{e.outcome}</span> · <span style={{ color: "var(--ink-faint)" }}>{e.target}</span>
                      {e.pr_url && <> <a href={e.pr_url} target="_blank" rel="noreferrer" style={{ color: "var(--amber-deep)" }}>PR ↗</a></>}
                    </div>
                  ))}
                </div>
              )}
          </div>
        )}
      </main>

      {modalOpen && (
        <div className="modal-backdrop open" onClick={(e) => { if (e.target === e.currentTarget) setModalOpen(false); }}>
          <div className="modal">
            <div className="modal-header">
              <div className="modal-title">Migrate {current?.lb_name}:{current?.port}</div>
              <button className="modal-close" onClick={() => setModalOpen(false)}>×</button>
            </div>
            <div className="modal-body">
              <div className="notice notice-info">
                This is a <strong>dry run</strong>. Review the diff below, then click &quot;Open PR&quot; to propose the change. Cryptiq will not merge the PR — a human does that.
              </div>
              <div className="field" style={{ marginBottom: 14 }}><label>GitHub Repo (owner/name)</label><input type="text" value={ghRepo} onChange={(e) => setGhRepo(e.target.value)} placeholder="e.g. acmecorp/infra" /></div>
              <div className="field" style={{ marginBottom: 14 }}><label>Terraform Repo Path (local)</label><input type="text" value={tfRepo} onChange={(e) => setTfRepo(e.target.value)} placeholder="e.g. /home/user/infra" /></div>
              <div className="section-label">Proposed Diff</div>
              <pre className="cmd-block">
                {(diff || 'Click "Preview Diff" to load.').split("\n").map((line, i) => (
                  <div key={i} style={{ color: line.startsWith("-") && !line.startsWith("---") ? "#ff8c7a" : line.startsWith("+") && !line.startsWith("+++") ? "var(--cyan-bright)" : undefined }}>{line}</div>
                ))}
              </pre>
              {prUrl && <div className="notice notice-info" style={{ marginTop: 14 }}>PR opened: <a href={prUrl} target="_blank" rel="noreferrer" style={{ color: "var(--blue-deep, var(--blue))" }}>{prUrl}</a></div>}
            </div>
            <div className="modal-footer">
              <button className="btn btn-ghost" onClick={() => setModalOpen(false)}>Cancel</button>
              <button className="btn btn-ghost" disabled={previewing} onClick={previewDiff}>{previewing ? <span className="spinner" /> : null} Preview Diff</button>
              <button className="btn btn-primary" disabled={!lastDryRun || openingPR} onClick={openPR}>{openingPR ? <span className="spinner" /> : null} Open PR</button>
            </div>
          </div>
        </div>
      )}

      <Toast />
    </div>
  );
}