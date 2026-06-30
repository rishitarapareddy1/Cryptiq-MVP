"use client";

import { useState } from "react";
import Topbar from "@/components/Topbar";
import Sidebar, { SidebarItem } from "@/components/Sidebar";
import { useToast } from "@/components/Toast";
import { RiskBadge, PqcBadge, QuantumVuln } from "@/components/Badges";
import { SSHResultCard } from "@/components/SSHResultCard";

const NAV: SidebarItem[] = [
  { key: "scan", label: "Scan host", icon: "search", section: "Scanning" },
  { key: "bulk", label: "Bulk scan", icon: "bulk" },
  { key: "discover", label: "Network discover", icon: "discover" },
  { key: "inventory", label: "Inventory", icon: "inventory", section: "Inventory" },
  { key: "assets", label: "Assets & tags", icon: "assets" },
  { key: "history", label: "Scan history", icon: "history" },
  { key: "report", label: "PDF report", icon: "report", section: "Reports" },
  { key: "cbom", label: "CBOM export", icon: "cbom" },
  { key: "trend", label: "Trend tracking", icon: "trend" },
];

export default function SSHPage() {
  const { toast, Toast } = useToast();
  const [page, setPage] = useState("scan");

  // scan
  const [host, setHost] = useState("");
  const [port, setPort] = useState(22);
  const [scanLoading, setScanLoading] = useState(false);
  const [scanResult, setScanResult] = useState<any>(null);

  // bulk
  const [bulkHosts, setBulkHosts] = useState("");
  const [bulkPort, setBulkPort] = useState(22);
  const [bulkWorkers, setBulkWorkers] = useState(20);
  const [bulkLoading, setBulkLoading] = useState(false);
  const [bulkResults, setBulkResults] = useState<any[]>([]);
  const [bulkSummary, setBulkSummary] = useState<any>(null);

  // discover
  const [discTarget, setDiscTarget] = useState("");
  const [discPort, setDiscPort] = useState(22);
  const [discTimeout, setDiscTimeout] = useState(3);
  const [discLoading, setDiscLoading] = useState(false);
  const [discData, setDiscData] = useState<any>(null);

  // inventory
  const [inventory, setInventory] = useState<any>(null);
  const [invLoading, setInvLoading] = useState(false);

  // assets
  const [assets, setAssets] = useState<any[] | null>(null);
  const [envFilter, setEnvFilter] = useState("");
  const [remFilter, setRemFilter] = useState("");
  const [tagModal, setTagModal] = useState(false);
  const [tagForm, setTagForm] = useState<any>({ host: "", port: 22, remediation_status: "pending", can_upgrade: "true" });

  // history
  const [history, setHistory] = useState<any[] | null>(null);
  const [historyFilter, setHistoryFilter] = useState("");
  const [historyDetail, setHistoryDetail] = useState<any>(null);

  // report
  const [reportOrg, setReportOrg] = useState("");
  const [reportStatus, setReportStatus] = useState("");
  const [reportLoading, setReportLoading] = useState(false);

  // cbom
  const [cbomHost, setCbomHost] = useState("");
  const [cbomData, setCbomData] = useState<any>(null);
  const [cbomLoading, setCbomLoading] = useState(false);

  // trend
  const [trend, setTrend] = useState<any[] | null>(null);

  async function doScan() {
    if (!host.trim()) { toast("Enter a hostname", "error"); return; }
    setScanLoading(true); setScanResult(null);
    try {
      const res = await fetch("/ssh/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ host: host.trim(), port }) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setScanResult(await res.json());
      toast(`Scanned ${host}`, "success");
    } catch (e: any) { toast("Scan failed: " + e.message, "error"); } finally { setScanLoading(false); }
  }

  async function doBulk() {
    const hosts = bulkHosts.trim().split("\n").map((h) => h.trim()).filter(Boolean);
    if (!hosts.length) { toast("Enter at least one host", "error"); return; }
    setBulkLoading(true); setBulkResults([]); setBulkSummary(null);
    try {
      const res = await fetch("/ssh/scan/bulk", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ hosts, port: bulkPort, max_workers: bulkWorkers }) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setBulkResults(data.results || []);
      setBulkSummary(data.summary);
      toast(`Scanned ${data.total_succeeded} of ${data.total_requested} hosts`, "success");
    } catch (e: any) { toast("Bulk scan failed: " + e.message, "error"); } finally { setBulkLoading(false); }
  }

  async function doDiscover(autoScan: boolean) {
    if (!discTarget.trim()) { toast("Enter a target", "error"); return; }
    setDiscLoading(true); setDiscData(null);
    try {
      const res = await fetch("/ssh/discover", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ target: discTarget.trim(), port: discPort, timeout: discTimeout, auto_scan: autoScan, max_workers: 100 }) });
      if (!res.ok) { const err = await res.json(); throw new Error(err.detail || `HTTP ${res.status}`); }
      const data = await res.json();
      setDiscData(data);
      toast(`Discovered ${data.total_discovered} hosts`, "success");
    } catch (e: any) { toast(e.message, "error"); } finally { setDiscLoading(false); }
  }

  function quickScanHost(h: string, p: number) {
    setHost(h); setPort(p); setPage("scan");
    setTimeout(doScan, 0);
  }

  async function loadInventory() {
    setInvLoading(true);
    try {
      const res = await fetch("/ssh/inventory");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setInventory(await res.json());
    } catch (e: any) { toast(e.message, "error"); } finally { setInvLoading(false); }
  }

  async function loadAssets() {
    setAssets(null);
    try {
      const res = await fetch("/ssh/assets/enriched");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      let data = await res.json();
      if (envFilter) data = data.filter((a: any) => a.environment === envFilter);
      if (remFilter) data = data.filter((a: any) => a.remediation_status === remFilter);
      setAssets(data);
    } catch (e: any) { toast(e.message, "error"); setAssets([]); }
  }

  function prefillTag(h: string, p: number) {
    setTagForm({ ...tagForm, host: h, port: p });
    setPage("assets");
    setTagModal(true);
  }

  async function submitTag() {
    if (!tagForm.host) { toast("Enter a host", "error"); return; }
    const tags = tagForm.tags ? String(tagForm.tags).split(",").map((t: string) => t.trim()).filter(Boolean) : undefined;
    const body = { ...tagForm, can_upgrade: tagForm.can_upgrade === "true", tags };
    try {
      const res = await fetch("/ssh/assets/tag", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      toast("Asset tagged", "success");
      setTagModal(false);
      loadAssets();
    } catch (e: any) { toast("Failed: " + e.message, "error"); }
  }

  async function loadHistory() {
    setHistory(null);
    try {
      const res = await fetch("/ssh/scans?limit=200");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setHistory(await res.json());
    } catch (e: any) { toast(e.message, "error"); setHistory([]); }
  }

  async function downloadReport() {
    const org = reportOrg.trim() || "Organisation";
    setReportLoading(true); setReportStatus("Building report — this may take a few seconds…");
    try {
      const res = await fetch(`/ssh/report?org_name=${encodeURIComponent(org)}`, { method: "POST" });
      if (!res.ok) { const d = await res.json(); throw new Error(d.detail || `HTTP ${res.status}`); }
      const blob = await res.blob();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `cryptiq_report_${Date.now()}.pdf`;
      a.click();
      setReportStatus("Report downloaded.");
      toast("PDF report downloaded", "success");
    } catch (e: any) { setReportStatus("Error: " + e.message); toast("Report failed: " + e.message, "error"); } finally { setReportLoading(false); }
  }

  async function loadCBOM() {
    if (!cbomHost.trim()) { toast("Enter a hostname", "error"); return; }
    setCbomLoading(true); setCbomData(null);
    try {
      const res = await fetch(`/ssh/cbom/${encodeURIComponent(cbomHost.trim())}`);
      if (res.status === 404) throw new Error(`No scan found for ${cbomHost} — scan it first.`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setCbomData(await res.json());
      toast("CBOM generated", "success");
    } catch (e: any) { toast(e.message, "error"); } finally { setCbomLoading(false); }
  }

  function downloadCBOM() {
    if (!cbomData) return;
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([JSON.stringify(cbomData, null, 2)], { type: "application/json" }));
    a.download = `cbom_${cbomHost}_${Date.now()}.json`;
    a.click();
  }

  async function loadTrend() {
    setTrend(null);
    try {
      const res = await fetch("/ssh/trend");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setTrend(await res.json());
    } catch (e: any) { toast(e.message, "error"); setTrend([]); }
  }

  async function takeSnapshot() {
    try {
      const res = await fetch("/ssh/snapshot?label=" + encodeURIComponent(new Date().toISOString().slice(0, 10)), { method: "POST" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const d = await res.json();
      toast(`Snapshot saved: ${d.label}`, "success");
      loadTrend();
    } catch (e: any) { toast("Snapshot failed: " + e.message, "error"); }
  }

  function select(key: string) {
    setPage(key);
    if (key === "inventory" && !inventory) loadInventory();
    if (key === "assets" && !assets) loadAssets();
    if (key === "history" && !history) loadHistory();
    if (key === "trend" && !trend) loadTrend();
  }

  const filteredHistory = history && historyFilter ? history.filter((r) => r.host.toLowerCase().includes(historyFilter.toLowerCase())) : history;

  const pqcColors: Record<string, string> = { vulnerable: "#b8391a", hybrid: "var(--blue-deep, var(--blue))", pqc_ready: "#0d7d89", unknown: "var(--ink-faint)" };

  function Bars({ obj, total }: { obj: Record<string, number>; total: number }) {
    const entries = Object.entries(obj || {}).sort((a, b) => b[1] - a[1]);
    return <>{entries.map(([k, v]) => {
      const w = total > 0 ? ((v / total) * 100).toFixed(1) : "0";
      return (
        <div className="bar-row" key={k}>
          <div className="bar-label">{k}</div>
          <div className="bar-track"><div className="bar-fill" style={{ width: `${w}%` }} /></div>
          <div className="bar-count">{v}</div>
        </div>
      );
    })}</>;
  }

  return (
    <div className="shell">
      <Topbar tag="v1.0" links={[{ href: "/", label: "Home" }, { href: "/docs", label: "API docs ↗", external: true }]} />
      <Sidebar items={NAV} active={page} onSelect={select} />
      <main className="main">

        {page === "scan" && (
          <div>
            <div style={{ marginBottom: 28 }}>
              <h1 style={{ fontFamily: "var(--serif)", fontSize: 22, fontWeight: 600, marginBottom: 4 }}>Scan a host</h1>
              <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>Connect to an SSH endpoint and extract its full cryptographic profile.</div>
            </div>
            <div className="field-row" style={{ alignItems: "flex-end" }}>
              <div className="field" style={{ maxWidth: 260 }}><label>Hostname or IP</label><input type="text" value={host} onChange={(e) => setHost(e.target.value)} onKeyDown={(e) => e.key === "Enter" && doScan()} placeholder="github.com" /></div>
              <div className="field" style={{ maxWidth: 90 }}><label>Port</label><input type="number" value={port} onChange={(e) => setPort(parseInt(e.target.value) || 22)} /></div>
              <button className="btn btn-primary" disabled={scanLoading} onClick={doScan}>{scanLoading ? <span className="spinner" /> : null} Scan</button>
            </div>
            {scanResult && <div style={{ marginTop: 20 }}><SSHResultCard r={scanResult} onTag={prefillTag} /></div>}
          </div>
        )}

        {page === "bulk" && (
          <div>
            <div style={{ marginBottom: 28 }}>
              <h1 style={{ fontFamily: "var(--serif)", fontSize: 22, fontWeight: 600, marginBottom: 4 }}>Bulk scan</h1>
              <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>Scan multiple hosts concurrently. One per line.</div>
            </div>
            <div className="field" style={{ marginBottom: 14 }}><label>Hosts</label><textarea value={bulkHosts} onChange={(e) => setBulkHosts(e.target.value)} placeholder={"github.com\ngitlab.com\nbitbucket.org"} /></div>
            <div className="field-row" style={{ alignItems: "flex-end" }}>
              <div className="field" style={{ maxWidth: 90 }}><label>Port</label><input type="number" value={bulkPort} onChange={(e) => setBulkPort(parseInt(e.target.value) || 22)} /></div>
              <div className="field" style={{ maxWidth: 120 }}><label>Concurrency</label><input type="number" value={bulkWorkers} onChange={(e) => setBulkWorkers(parseInt(e.target.value) || 20)} /></div>
              <button className="btn btn-primary" disabled={bulkLoading} onClick={doBulk}>{bulkLoading ? <span className="spinner" /> : null} Scan all</button>
            </div>
            {!!bulkResults.length && bulkSummary && (
              <div style={{ marginTop: 24 }}>
                <div className="stat-grid">
                  <div className="stat-card"><div className="stat-label">Scanned</div><div className="stat-value">{bulkSummary.total_scanned}</div></div>
                  <div className="stat-card"><div className="stat-label">Quantum vulnerable</div><div className="stat-value" style={{ color: "#b8391a" }}>{bulkSummary.quantum_vulnerable}</div></div>
                  <div className="stat-card"><div className="stat-label">High risk</div><div className="stat-value" style={{ color: "var(--amber-deep)" }}>{bulkSummary.by_risk_level?.high ?? 0}</div></div>
                  <div className="stat-card"><div className="stat-label">PQC ready</div><div className="stat-value" style={{ color: "#0d7d89" }}>{bulkSummary.by_pqc_status?.pqc_ready ?? 0}</div></div>
                </div>
                <hr className="divider" />
                {bulkResults.map((r, i) => <SSHResultCard key={i} r={r} onTag={prefillTag} />)}
              </div>
            )}
          </div>
        )}

        {page === "discover" && (
          <div>
            <div style={{ marginBottom: 28 }}>
              <h1 style={{ fontFamily: "var(--serif)", fontSize: 22, fontWeight: 600, marginBottom: 4 }}>Network discovery</h1>
              <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>Find all SSH hosts on a network. Accepts CIDR ranges, IP ranges, or comma-separated hosts.</div>
            </div>
            <div className="field-row">
              <div className="field" style={{ maxWidth: 320 }}><label>Target</label><input type="text" value={discTarget} onChange={(e) => setDiscTarget(e.target.value)} placeholder="192.168.1.0/24" /></div>
              <div className="field" style={{ maxWidth: 90 }}><label>Port</label><input type="number" value={discPort} onChange={(e) => setDiscPort(parseInt(e.target.value) || 22)} /></div>
              <div className="field" style={{ maxWidth: 100 }}><label>Timeout (s)</label><input type="number" value={discTimeout} onChange={(e) => setDiscTimeout(parseFloat(e.target.value) || 3)} /></div>
            </div>
            <div className="btn-row" style={{ marginBottom: 24 }}>
              <button className="btn btn-primary" disabled={discLoading} onClick={() => doDiscover(false)}>{discLoading ? <span className="spinner" /> : null} Discover</button>
              <button className="btn btn-ghost" disabled={discLoading} onClick={() => doDiscover(true)}>Discover + scan crypto</button>
              <span style={{ fontSize: 12, color: "var(--ink-faint)" }}>CIDR e.g. 10.0.0.0/24 · Range e.g. 10.0.0.1-10.0.0.50 · Comma-separated IPs</span>
            </div>

            {discData && (!discData.scan_results ? (
              <div>
                <div style={{ marginBottom: 16, color: "var(--ink-faint)", fontSize: 13 }}>Found <b style={{ color: "var(--ink)" }}>{discData.total_discovered}</b> SSH hosts on <code style={{ color: "var(--blue-deep, var(--blue))" }}>{discTarget}</code></div>
                {!discData.discovered.length ? <div className="empty"><div className="empty-icon">◎</div><div className="empty-title">No SSH hosts found</div></div> : (
                  <div className="table-wrap">
                    <table className="data-table">
                      <thead><tr><th>IP</th><th>Hostname</th><th>Port</th><th>Banner</th><th>Device type</th><th>OS hint</th><th>Action</th></tr></thead>
                      <tbody>
                        {discData.discovered.map((h: any, i: number) => (
                          <tr key={i}>
                            <td style={{ color: "var(--blue-deep, var(--blue))" }}>{h.ip}</td>
                            <td>{h.hostname || "—"}</td>
                            <td>{h.port}</td>
                            <td className="domain-cell">{h.ssh_banner || "—"}</td>
                            <td>{deviceBadgeText(h.device_type)}</td>
                            <td>{h.os_hint || "—"}</td>
                            <td><button className="btn btn-ghost btn-sm" onClick={() => quickScanHost(h.hostname || h.ip, h.port)}>Scan</button></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            ) : (
              <div>
                <div style={{ marginBottom: 16, color: "var(--ink-faint)", fontSize: 13 }}>Found <b style={{ color: "var(--ink)" }}>{discData.total_discovered}</b> SSH hosts on <code style={{ color: "var(--blue-deep, var(--blue))" }}>{discTarget}</code></div>
                {discData.summary && (
                  <div className="stat-grid">
                    <div className="stat-card"><div className="stat-label">Discovered</div><div className="stat-value">{discData.total_discovered}</div></div>
                    <div className="stat-card"><div className="stat-label">Vulnerable</div><div className="stat-value" style={{ color: "#b8391a" }}>{discData.summary.quantum_vulnerable}</div></div>
                    <div className="stat-card"><div className="stat-label">High risk</div><div className="stat-value" style={{ color: "var(--amber-deep)" }}>{discData.summary.by_risk_level?.high ?? 0}</div></div>
                    <div className="stat-card"><div className="stat-label">PQC ready</div><div className="stat-value" style={{ color: "#0d7d89" }}>{discData.summary.pqc_readiness_percent}%</div></div>
                  </div>
                )}
                <hr className="divider" />
                {discData.scan_results.map((r: any, i: number) => <SSHResultCard key={i} r={r} onTag={prefillTag} />)}
              </div>
            ))}
          </div>
        )}

        {page === "inventory" && (
          <div>
            <div style={{ display: "flex", alignItems: "flex-start", gap: 16, flexWrap: "wrap", marginBottom: 28 }}>
              <div style={{ flex: 1 }}>
                <h1 style={{ fontFamily: "var(--serif)", fontSize: 22, fontWeight: 600, marginBottom: 4 }}>Inventory</h1>
                <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>Aggregate crypto asset view across all scanned hosts.</div>
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                <button className="btn btn-ghost" onClick={takeSnapshot}>📸 Snapshot</button>
                <button className="btn btn-ghost" onClick={loadInventory}>Refresh</button>
              </div>
            </div>
            {invLoading || !inventory ? <div className="empty"><div className="empty-icon">◎</div><div className="empty-title">Loading…</div></div> :
              !inventory.total_hosts ? <div className="empty"><div className="empty-icon">◎</div><div className="empty-title">No hosts scanned yet</div></div> : (
                <div>
                  {(() => {
                    const r = 34, circ = 2 * Math.PI * r, pct = inventory.pqc_readiness_percent || 0, dash = (pct / 100) * circ;
                    return (
                      <div style={{ display: "flex", alignItems: "center", gap: 20, marginBottom: 20 }}>
                        <div className="ring-wrap">
                          <svg width="80" height="80" viewBox="0 0 80 80">
                            <circle cx="40" cy="40" r={r} fill="none" stroke="var(--line)" strokeWidth={7} />
                            <circle cx="40" cy="40" r={r} fill="none" stroke="#0d7d89" strokeWidth={7} strokeDasharray={`${dash} ${circ}`} strokeLinecap="round" />
                          </svg>
                          <div className="ring-center">{pct}%</div>
                        </div>
                        <div>
                          <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 4 }}>PQC Readiness</div>
                          <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>{inventory.total_hosts} hosts · {inventory.quantum_vulnerable} quantum-vulnerable</div>
                        </div>
                      </div>
                    );
                  })()}
                  <div className="stat-grid">
                    <div className="stat-card"><div className="stat-label">Total</div><div className="stat-value">{inventory.total_hosts}</div></div>
                    <div className="stat-card"><div className="stat-label">Critical</div><div className="stat-value" style={{ color: "#b8391a" }}>{inventory.by_risk_level?.critical ?? 0}</div></div>
                    <div className="stat-card"><div className="stat-label">High</div><div className="stat-value" style={{ color: "var(--amber-deep)" }}>{inventory.by_risk_level?.high ?? 0}</div></div>
                    <div className="stat-card"><div className="stat-label">PQC ready</div><div className="stat-value" style={{ color: "#0d7d89" }}>{inventory.by_pqc_status?.pqc_ready ?? 0}</div></div>
                    <div className="stat-card"><div className="stat-label">Hybrid</div><div className="stat-value" style={{ color: "var(--blue-deep, var(--blue))" }}>{inventory.by_pqc_status?.hybrid ?? 0}</div></div>
                  </div>
                  <hr className="divider" />
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 32 }}>
                    <div><div className="section-label">Host key algorithms</div><Bars obj={inventory.all_host_key_algorithms || inventory.by_primary_host_key_algorithm || {}} total={inventory.total_hosts} /></div>
                    <div><div className="section-label">PQC status</div><Bars obj={inventory.by_pqc_status || {}} total={inventory.total_hosts} /></div>
                  </div>
                  <div style={{ marginTop: 20 }}><div className="section-label">Key exchange algorithms</div><Bars obj={inventory.by_negotiated_kex || {}} total={inventory.total_hosts} /></div>
                  {!!((inventory.critical_migration_targets || []).length || (inventory.high_priority_targets || []).length) && (
                    <>
                      <hr className="divider" />
                      <div className="section-label">Migration targets</div>
                      {(inventory.critical_migration_targets || []).map((h: string) => <div className="bar-row" key={h}><div className="bar-label">{h}</div><RiskBadge level="critical" /></div>)}
                      {(inventory.high_priority_targets || []).map((h: string) => <div className="bar-row" key={h}><div className="bar-label">{h}</div><RiskBadge level="high" /></div>)}
                    </>
                  )}
                </div>
              )}
          </div>
        )}

        {page === "assets" && (
          <div>
            <div style={{ display: "flex", alignItems: "flex-start", gap: 16, flexWrap: "wrap", marginBottom: 20 }}>
              <div style={{ flex: 1 }}>
                <h1 style={{ fontFamily: "var(--serif)", fontSize: 22, fontWeight: 600, marginBottom: 4 }}>Assets & tags</h1>
                <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>Attach business context to SSH assets — names, owners, environments, remediation status.</div>
              </div>
              <button className="btn btn-primary" onClick={() => { setTagForm({ host: "", port: 22, remediation_status: "pending", can_upgrade: "true" }); setTagModal(true); }}>+ Tag asset</button>
            </div>
            <div className="field-row">
              <div className="field" style={{ maxWidth: 180 }}>
                <label>Filter env</label>
                <select value={envFilter} onChange={(e) => { setEnvFilter(e.target.value); setTimeout(loadAssets, 0); }}>
                  <option value="">All environments</option><option>production</option><option>staging</option><option>dev</option><option>dmz</option>
                </select>
              </div>
              <div className="field" style={{ maxWidth: 180 }}>
                <label>Remediation</label>
                <select value={remFilter} onChange={(e) => { setRemFilter(e.target.value); setTimeout(loadAssets, 0); }}>
                  <option value="">All statuses</option><option value="pending">Pending</option><option value="in_progress">In progress</option><option value="completed">Completed</option><option value="blocked">Blocked</option>
                </select>
              </div>
              <button className="btn btn-ghost" onClick={loadAssets} style={{ alignSelf: "flex-end" }}>Refresh</button>
            </div>

            {assets === null ? <div className="empty"><div className="empty-icon">◎</div><div className="empty-title">Loading…</div></div> :
              !assets.length ? <div className="empty"><div className="empty-icon">◎</div><div className="empty-title">No assets</div><div className="empty-sub">Tag assets after scanning to see them here.</div></div> : (
                <div className="table-wrap">
                  <table className="data-table">
                    <thead><tr><th>Host</th><th>Name</th><th>Environment</th><th>Owner</th><th>Risk</th><th>PQC</th><th>Status</th><th>Tags</th></tr></thead>
                    <tbody>
                      {assets.map((a, i) => (
                        <tr key={i} onClick={() => prefillTag(a.host, a.port)} style={{ cursor: "pointer" }}>
                          <td style={{ color: "var(--blue-deep, var(--blue))" }}>{a.host}:{a.port}</td>
                          <td>{a.asset_name || "—"}</td>
                          <td>{a.environment || "—"}</td>
                          <td>{a.asset_owner || "—"}</td>
                          <td><RiskBadge level={a.risk_level} /></td>
                          <td><PqcBadge status={a.pqc_status} /></td>
                          <td>{a.remediation_status || "pending"}</td>
                          <td><div className="pill-list">{(a.tags || []).map((t: string) => <span key={t} className="pill" style={{ fontSize: 10 }}>{t}</span>)}</div></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
          </div>
        )}

        {page === "history" && (
          <div>
            <div style={{ display: "flex", alignItems: "flex-start", gap: 16, flexWrap: "wrap", marginBottom: 20 }}>
              <div style={{ flex: 1 }}>
                <h1 style={{ fontFamily: "var(--serif)", fontSize: 22, fontWeight: 600, marginBottom: 4 }}>Scan history</h1>
                <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>All scans, most recent first. Click a row to expand.</div>
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                <input type="text" value={historyFilter} onChange={(e) => setHistoryFilter(e.target.value)} placeholder="Filter by host…" style={{ width: 200 }} />
                <button className="btn btn-ghost" onClick={loadHistory}>Refresh</button>
              </div>
            </div>
            {history === null ? <div className="empty"><div className="empty-icon">◎</div><div className="empty-title">Loading…</div></div> :
              !filteredHistory?.length ? <div className="empty"><div className="empty-icon">◎</div><div className="empty-title">No scans yet</div></div> : (
                <>
                  <div className="table-wrap">
                    <table className="data-table">
                      <thead><tr><th>Host</th><th>Port</th><th>Version</th><th>Host key</th><th>KEX</th><th>Risk</th><th>PQC</th><th>Scanned</th></tr></thead>
                      <tbody>
                        {filteredHistory!.map((r, i) => (
                          <tr key={i} onClick={() => setHistoryDetail(r)} style={{ cursor: "pointer" }}>
                            <td style={{ color: "var(--blue-deep, var(--blue))" }}>{r.host}</td>
                            <td>{r.port}</td>
                            <td style={{ color: "var(--ink-faint)" }}>{r.ssh_version ?? "—"}</td>
                            <td>{r.host_key_algorithm ?? "—"}{r.host_key_size ? " / " + r.host_key_size + "b" : ""}</td>
                            <td className="domain-cell">{r.key_exchange ?? "—"}</td>
                            <td><RiskBadge level={r.risk_level} /></td>
                            <td><PqcBadge status={r.pqc_status} /></td>
                            <td style={{ color: "var(--ink-faint)" }}>{r.scanned_at ? new Date(r.scanned_at).toLocaleString() : "—"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  {historyDetail && <div style={{ marginTop: 20 }}><SSHResultCard r={historyDetail} onTag={prefillTag} /></div>}
                </>
              )}
          </div>
        )}

        {page === "report" && (
          <div>
            <div style={{ marginBottom: 28 }}>
              <h1 style={{ fontFamily: "var(--serif)", fontSize: 22, fontWeight: 600, marginBottom: 4 }}>PDF report</h1>
              <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>Generate a consulting-grade PDF covering executive summary, full inventory, critical findings, and remediation roadmap.</div>
            </div>
            <div className="field-row" style={{ alignItems: "flex-end" }}>
              <div className="field" style={{ maxWidth: 280 }}><label>Organisation name</label><input type="text" value={reportOrg} onChange={(e) => setReportOrg(e.target.value)} placeholder="Acme Corp" /></div>
              <button className="btn btn-primary" disabled={reportLoading} onClick={downloadReport}>{reportLoading ? <span className="spinner" /> : null} Generate & download PDF</button>
            </div>
            {reportStatus && <div style={{ color: "var(--ink-faint)", fontSize: 13, marginTop: 10 }}>{reportStatus}</div>}
            <div className="card" style={{ marginTop: 28 }}>
              <div className="section-label" style={{ marginBottom: 16 }}>Report includes</div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                {["Cover page + executive summary with risk stats", "Full asset inventory table", "Critical & high risk detailed findings", "4-phase remediation roadmap", "Algorithm reference (non-technical explanations)", "Trend data (if snapshots taken)"].map((t) => (
                  <div className="finding" key={t}>{t}</div>
                ))}
              </div>
            </div>
          </div>
        )}

        {page === "cbom" && (
          <div>
            <div style={{ marginBottom: 28 }}>
              <h1 style={{ fontFamily: "var(--serif)", fontSize: 22, fontWeight: 600, marginBottom: 4 }}>CBOM export</h1>
              <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>Generate a CycloneDX 1.6 Cryptography Bill of Materials for a scanned host.</div>
            </div>
            <div className="field-row" style={{ alignItems: "flex-end" }}>
              <div className="field" style={{ maxWidth: 260 }}><label>Host</label><input type="text" value={cbomHost} onChange={(e) => setCbomHost(e.target.value)} onKeyDown={(e) => e.key === "Enter" && loadCBOM()} placeholder="github.com" /></div>
              <button className="btn btn-primary" disabled={cbomLoading} onClick={loadCBOM}>Generate CBOM</button>
              {cbomData && <button className="btn btn-ghost" onClick={downloadCBOM}>Download JSON</button>}
            </div>
            {cbomLoading && <div className="empty"><div className="empty-icon">◎</div><div className="empty-title">Generating…</div></div>}
            {cbomData && (
              <>
                <div style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--ink-faint)", margin: "16px 0 6px" }}>CycloneDX {cbomData.specVersion} · {cbomData.components?.length ?? 0} components</div>
                <pre className="cbom-pre">{JSON.stringify(cbomData, null, 2)}</pre>
              </>
            )}
          </div>
        )}

        {page === "trend" && (
          <div>
            <div style={{ display: "flex", alignItems: "flex-start", gap: 16, flexWrap: "wrap", marginBottom: 20 }}>
              <div style={{ flex: 1 }}>
                <h1 style={{ fontFamily: "var(--serif)", fontSize: 22, fontWeight: 600, marginBottom: 4 }}>Trend tracking</h1>
                <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>Fleet posture over time. Take snapshots to track remediation progress.</div>
              </div>
              <button className="btn btn-primary" onClick={takeSnapshot}>📸 Take snapshot</button>
            </div>
            {trend === null ? <div className="empty"><div className="empty-icon">◎</div><div className="empty-title">Loading…</div></div> :
              !trend.length ? <div className="empty"><div className="empty-icon">◎</div><div className="empty-title">No snapshots yet</div><div className="empty-sub">Click &quot;Take snapshot&quot; to capture the current fleet posture. Do this weekly to track progress.</div></div> : (
                (() => {
                  const ordered = [...trend].reverse();
                  const maxVuln = Math.max(...ordered.map((s) => s.quantum_vulnerable), 1);
                  return (
                    <div>
                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 32, marginBottom: 28 }}>
                        <div>
                          <div className="section-label">Quantum-vulnerable hosts over time</div>
                          <div className="trend-grid">
                            {ordered.map((s, i) => (
                              <div className="trend-bar-wrap" key={i}>
                                <div className="trend-val">{s.quantum_vulnerable}</div>
                                <div className="trend-bar" style={{ height: Math.round((s.quantum_vulnerable / maxVuln) * 100), background: "#ff6a4a" }} />
                                <div className="trend-label">{s.label}</div>
                              </div>
                            ))}
                          </div>
                        </div>
                        <div>
                          <div className="section-label">PQC readiness % over time</div>
                          <div className="trend-grid">
                            {ordered.map((s, i) => (
                              <div className="trend-bar-wrap" key={i}>
                                <div className="trend-val">{s.pqc_readiness_percent}%</div>
                                <div className="trend-bar" style={{ height: Math.round((s.pqc_readiness_percent / 100) * 100), background: "#0d7d89" }} />
                                <div className="trend-label">{s.label}</div>
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                      <hr className="divider" />
                      <div className="table-wrap">
                        <table className="data-table">
                          <thead><tr><th>Snapshot</th><th>Date</th><th>Hosts</th><th>Vulnerable</th><th>Critical</th><th>High</th><th>Hybrid</th><th>PQC ready</th><th>Readiness</th></tr></thead>
                          <tbody>
                            {ordered.map((s, i) => (
                              <tr key={i}>
                                <td>{s.label}</td>
                                <td>{new Date(s.snapshot_at).toLocaleDateString()}</td>
                                <td>{s.total_hosts}</td>
                                <td style={{ color: "#b8391a" }}>{s.quantum_vulnerable}</td>
                                <td style={{ color: "#b8391a" }}>{s.critical_count}</td>
                                <td style={{ color: "var(--amber-deep)" }}>{s.high_count}</td>
                                <td style={{ color: "var(--blue-deep, var(--blue))" }}>{s.hybrid_count}</td>
                                <td style={{ color: "#0d7d89" }}>{s.pqc_ready_count}</td>
                                <td style={{ color: "#0d7d89" }}>{s.pqc_readiness_percent}%</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  );
                })()
              )}
          </div>
        )}

      </main>

      {tagModal && (
        <div className="modal-backdrop open" onClick={(e) => { if (e.target === e.currentTarget) setTagModal(false); }}>
          <div className="modal">
            <div className="modal-header">
              <div className="modal-title">Tag asset</div>
              <button className="modal-close" onClick={() => setTagModal(false)}>×</button>
            </div>
            <div className="modal-body">
              <div className="field" style={{ marginBottom: 12 }}><label>Host *</label><input type="text" value={tagForm.host} onChange={(e) => setTagForm({ ...tagForm, host: e.target.value })} placeholder="192.168.1.42" /></div>
              <div className="field" style={{ marginBottom: 12 }}><label>Port</label><input type="number" value={tagForm.port} onChange={(e) => setTagForm({ ...tagForm, port: parseInt(e.target.value) || 22 })} /></div>
              <div className="field" style={{ marginBottom: 12 }}><label>Asset name</label><input type="text" value={tagForm.asset_name || ""} onChange={(e) => setTagForm({ ...tagForm, asset_name: e.target.value })} placeholder="Jenkins CI" /></div>
              <div className="field" style={{ marginBottom: 12 }}><label>Owner</label><input type="text" value={tagForm.asset_owner || ""} onChange={(e) => setTagForm({ ...tagForm, asset_owner: e.target.value })} placeholder="devops@company.com" /></div>
              <div className="field" style={{ marginBottom: 12 }}>
                <label>Environment</label>
                <select value={tagForm.environment || ""} onChange={(e) => setTagForm({ ...tagForm, environment: e.target.value })}>
                  <option value="">— select —</option><option value="production">Production</option><option value="staging">Staging</option><option value="dev">Development</option><option value="dmz">DMZ</option>
                </select>
              </div>
              <div className="field" style={{ marginBottom: 12 }}><label>Business unit</label><input type="text" value={tagForm.business_unit || ""} onChange={(e) => setTagForm({ ...tagForm, business_unit: e.target.value })} placeholder="Engineering" /></div>
              <div className="field" style={{ marginBottom: 12 }}><label>Location</label><input type="text" value={tagForm.location || ""} onChange={(e) => setTagForm({ ...tagForm, location: e.target.value })} placeholder="AWS us-east-1" /></div>
              <div className="field" style={{ marginBottom: 12 }}>
                <label>Remediation status</label>
                <select value={tagForm.remediation_status} onChange={(e) => setTagForm({ ...tagForm, remediation_status: e.target.value })}>
                  <option value="pending">Pending</option><option value="in_progress">In progress</option><option value="completed">Completed</option><option value="blocked">Blocked</option><option value="waiver">Waiver</option>
                </select>
              </div>
              <div className="field" style={{ marginBottom: 12 }}>
                <label>Can upgrade?</label>
                <select value={tagForm.can_upgrade} onChange={(e) => setTagForm({ ...tagForm, can_upgrade: e.target.value })}>
                  <option value="true">Yes</option><option value="false">No (blocked)</option>
                </select>
              </div>
              <div className="field" style={{ marginBottom: 12 }}><label>Upgrade blocker / notes</label><textarea value={tagForm.notes || ""} onChange={(e) => setTagForm({ ...tagForm, notes: e.target.value })} placeholder="Vendor EOL — no PQC support until firmware 2.0" style={{ minHeight: 60 }} /></div>
              <div className="field"><label>Tags (comma-separated)</label><input type="text" value={tagForm.tags || ""} onChange={(e) => setTagForm({ ...tagForm, tags: e.target.value })} placeholder="internet-facing, critical-infra" /></div>
            </div>
            <div className="modal-footer">
              <button className="btn btn-ghost" onClick={() => setTagModal(false)}>Cancel</button>
              <button className="btn btn-primary" onClick={submitTag}>Save</button>
            </div>
          </div>
        </div>
      )}

      <Toast />
    </div>
  );
}

function deviceBadgeText(t?: string) {
  if (!t || t === "unknown") return "—";
  return <span className="badge badge-unknown" style={{ fontSize: 10 }}>{t}</span>;
}