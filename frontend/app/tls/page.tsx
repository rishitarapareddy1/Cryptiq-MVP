"use client";

import { useState } from "react";
import Topbar from "@/components/Topbar";
import Sidebar, { SidebarItem } from "@/components/Sidebar";
import { useToast } from "@/components/Toast";
import { RiskBadge, PqcBadge, QuantumVuln } from "@/components/Badges";

const NAV: SidebarItem[] = [
  { key: "scan", label: "Scan domain", icon: "search", section: "Scanning" },
  { key: "discover", label: "Discover & scan", icon: "discover" },
  { key: "bulk", label: "Bulk scan", icon: "bulk" },
  { key: "aws-certs", label: "ACM Certificates", icon: "cert", section: "AWS" },
  { key: "aws-keys", label: "KMS Keys", icon: "key" },
  { key: "history", label: "Scan history", icon: "history", section: "History" },
  { key: "cbom", label: "CBOM export", icon: "cbom" },
];

function TLSResultCard({ r }: { r: any }) {
  return (
    <div className="result-card">
      <div className="result-header">
        <div className="result-domain">{r.domain}</div>
        <RiskBadge level={r.risk_level} />
        <PqcBadge status={r.pqc_status} />
      </div>
      <div className="result-grid">
        <div><div className="result-field-label">TLS version</div><div className="result-field-value">{r.tls_version || "—"}</div></div>
        <div><div className="result-field-label">Algorithm</div><div className="result-field-value">{r.algorithm || "—"}</div></div>
        <div><div className="result-field-label">Key size</div><div className="result-field-value">{r.keysize ?? "—"} bit</div></div>
        <div><div className="result-field-label">Signature algo</div><div className="result-field-value">{r.signature_algorithm || "—"}</div></div>
        <div><div className="result-field-label">Issuer</div><div className="result-field-value" style={{ fontSize: 11 }}>{r.issuer || "—"}</div></div>
        <div><div className="result-field-label">Expires</div><div className="result-field-value" style={{ fontSize: 11 }}>{r.expiry || "—"}</div></div>
        <div><div className="result-field-label">Days left</div><div className="result-field-value" style={{ color: (r.days_until_expiry || 0) < 30 ? "#b8391a" : (r.days_until_expiry || 0) < 90 ? "var(--amber-deep)" : "#0d7d89" }}>{r.days_until_expiry ?? "—"}</div></div>
        <div><div className="result-field-label">Quantum vulnerable</div><div className="result-field-value"><QuantumVuln vuln={r.quantum_vulnerable} /></div></div>
      </div>
      {!!(r.ct_logs && r.ct_logs.length) && (
        <div className="findings">
          <div className="findings-title">CT log entries (recent)</div>
          {r.ct_logs.map((c: any, i: number) => (
            <div key={i} style={{ display: "flex", gap: 16, flexWrap: "wrap", fontFamily: "var(--mono)", fontSize: 11, color: "var(--ink-faint)", padding: "4px 0", borderBottom: "1px solid var(--line)" }}>
              <span>{c.common_name}</span>
              <span style={{ color: "var(--ink)" }}>{c.issuer?.split(",")[0] || "—"}</span>
              <span>{c.not_after?.slice(0, 10) || "—"}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function TLSPage() {
  const { toast, Toast } = useToast();
  const [page, setPage] = useState("scan");

  // scan
  const [scanDomain, setScanDomain] = useState("");
  const [scanLoading, setScanLoading] = useState(false);
  const [scanResult, setScanResult] = useState<any>(null);

  // discover
  const [discDomain, setDiscDomain] = useState("");
  const [discLoading, setDiscLoading] = useState(false);
  const [discOnly, setDiscOnly] = useState<any>(null);
  const [discScan, setDiscScan] = useState<any>(null);

  // bulk
  const [bulkText, setBulkText] = useState("");
  const [bulkLoading, setBulkLoading] = useState(false);
  const [bulkResults, setBulkResults] = useState<any[]>([]);

  // aws
  const [certs, setCerts] = useState<any[] | null>(null);
  const [keys, setKeys] = useState<any[] | null>(null);

  // history
  const [history, setHistory] = useState<any[] | null>(null);

  // cbom
  const [cbomDomain, setCbomDomain] = useState("");
  const [cbomData, setCbomData] = useState<any>(null);
  const [cbomLoading, setCbomLoading] = useState(false);

  async function doScan() {
    if (!scanDomain.trim()) { toast("Enter a domain", "error"); return; }
    setScanLoading(true); setScanResult(null);
    try {
      const res = await fetch("/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain: scanDomain.trim() }) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setScanResult(data.result || data);
      toast(`Scanned ${scanDomain}`, "success");
    } catch (e: any) {
      toast("Failed: " + e.message, "error");
    } finally { setScanLoading(false); }
  }

  async function doDiscover() {
    if (!discDomain.trim()) { toast("Enter a root domain", "error"); return; }
    setDiscLoading(true); setDiscOnly(null); setDiscScan(null);
    try {
      const res = await fetch("/discover", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ root_domain: discDomain.trim() }) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setDiscOnly(data);
      toast(`Found ${(data.domains || []).length} domains`, "success");
    } catch (e: any) {
      toast("Failed: " + e.message, "error");
    } finally { setDiscLoading(false); }
  }

  async function doDiscoverAndScan() {
    if (!discDomain.trim()) { toast("Enter a root domain", "error"); return; }
    setDiscLoading(true); setDiscOnly(null); setDiscScan(null);
    try {
      const res = await fetch("/discover/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ root_domain: discDomain.trim() }) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setDiscScan(data);
      toast(`Scanned ${(data.results || []).length} domains`, "success");
    } catch (e: any) {
      toast("Failed: " + e.message, "error");
    } finally { setDiscLoading(false); }
  }

  async function doBulk() {
    const domains = bulkText.trim().split("\n").map((d) => d.trim()).filter(Boolean);
    if (!domains.length) { toast("Enter at least one domain", "error"); return; }
    setBulkLoading(true); setBulkResults([]);
    try {
      const res = await fetch("/scan/bulk", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domains }) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setBulkResults(data.results || []);
      toast(`Scanned ${(data.results || []).length} domains`, "success");
    } catch (e: any) {
      toast("Failed: " + e.message, "error");
    } finally { setBulkLoading(false); }
  }

  async function loadAWSCerts() {
    setCerts(null);
    try {
      const res = await fetch("/aws/certificates");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setCerts(data.results || []);
    } catch (e: any) { toast(e.message, "error"); setCerts([]); }
  }

  async function loadAWSKeys() {
    setKeys(null);
    try {
      const res = await fetch("/aws/keys");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setKeys(data.results || []);
    } catch (e: any) { toast(e.message, "error"); setKeys([]); }
  }

  async function loadHistory() {
    setHistory(null);
    try {
      const res = await fetch("/scans");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setHistory(data.scans || []);
    } catch (e: any) { toast(e.message, "error"); setHistory([]); }
  }

  async function loadTLSCBOM() {
    if (!cbomDomain.trim()) { toast("Enter a domain", "error"); return; }
    setCbomLoading(true); setCbomData(null);
    try {
      const res = await fetch(`/tls/cbom/${encodeURIComponent(cbomDomain.trim())}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setCbomData(await res.json());
      toast("CBOM generated", "success");
    } catch (e: any) { toast(e.message, "error"); } finally { setCbomLoading(false); }
  }

  async function loadAWSCBOM() {
    setCbomLoading(true); setCbomData(null);
    try {
      const res = await fetch("/aws/cbom");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setCbomData(await res.json());
      toast("CBOM generated", "success");
    } catch (e: any) { toast(e.message, "error"); } finally { setCbomLoading(false); }
  }

  function downloadCBOM() {
    if (!cbomData) return;
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([JSON.stringify(cbomData, null, 2)], { type: "application/json" }));
    a.download = `cbom_tls_${Date.now()}.json`;
    a.click();
  }

  function select(key: string) {
    setPage(key);
    if (key === "history" && !history) loadHistory();
    if (key === "aws-certs" && !certs) loadAWSCerts();
    if (key === "aws-keys" && !keys) loadAWSKeys();
  }

  return (
    <div className="shell">
      <Topbar tag="v1.0" links={[{ href: "/", label: "Home" }, { href: "/docs", label: "API docs ↗", external: true }]} />
      <Sidebar items={NAV} active={page} onSelect={select} />
      <main className="main">

        {page === "scan" && (
          <div>
            <div className="page-header" style={{ marginBottom: 28 }}>
              <h1 style={{ fontFamily: "var(--serif)", fontSize: 22, fontWeight: 600, marginBottom: 4 }}>Scan a domain</h1>
              <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>Extract TLS certificate details, algorithm, key exchange, and PQC readiness for any HTTPS domain.</div>
            </div>
            <div className="field-row" style={{ alignItems: "flex-end" }}>
              <div className="field" style={{ maxWidth: 300 }}><label>Domain</label><input type="text" value={scanDomain} onChange={(e) => setScanDomain(e.target.value)} onKeyDown={(e) => e.key === "Enter" && doScan()} placeholder="google.com" /></div>
              <button className="btn btn-primary" disabled={scanLoading} onClick={doScan}>{scanLoading ? <span className="spinner" /> : null} Scan</button>
            </div>
            {scanResult && <div style={{ marginTop: 20 }}><TLSResultCard r={scanResult} /></div>}
          </div>
        )}

        {page === "discover" && (
          <div>
            <div className="page-header" style={{ marginBottom: 28 }}>
              <h1 style={{ fontFamily: "var(--serif)", fontSize: 22, fontWeight: 600, marginBottom: 4 }}>Discover & scan</h1>
              <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>Auto-discover all subdomains from CT logs and Route53, then bulk scan them.</div>
            </div>
            <div className="field-row" style={{ alignItems: "flex-end" }}>
              <div className="field" style={{ maxWidth: 300 }}><label>Root domain</label><input type="text" value={discDomain} onChange={(e) => setDiscDomain(e.target.value)} placeholder="stripe.com" /></div>
              <button className="btn btn-ghost" disabled={discLoading} onClick={doDiscover}>{discLoading ? <span className="spinner" /> : null} Discover only</button>
              <button className="btn btn-primary" disabled={discLoading} onClick={doDiscoverAndScan}>{discLoading ? <span className="spinner" /> : null} Discover & scan all</button>
            </div>

            {discOnly && (
              <div style={{ marginTop: 20 }}>
                <div className="stat-grid">
                  <div className="stat-card"><div className="stat-label">Domains found</div><div className="stat-value">{(discOnly.domains || []).length}</div></div>
                  <div className="stat-card"><div className="stat-label">EC2 hosts</div><div className="stat-value">{(discOnly.hosts || []).length}</div></div>
                </div>
                <hr className="divider" />
                <div className="section-label">Discovered domains</div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                  {(discOnly.domains || []).map((d: string) => <span key={d} className="tool-chip">{d}</span>)}
                </div>
              </div>
            )}

            {discScan && (
              <div style={{ marginTop: 20 }}>
                <div className="stat-grid">
                  <div className="stat-card"><div className="stat-label">Domains found</div><div className="stat-value">{discScan.domains_found || 0}</div></div>
                  <div className="stat-card"><div className="stat-label">Scanned</div><div className="stat-value">{discScan.domains_scanned || 0}</div></div>
                  <div className="stat-card"><div className="stat-label">Vulnerable</div><div className="stat-value" style={{ color: "#b8391a" }}>{(discScan.results || []).filter((r: any) => r.quantum_vulnerable).length}</div></div>
                  <div className="stat-card"><div className="stat-label">EC2 hosts</div><div className="stat-value">{(discScan.ec2_hosts || []).length}</div></div>
                </div>
                <hr className="divider" />
                {(discScan.results || []).map((r: any, i: number) => <TLSResultCard key={i} r={r} />)}
              </div>
            )}
          </div>
        )}

        {page === "bulk" && (
          <div>
            <div className="page-header" style={{ marginBottom: 28 }}>
              <h1 style={{ fontFamily: "var(--serif)", fontSize: 22, fontWeight: 600, marginBottom: 4 }}>Bulk scan</h1>
              <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>Scan multiple domains at once. One per line.</div>
            </div>
            <div className="field" style={{ marginBottom: 14 }}><label>Domains</label><textarea value={bulkText} onChange={(e) => setBulkText(e.target.value)} placeholder={"google.com\ngithub.com\nstripe.com"} /></div>
            <button className="btn btn-primary" disabled={bulkLoading} onClick={doBulk}>{bulkLoading ? <span className="spinner" /> : null} Scan all</button>

            {!!bulkResults.length && (
              <div style={{ marginTop: 24 }}>
                <div className="stat-grid">
                  <div className="stat-card"><div className="stat-label">Scanned</div><div className="stat-value">{bulkResults.length}</div></div>
                  <div className="stat-card"><div className="stat-label">Vulnerable</div><div className="stat-value" style={{ color: "#b8391a" }}>{bulkResults.filter((r) => r.quantum_vulnerable).length}</div></div>
                  <div className="stat-card"><div className="stat-label">High risk</div><div className="stat-value" style={{ color: "var(--amber-deep)" }}>{bulkResults.filter((r) => (r.risk_level || "").toLowerCase() === "high").length}</div></div>
                </div>
                <hr className="divider" />
                {bulkResults.map((r, i) => <TLSResultCard key={i} r={r} />)}
              </div>
            )}
          </div>
        )}

        {page === "aws-certs" && (
          <div>
            <div className="page-header" style={{ display: "flex", alignItems: "flex-start", gap: 16, flexWrap: "wrap", marginBottom: 28 }}>
              <div style={{ flex: 1 }}>
                <h1 style={{ fontFamily: "var(--serif)", fontSize: 22, fontWeight: 600, marginBottom: 4 }}>ACM Certificates</h1>
                <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>AWS Certificate Manager — all certificates in us-east-1.</div>
              </div>
              <button className="btn btn-ghost" onClick={loadAWSCerts}>Refresh</button>
            </div>
            {certs === null ? <div className="empty"><div className="empty-icon">◎</div><div className="empty-title">Loading…</div></div> :
              !certs.length ? <div className="empty"><div className="empty-icon">◎</div><div className="empty-title">No certificates found</div></div> : (
                <div className="table-wrap">
                  <table className="data-table">
                    <thead><tr><th>Domain</th><th>Algorithm</th><th>Key size</th><th>Status</th><th>Expires</th><th>Issuer</th><th>Quantum vuln</th></tr></thead>
                    <tbody>
                      {certs.map((c, i) => (
                        <tr key={i}>
                          <td className="domain-cell">{c.domain_name}</td>
                          <td>{c.algorithm}</td>
                          <td>{c.key_size ?? "—"}</td>
                          <td>{c.status}</td>
                          <td>{c.expiry?.slice(0, 10) || "—"}</td>
                          <td>{c.issuer?.slice(0, 30) || "—"}</td>
                          <td><QuantumVuln vuln={c.quantum_vulnerable} /></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
          </div>
        )}

        {page === "aws-keys" && (
          <div>
            <div className="page-header" style={{ display: "flex", alignItems: "flex-start", gap: 16, flexWrap: "wrap", marginBottom: 28 }}>
              <div style={{ flex: 1 }}>
                <h1 style={{ fontFamily: "var(--serif)", fontSize: 22, fontWeight: 600, marginBottom: 4 }}>KMS Keys</h1>
                <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>AWS Key Management Service — all keys and their algorithm classification.</div>
              </div>
              <button className="btn btn-ghost" onClick={loadAWSKeys}>Refresh</button>
            </div>
            {keys === null ? <div className="empty"><div className="empty-icon">◎</div><div className="empty-title">Loading…</div></div> :
              !keys.length ? <div className="empty"><div className="empty-icon">◎</div><div className="empty-title">No KMS keys found</div></div> : (
                <div className="table-wrap">
                  <table className="data-table">
                    <thead><tr><th>Key ID</th><th>Algorithm</th><th>State</th><th>Description</th><th>Quantum vuln</th></tr></thead>
                    <tbody>
                      {keys.map((k, i) => (
                        <tr key={i}>
                          <td style={{ color: "var(--blue-deep, var(--blue))" }}>{k.key_id}</td>
                          <td>{k.algorithm}</td>
                          <td>{k.status}</td>
                          <td className="domain-cell">{k.description || "—"}</td>
                          <td><QuantumVuln vuln={k.quantum_vulnerable} /></td>
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
            <div className="page-header" style={{ display: "flex", alignItems: "flex-start", gap: 16, flexWrap: "wrap", marginBottom: 28 }}>
              <div style={{ flex: 1 }}>
                <h1 style={{ fontFamily: "var(--serif)", fontSize: 22, fontWeight: 600, marginBottom: 4 }}>Scan history</h1>
                <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>All domain scans, most recent first.</div>
              </div>
              <button className="btn btn-ghost" onClick={loadHistory}>Refresh</button>
            </div>
            {history === null ? <div className="empty"><div className="empty-icon">◎</div><div className="empty-title">Loading…</div></div> :
              !history.length ? <div className="empty"><div className="empty-icon">◎</div><div className="empty-title">No scans yet</div></div> : (
                <div className="table-wrap">
                  <table className="data-table">
                    <thead><tr><th>Domain</th><th>TLS</th><th>Algorithm</th><th>Vuln</th><th>Risk</th><th>PQC</th><th>Scanned</th></tr></thead>
                    <tbody>
                      {history.map((s, i) => (
                        <tr key={i}>
                          <td style={{ color: "var(--blue-deep, var(--blue))" }}>{s.domain}</td>
                          <td>{s.tls_version || "—"}</td>
                          <td>{s.algorithm || "—"}</td>
                          <td><QuantumVuln vuln={s.quantum_vulnerable} /></td>
                          <td><RiskBadge level={s.risk_level} /></td>
                          <td><PqcBadge status={s.pqc_status} /></td>
                          <td style={{ color: "var(--ink-faint)", fontSize: 11 }}>{s.scanned_at ? new Date(s.scanned_at).toLocaleString() : "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
          </div>
        )}

        {page === "cbom" && (
          <div>
            <div className="page-header" style={{ marginBottom: 28 }}>
              <h1 style={{ fontFamily: "var(--serif)", fontSize: 22, fontWeight: 600, marginBottom: 4 }}>CBOM export</h1>
              <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>Generate a CycloneDX 1.6 CBOM for scanned domains or AWS assets.</div>
            </div>
            <div className="field-row" style={{ alignItems: "flex-end" }}>
              <div className="field" style={{ maxWidth: 260 }}><label>Domain</label><input type="text" value={cbomDomain} onChange={(e) => setCbomDomain(e.target.value)} placeholder="google.com" /></div>
              <button className="btn btn-primary" disabled={cbomLoading} onClick={loadTLSCBOM}>TLS CBOM</button>
              <button className="btn btn-ghost" disabled={cbomLoading} onClick={loadAWSCBOM}>AWS CBOM</button>
              {cbomData && <button className="btn btn-ghost" onClick={downloadCBOM}>Download JSON</button>}
            </div>
            {cbomLoading && <div className="empty"><div className="empty-icon">◎</div><div className="empty-title">Generating…</div></div>}
            {cbomData && <pre className="cbom-pre">{JSON.stringify(cbomData, null, 2)}</pre>}
          </div>
        )}

      </main>
      <Toast />
    </div>
  );
}