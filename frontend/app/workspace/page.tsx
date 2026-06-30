"use client";

import { useEffect, useRef, useState } from "react";
import Topbar from "@/components/Topbar";
import { useToast } from "@/components/Toast";
import { QuantumVuln } from "@/components/Badges";

type Workspace = {
  id: number;
  org_name: string;
  root_domain: string;
  aws_connected?: boolean;
};

type ScanResult = {
  domain: string;
  tls_version?: string;
  algorithm?: string;
  quantum_vulnerable?: boolean;
  risk_level?: string;
  scanned_at?: string;
};

type JobStatus = {
  status: "pending" | "running" | "complete" | "failed";
  domains_found?: number;
  domains_scanned?: number;
  error?: string;
};

const CIRC = 2 * Math.PI * 60;

const headlines: Record<string, string> = {
  pending: "Waiting to start",
  running: "Scanning your attack surface",
  complete: "Scan complete",
  failed: "Scan hit a snag",
};

export default function WorkspacePage() {
  const { toast, Toast } = useToast();
  const [ws, setWs] = useState<Workspace | null>(null);
  const [orgName, setOrgName] = useState("");
  const [rootDomain, setRootDomain] = useState("");
  const [loadId, setLoadId] = useState("");
  const [creating, setCreating] = useState(false);

  const [awsKey, setAwsKey] = useState("");
  const [awsSecret, setAwsSecret] = useState("");
  const [awsRegion, setAwsRegion] = useState("us-east-1");
  const [connecting, setConnecting] = useState(false);

  const [scanning, setScanning] = useState(false);
  const [job, setJob] = useState<JobStatus | null>(null);
  const [results, setResults] = useState<ScanResult[]>([]);
  const pollTimer = useRef<ReturnType<typeof setInterval> | null>(null);

  const [sshScanning, setSshScanning] = useState(false);
  const [sshJob, setSshJob] = useState<JobStatus | null>(null);
  const [sshResults, setSshResults] = useState<any[]>([]);
  const sshPollTimer = useRef<ReturnType<typeof setInterval> | null>(null);

  const found = job?.domains_found || 0;
  const scanned = job?.domains_scanned || 0;
  const dialOffset = CIRC - (found > 0 ? Math.min(scanned / found, 1) : 0) * CIRC;

  const sshFound = sshJob?.domains_found || 0;
  const sshScanned = sshJob?.domains_scanned || 0;
  const sshDialOffset = CIRC - (sshFound > 0 ? Math.min(sshScanned / sshFound, 1) : 0) * CIRC;

  useEffect(() => {
    return () => {
      if (pollTimer.current) clearInterval(pollTimer.current);
      if (sshPollTimer.current) clearInterval(sshPollTimer.current);
    };
  }, []);

  async function createWorkspace() {
    if (!orgName.trim() || !rootDomain.trim()) { toast("Enter both organisation name and root domain", "error"); return; }
    setCreating(true);
    try {
      const res = await fetch("/workspace", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ org_name: orgName.trim(), root_domain: rootDomain.trim().toLowerCase() }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setWs(data);
      toast("Workspace opened", "success");
    } catch (e: any) {
      toast("Failed: " + e.message, "error");
    } finally {
      setCreating(false);
    }
  }

  async function loadWorkspace() {
    if (!loadId.trim()) { toast("Enter a workspace ID", "error"); return; }
    try {
      const res = await fetch(`/workspace/${loadId.trim()}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setWs(data);
      loadResults(data.id);
      loadSSHResults(data.id);
    } catch (e: any) {
      toast("Failed: " + e.message, "error");
    }
  }

  async function connectAWS() {
    if (!ws) return;
    if (!awsKey.trim() || !awsSecret.trim()) { toast("Enter both access key and secret key", "error"); return; }
    setConnecting(true);
    try {
      const res = await fetch(`/workspace/${ws.id}/connect/aws`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ aws_access_key: awsKey.trim(), aws_secret_key: awsSecret.trim(), aws_region: awsRegion || "us-east-1" }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setWs(data);
      setAwsKey(""); setAwsSecret("");
      toast("AWS account connected", "success");
    } catch (e: any) {
      toast("Failed: " + e.message, "error");
    } finally {
      setConnecting(false);
    }
  }

  async function startScan() {
    if (!ws) { toast("Open a workspace first", "error"); return; }
    setScanning(true);
    try {
      const res = await fetch(`/workspace/${ws.id}/scan`, { method: "POST" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setJob({ status: "pending" });
      toast("Scan started", "success");
      pollStatus(ws.id, data.job_id);
    } catch (e: any) {
      toast("Failed: " + e.message, "error");
    } finally {
      setScanning(false);
    }
  }

  function pollStatus(wsId: number, jobId: number) {
    if (pollTimer.current) clearInterval(pollTimer.current);
    const tick = async () => {
      try {
        const res = await fetch(`/workspace/${wsId}/scan/${jobId}/status`);
        if (!res.ok) return;
        const j: JobStatus = await res.json();
        setJob(j);
        loadResults(wsId);
        if (j.status === "complete" || j.status === "failed") {
          if (pollTimer.current) clearInterval(pollTimer.current);
          if (j.status === "complete") toast("Scan complete", "success");
          if (j.status === "failed") toast("Scan failed: " + (j.error || "unknown error"), "error");
        }
      } catch {}
    };
    tick();
    pollTimer.current = setInterval(tick, 5000);
  }

  async function loadResults(wsId?: number) {
    const id = wsId ?? ws?.id;
    if (!id) return;
    try {
      const res = await fetch(`/workspace/${id}/results`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setResults(data.results || []);
    } catch (e: any) {
      toast("Failed to load results: " + e.message, "error");
    }
  }

  async function startSSHScan() {
    if (!ws) { toast("Open a workspace first", "error"); return; }
    setSshScanning(true);
    try {
      const res = await fetch(`/workspace/${ws.id}/scan/ssh`, { method: "POST" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setSshJob({ status: "pending" });
      toast("SSH scan started", "success");
      pollSSHStatus(ws.id, data.job_id);
    } catch (e: any) {
      toast("Failed: " + e.message, "error");
    } finally {
      setSshScanning(false);
    }
  }

  function pollSSHStatus(wsId: number, jobId: number) {
    if (sshPollTimer.current) clearInterval(sshPollTimer.current);
    const tick = async () => {
      try {
        const res = await fetch(`/workspace/${wsId}/scan/${jobId}/status`);
        if (!res.ok) return;
        const j: JobStatus = await res.json();
        setSshJob(j);
        loadSSHResults(wsId);
        if (j.status === "complete" || j.status === "failed") {
          if (sshPollTimer.current) clearInterval(sshPollTimer.current);
          if (j.status === "complete") toast("SSH scan complete", "success");
          if (j.status === "failed") toast("SSH scan failed: " + (j.error || "unknown error"), "error");
        }
      } catch {}
    };
    tick();
    sshPollTimer.current = setInterval(tick, 5000);
  }

  async function loadSSHResults(wsId?: number) {
    const id = wsId ?? ws?.id;
    if (!id) return;
    try {
      const res = await fetch(`/workspace/${id}/ssh/results`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setSshResults(data.results || []);
    } catch (e: any) {
      toast("Failed to load SSH results: " + e.message, "error");
    }
  }

  async function downloadCBOM() {
    if (!ws) { toast("Open a workspace first", "error"); return; }
    try {
      const res = await fetch(`/workspace/${ws.id}/cbom`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
      a.download = `cryptiq_cbom_workspace_${ws.id}.json`;
      a.click();
      toast("CBOM downloaded", "success");
    } catch (e: any) {
      toast("Failed: " + e.message, "error");
    }
  }

  return (
    <>
      <Topbar />
      <main className="shell-simple">
        {!ws ? (
          <>
            <div className="hero-eyebrow"><span className="pip" />The quantum clock is running</div>
            <h1 className="hero-title">Open a <span className="accent">workspace</span>,<br />find what&apos;s exposed.</h1>
            <p className="hero-sub">One workspace per organisation. Give it a name and a root domain — Cryptiq pulls every subdomain straight out of certificate transparency logs and gets scanning.</p>

            <div className="card">
              <div className="card-title">Start a new case</div>
              <div className="card-sub">Takes about ten seconds. No credit card, no calendar invite.</div>
              <div className="field-row">
                <div className="field"><label>Organisation name</label><input type="text" value={orgName} onChange={(e) => setOrgName(e.target.value)} placeholder="Acme Corp" /></div>
                <div className="field"><label>Root domain</label><input type="text" value={rootDomain} onChange={(e) => setRootDomain(e.target.value)} placeholder="acme.com" /></div>
              </div>
              <div className="btn-row">
                <button className="btn btn-primary" disabled={creating} onClick={createWorkspace}>
                  {creating ? <span className="spinner" /> : null} Open workspace →
                </button>
              </div>
            </div>

            <div className="lite-card">
              <div className="card-title" style={{ fontSize: 15, marginBottom: 14 }}>Already have one open?</div>
              <div className="field-row" style={{ marginBottom: 0, alignItems: "flex-end" }}>
                <div className="field" style={{ maxWidth: 160 }}><label>Workspace ID</label><input type="text" value={loadId} onChange={(e) => setLoadId(e.target.value)} placeholder="3" /></div>
                <button className="btn btn-ghost" onClick={loadWorkspace}>Jump back in</button>
              </div>
            </div>
          </>
        ) : (
          <>
            <div className="identity">
              <div>
                <div className="identity-name">{ws.org_name}</div>
                <div className="identity-domain">{ws.root_domain}</div>
              </div>
              <div className="identity-spacer" />
              <span className={`badge ${ws.aws_connected ? "badge-on" : "badge-off"}`}>
                {ws.aws_connected ? "AWS connected" : "AWS not connected"}
              </span>
            </div>

            {/* AWS Connect */}
            <div className="card">
              <div className="card-title">Connect AWS</div>
              <div className="card-sub">Cryptiq reads ACM certificates, KMS keys, Route53 records, and EC2 hosts — read-only, nothing is ever modified. Keys are encrypted at rest and never appear in logs.</div>

              <div style={{ fontSize: 13.5, marginBottom: 10 }}><b>1.</b> Create an IAM user named <code style={{ fontFamily: "var(--mono)", background: "var(--paper-2)", padding: "2px 7px", borderRadius: 5 }}>cryptiq-scanner</code>.</div>
              <div style={{ fontSize: 13.5, marginBottom: 10 }}><b>2.</b> Attach a read-only policy granting ACM, KMS, EC2, Route53, and ELB describe/list permissions.</div>
              <div style={{ fontSize: 13.5, marginBottom: 18 }}><b>3.</b> Generate an access key for that user and drop both values in here.</div>

              <div className="field-row">
                <div className="field"><label>Access key ID</label><input type="text" value={awsKey} onChange={(e) => setAwsKey(e.target.value)} placeholder="AKIA..." /></div>
                <div className="field"><label>Secret access key</label><input type="password" value={awsSecret} onChange={(e) => setAwsSecret(e.target.value)} placeholder="••••••••••••••••" /></div>
                <div className="field" style={{ maxWidth: 150 }}><label>Region</label><input type="text" value={awsRegion} onChange={(e) => setAwsRegion(e.target.value)} placeholder="us-east-1" /></div>
              </div>
              <div className="btn-row" style={{ alignItems: "center", flexWrap: "wrap", gap: 14 }}>
                <button className="btn btn-cyan" disabled={connecting} onClick={connectAWS}>
                  {connecting ? <span className="spinner" /> : null} Connect AWS account
                </button>
                <div style={{
                  display: "flex", alignItems: "center", gap: 7,
                  fontFamily: "var(--mono)", fontSize: 11.5,
                  color: "var(--teal-bright, #28a48f)",
                  background: "var(--teal-glow, #dcf3ee)",
                  padding: "6px 13px", borderRadius: 20,
                }}>
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                  </svg>
                  AES-256 encrypted at rest · never logged
                </div>
              </div>
            </div>

            {/* TLS Scan */}
            <div className="card">
              <div className="card-title">Run a TLS scan</div>
              <div className="card-sub">Discovers every subdomain from certificate transparency logs, then checks each one&apos;s TLS posture. Runs in the background — close the tab if you want, the dial will be waiting when you&apos;re back.</div>
              <div className="btn-row">
                <button className="btn btn-primary" disabled={scanning} onClick={startScan}>
                  {scanning ? <span className="spinner" /> : null} Start scan →
                </button>
                <button className="btn btn-ghost" onClick={() => loadResults()}>Refresh</button>
                <button className="btn btn-ghost" onClick={downloadCBOM}>Export CBOM</button>
              </div>
            </div>

            {job && (
              <div className="dial-wrap">
                <div className="dial">
                  <svg width="140" height="140" viewBox="0 0 140 140">
                    <circle className="dial-track" cx="70" cy="70" r="60" />
                    <circle className={`dial-fill${job.status === "complete" ? " done" : ""}`} cx="70" cy="70" r="60" style={{ strokeDashoffset: dialOffset }} />
                  </svg>
                  <div className="dial-center">
                    <div className="dial-num">{scanned}</div>
                    <div className="dial-den">of {found}</div>
                  </div>
                </div>
                <div className="dial-info">
                  <div className={`dial-status ${job.status}`}>
                    {job.status === "running" && <span className="pip-live" />}
                    <span>{job.status}</span>
                  </div>
                  <div className="dial-headline">{headlines[job.status]}</div>
                  <div className="dial-sub">{found ? `${scanned} of ${found} domains scanned` : "spinning up…"}</div>
                </div>
              </div>
            )}

            <hr className="divider" />

            <div className="register-head">
              <div className="register-title">TLS Findings</div>
              <div className="register-meta">{results.length} record{results.length === 1 ? "" : "s"}</div>
            </div>

            {!results.length ? (
              <div className="empty">
                <div className="empty-icon">◐</div>
                <div className="empty-title">Nothing here yet</div>
                <div className="empty-sub">Run a TLS scan above and findings will land in this table.</div>
              </div>
            ) : (
              <div className="table-wrap">
                <table className="register">
                  <thead><tr><th>Domain</th><th>TLS</th><th>Algorithm</th><th>Quantum vuln</th><th>Risk</th><th>Scanned</th></tr></thead>
                  <tbody>
                    {results.map((r, i) => (
                      <tr key={i}>
                        <td className="domain-cell">{r.domain}</td>
                        <td>{r.tls_version || "—"}</td>
                        <td>{r.algorithm || "—"}</td>
                        <td><QuantumVuln vuln={r.quantum_vulnerable} /></td>
                        <td><span className={`risk-pill risk-${r.risk_level}`}>{r.risk_level || "—"}</span></td>
                        <td style={{ color: "var(--ink-faint)", fontSize: 11 }}>{r.scanned_at ? new Date(r.scanned_at).toLocaleTimeString() : "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* SSH Scan */}
            <hr className="divider" />

            <div className="card">
              <div className="card-title">Scan SSH hosts</div>
              <div className="card-sub">
                Discovers EC2 hosts from your connected AWS account and scans each one for
                SSH cryptographic posture — host keys, key exchange algorithms, ciphers, and PQC readiness.
              </div>
              <div className="btn-row">
                <button className="btn btn-primary" disabled={sshScanning} onClick={startSSHScan}>
                  {sshScanning ? <span className="spinner" /> : null} Scan SSH hosts →
                </button>
                <button className="btn btn-ghost" onClick={() => loadSSHResults()}>Refresh</button>
              </div>
            </div>

            {sshJob && (
              <div className="dial-wrap">
                <div className="dial">
                  <svg width="140" height="140" viewBox="0 0 140 140">
                    <circle className="dial-track" cx="70" cy="70" r="60" />
                    <circle
                      className={`dial-fill${sshJob.status === "complete" ? " done" : ""}`}
                      cx="70" cy="70" r="60"
                      style={{ strokeDashoffset: sshDialOffset }}
                    />
                  </svg>
                  <div className="dial-center">
                    <div className="dial-num">{sshScanned}</div>
                    <div className="dial-den">of {sshFound}</div>
                  </div>
                </div>
                <div className="dial-info">
                  <div className={`dial-status ${sshJob.status}`}>
                    {sshJob.status === "running" && <span className="pip-live" />}
                    <span>{sshJob.status}</span>
                  </div>
                  <div className="dial-headline">{headlines[sshJob.status]}</div>
                  <div className="dial-sub">
                    {sshFound ? `${sshScanned} of ${sshFound} hosts scanned` : "discovering hosts…"}
                  </div>
                </div>
              </div>
            )}

            <hr className="divider" />

            <div className="register-head">
              <div className="register-title">SSH Findings</div>
              <div className="register-meta">{sshResults.length} host{sshResults.length === 1 ? "" : "s"}</div>
            </div>

            {!sshResults.length ? (
              <div className="empty">
                <div className="empty-icon">◐</div>
                <div className="empty-title">No SSH findings yet</div>
                <div className="empty-sub">Scan SSH hosts above to populate this table.</div>
              </div>
            ) : (
              <div className="table-wrap">
                <table className="register">
                  <thead>
                    <tr>
                      <th>Host</th>
                      <th>SSH version</th>
                      <th>Host key</th>
                      <th>KEX</th>
                      <th>Quantum vuln</th>
                      <th>Risk</th>
                      <th>Scanned</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sshResults.map((r: any, i: number) => (
                      <tr key={i}>
                        <td className="domain-cell">{r.host}:{r.port}</td>
                        <td>{r.ssh_version || "—"}</td>
                        <td>{r.host_key_algorithm || "—"}</td>
                        <td>{r.key_exchange || "—"}</td>
                        <td><QuantumVuln vuln={r.quantum_vulnerable} /></td>
                        <td><span className={`risk-pill risk-${r.risk_level}`}>{r.risk_level || "—"}</span></td>
                        <td style={{ color: "var(--ink-faint)", fontSize: 11 }}>
                          {r.scanned_at ? new Date(r.scanned_at).toLocaleTimeString() : "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </main>
      <Toast />
    </>
  );
}
