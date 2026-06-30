"use client";

import { useState } from "react";
import Topbar from "@/components/Topbar";
import Sidebar, { SidebarItem } from "@/components/Sidebar";
import { useToast } from "@/components/Toast";

const NAV: SidebarItem[] = [
  { key: "plan", label: "Migration plan", icon: "plan", section: "Plan" },
  { key: "algorithms", label: "Algorithm picker", icon: "algo" },
  { key: "keygen", label: "Key generation", icon: "key", section: "Execute" },
  { key: "hardening", label: "Config hardening", icon: "harden" },
  { key: "execute", label: "Execute action", icon: "execute" },
  { key: "tools", label: "Tools check", icon: "tools", section: "Reference" },
];

const EXAMPLE_SCAN = {
  host: "github.com", port: 22, ssh_version: "babeld-...", ssh_protocol: "2.0",
  raw_banner: "SSH-2.0-babeld-...",
  host_key_algorithm: "ssh-rsa", host_key_size: 3072,
  key_exchange: "sntrup761x25519-sha512", cipher: "aes128-ctr", mac: "hmac-sha2-256",
  host_keys: [
    { algorithm: "ssh-rsa", key_size: 3072, fingerprint: "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s" },
    { algorithm: "ecdsa-sha2-nistp256", key_size: null, fingerprint: "SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM" },
    { algorithm: "ssh-ed25519", key_size: null, fingerprint: "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU" },
  ],
  server_kex_algorithms: ["sntrup761x25519-sha512", "curve25519-sha256", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1"],
  server_ciphers: ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-cbc", "3des-cbc"],
  server_macs: ["hmac-sha2-256-etm@openssh.com", "hmac-sha2-256", "hmac-sha1"],
  server_host_key_algorithms: ["ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"],
  server_compression: ["none"],
  quantum_vulnerable: true, risk_level: "high", pqc_status: "vulnerable", migration_priority: "high",
  findings: ["RSA host key — Shor-vulnerable", "Weak KEX: diffie-hellman-group14-sha1"],
  scan_success: true,
};

function priorityClass(p: string) {
  const m: Record<string, string> = { critical: "badge-critical", high: "badge-high", normal: "badge-medium", low: "badge-low" };
  return m[p] || "badge-medium";
}

export default function MigratePage() {
  const { toast, Toast } = useToast();
  const [page, setPage] = useState("plan");

  // plan
  const [planJson, setPlanJson] = useState("");
  const [conservative, setConservative] = useState(true);
  const [planLoading, setPlanLoading] = useState(false);
  const [plan, setPlan] = useState<any>(null);
  const [planError, setPlanError] = useState("");

  // algorithms
  const [algos, setAlgos] = useState<any>(null);
  const [selected, setSelected] = useState<Record<string, string[]>>({ host_key: [], kex: [], cipher: [], mac: [] });

  // keygen
  const [keygenAlgos, setKeygenAlgos] = useState<string[]>(["ed25519"]);
  const [keygenComment, setKeygenComment] = useState("cryptiq-migration");
  const [keygenLoading, setKeygenLoading] = useState(false);
  const [keygenResult, setKeygenResult] = useState<any>(null);

  // hardening
  const [hardenJson, setHardenJson] = useState("");
  const [hardenLoading, setHardenLoading] = useState(false);
  const [patch, setPatch] = useState<any>(null);

  // execute
  const [execJson, setExecJson] = useState("");
  const [execHost, setExecHost] = useState("");
  const [execUser, setExecUser] = useState("");
  const [execKey, setExecKey] = useState("");
  const [dryRun, setDryRun] = useState(true);
  const [execLoading, setExecLoading] = useState(false);
  const [execResult, setExecResult] = useState<any>(null);

  // tools
  const [tools, setTools] = useState<any>(null);

  async function generatePlan() {
    if (!planJson.trim()) { toast("Paste a scan result first", "error"); return; }
    let scan;
    try { scan = JSON.parse(planJson); } catch (e: any) { toast("Invalid JSON: " + e.message, "error"); return; }
    setPlanLoading(true); setPlan(null); setPlanError("");
    try {
      const res = await fetch("/migrate/ssh/plan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ scan_result: scan, conservative }) });
      if (!res.ok) { const e = await res.json(); throw new Error(e.detail || `HTTP ${res.status}`); }
      setPlan(await res.json());
      toast("Plan generated", "success");
    } catch (e: any) { toast(e.message, "error"); setPlanError(e.message); } finally { setPlanLoading(false); }
  }

  async function loadAlgorithms() {
    try {
      const res = await fetch("/migrate/ssh/algorithms");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setAlgos(await res.json());
    } catch (e: any) { toast(e.message, "error"); }
  }

  function toggleAlgo(type: string, id: string, deprecated?: boolean) {
    if (deprecated) return;
    setSelected((s) => {
      const list = s[type] || [];
      const has = list.includes(id);
      return { ...s, [type]: has ? list.filter((x) => x !== id) : [...list, id] };
    });
  }

  async function generateKeys() {
    if (!keygenAlgos.length) { toast("Select at least one algorithm", "error"); return; }
    setKeygenLoading(true);
    try {
      const res = await fetch("/migrate/ssh/keygen", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ algorithms: keygenAlgos, comment: keygenComment || "cryptiq-migration" }) });
      if (!res.ok) { const e = await res.json(); throw new Error(e.detail || `HTTP ${res.status}`); }
      setKeygenResult(await res.json());
      toast("Keys generated", "success");
    } catch (e: any) { toast(e.message, "error"); } finally { setKeygenLoading(false); }
  }

  async function generatePatch() {
    if (!hardenJson.trim()) { toast("Paste a scan result first", "error"); return; }
    let scan;
    try { scan = JSON.parse(hardenJson); } catch { toast("Invalid JSON", "error"); return; }
    setHardenLoading(true); setPatch(null);
    try {
      const res = await fetch("/migrate/ssh/patch", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ scan_result: scan, conservative: true }) });
      if (!res.ok) { const e = await res.json(); throw new Error(e.detail || `HTTP ${res.status}`); }
      setPatch(await res.json());
      toast("Patch generated", "success");
    } catch (e: any) { toast(e.message, "error"); } finally { setHardenLoading(false); }
  }

  function copyText(text: string) {
    navigator.clipboard.writeText(text).then(() => toast("Copied to clipboard", "success"));
  }

  function prefillExecute(action: any) {
    setExecJson(JSON.stringify(action, null, 2));
    setPage("execute");
  }

  async function executeAction() {
    if (!execJson.trim()) { toast("Paste an action JSON first", "error"); return; }
    let action;
    try { action = JSON.parse(execJson); } catch { toast("Invalid JSON", "error"); return; }
    const conn = execHost.trim() ? { host: execHost.trim(), username: execUser.trim() || "root", key_path: execKey.trim() || null } : null;
    setExecLoading(true); setExecResult(null);
    try {
      const res = await fetch("/migrate/ssh/execute", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action, connection: conn, dry_run: dryRun }) });
      if (!res.ok) { const e = await res.json(); throw new Error(e.detail || `HTTP ${res.status}`); }
      const result = await res.json();
      setExecResult(result);
      toast(result.success ? "Execution complete" : "Execution failed", result.success ? "success" : "error");
    } catch (e: any) { toast(e.message, "error"); } finally { setExecLoading(false); }
  }

  async function loadTools() {
    setTools(null);
    try {
      const res = await fetch("/migrate/ssh/tools");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setTools(await res.json());
    } catch (e: any) { toast(e.message, "error"); }
  }

  function select(key: string) {
    setPage(key);
    if (key === "algorithms" && !algos) loadAlgorithms();
    if (key === "tools") loadTools();
  }

  return (
    <div className="shell">
      <Topbar tag="ssh" links={[{ href: "/", label: "Home" }, { href: "/docs", label: "API docs ↗", external: true }]} />
      <Sidebar items={NAV} active={page} onSelect={select} />
      <main className="main">

        {page === "plan" && (
          <div>
            <div style={{ marginBottom: 28 }}>
              <h1 style={{ fontFamily: "var(--serif)", fontSize: 22, fontWeight: 600, marginBottom: 4 }}>Migration plan</h1>
              <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>Paste a scan result to generate a phased PQC migration plan with concrete actions.</div>
            </div>
            <div className="field" style={{ marginBottom: 14 }}>
              <label>Scan result JSON (from /ssh/scan)</label>
              <textarea value={planJson} onChange={(e) => setPlanJson(e.target.value)} placeholder='{"host":"github.com","port":22,...}' />
            </div>
            <div className="btn-row" style={{ marginBottom: 24 }}>
              <button className="btn btn-primary" disabled={planLoading} onClick={generatePlan}>{planLoading ? <span className="spinner" /> : null} Generate plan</button>
              <div className="toggle-row">
                <div className={`toggle${conservative ? " on" : ""}`} onClick={() => setConservative(!conservative)} />
                <div><div className="toggle-label">Conservative mode</div><div className="toggle-sub">Keep existing safe algorithms</div></div>
              </div>
              <button className="btn btn-ghost" onClick={() => { setPlanJson(JSON.stringify(EXAMPLE_SCAN, null, 2)); toast("Example scan loaded"); }}>Load example</button>
            </div>

            {planError && !plan && <div className="empty"><div className="empty-icon">✕</div><div className="empty-title">Failed</div><div className="empty-sub">{planError}</div></div>}

            {plan && (
              <div>
                <div className="card">
                  <div className="card-header">
                    <div className="card-title" style={{ flex: 1 }}>{plan.host}</div>
                    <span className={`badge ${priorityClass(plan.scan_risk_level)}`}>{(plan.scan_risk_level || "").toUpperCase()}</span>
                    <span className="badge badge-hybrid">{(plan.scan_pqc_status || "").toUpperCase()}</span>
                  </div>
                  <div style={{ fontSize: 12, color: "var(--ink-faint)", marginBottom: 10 }}>{plan.total_actions} actions across {plan.phases.length} phases · {plan.overall_progress_pct || 0}% complete</div>
                  <div className="bar-track" style={{ height: 8 }}><div className="bar-fill" style={{ width: `${plan.overall_progress_pct || 0}%` }} /></div>
                </div>

                {plan.config_analysis && plan.config_analysis.total_issues > 0 && (
                  <div className="card warn">
                    <div style={{ color: "var(--amber-deep)", fontWeight: 700, marginBottom: 10 }}>⚠ {plan.config_analysis.total_issues} issues found ({plan.config_analysis.critical_issues} critical)</div>
                    {!!plan.config_analysis.weak_kex?.length && <div style={{ fontSize: 12, marginBottom: 4, color: "var(--ink-faint)" }}>Weak KEX: <span style={{ color: "#b8391a" }}>{plan.config_analysis.weak_kex.join(", ")}</span></div>}
                    {!!plan.config_analysis.weak_ciphers?.length && <div style={{ fontSize: 12, marginBottom: 4, color: "var(--ink-faint)" }}>Weak ciphers: <span style={{ color: "#b8391a" }}>{plan.config_analysis.weak_ciphers.join(", ")}</span></div>}
                    {!!plan.config_analysis.weak_macs?.length && <div style={{ fontSize: 12, marginBottom: 4, color: "var(--ink-faint)" }}>Weak MACs: <span style={{ color: "#b8391a" }}>{plan.config_analysis.weak_macs.join(", ")}</span></div>}
                  </div>
                )}

                {(plan.phases || []).map((phase: any) => (
                  <div key={phase.number} style={{ marginBottom: 24 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 12, padding: "14px 0", borderBottom: "2px solid var(--line)", marginBottom: 16 }}>
                      <span className="badge badge-hybrid">Phase {phase.number}</span>
                      <span style={{ fontFamily: "var(--serif)", fontSize: 16, fontWeight: 600 }}>{phase.name}</span>
                      <span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--ink-faint)", marginLeft: "auto" }}>{phase.timeline}</span>
                    </div>
                    <div style={{ fontSize: 12, color: "var(--ink-faint)", marginBottom: 14 }}>{phase.description}</div>
                    {(phase.actions || []).map((action: any, i: number) => (
                      <div key={i} className="result-card" style={{ marginBottom: 10 }}>
                        <div className="result-header">
                          <div style={{ fontSize: 13, fontWeight: 700, flex: 1 }}>{action.title}</div>
                          <span className={`badge ${priorityClass(action.priority)}`}>{(action.priority || "").toUpperCase()}</span>
                        </div>
                        <div style={{ fontSize: 12, color: "var(--ink-faint)", marginBottom: 10 }}>{action.description}</div>
                        <div style={{ display: "flex", gap: 12, fontFamily: "var(--mono)", fontSize: 10, color: "var(--ink-faint)" }}>
                          <span>{action.automated ? "✓ Automated" : "○ Manual"}</span>
                          <span style={{ color: action.requires_downtime ? "var(--amber-deep)" : "#0d7d89" }}>{action.requires_downtime ? "⚡ Restart" : "✓ No restart"}</span>
                          <span>~{action.estimated_minutes} min</span>
                        </div>
                        {!!(action.commands && action.commands.length) && (
                          <div className="cmd-block">
                            {action.commands.map((c: string, j: number) => c.startsWith("#") ? <div className="cmd-comment" key={j}># {c.slice(1).trim()}</div> : c.trim() ? <div className="cmd-line" key={j}>$ {c}</div> : <br key={j} />)}
                          </div>
                        )}
                        {action.notes && <div style={{ marginTop: 8, fontSize: 11, color: "var(--ink-faint)", fontStyle: "italic" }}>Note: {action.notes}</div>}
                        <div style={{ marginTop: 10 }}>
                          <button className="btn btn-ghost btn-sm" onClick={() => prefillExecute(action)}>Run this action</button>
                        </div>
                      </div>
                    ))}
                  </div>
                ))}

                {plan.config_patch?.hardened_snippet && (
                  <>
                    <hr className="divider" />
                    <div style={{ fontWeight: 700, fontSize: 14, marginBottom: 8 }}>Generated sshd_config snippet</div>
                    <pre className="cmd-block">{plan.config_patch.hardened_snippet}</pre>
                    <button className="btn btn-ghost" style={{ marginTop: 10 }} onClick={() => copyText(plan.config_patch.hardened_snippet)}>Copy snippet</button>
                  </>
                )}
              </div>
            )}
          </div>
        )}

        {page === "algorithms" && (
          <div>
            <div style={{ marginBottom: 28 }}>
              <h1 style={{ fontFamily: "var(--serif)", fontSize: 22, fontWeight: 600, marginBottom: 4 }}>Algorithm picker</h1>
              <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>Choose your target algorithms. Selected algorithms are used in plan and patch generation.</div>
            </div>
            {!algos ? <div className="empty"><div className="empty-icon">◎</div><div className="empty-title">Loading…</div></div> : (
              ["host_key", "kex", "cipher", "mac"].map((key) => (
                <div key={key} style={{ marginBottom: 28 }}>
                  <div className="section-label">{{ host_key: "Host key algorithms", kex: "Key exchange (KEX)", cipher: "Ciphers", mac: "MACs" }[key]}</div>
                  <div className="algo-grid">
                    {(algos[key] || []).map((algo: any) => {
                      const sel = selected[key]?.includes(algo.id);
                      return (
                        <div key={algo.id} className={`algo-card${sel ? " selected" : ""}${algo.deprecated ? " deprecated" : ""}`} onClick={() => toggleAlgo(key, algo.id, algo.deprecated)}>
                          <div className="check-mark">✓</div>
                          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                            <span className={`badge ${algo.category === "pqc" ? "badge-low" : algo.category === "hybrid" ? "badge-hybrid" : "badge-unknown"}`} style={{ fontSize: 10 }}>{algo.category?.toUpperCase()}</span>
                            <div className="ql-dots">{[1, 2, 3].map((i) => <div key={i} className={`ql-dot${i <= algo.quantum_security_level ? " filled" : ""}`} />)}</div>
                          </div>
                          <div className="algo-name">{algo.name}</div>
                          <div className="algo-desc">{algo.description}</div>
                          <div className="algo-meta">
                            {algo.nist_standard && <span className="algo-chip">{algo.nist_standard}</span>}
                            <span className="algo-chip">OpenSSH {algo.min_openssh_version}+</span>
                            {algo.deprecated && <span className="algo-chip" style={{ color: "#b8391a" }}>Deprecated</span>}
                            {algo.recommended && <span className="algo-chip" style={{ color: "#0d7d89" }}>Recommended</span>}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {page === "keygen" && (
          <div>
            <div style={{ marginBottom: 28 }}>
              <h1 style={{ fontFamily: "var(--serif)", fontSize: 22, fontWeight: 600, marginBottom: 4 }}>Key generation</h1>
              <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>Generate SSH key pairs locally. Private keys stay on this server.</div>
            </div>
            <div className="section-label">Select algorithms to generate</div>
            <div style={{ display: "flex", gap: 14, flexWrap: "wrap", marginBottom: 16 }}>
              {["ed25519", "rsa", "ecdsa"].map((a) => (
                <label key={a} style={{ display: "flex", alignItems: "center", gap: 6, cursor: "pointer", fontSize: 13 }}>
                  <input type="checkbox" checked={keygenAlgos.includes(a)} onChange={(e) => setKeygenAlgos((s) => e.target.checked ? [...s, a] : s.filter((x) => x !== a))} />
                  {a === "ed25519" ? "Ed25519" : a === "rsa" ? "RSA-3072" : "ECDSA-P256"}
                </label>
              ))}
            </div>
            <div className="field" style={{ maxWidth: 260, marginBottom: 16 }}><label>Comment</label><input type="text" value={keygenComment} onChange={(e) => setKeygenComment(e.target.value)} /></div>
            <button className="btn btn-primary" disabled={keygenLoading} onClick={generateKeys}>{keygenLoading ? <span className="spinner" /> : null} Generate keys</button>

            {keygenResult && (
              <div style={{ marginTop: 20 }}>
                {Object.entries(keygenResult).map(([algo, result]: [string, any]) => (
                  <div className="card" key={algo}>
                    <div className="card-header">
                      <div className="card-title" style={{ flex: 1 }}>{algo}</div>
                      <span className={`badge ${result.success ? "badge-low" : "badge-critical"}`}>{result.success ? "GENERATED" : "FAILED"}</span>
                    </div>
                    {result.success ? (
                      <>
                        <div style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--ink-faint)", marginBottom: 6 }}>Fingerprint: <span style={{ color: "var(--blue-deep, var(--blue))" }}>{result.fingerprint}</span></div>
                        <pre className="cmd-block" style={{ maxHeight: 80 }}>{result.public_key || ""}</pre>
                        <div style={{ fontSize: 11, color: "var(--ink-faint)", marginTop: 8 }}>Private key: <code style={{ color: "var(--blue-deep, var(--blue))" }}>{result.private_key_path || ""}</code></div>
                        <button className="btn btn-ghost btn-sm" style={{ marginTop: 10 }} onClick={() => copyText(result.public_key || "")}>Copy public key</button>
                      </>
                    ) : <div style={{ fontSize: 12, color: "#b8391a" }}>{result.error || "Unknown error"}</div>}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {page === "hardening" && (
          <div>
            <div style={{ marginBottom: 28 }}>
              <h1 style={{ fontFamily: "var(--serif)", fontSize: 22, fontWeight: 600, marginBottom: 4 }}>Config hardening</h1>
              <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>Generate a hardened sshd_config patch from a scan result. Ready to copy-paste to your server.</div>
            </div>
            <div className="field" style={{ marginBottom: 14 }}><label>Scan result JSON</label><textarea value={hardenJson} onChange={(e) => setHardenJson(e.target.value)} placeholder='{"host":"...","server_kex_algorithms":[...],...}' /></div>
            <div className="btn-row" style={{ marginBottom: 24 }}>
              <button className="btn btn-primary" disabled={hardenLoading} onClick={generatePatch}>{hardenLoading ? <span className="spinner" /> : null} Generate patch</button>
              <button className="btn btn-ghost" onClick={() => setHardenJson(JSON.stringify(EXAMPLE_SCAN, null, 2))}>Load example</button>
            </div>
            {patch && (
              <div>
                <div className="card">
                  <div className="card-header"><div className="card-title" style={{ flex: 1 }}>Config changes</div><span className="badge badge-high">{patch.change_count} changes</span></div>
                  {(patch.changes || []).map((ch: any, i: number) => (
                    <div key={i} style={{ marginBottom: 12 }}>
                      <div style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--blue-deep, var(--blue))", marginBottom: 4 }}>{ch.directive}</div>
                      {!!ch.removed?.length && <div style={{ fontSize: 11, color: "var(--ink-faint)" }}>Removing: <span style={{ color: "#b8391a" }}>{ch.removed.join(", ")}</span></div>}
                      {!!ch.added?.length && <div style={{ fontSize: 11, color: "var(--ink-faint)" }}>Adding: <span style={{ color: "#0d7d89" }}>{ch.added.join(", ")}</span></div>}
                    </div>
                  ))}
                </div>
                {patch.hardened_snippet && (
                  <>
                    <div style={{ fontWeight: 700, marginBottom: 8 }}>sshd_config snippet</div>
                    <pre className="cmd-block">{patch.hardened_snippet}</pre>
                    <button className="btn btn-ghost" style={{ marginTop: 10 }} onClick={() => copyText(patch.hardened_snippet)}>Copy snippet</button>
                  </>
                )}
                {!!patch.apply_commands?.length && (
                  <>
                    <hr className="divider" />
                    <div style={{ fontWeight: 700, marginBottom: 8 }}>Apply commands</div>
                    <pre className="cmd-block">{patch.apply_commands.map((c: string, i: number) => c.startsWith("#") ? <div className="cmd-comment" key={i}>{c}</div> : <div className="cmd-line" key={i}>$ {c}</div>)}</pre>
                  </>
                )}
              </div>
            )}
          </div>
        )}

        {page === "execute" && (
          <div>
            <div style={{ marginBottom: 28 }}>
              <h1 style={{ fontFamily: "var(--serif)", fontSize: 22, fontWeight: 600, marginBottom: 4 }}>Execute action</h1>
              <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>Run a migration action. Always test with dry run first.</div>
            </div>

            <div className="card warn">
              <div style={{ display: "flex", alignItems: "center", gap: 10, color: "var(--amber-deep)", fontSize: 13, fontWeight: 700, marginBottom: 8 }}>⚠ Dry run is ON by default</div>
              <div style={{ fontSize: 12, color: "var(--ink-faint)" }}>Commands are shown but not run. Toggle off only when you&apos;re ready to apply changes to a real server.</div>
            </div>

            <div className="field" style={{ marginBottom: 12 }}><label>Action JSON (from a migration plan)</label><textarea style={{ minHeight: 120 }} value={execJson} onChange={(e) => setExecJson(e.target.value)} placeholder='{"id":"...","action_type":"harden_config","host":"...","commands":[...]}' /></div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10, marginBottom: 16 }}>
              <div className="field"><label>Host (for SSH)</label><input type="text" value={execHost} onChange={(e) => setExecHost(e.target.value)} placeholder="192.168.1.42" /></div>
              <div className="field"><label>Username</label><input type="text" value={execUser} onChange={(e) => setExecUser(e.target.value)} placeholder="root" /></div>
              <div className="field"><label>Key path</label><input type="text" value={execKey} onChange={(e) => setExecKey(e.target.value)} placeholder="~/.ssh/id_ed25519" /></div>
            </div>

            <div className="btn-row" style={{ marginBottom: 24 }}>
              <div className="toggle-row">
                <div className={`toggle${dryRun ? " on" : ""}`} onClick={() => setDryRun(!dryRun)} />
                <div><div className="toggle-label">Dry run</div><div className="toggle-sub">Show commands without running</div></div>
              </div>
              <button className="btn btn-primary" disabled={execLoading} onClick={executeAction}>{execLoading ? <span className="spinner" /> : null} Execute</button>
            </div>

            {execResult && (
              <div className="card">
                <div className="card-header">
                  <div className="card-title" style={{ flex: 1 }}>{execResult.action_type}</div>
                  <span className={`badge ${execResult.success ? "badge-low" : "badge-critical"}`}>{execResult.success ? "SUCCESS" : "FAILED"}</span>
                  {execResult.dry_run && <span className="badge badge-hybrid">DRY RUN</span>}
                </div>
                <div style={{ fontSize: 12, color: "var(--ink-faint)", marginBottom: 12 }}>Host: {execResult.host} · Duration: {execResult.duration_seconds?.toFixed(2) || "?"}s</div>
                {execResult.error && <div style={{ color: "#b8391a", fontSize: 12, marginBottom: 10 }}>Error: {execResult.error}</div>}
                <div className="cmd-block">
                  {(execResult.outputs || []).map((out: any, i: number) => (
                    <div key={i}>
                      <div className="cmd-comment"># {out.cmd || ""}</div>
                      {out.stdout?.trim() && <div>{out.stdout.trim()}</div>}
                      {out.stderr?.trim() && <div style={{ color: "var(--amber-deep)" }}>{out.stderr.trim()}</div>}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {page === "tools" && (
          <div>
            <div style={{ display: "flex", alignItems: "flex-start", gap: 16, marginBottom: 28 }}>
              <div style={{ flex: 1 }}>
                <h1 style={{ fontFamily: "var(--serif)", fontSize: 22, fontWeight: 600, marginBottom: 4 }}>Tools check</h1>
                <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>Verify ssh-keygen and openssl are available on the Cryptiq server.</div>
              </div>
              <button className="btn btn-ghost" onClick={loadTools}>Refresh</button>
            </div>
            {!tools ? <div className="empty"><div className="empty-icon">◎</div><div className="empty-title">Loading…</div></div> : (
              Object.entries(tools).map(([tool, info]: [string, any]) => (
                <div className={`card${info.available ? "" : " warn"}`} key={tool}>
                  <div className="card-header">
                    <div className="card-title" style={{ flex: 1 }}>{tool}</div>
                    <span className={`badge ${info.available ? "badge-low" : "badge-critical"}`}>{info.available ? "AVAILABLE" : "NOT FOUND"}</span>
                  </div>
                  <div style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--ink-faint)" }}>{info.version || ""}</div>
                  {!info.available && <div style={{ marginTop: 8, fontSize: 12, color: "var(--ink-faint)" }}>Install: <code style={{ color: "var(--blue-deep, var(--blue))" }}>brew install openssh</code> / <code style={{ color: "var(--blue-deep, var(--blue))" }}>apt install openssh-client openssl</code></div>}
                </div>
              ))
            )}
          </div>
        )}

      </main>
      <Toast />
    </div>
  );
}