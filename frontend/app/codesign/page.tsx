"use client";

import { useEffect, useState } from "react";
import Topbar from "@/components/Topbar";
import Sidebar, { SidebarItem } from "@/components/Sidebar";
import { useToast } from "@/components/Toast";

// If next.config.js's rewrite proxy ever misbehaves (wrong file, not
// restarted after editing, version drift, whatever), setting
// NEXT_PUBLIC_API_URL in frontend/.env.local bypasses it entirely and
// talks to the FastAPI backend directly. Leave it unset to keep using
// the proxy as before -- this is purely additive, zero behavior change
// if NEXT_PUBLIC_API_URL is not set.
const API_BASE = process.env.NEXT_PUBLIC_API_URL || "";
const api = (path: string) => `${API_BASE}${path}`;

// frontend/app/codesign/page.tsx
// Backend: code_signing/api.py mounted at /codesign
// Backends (native tools, generic, github_actions proposal) are driven by
// GET /codesign/backends — the registry in code_signing/backends/ — so a
// newly-registered backend appears here with no frontend change.

const NAV: SidebarItem[] = [
  { key: "discover", label: "Discover & Sign", icon: "scan", section: "Sign" },
  { key: "verify", label: "Verify", icon: "verify", section: "Sign" },
  { key: "workflow", label: "CI/CD Workflow", icon: "workflow", section: "Sign" },
  { key: "keys", label: "Signing Keys", icon: "key", section: "Manage" },
  { key: "backends", label: "Backends", icon: "tools", section: "Manage" },
  { key: "history", label: "History", icon: "history", section: "Manage" },
];

export default function CodeSigningPage() {
  const { toast, Toast } = useToast();
  const [page, setPage] = useState("discover");

  // discover / sign
  const [rootPath, setRootPath] = useState("");
  const [discovering, setDiscovering] = useState(false);
  const [files, setFiles] = useState<any[] | null>(null);
  const [summary, setSummary] = useState<any>(null);
  const [signEverything, setSignEverything] = useState(false);
  const [preferNative, setPreferNative] = useState(true);
  const [signing, setSigning] = useState(false);
  const [manifest, setManifest] = useState<any>(null);

  // verify
  const [verifyPath, setVerifyPath] = useState("");
  const [verifyKeyId, setVerifyKeyId] = useState("");
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<any>(null);

  // ci/cd workflow proposal
  const [workflowMethod, setWorkflowMethod] = useState("cosign");
  const [globPattern, setGlobPattern] = useState("dist/*");
  const [generatingWorkflow, setGeneratingWorkflow] = useState(false);
  const [workflowResult, setWorkflowResult] = useState<any>(null);

  // keys
  const [keys, setKeys] = useState<any[] | null>(null);
  const [keyAlgo, setKeyAlgo] = useState("ed25519");
  const [keyLabel, setKeyLabel] = useState("default");
  const [generatingKey, setGeneratingKey] = useState(false);

  // backends
  const [backendList, setBackendList] = useState<any[] | null>(null);

  // history
  const [history, setHistory] = useState<any[] | null>(null);
  const [historyLoading, setHistoryLoading] = useState(false);

  useEffect(() => {
    fetch(api("/codesign/backends")).then((r) => r.ok && r.json()).then((d) => d && setBackendList(d));
  }, []);

  async function discover() {
    if (!rootPath.trim()) { toast("Enter a directory path.", "error"); return; }
    setDiscovering(true); setFiles(null); setSummary(null); setManifest(null);
    try {
      const res = await fetch(api("/codesign/discover"), {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ root_path: rootPath, sign_everything: signEverything }),
      });
      if (!res.ok) throw new Error((await res.json()).detail || res.statusText);
      const data = await res.json();
      setFiles(data.files);
      setSummary(data.summary);
    } catch (e: any) {
      toast("Discovery failed: " + e.message, "error");
    } finally { setDiscovering(false); }
  }

  async function signAll(dryRun: boolean) {
    if (!rootPath.trim()) return;
    if (!dryRun && !window.confirm(`Sign all ${files?.length ?? 0} files under ${rootPath} now?`)) return;
    setSigning(true);
    try {
      const res = await fetch(api("/codesign/sign/directory"), {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ root_path: rootPath, sign_everything: signEverything, prefer_native: preferNative, dry_run: dryRun }),
      });
      if (!res.ok) throw new Error((await res.json()).detail || res.statusText);
      const data = await res.json();
      setManifest(data);
      if (data.key_id) setVerifyKeyId(data.key_id);
      toast(dryRun ? "Dry run complete — review below." : `Signed ${data.success_count}/${data.file_count} files.`, "success");
    } catch (e: any) {
      toast("Signing failed: " + e.message, "error");
    } finally { setSigning(false); }
  }

  async function runVerify() {
    if (!verifyPath.trim() || !verifyKeyId.trim()) { toast("Path and key ID are both required.", "error"); return; }
    setVerifying(true); setVerifyResult(null);
    try {
      const res = await fetch(api("/codesign/verify"), {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path: verifyPath, key_id: verifyKeyId }),
      });
      if (!res.ok) throw new Error((await res.json()).detail || res.statusText);
      setVerifyResult(await res.json());
    } catch (e: any) {
      toast("Verify failed: " + e.message, "error");
    } finally { setVerifying(false); }
  }

  async function generateWorkflow() {
    setGeneratingWorkflow(true); setWorkflowResult(null);
    try {
      const res = await fetch(api("/codesign/propose/github-actions"), {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ method: workflowMethod, glob_pattern: globPattern, dry_run: true }),
      });
      if (!res.ok) throw new Error((await res.json()).detail || res.statusText);
      setWorkflowResult(await res.json());
    } catch (e: any) {
      toast("Workflow generation failed: " + e.message, "error");
    } finally { setGeneratingWorkflow(false); }
  }

  async function loadKeys() {
    const res = await fetch(api("/codesign/keys"));
    setKeys(await res.json());
  }

  async function generateKey() {
    setGeneratingKey(true);
    try {
      const res = await fetch(api("/codesign/keys"), {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ algorithm: keyAlgo, label: keyLabel }),
      });
      if (!res.ok) throw new Error((await res.json()).detail || res.statusText);
      toast("Key generated.", "success");
      loadKeys();
    } catch (e: any) {
      toast("Key generation failed: " + e.message, "error");
    } finally { setGeneratingKey(false); }
  }

  async function loadHistory() {
    setHistoryLoading(true);
    try {
      const res = await fetch(api("/codesign/manifests?limit=50"));
      setHistory(await res.json());
    } finally { setHistoryLoading(false); }
  }

  function selectPage(key: string) {
    setPage(key);
    if (key === "keys") loadKeys();
    if (key === "history") loadHistory();
  }

  return (
    <div className="shell">
      <Topbar
        tag="Code Signing"
        links={[{ href: "/", label: "Home" }, { href: "/ssh", label: "SSH" }, { href: "/pwhash", label: "Password Hashing" }, { href: "/docs", label: "API", external: true }]}
      />
      <Sidebar items={NAV} active={page} onSelect={selectPage} />

      <main className="main">
        {page === "discover" && (
          <div>
            <div style={{ marginBottom: 28 }}>
              <h1 style={{ fontFamily: "var(--serif)", fontSize: 22, fontWeight: 600, marginBottom: 4 }}>Discover &amp; Sign</h1>
              <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>
                Recursively scans a directory, hashes every signable file, and produces a signed manifest.
                Native OS signers are used automatically when present and applicable; everything else gets a
                generic Ed25519 detached signature. See the Backends tab for what's available on this host.
              </div>
            </div>

            <div className="field-row" style={{ alignItems: "flex-end", flexWrap: "wrap", gap: 12 }}>
              <div className="field" style={{ minWidth: 320 }}>
                <label>Directory Path</label>
                <input type="text" value={rootPath} onChange={(e) => setRootPath(e.target.value)} placeholder="/path/to/release/artifacts" />
              </div>
              <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13 }}>
                <input type="checkbox" checked={signEverything} onChange={(e) => setSignEverything(e.target.checked)} />
                Sign every file (not just known extensions)
              </label>
              <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13 }}>
                <input type="checkbox" checked={preferNative} onChange={(e) => setPreferNative(e.target.checked)} />
                Prefer native OS signer when available
              </label>
              <button className="btn btn-primary" disabled={discovering} onClick={discover}>{discovering ? <span className="spinner" /> : null} Discover</button>
            </div>

            {summary && (
              <div className="stat-grid" style={{ marginTop: 24 }}>
                <div className="stat-card"><div className="stat-label">Files Found</div><div className="stat-value">{summary.total_files}</div></div>
                <div className="stat-card"><div className="stat-label">Total Size</div><div className="stat-value">{(summary.total_bytes / 1024).toFixed(1)} KB</div></div>
                <div className="stat-card"><div className="stat-label">Signer Types</div><div className="stat-value">{Object.keys(summary.by_recommended_signer || {}).length}</div></div>
              </div>
            )}

            {files && !!files.length && (
              <>
                <div className="btn-row" style={{ marginTop: 20 }}>
                  <button className="btn btn-ghost" disabled={signing} onClick={() => signAll(true)}>{signing ? <span className="spinner" /> : null} Dry Run</button>
                  <button className="btn btn-danger" disabled={signing} onClick={() => signAll(false)}>{signing ? <span className="spinner" /> : null} Sign All Files</button>
                </div>

                <div className="table-wrap" style={{ marginTop: 16 }}>
                  <table className="data-table">
                    <thead><tr><th>Path</th><th>Size</th><th>Recommended Signer</th><th>SHA-256</th></tr></thead>
                    <tbody>
                      {files.map((f, i) => (
                        <tr key={i}>
                          <td style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{f.path}</td>
                          <td style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{f.size_bytes} B</td>
                          <td><span className="pill pill-muted">{f.recommended_signer}</span></td>
                          <td style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--ink-faint)" }}>{f.sha256.slice(0, 16)}…</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            )}

            {files && !files.length && (
              <div className="empty"><div className="empty-icon">📄</div><div className="empty-title">No signable files found under that path.</div></div>
            )}

            {manifest && (
              <div className="notice notice-info" style={{ marginTop: 20 }}>
                Manifest <code>{manifest.manifest_id}</code> — {manifest.success_count}/{manifest.file_count} signed successfully.
                {manifest.entries?.some((e: any) => !e.success) && (
                  <ul style={{ marginTop: 8 }}>
                    {manifest.entries.filter((e: any) => !e.success).map((e: any, i: number) => (
                      <li key={i} style={{ fontSize: 12 }}>{e.path}: {e.error}</li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </div>
        )}

        {page === "verify" && (
          <div>
            <div style={{ marginBottom: 28 }}>
              <h1 style={{ fontFamily: "var(--serif)", fontSize: 22, fontWeight: 600, marginBottom: 4 }}>Verify a Signature</h1>
              <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>Checks a file against its <code>.cryptiq.sig.json</code> sidecar and the given key.</div>
            </div>
            <div className="field-row" style={{ alignItems: "flex-end", flexWrap: "wrap", gap: 12 }}>
              <div className="field" style={{ minWidth: 320 }}>
                <label>File Path</label>
                <input type="text" value={verifyPath} onChange={(e) => setVerifyPath(e.target.value)} placeholder="/path/to/release/artifacts/app.py" />
              </div>
              <div className="field" style={{ minWidth: 220 }}>
                <label>Key ID</label>
                <input type="text" value={verifyKeyId} onChange={(e) => setVerifyKeyId(e.target.value)} placeholder="key id used to sign" />
              </div>
              <button className="btn btn-primary" disabled={verifying} onClick={runVerify}>{verifying ? <span className="spinner" /> : null} Verify</button>
            </div>
            {verifyResult && (
              <div className={`notice ${verifyResult.valid ? "notice-info" : "notice-error"}`} style={{ marginTop: 20 }}>
                {verifyResult.valid ? "✅ Signature is valid — file has not been modified since signing." : "❌ Signature is invalid or the file has been tampered with."}
              </div>
            )}
          </div>
        )}

        {page === "workflow" && (
          <div>
            <div style={{ marginBottom: 28 }}>
              <h1 style={{ fontFamily: "var(--serif)", fontSize: 22, fontWeight: 600, marginBottom: 4 }}>CI/CD Signing Workflow</h1>
              <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>
                Most companies sign release artifacts as an automated CI step, not by hand. This generates a
                GitHub Actions workflow that signs every future release automatically — nothing runs until
                you commit the file. It's a proposal, same posture as the ALB TLS migration feature: review, then apply.
              </div>
            </div>
            <div className="field-row" style={{ alignItems: "flex-end", flexWrap: "wrap", gap: 12 }}>
              <div className="field" style={{ maxWidth: 220 }}>
                <label>Signing Method</label>
                <select value={workflowMethod} onChange={(e) => setWorkflowMethod(e.target.value)}>
                  <option value="cosign">cosign (keyless OIDC)</option>
                  <option value="gpg">GPG (secret key)</option>
                </select>
              </div>
              <div className="field" style={{ minWidth: 240 }}>
                <label>Release Asset Glob</label>
                <input type="text" value={globPattern} onChange={(e) => setGlobPattern(e.target.value)} placeholder="dist/*" />
              </div>
              <button className="btn btn-primary" disabled={generatingWorkflow} onClick={generateWorkflow}>{generatingWorkflow ? <span className="spinner" /> : null} Generate Workflow</button>
            </div>
            {workflowResult && (
              <div style={{ marginTop: 20 }}>
                <div className="section-label">{workflowResult.path}</div>
                <pre className="cmd-block">{workflowResult.content}</pre>
                <div style={{ fontSize: 12, color: "var(--ink-faint)", marginTop: 8 }}>
                  Commit this to your repo at the path above (or open it as a PR) to enable automatic signing on every release.
                </div>
              </div>
            )}
          </div>
        )}

        {page === "keys" && (
          <div>
            <div style={{ marginBottom: 28 }}>
              <h1 style={{ fontFamily: "var(--serif)", fontSize: 22, fontWeight: 600, marginBottom: 4 }}>Signing Keys</h1>
              <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>Private keys never leave the server. Only public keys and fingerprints are shown here.</div>
            </div>

            <div className="field-row" style={{ alignItems: "flex-end" }}>
              <div className="field" style={{ maxWidth: 200 }}>
                <label>Algorithm</label>
                <select value={keyAlgo} onChange={(e) => setKeyAlgo(e.target.value)}>
                  <option value="ed25519">Ed25519</option>
                  <option value="rsa-pss-3072">RSA-PSS 3072</option>
                  <option value="rsa-pss-4096">RSA-PSS 4096</option>
                </select>
              </div>
              <div className="field" style={{ maxWidth: 200 }}>
                <label>Label</label>
                <input type="text" value={keyLabel} onChange={(e) => setKeyLabel(e.target.value)} />
              </div>
              <button className="btn btn-primary" disabled={generatingKey} onClick={generateKey}>{generatingKey ? <span className="spinner" /> : null} Generate Key</button>
            </div>

            {keys && (
              <div className="table-wrap" style={{ marginTop: 20 }}>
                <table className="data-table">
                  <thead><tr><th>Key ID</th><th>Algorithm</th><th>Label</th><th>Fingerprint</th><th>Created</th></tr></thead>
                  <tbody>
                    {keys.map((k, i) => (
                      <tr key={i}>
                        <td style={{ fontFamily: "var(--mono)" }}>{k.key_id}</td>
                        <td><span className="pill pill-muted">{k.algorithm}</span></td>
                        <td>{k.label}</td>
                        <td style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{k.fingerprint_sha256.slice(0, 24)}…</td>
                        <td style={{ fontSize: 12, color: "var(--ink-faint)" }}>{k.created_at}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {page === "backends" && (
          <div>
            <div style={{ marginBottom: 28 }}>
              <h1 style={{ fontFamily: "var(--serif)", fontSize: 22, fontWeight: 600, marginBottom: 4 }}>Signing Backends</h1>
              <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>
                Every backend Cryptiq knows about — native OS tools, the built-in generic signer, and CI/CD
                proposal generators. Registering a new one (a cloud KMS signer, a different CI system, Sigstore)
                shows up here automatically — no frontend change needed.
              </div>
            </div>
            {backendList ? (
              <div className="table-wrap">
                <table className="data-table">
                  <thead><tr><th>Backend</th><th>Kind</th><th>Available Here</th><th>Description</th></tr></thead>
                  <tbody>
                    {backendList.map((b, i) => (
                      <tr key={i}>
                        <td style={{ fontFamily: "var(--mono)" }}>{b.label}</td>
                        <td><span className="pill pill-muted">{b.kind}</span></td>
                        <td><span className={`pill ${b.available ? "pill-green" : "pill-muted"}`}>{b.available ? "yes" : "no"}</span></td>
                        <td style={{ fontSize: 12, color: "var(--ink-faint)" }}>{b.description}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>Loading…</div>}
          </div>
        )}

        {page === "history" && (
          <div>
            <div style={{ marginBottom: 28 }}>
              <h1 style={{ fontFamily: "var(--serif)", fontSize: 22, fontWeight: 600, marginBottom: 4 }}>Signing History</h1>
              <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>Every signing run, append-only.</div>
            </div>
            <div className="btn-row" style={{ marginBottom: 20 }}><button className="btn btn-ghost" onClick={loadHistory}>Refresh</button></div>
            {historyLoading || history === null ? <div style={{ color: "var(--ink-faint)", fontSize: 13 }}>Loading…</div> :
              !history.length ? <div className="empty"><div className="empty-icon">🔏</div><div className="empty-title">No signing runs yet.</div></div> : (
                <div className="table-wrap">
                  <table className="data-table">
                    <thead><tr><th>Manifest</th><th>Root</th><th>Files</th><th>Succeeded</th><th>Dry Run</th><th>When</th></tr></thead>
                    <tbody>
                      {history.map((h, i) => (
                        <tr key={i}>
                          <td style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{h.manifest_id}</td>
                          <td style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{h.root_path}</td>
                          <td>{h.file_count}</td>
                          <td>{h.success_count}</td>
                          <td><span className={`pill ${h.dry_run ? "pill-muted" : "pill-green"}`}>{h.dry_run ? "dry run" : "applied"}</span></td>
                          <td style={{ fontSize: 12, color: "var(--ink-faint)" }}>{h.created_at}</td>
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