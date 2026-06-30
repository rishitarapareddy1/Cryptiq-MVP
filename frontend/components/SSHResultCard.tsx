"use client";

import { RiskBadge, PqcBadge, QuantumVuln } from "@/components/Badges";

const HYBRID_KEX = new Set(["sntrup761x25519-sha512@openssh.com", "sntrup761x25519-sha512", "mlkem768x25519-sha256", "x25519-kyber-512r3-sha256-d00@amazon.com"]);
const PQC_KEX = new Set(["mlkem768-sha256", "mlkem1024-sha384"]);
const VULN_KEX = new Set(["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group14-sha256", "diffie-hellman-group16-sha512", "diffie-hellman-group18-sha512", "diffie-hellman-group-exchange-sha1", "diffie-hellman-group-exchange-sha256", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521"]);
const WEAK_MACS = new Set(["hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96", "umac-32@openssh.com", "umac-64@openssh.com"]);

export function kexClass(k: string) {
  if (PQC_KEX.has(k)) return "safe";
  if (HYBRID_KEX.has(k)) return "hybrid";
  if (VULN_KEX.has(k)) return "vulnerable";
  return "";
}
export function macClass(m: string) {
  return WEAK_MACS.has(m) ? "weak" : "";
}

export function deviceBadge(t?: string) {
  if (!t || t === "unknown") return null;
  return <span className="badge badge-unknown" style={{ fontSize: 10 }}>{t}</span>;
}

export function SSHResultCard({ r, onTag }: { r: any; onTag?: (host: string, port: number) => void }) {
  const ts = r.scanned_at ? new Date(r.scanned_at).toLocaleString() : "";
  return (
    <div className="result-card">
      <div className="result-header">
        <div>
          <div className="result-host">{r.host}:{r.port || 22}</div>
          {r.asset_name && <span style={{ fontSize: 12, color: "var(--ink-faint)" }}>{r.asset_name}{r.environment ? " · " + r.environment : ""}</span>}
        </div>
        <RiskBadge level={r.risk_level} />
        <PqcBadge status={r.pqc_status} />
        {deviceBadge(r.device_type || r.os_hint?.split(" ")[0])}
        {onTag && <button className="btn btn-ghost btn-sm" style={{ marginLeft: "auto" }} onClick={() => onTag(r.host, r.port || 22)}>Tag asset</button>}
      </div>
      <div className="result-grid">
        <div><div className="result-field-label">SSH version</div><div className="result-field-value">{r.ssh_version ?? "—"}</div></div>
        <div><div className="result-field-label">Host key</div><div className="result-field-value">{r.host_key_algorithm ?? "—"}{r.host_key_size ? " / " + r.host_key_size + "-bit" : ""}</div></div>
        <div><div className="result-field-label">KEX</div><div className="result-field-value">{r.key_exchange ?? "—"}</div></div>
        <div><div className="result-field-label">Cipher</div><div className="result-field-value">{r.cipher ?? "—"}</div></div>
        <div><div className="result-field-label">MAC</div><div className="result-field-value">{r.mac ?? "—"}</div></div>
        <div><div className="result-field-label">Quantum vulnerable</div><div className="result-field-value"><QuantumVuln vuln={r.quantum_vulnerable} /></div></div>
        {r.os_hint && <div><div className="result-field-label">OS hint</div><div className="result-field-value">{r.os_hint}</div></div>}
        {ts && <div><div className="result-field-label">Scanned</div><div className="result-field-value" style={{ color: "var(--ink-faint)" }}>{ts}</div></div>}
      </div>
      {!!(r.host_keys && r.host_keys.length) && (
        <table className="key-table">
          <thead><tr><th>Algorithm</th><th>Bits</th><th>Fingerprint</th></tr></thead>
          <tbody>{r.host_keys.map((hk: any, i: number) => <tr key={i}><td>{hk.algorithm}</td><td>{hk.key_size ?? "—"}</td><td style={{ color: "var(--ink-faint)", fontSize: 10 }}>{hk.fingerprint ?? "—"}</td></tr>)}</tbody>
        </table>
      )}
      {!!(r.server_kex_algorithms && r.server_kex_algorithms.length) && (
        <details style={{ marginTop: 8 }}>
          <summary className="collapse-toggle" style={{ display: "inline-flex", cursor: "pointer" }}>Advertised algorithms</summary>
          <div className="collapse-content open">
            <div className="result-field-label" style={{ marginBottom: 4 }}>KEX</div>
            <div className="pill-list">{r.server_kex_algorithms.map((k: string) => <span key={k} className={`pill ${kexClass(k)}`}>{k}</span>)}</div>
            <div className="result-field-label" style={{ marginTop: 10, marginBottom: 4 }}>Ciphers</div>
            <div className="pill-list">{(r.server_ciphers || []).map((c: string) => <span key={c} className="pill">{c}</span>)}</div>
            <div className="result-field-label" style={{ marginTop: 10, marginBottom: 4 }}>MACs</div>
            <div className="pill-list">{(r.server_macs || []).map((m: string) => <span key={m} className={`pill ${macClass(m)}`}>{m}</span>)}</div>
          </div>
        </details>
      )}
      {!!(r.findings && r.findings.length) && (
        <div className="findings">
          <div className="findings-title">Findings</div>
          {r.findings.map((f: string, i: number) => <div key={i} className="finding">{f}</div>)}
        </div>
      )}
    </div>
  );
}