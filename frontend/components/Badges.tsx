export function RiskBadge({ level }: { level?: string | null }) {
  if (!level) return <span className="badge badge-unknown">—</span>;
  const cls = level.toLowerCase();
  return <span className={`badge badge-${cls}`}>{level.toUpperCase()}</span>;
}

export function PqcBadge({ status }: { status?: string | null }) {
  const labels: Record<string, string> = {
    vulnerable: "VULNERABLE",
    hybrid: "HYBRID",
    hybrid_pqc: "HYBRID PQC",
    pqc_ready: "PQC-READY",
    unknown: "UNKNOWN",
  };
  const s = status || "unknown";
  return <span className={`badge badge-${s}`}>{labels[s] || s.toUpperCase()}</span>;
}

export function QuantumVuln({ vuln }: { vuln?: boolean }) {
  return <span className={vuln ? "qv-yes" : "qv-no"}>{vuln ? "Yes" : "No"}</span>;
}