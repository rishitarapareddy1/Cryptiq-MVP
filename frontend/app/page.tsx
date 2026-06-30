"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import Topbar from "@/components/Topbar";

type ToolCard = {
  href: string;
  accent: string;
  iconBg: string;
  tag: string;
  name: string;
  desc: string;
  chips: string[];
  available: boolean;
  iconPath: JSX.Element;
};

const TOOLS: ToolCard[] = [
  {
    href: "/tls", accent: "var(--blue-bright)", iconBg: "var(--blue-glow)", tag: "Live",
    name: "TLS Scanner",
    desc: "Scan HTTPS endpoints for certificate algorithms, TLS version, key exchange, and PQC readiness. Supports CT log integration.",
    chips: ["x.509 certs", "KEX analysis", "CBOM", "AWS ACM"],
    available: true,
    iconPath: <><rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></>,
  },
  {
    href: "/ssh", accent: "var(--amber-deep)", iconBg: "var(--amber-glow)", tag: "Live",
    name: "SSH Scanner",
    desc: "Discover SSH hosts on your network. Extract host keys, KEX algorithms, ciphers, and MACs. Network-wide CIDR scanning included.",
    chips: ["Network discover", "Host keys", "CBOM", "PDF report"],
    available: true,
    iconPath: <><rect x="2" y="3" width="20" height="14" rx="2" /><path d="M8 21h8M12 17v4" /></>,
  },
  {
    href: "#", accent: "var(--slate)", iconBg: "var(--slate-glow)", tag: "Coming soon",
    name: "PKI Discovery",
    desc: "Map your internal certificate authority hierarchy, discover all issued certificates, and flag quantum-vulnerable signing algorithms.",
    chips: ["CA hierarchy", "CRL/OCSP", "CBOM"],
    available: false,
    iconPath: <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />,
  },
  {
    href: "#", accent: "var(--slate)", iconBg: "var(--slate-glow)", tag: "Coming soon",
    name: "Code Signing",
    desc: "Discover code signing certificates, verify algorithm strength, and track signing key rotation across your release pipeline.",
    chips: ["CI/CD", "Key vaults", "SBOM"],
    available: false,
    iconPath: <><ellipse cx="12" cy="5" rx="9" ry="3" /><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3" /><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5" /></>,
  },
  {
    href: "#", accent: "var(--slate)", iconBg: "var(--slate-glow)", tag: "Coming soon",
    name: "VPN Discovery",
    desc: "Probe VPN endpoints for IKE version, cipher suites, and DH group strength. Identify legacy configurations at risk.",
    chips: ["IKEv1/v2", "IPSec", "DH groups"],
    available: false,
    iconPath: <path d="M22 12h-4l-3 9L9 3l-3 9H2" />,
  },
  {
    href: "/alb", accent: "var(--amber)", iconBg: "var(--amber-glow)", tag: "Live",
    name: "ALB PQC Migration",
    desc: "Discover AWS ALB/NLB HTTPS listeners on classical TLS policies and propose a post-quantum hybrid migration as a pull request.",
    chips: ["ALB / NLB", "PQ diff", "GitHub PR", "Rollback"],
    available: true,
    iconPath: <><rect x="2" y="3" width="20" height="14" rx="2" /><path d="M8 21h8M12 17v4" /></>,
  },
  {
    href: "/migrate", accent: "var(--cyan-bright)", iconBg: "var(--cyan-glow)", tag: "Live",
    name: "SSH Migration",
    desc: "Generate migration plans, harden sshd_config, generate PQC-ready keys, and execute migration actions on remote hosts.",
    chips: ["Key generation", "Config patch", "Phased plan", "Execute"],
    available: true,
    iconPath: <path d="M5 12h14M12 5l7 7-7 7" />,
  },
  {
    href: "/ssh#report", accent: "var(--blue)", iconBg: "var(--blue-glow)", tag: "Live",
    name: "Readiness Report",
    desc: "Generate a consulting-grade PDF covering your full crypto asset inventory, risk breakdown, and 4-phase remediation roadmap.",
    chips: ["Executive summary", "Roadmap", "PDF"],
    available: true,
    iconPath: <><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /><line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" /></>,
  },
];

const STEPS = [
  { n: "01", t: "Discover", d: "Scan domains, IP ranges, or cloud accounts. Find every SSH server, TLS endpoint, and cryptographic asset automatically." },
  { n: "02", t: "Classify", d: "Every algorithm is classified by quantum vulnerability. RSA, ECDSA, DH — flagged. Hybrid PQC, ML-KEM — noted. Pure PQC — green." },
  { n: "03", t: "Inventory", d: "Build a CBOM (Cryptography Bill of Materials) in CycloneDX 1.6 format. Tag assets with owner, environment, and upgrade status." },
  { n: "04", t: "Report", d: "Generate a consulting PDF with executive summary, critical findings, and a phased remediation roadmap tied to NIST PQC standards." },
];

export default function Home() {
  const [stats, setStats] = useState({ scans: "—", hosts: "—", vuln: "—", pct: "—" });
  const [apiOnline, setApiOnline] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const res = await fetch("/health");
        setApiOnline(res.ok);
      } catch {
        setApiOnline(false);
      }
      try {
        const [invRes, scansRes] = await Promise.all([
          fetch("/ssh/inventory").then((r) => (r.ok ? r.json() : null)),
          fetch("/scans").then((r) => (r.ok ? r.json() : null)),
        ]);
        setStats((s) => ({
          ...s,
          hosts: invRes ? String(invRes.total_hosts) : s.hosts,
          vuln: invRes ? String(invRes.quantum_vulnerable) : s.vuln,
          pct: invRes ? `${invRes.pqc_readiness_percent}%` : s.pct,
          scans: scansRes?.scans ? String(scansRes.scans.length) : s.scans,
        }));
      } catch {}
    })();
  }, []);

  return (
    <>
      <Topbar tag="beta" links={[{ href: "/docs", label: "API docs ↗", external: true }]} />

      <section className="shell-simple" style={{ textAlign: "center", maxWidth: 860 }}>
        <div className="hero-eyebrow" style={{ margin: "0 auto 18px" }}>
          <span className="pip" />
          Post-Quantum Cryptography Readiness
        </div>
        <h1 className="hero-title">
          Know your crypto.
          <br />
          <span className="dim">Before quantum does.</span>
        </h1>
        <p className="hero-sub" style={{ margin: "0 auto 36px" }}>
          Cryptiq discovers every cryptographic asset in your infrastructure, scores its quantum
          risk, and gives you a prioritised migration roadmap — before a cryptographically-relevant
          quantum computer arrives.
        </p>
        <a href="#tools" className="btn btn-primary">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.5}>
            <circle cx="11" cy="11" r="8" />
            <path d="m21 21-4.35-4.35" />
          </svg>
          Start scanning
        </a>
      </section>

      <div className="stat-strip">
        <div className="stat-item"><div className="stat-value">{stats.scans}</div><div className="stat-label">Total scans</div></div>
        <div className="stat-item"><div className="stat-value">{stats.hosts}</div><div className="stat-label">SSH hosts</div></div>
        <div className="stat-item"><div className="stat-value" style={{ color: "#b8391a" }}>{stats.vuln}</div><div className="stat-label">Vulnerable</div></div>
        <div className="stat-item"><div className="stat-value" style={{ color: "#0d7d89" }}>{stats.pct}</div><div className="stat-label">PQC ready</div></div>
      </div>

      <section className="shell-simple" id="tools" style={{ maxWidth: 1040 }}>
        <div className="section-label">Scanning tools</div>
        <div className="tools-grid">
          {TOOLS.map((t) => (
            <Link
              key={t.name}
              href={t.href}
              className={`tool-card ${t.available ? "available" : "coming-soon"}`}
              style={{ ["--card-accent" as any]: t.accent }}
              onClick={(e) => { if (!t.available) e.preventDefault(); }}
            >
              <div className="tool-header2">
                <div className="tool-icon" style={{ ["--icon-bg" as any]: t.iconBg }}>
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
                    {t.iconPath}
                  </svg>
                </div>
                <span className={`tool-tag${t.available ? "" : " soon"}`}>{t.tag}</span>
              </div>
              <div>
                <div className="tool-name">{t.name}</div>
                <div className="tool-desc">{t.desc}</div>
              </div>
              <div className="tool-meta">
                {t.chips.map((c) => <span key={c} className="tool-chip">{c}</span>)}
              </div>
            </Link>
          ))}
        </div>

        <div className="section-label">How it works</div>
        <div className="steps">
          {STEPS.map((s) => (
            <div className="step" key={s.n}>
              <div className="step-num">{s.n}</div>
              <div className="step-title">{s.t}</div>
              <div className="step-desc">{s.d}</div>
            </div>
          ))}
        </div>
      </section>

      <footer className="site-footer">
        <div className="footer-left">cryptiq · internal tool · not for public distribution</div>
        <div className="footer-right">
          <a href="/docs" className="footer-link" target="_blank" rel="noreferrer">API docs</a>
          <a href="/ssh/docs" className="footer-link" target="_blank" rel="noreferrer">SSH API</a>
          <a href="/health" className="footer-link" target="_blank" rel="noreferrer">
            {apiOnline ? "● Health (online)" : "● Health (offline)"}
          </a>
        </div>
      </footer>
    </>
  );
}