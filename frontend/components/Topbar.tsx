"use client";

import Link from "next/link";

export default function Topbar({
  tag = "v1.0",
  links = [{ href: "/", label: "Home" }, { href: "/docs", label: "API docs ↗", external: true }],
}: {
  tag?: string;
  links?: { href: string; label: string; external?: boolean }[];
}) {
  return (
    <header className="topbar">
      <Link href="/" className="brand">
        cryptiq<span className="dot">.</span>
      </Link>
      <div className="topbar-tag">{tag}</div>
      <div className="topbar-spacer" />
      {links.map((l) =>
        l.external ? (
          <a key={l.href} href={l.href} className="topbar-link" target="_blank" rel="noreferrer">
            {l.label}
          </a>
        ) : (
          <Link key={l.href} href={l.href} className="topbar-link">
            {l.label}
          </Link>
        )
      )}
    </header>
  );
}