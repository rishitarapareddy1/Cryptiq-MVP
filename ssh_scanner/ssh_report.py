"""
ssh_report.py
-------------
Consulting-grade PDF report generator.

Produces a structured report with:
  1. Executive Summary  — readiness %, risk breakdown, key findings
  2. Inventory Table    — every asset with crypto profile + risk
  3. Critical Findings  — detailed per-host findings for critical/high assets
  4. Remediation Roadmap — prioritised action plan with timelines
  5. Algorithm Reference — explanation of vulnerabilities for non-technical readers
  6. Appendix: CBOM     — machine-readable component list summary

Uses reportlab Platypus for structured layout.
"""

from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether,
)
from reportlab.platypus import BaseDocTemplate, Frame, PageTemplate
from reportlab.lib.colors import HexColor

from ssh_scanner.ssh_assets import EnrichedAsset, SSHFleetSnapshot


# ---------------------------------------------------------------------------
# Brand colours (dark-navy + electric-blue palette matching the UI)
# ---------------------------------------------------------------------------

C_NAVY     = HexColor("#0b0d11")
C_SURFACE  = HexColor("#13161d")
C_BORDER   = HexColor("#1f2330")
C_TEXT     = HexColor("#e2e4ee")
C_MUTED    = HexColor("#6b7194")
C_ACCENT   = HexColor("#4f8fff")
C_CRITICAL = HexColor("#ff4d4d")
C_HIGH     = HexColor("#ff8c42")
C_MEDIUM   = HexColor("#f5c842")
C_LOW      = HexColor("#3ecf8e")
C_HYBRID   = HexColor("#a78bfa")
C_WHITE    = HexColor("#ffffff")
C_LIGHT    = HexColor("#e2e4ee")
C_DARK_ROW = HexColor("#1a1d27")

RISK_COLORS = {
    "critical": C_CRITICAL,
    "high":     C_HIGH,
    "medium":   C_MEDIUM,
    "low":      C_LOW,
    "unknown":  C_MUTED,
}

PQC_COLORS = {
    "vulnerable": C_CRITICAL,
    "hybrid":     C_HYBRID,
    "pqc_ready":  C_LOW,
    "unknown":    C_MUTED,
}


# ---------------------------------------------------------------------------
# Style sheet
# ---------------------------------------------------------------------------

def _build_styles():
    base = getSampleStyleSheet()

    styles = {
        "cover_title": ParagraphStyle(
            "cover_title",
            fontSize=32, leading=38, textColor=C_WHITE,
            fontName="Helvetica-Bold", spaceAfter=8,
        ),
        "cover_sub": ParagraphStyle(
            "cover_sub",
            fontSize=14, leading=20, textColor=C_ACCENT,
            fontName="Helvetica", spaceAfter=4,
        ),
        "cover_meta": ParagraphStyle(
            "cover_meta",
            fontSize=10, leading=14, textColor=C_MUTED,
            fontName="Helvetica",
        ),
        "h1": ParagraphStyle(
            "h1",
            fontSize=18, leading=24, textColor=C_ACCENT,
            fontName="Helvetica-Bold", spaceBefore=24, spaceAfter=10,
            borderPad=0,
        ),
        "h2": ParagraphStyle(
            "h2",
            fontSize=13, leading=18, textColor=C_WHITE,
            fontName="Helvetica-Bold", spaceBefore=16, spaceAfter=6,
        ),
        "h3": ParagraphStyle(
            "h3",
            fontSize=11, leading=15, textColor=C_LIGHT,
            fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "body",
            fontSize=9, leading=14, textColor=C_LIGHT,
            fontName="Helvetica", spaceAfter=6,
        ),
        "body_muted": ParagraphStyle(
            "body_muted",
            fontSize=9, leading=14, textColor=C_MUTED,
            fontName="Helvetica", spaceAfter=4,
        ),
        "mono": ParagraphStyle(
            "mono",
            fontSize=8, leading=12, textColor=C_ACCENT,
            fontName="Courier", spaceAfter=2,
        ),
        "finding": ParagraphStyle(
            "finding",
            fontSize=9, leading=13, textColor=C_LIGHT,
            fontName="Helvetica", leftIndent=12, spaceAfter=3,
            bulletIndent=4, bulletFontName="Helvetica",
        ),
        "caption": ParagraphStyle(
            "caption",
            fontSize=8, leading=11, textColor=C_MUTED,
            fontName="Helvetica", alignment=TA_CENTER, spaceAfter=4,
        ),
        "stat_big": ParagraphStyle(
            "stat_big",
            fontSize=28, leading=32, textColor=C_WHITE,
            fontName="Helvetica-Bold", alignment=TA_CENTER,
        ),
        "stat_label": ParagraphStyle(
            "stat_label",
            fontSize=8, leading=11, textColor=C_MUTED,
            fontName="Helvetica", alignment=TA_CENTER, spaceAfter=2,
        ),
        "toc_entry": ParagraphStyle(
            "toc_entry",
            fontSize=10, leading=16, textColor=C_LIGHT,
            fontName="Helvetica", leftIndent=0,
        ),
    }
    return styles


# ---------------------------------------------------------------------------
# Page templates
# ---------------------------------------------------------------------------

class _ReportDoc(BaseDocTemplate):
    def __init__(self, filename_or_buffer, org_name: str, **kwargs):
        super().__init__(filename_or_buffer, **kwargs)
        self.org_name = org_name
        self._page_num = 0

        frame = Frame(
            0.75 * inch, 0.75 * inch,
            self.width - 1.5 * inch,
            self.height - 1.5 * inch,
            id="body",
        )
        self.addPageTemplates([
            PageTemplate(id="main", frames=[frame], onPage=self._draw_page),
        ])

    def _draw_page(self, canvas, doc):
        canvas.saveState()
        w, h = doc.pagesize

        # Dark background
        canvas.setFillColor(C_NAVY)
        canvas.rect(0, 0, w, h, fill=1, stroke=0)

        # Top accent bar
        canvas.setFillColor(C_ACCENT)
        canvas.rect(0, h - 4, w, 4, fill=1, stroke=0)

        # Header line
        canvas.setStrokeColor(C_BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(0.75 * inch, h - 0.65 * inch, w - 0.75 * inch, h - 0.65 * inch)

        # Header: org name left, product right
        canvas.setFillColor(C_MUTED)
        canvas.setFont("Helvetica", 8)
        canvas.drawString(0.75 * inch, h - 0.52 * inch, self.org_name)
        canvas.drawRightString(w - 0.75 * inch, h - 0.52 * inch, "Cryptiq SSH Security Assessment")

        # Footer line + page number
        canvas.setStrokeColor(C_BORDER)
        canvas.line(0.75 * inch, 0.55 * inch, w - 0.75 * inch, 0.55 * inch)
        canvas.setFillColor(C_MUTED)
        canvas.setFont("Helvetica", 8)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        canvas.drawString(0.75 * inch, 0.38 * inch, f"Confidential — {ts}")
        canvas.drawRightString(
            w - 0.75 * inch, 0.38 * inch,
            f"Page {doc.page}"
        )
        canvas.restoreState()


# ---------------------------------------------------------------------------
# Table helpers
# ---------------------------------------------------------------------------

def _risk_cell(level: str) -> Paragraph:
    color = RISK_COLORS.get(level, C_MUTED)
    style = ParagraphStyle(
        "risk_cell",
        fontSize=8, fontName="Helvetica-Bold",
        textColor=color, alignment=TA_CENTER,
    )
    return Paragraph(level.upper(), style)


def _pqc_cell(status: str) -> Paragraph:
    color = PQC_COLORS.get(status, C_MUTED)
    label = {"vulnerable": "VULN", "hybrid": "HYBRID", "pqc_ready": "PQC-READY", "unknown": "?"}.get(status, status)
    style = ParagraphStyle(
        "pqc_cell",
        fontSize=8, fontName="Helvetica-Bold",
        textColor=color, alignment=TA_CENTER,
    )
    return Paragraph(label, style)


def _mono(text: str, styles: dict) -> Paragraph:
    return Paragraph(str(text) if text else "—", styles["mono"])


def _body(text: str, styles: dict) -> Paragraph:
    return Paragraph(str(text) if text else "—", styles["body"])


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _cover_page(story: list, styles: dict, org_name: str, report_date: str, scan_count: int):
    story.append(Spacer(1, 1.5 * inch))
    story.append(Paragraph("SSH Cryptographic", styles["cover_title"]))
    story.append(Paragraph("Security Assessment", styles["cover_title"]))
    story.append(Spacer(1, 0.3 * inch))
    story.append(Paragraph("Post-Quantum Readiness Report", styles["cover_sub"]))
    story.append(Spacer(1, 0.5 * inch))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
    story.append(Spacer(1, 0.3 * inch))
    story.append(Paragraph(f"Prepared for: {org_name}", styles["cover_meta"]))
    story.append(Paragraph(f"Report date: {report_date}", styles["cover_meta"]))
    story.append(Paragraph(f"Assets scanned: {scan_count}", styles["cover_meta"]))
    story.append(Paragraph("Generated by: Cryptiq SSH Scanner v1.0", styles["cover_meta"]))
    story.append(PageBreak())


def _executive_summary(story: list, styles: dict, assets: list[EnrichedAsset], snapshots: list[SSHFleetSnapshot]):
    story.append(Paragraph("Executive Summary", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
    story.append(Spacer(1, 0.15 * inch))

    total = len(assets)
    critical = sum(1 for a in assets if a.risk_level == "critical")
    high = sum(1 for a in assets if a.risk_level == "high")
    medium = sum(1 for a in assets if a.risk_level == "medium")
    low = sum(1 for a in assets if a.risk_level == "low")
    vulnerable = sum(1 for a in assets if a.quantum_vulnerable)
    pqc_ready = sum(1 for a in assets if a.pqc_status == "pqc_ready")
    hybrid = sum(1 for a in assets if a.pqc_status == "hybrid")
    pct = round(pqc_ready / total * 100, 1) if total > 0 else 0

    intro = (
        f"This report presents the findings of a cryptographic asset discovery "
        f"scan covering <b>{total} SSH-enabled systems</b>. The assessment identifies "
        f"cryptographic algorithms in use across the environment, classifies their "
        f"post-quantum risk, and provides a prioritised remediation roadmap."
    )
    story.append(Paragraph(intro, styles["body"]))
    story.append(Spacer(1, 0.2 * inch))

    # Key stats table
    stat_data = [
        [
            Paragraph(str(total),    styles["stat_big"]),
            Paragraph(str(vulnerable), styles["stat_big"]),
            Paragraph(str(critical + high), styles["stat_big"]),
            Paragraph(f"{pct}%",     styles["stat_big"]),
        ],
        [
            Paragraph("Total hosts",         styles["stat_label"]),
            Paragraph("Quantum vulnerable",  styles["stat_label"]),
            Paragraph("Priority targets",    styles["stat_label"]),
            Paragraph("PQC ready",           styles["stat_label"]),
        ],
    ]
    col_w = (letter[0] - 1.5 * inch) / 4
    stat_table = Table(stat_data, colWidths=[col_w] * 4)
    stat_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_SURFACE),
        ("BOX",        (0, 0), (-1, -1), 0.5, C_BORDER),
        ("INNERGRID",  (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("TEXTCOLOR",  (1, 0), (1, 0), C_CRITICAL),
        ("TEXTCOLOR",  (2, 0), (2, 0), C_HIGH),
        ("TEXTCOLOR",  (3, 0), (3, 0), C_LOW),
    ]))
    story.append(stat_table)
    story.append(Spacer(1, 0.2 * inch))

    # Risk breakdown bar chart (text-based, works in reportlab without matplotlib)
    story.append(Paragraph("Risk Distribution", styles["h2"]))
    risk_rows = []
    for level, count, color in [
        ("Critical", critical, C_CRITICAL),
        ("High",     high,     C_HIGH),
        ("Medium",   medium,   C_MEDIUM),
        ("Low",      low,      C_LOW),
    ]:
        pct_bar = int((count / total * 40)) if total > 0 else 0
        bar = "█" * pct_bar
        pct_str = f"{round(count/total*100, 1)}%" if total > 0 else "0%"
        label_style = ParagraphStyle("rl", fontSize=9, fontName="Helvetica-Bold", textColor=color)
        bar_style   = ParagraphStyle("rb", fontSize=9, fontName="Courier", textColor=color)
        risk_rows.append([
            Paragraph(level, label_style),
            Paragraph(bar, bar_style),
            Paragraph(f"{count} ({pct_str})", label_style),
        ])

    risk_table = Table(risk_rows, colWidths=[1*inch, 4.5*inch, 1*inch])
    risk_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_SURFACE),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(risk_table)
    story.append(Spacer(1, 0.2 * inch))

    # Key findings bullets
    story.append(Paragraph("Key Findings", styles["h2"]))
    findings_bullets = []
    if critical > 0:
        findings_bullets.append(
            f"<b>{critical} systems</b> have critically weak cryptography (legacy DH or sub-2048 RSA) "
            f"and require immediate remediation."
        )
    if high > 0:
        findings_bullets.append(
            f"<b>{high} systems</b> use RSA or ECDSA host keys — vulnerable to harvest-now-decrypt-later attacks."
        )
    findings_bullets.append(
        f"<b>{vulnerable} of {total} systems</b> ({round(vulnerable/total*100) if total else 0}%) "
        f"are quantum-vulnerable, relying on algorithms broken by Shor's algorithm."
    )
    if hybrid > 0:
        findings_bullets.append(
            f"<b>{hybrid} systems</b> have deployed hybrid PQC key exchange — positive progress "
            f"but host authentication remains classically vulnerable."
        )
    if pqc_ready == 0:
        findings_bullets.append(
            "No systems are fully PQC-ready. Host key algorithms must be migrated "
            "to ML-DSA or similar NIST-standardised schemes."
        )
    findings_bullets.append(
        "NIST finalised PQC standards (FIPS 203/204/205) in August 2024. "
        "CISA and NSA recommend completing cryptographic migration before 2030."
    )

    for bullet in findings_bullets:
        story.append(Paragraph(f"• {bullet}", styles["finding"]))
    story.append(Spacer(1, 0.1 * inch))

    # Trend data if available
    if len(snapshots) >= 2:
        story.append(Paragraph("Trend", styles["h2"]))
        newest = snapshots[0]
        oldest = snapshots[-1]
        delta_vuln = newest.quantum_vulnerable - oldest.quantum_vulnerable
        delta_pct  = newest.pqc_readiness_percent - oldest.pqc_readiness_percent
        trend_text = (
            f"Since the baseline ({oldest.label}), quantum-vulnerable hosts have "
            f"{'decreased' if delta_vuln < 0 else 'increased'} by {abs(delta_vuln)} "
            f"({abs(delta_pct)} percentage point {'improvement' if delta_pct > 0 else 'regression'} "
            f"in PQC readiness)."
        )
        story.append(Paragraph(trend_text, styles["body"]))

    story.append(PageBreak())


def _inventory_table(story: list, styles: dict, assets: list[EnrichedAsset]):
    story.append(Paragraph("Asset Inventory", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
    story.append(Spacer(1, 0.1 * inch))
    story.append(Paragraph(
        "Complete inventory of discovered SSH assets with their cryptographic profiles. "
        "Assets are sorted by risk level (most critical first).",
        styles["body_muted"]
    ))
    story.append(Spacer(1, 0.15 * inch))

    headers = ["Host", "Asset Name", "Environment", "SSH Version", "Host Key", "KEX", "Risk", "PQC"]
    col_widths = [1.3*inch, 1.2*inch, 0.8*inch, 1.0*inch, 1.1*inch, 1.2*inch, 0.6*inch, 0.7*inch]

    header_style = ParagraphStyle("th", fontSize=8, fontName="Helvetica-Bold", textColor=C_MUTED, alignment=TA_LEFT)
    rows = [[Paragraph(h, header_style) for h in headers]]

    for i, a in enumerate(assets):
        hk = f"{a.host_key_algorithm or '?'}"
        if a.host_key_size:
            hk += f"/{a.host_key_size}b"
        env = a.environment or "—"
        rows.append([
            _mono(f"{a.host}:{a.port}", styles),
            _body(a.asset_name or "—", styles),
            _body(env, styles),
            _mono(a.ssh_version or "—", styles),
            _mono(hk, styles),
            _mono((a.key_exchange or "—")[:28], styles),
            _risk_cell(a.risk_level),
            _pqc_cell(a.pqc_status),
        ])

    table = Table(rows, colWidths=col_widths, repeatRows=1)
    row_colors = []
    for i in range(1, len(rows)):
        bg = C_DARK_ROW if i % 2 == 0 else C_SURFACE
        row_colors.append(("BACKGROUND", (0, i), (-1, i), bg))

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), C_BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, 0), 0.5, C_ACCENT),
        ("LINEBELOW", (0, 1), (-1, -1), 0.3, C_BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ] + row_colors))

    story.append(table)
    story.append(PageBreak())


def _critical_findings(story: list, styles: dict, assets: list[EnrichedAsset]):
    priority_assets = [a for a in assets if a.risk_level in ("critical", "high")]
    if not priority_assets:
        return

    story.append(Paragraph("Critical & High Risk Findings", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
    story.append(Spacer(1, 0.1 * inch))

    for a in priority_assets[:30]:  # cap at 30 for readability
        color = RISK_COLORS.get(a.risk_level, C_MUTED)
        label = f"{a.asset_name or a.host} — {a.risk_level.upper()}"
        label_style = ParagraphStyle("fl", fontSize=11, fontName="Helvetica-Bold", textColor=color, spaceBefore=12)

        block = [
            Paragraph(label, label_style),
            HRFlowable(width="100%", thickness=0.3, color=C_BORDER),
        ]

        # Detail table
        detail_rows = [
            ["Host",        f"{a.host}:{a.port}"],
            ["SSH Version", a.ssh_version or "Unknown"],
            ["Host Key",    f"{a.host_key_algorithm or '?'}" + (f" / {a.host_key_size}-bit" if a.host_key_size else "")],
            ["KEX",         a.key_exchange or "Unknown"],
            ["Cipher",      a.cipher or "Unknown"],
            ["PQC Status",  a.pqc_status.replace("_", " ").upper()],
        ]
        if a.environment:
            detail_rows.insert(1, ["Environment", a.environment])
        if a.asset_owner:
            detail_rows.append(["Owner", a.asset_owner])
        if a.can_upgrade is False:
            detail_rows.append(["Upgrade blocker", a.upgrade_blocker or "Cannot upgrade"])

        key_style  = ParagraphStyle("dk", fontSize=8, fontName="Helvetica-Bold", textColor=C_MUTED)
        val_style  = ParagraphStyle("dv", fontSize=8, fontName="Courier", textColor=C_ACCENT)
        detail_table = Table(
            [[Paragraph(k, key_style), Paragraph(v, val_style)] for k, v in detail_rows],
            colWidths=[1.2*inch, 5.5*inch],
        )
        detail_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), C_SURFACE),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("LINEBELOW", (0, 0), (-1, -1), 0.3, C_BORDER),
        ]))
        block.append(detail_table)

        if a.findings:
            block.append(Spacer(1, 0.06 * inch))
            block.append(Paragraph("Findings:", ParagraphStyle("fh", fontSize=8, fontName="Helvetica-Bold", textColor=C_MUTED)))
            for f in a.findings:
                block.append(Paragraph(f"› {f}", styles["finding"]))

        story.append(KeepTogether(block))

    story.append(PageBreak())


def _remediation_roadmap(story: list, styles: dict, assets: list[EnrichedAsset]):
    story.append(Paragraph("Remediation Roadmap", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
    story.append(Spacer(1, 0.1 * inch))
    story.append(Paragraph(
        "The following roadmap prioritises remediation actions based on risk level and migration complexity. "
        "All timelines assume NIST PQC standards (FIPS 203/204/205) as the migration target.",
        styles["body"]
    ))
    story.append(Spacer(1, 0.15 * inch))

    phases = [
        (
            "Phase 1 — Immediate (0–90 days)",
            C_CRITICAL,
            [
                "Disable all legacy KEX: diffie-hellman-group1-sha1, diffie-hellman-group14-sha1.",
                "Enforce minimum RSA key size of 3072-bit on all SSH servers.",
                "Disable DSA (ssh-dss) host key support — DSA is cryptographically broken.",
                "Enable Ed25519 host keys as a transition measure on all servers.",
                "Audit and rotate any RSA keys smaller than 2048-bit immediately.",
            ],
            [a for a in assets if a.risk_level == "critical"],
        ),
        (
            "Phase 2 — Near-term (90–180 days)",
            C_HIGH,
            [
                "Deploy hybrid PQC KEX (sntrup761x25519 or mlkem768x25519) on all SSH servers running OpenSSH 9.0+.",
                "Update SSH server software to OpenSSH 9.x on all eligible systems.",
                "Implement centralised SSH key management and certificate authority (SSH CA).",
                "Tag all non-upgradeable systems (embedded, EOL appliances) for network isolation planning.",
                "Enforce ETM (Encrypt-Then-MAC) modes; disable legacy HMAC-MD5 and HMAC-SHA1.",
            ],
            [a for a in assets if a.risk_level == "high"],
        ),
        (
            "Phase 3 — Medium-term (6–18 months)",
            C_MEDIUM,
            [
                "Migrate host keys to ML-DSA-65 (FIPS 204) once OpenSSH support ships.",
                "Replace all remaining RSA/ECDSA host keys with PQC alternatives.",
                "Implement SSH certificate-based authentication fleet-wide (eliminates per-user RSA keys).",
                "Complete vendor upgrade path for network appliances currently blocked on PQC.",
            ],
            [a for a in assets if a.risk_level == "medium"],
        ),
        (
            "Phase 4 — Long-term (18–36 months)",
            C_LOW,
            [
                "Full PQC host key deployment across all systems.",
                "Deprecate all pre-PQC SSH configurations via policy enforcement.",
                "Conduct follow-up assessment to verify PQC readiness target (>95%).",
                "Implement continuous cryptographic monitoring (re-run Cryptiq suite quarterly).",
            ],
            [],
        ),
    ]

    for phase_title, color, actions, phase_assets in phases:
        title_style = ParagraphStyle("pt", fontSize=12, fontName="Helvetica-Bold", textColor=color, spaceBefore=16, spaceAfter=6)
        story.append(Paragraph(phase_title, title_style))

        for action in actions:
            story.append(Paragraph(f"□  {action}", styles["finding"]))

        if phase_assets:
            story.append(Spacer(1, 0.06 * inch))
            asset_style = ParagraphStyle("pa", fontSize=8, fontName="Courier", textColor=C_MUTED)
            hosts = ", ".join(f"{a.host}" for a in phase_assets[:10])
            if len(phase_assets) > 10:
                hosts += f" + {len(phase_assets)-10} more"
            story.append(Paragraph(f"Affected assets: {hosts}", asset_style))

        story.append(Spacer(1, 0.05 * inch))

    story.append(PageBreak())


def _algorithm_reference(story: list, styles: dict):
    story.append(Paragraph("Algorithm Reference", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
    story.append(Spacer(1, 0.1 * inch))
    story.append(Paragraph(
        "This section provides non-technical context for the algorithms identified in this assessment "
        "and their quantum vulnerability status.",
        styles["body_muted"]
    ))
    story.append(Spacer(1, 0.15 * inch))

    ref_data = [
        ("Algorithm", "Type", "Quantum risk", "Notes"),
        ("ssh-rsa / RSA-2048+", "Host key / auth", "HIGH", "Shor's algorithm breaks RSA. Priority migration target."),
        ("ecdsa-sha2-nistp256", "Host key / auth", "HIGH", "Elliptic curve discrete log — also broken by Shor."),
        ("ssh-ed25519", "Host key / auth", "MEDIUM", "Not immediately Shor-vulnerable but not PQC-safe long-term."),
        ("diffie-hellman-group14", "Key exchange", "HIGH", "Classical DH — broken by Shor. Disable immediately."),
        ("diffie-hellman-group1-sha1", "Key exchange", "CRITICAL", "768-bit DH + SHA-1. Classically and quantum-broken."),
        ("ecdh-sha2-nistp256", "Key exchange", "HIGH", "ECDH on NIST curves — Shor-vulnerable."),
        ("curve25519-sha256", "Key exchange", "MEDIUM", "Better than ECDH but still broken by large CRQC."),
        ("sntrup761x25519-sha512", "Key exchange", "LOW (hybrid)", "NIST PQC finalist + Curve25519. Harvest-now protection."),
        ("mlkem768x25519-sha256", "Key exchange", "LOW (hybrid)", "ML-KEM (FIPS 203) hybrid. Current best practice."),
        ("aes256-gcm / chacha20", "Cipher", "LOW", "Symmetric — resistant with 256-bit keys (Grover's halves security)."),
        ("hmac-sha2-256-etm", "MAC", "LOW", "SHA-2 family. Quantum-resistant at 256-bit."),
        ("hmac-sha1 / hmac-md5", "MAC", "CRITICAL", "Classically broken hash functions. Disable immediately."),
    ]

    col_widths = [1.6*inch, 1.2*inch, 1.0*inch, 3.0*inch]
    h_style = ParagraphStyle("rh", fontSize=8, fontName="Helvetica-Bold", textColor=C_MUTED)
    rows = []
    for i, row in enumerate(ref_data):
        if i == 0:
            rows.append([Paragraph(c, h_style) for c in row])
        else:
            risk = row[2]
            risk_color = C_CRITICAL if "CRITICAL" in risk else C_HIGH if "HIGH" in risk else C_MEDIUM if "MEDIUM" in risk else C_LOW
            risk_style = ParagraphStyle("rr", fontSize=8, fontName="Helvetica-Bold", textColor=risk_color)
            rows.append([
                _mono(row[0], styles),
                _body(row[1], styles),
                Paragraph(risk, risk_style),
                _body(row[3], styles),
            ])

    ref_table = Table(rows, colWidths=col_widths, repeatRows=1)
    ref_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), C_BORDER),
        ("LINEBELOW",  (0, 0), (-1, 0), 0.5, C_ACCENT),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW",  (0, 1), (-1, -1), 0.3, C_BORDER),
        *[("BACKGROUND", (0, i), (-1, i), C_DARK_ROW if i % 2 == 0 else C_SURFACE)
          for i in range(1, len(rows))],
    ]))
    story.append(ref_table)
    story.append(PageBreak())


# ---------------------------------------------------------------------------
# Main report builder
# ---------------------------------------------------------------------------

def generate_report(
    assets: list[EnrichedAsset],
    org_name: str = "Organisation",
    snapshots: Optional[list[SSHFleetSnapshot]] = None,
    output_path: Optional[str] = None,
) -> bytes:
    """
    Generate a full consulting PDF report.

    Args:
        assets      : enriched asset list from get_enriched_assets()
        org_name    : client organisation name (appears in header/cover)
        snapshots   : optional trend data from get_fleet_trend()
        output_path : if given, also save to disk

    Returns:
        PDF as bytes (suitable for HTTP response or file write)
    """
    buf = io.BytesIO()
    doc = _ReportDoc(
        buf,
        org_name=org_name,
        pagesize=letter,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.85 * inch,
        bottomMargin=0.75 * inch,
    )

    styles = _build_styles()
    story = []
    report_date = datetime.now(timezone.utc).strftime("%B %d, %Y")

    _cover_page(story, styles, org_name, report_date, len(assets))
    _executive_summary(story, styles, assets, snapshots or [])
    _inventory_table(story, styles, assets)
    _critical_findings(story, styles, assets)
    _remediation_roadmap(story, styles, assets)
    _algorithm_reference(story, styles)

    doc.build(story)
    pdf_bytes = buf.getvalue()

    if output_path:
        with open(output_path, "wb") as f:
            f.write(pdf_bytes)

    return pdf_bytes