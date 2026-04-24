import re
from html import unescape
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Flowable, KeepTogether
)
from reportlab.pdfgen import canvas as pdfcanvas
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
from collections import defaultdict, Counter

# --- Configuration & Palette ---
BG_MAIN = colors.white
TEXT_PRIMARY = colors.HexColor("#0f172a")  # Slate 900
TEXT_MUTED = colors.HexColor("#64748b")  # Slate 500
ACCENT_BLUE = colors.HexColor("#667eea")  # Deep Eye Theme
BORDER_COLOR = colors.HexColor("#e2e8f0")  # Slate 200
BG_CARD_HEADER = colors.HexColor("#f8fafc")  # Slate 50

SEV_COLORS = {
    "high": colors.HexColor("#ef4444"),
    "medium": colors.HexColor("#f59e0b"),
    "low": colors.HexColor("#10b981"),
    "info": colors.HexColor("#64748b"),
}


def sanitize_html_for_pdf(text):
    """Clean HTML content for PDF generation"""
    if not isinstance(text, str):
        return str(text) if text is not None else "-"

    text = re.sub(r'<[^>]+>', '', text)
    text = unescape(text)
    text = text.replace('&', '&amp;')
    text = text.replace('<', '&lt;')
    text = text.replace('>', '&gt;')
    text = text.replace('"', '&quot;')
    text = text.replace("'", '&#x27;')
    text = re.sub(r'\s+', ' ', text).strip()

    if len(text) > 1000:
        text = text[:997] + "..."

    return text or "-"


def sanitize_code_for_pdf(text):
    """Sanitize code while preserving formatting"""
    if not isinstance(text, str):
        return str(text) if text is not None else "-"

    # Remove HTML tags but keep line breaks and indentation
    text = re.sub(r'<[^>]+>', '', text)
    text = unescape(text)
    text = text.replace('&', '&amp;')
    text = text.replace('<', '&lt;')
    text = text.replace('>', '&gt;')
    text = text.replace('"', '&quot;')
    text = text.replace("'", '&#x27;')
    # DON'T collapse whitespace for code
    text = text.strip()

    return text or "-"


def sev_bucket(score: int) -> str:
    if score <= 0:
        return "info"
    if 1 <= score <= 2:
        return "low"
    if 3 <= score <= 5:
        return "medium"
    return "high"


class Pill(Flowable):
    """Rounded label 'pill' with colored background."""

    def __init__(self, text, color=colors.HexColor("#64748b"), txt_color=colors.white, padding=3, r=5):
        Flowable.__init__(self)
        self.text = text
        self.color = color
        self.txt_color = txt_color
        self.padding = padding
        self.radius = r

    def wrap(self, availWidth, availHeight):
        w = len(self.text) * 6 + self.padding * 2 + 20
        h = 12 + self.padding * 2
        return (min(w, availWidth), h)

    def draw(self):
        w, h = self.wrap(0, 0)
        self.canv.setFillColor(self.color)
        self.canv.setStrokeColor(self.color)
        self.canv.roundRect(0, 0, w, h, self.radius, stroke=1, fill=1)
        self.canv.setFillColor(colors.white)
        self.canv.setFont("Helvetica-Bold", 8)
        text_x = self.padding + 8
        text_y = h // 2 - 3
        self.canv.drawString(text_x, text_y, self.text)


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle(name="H2", fontName="Helvetica-Bold", fontSize=18, textColor=TEXT_PRIMARY, spaceAfter=10))
    ss.add(ParagraphStyle(name="H3", fontName="Helvetica-Bold", fontSize=14, textColor=ACCENT_BLUE, spaceBefore=10,
                          spaceAfter=6))
    ss.add(ParagraphStyle(name="Label", fontName="Helvetica-Bold", fontSize=8, textColor=TEXT_MUTED, leading=10))
    ss.add(ParagraphStyle(name="Body", fontName="Helvetica", fontSize=9, textColor=TEXT_PRIMARY, leading=12))
    ss.add(ParagraphStyle(name="BodySmall", fontName="Helvetica", fontSize=8, textColor=TEXT_MUTED, leading=10))
    return ss


def _draw_header_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(TEXT_MUTED)
    canvas.drawString(15 * mm, 10 * mm, "DIDEPTES Security Report - Confidential")
    canvas.drawRightString(A4[0] - 15 * mm, 10 * mm, f"Page {canvas.getPageNumber()}")
    canvas.restoreState()


def _create_finding_card(it, styles):
    """Creates a modern card for each finding with auto-adjusting heights."""
    sev = sev_bucket(it.get("severity_score", 0))

    # Build rows - keeping existing structure intact
    title = sanitize_html_for_pdf(it.get("type", "Security Finding")).replace('_', ' ').title()

    rows = [
        ["URL", Paragraph(sanitize_html_for_pdf(it.get("url")), styles["Body"])],
        ["Param", Paragraph(sanitize_html_for_pdf(it.get("param")), styles["Body"])],
        ["Payload", Paragraph(sanitize_html_for_pdf(it.get("payload")), styles["Body"])],
        ["Evidence", Paragraph(sanitize_html_for_pdf(it.get("evidence")), styles["Body"])],
    ]

    # CWE IDs
    cwe_text = ", ".join(it.get("cwe_ids", [])[:2]) if it.get("cwe_ids") else "-"
    rows.append(["CWE ID", Paragraph(sanitize_html_for_pdf(cwe_text), styles["Body"])])

    # References
    refs = it.get("references", [])
    ref_links = []
    for ref in refs[:2]:
        ref_url = ref.get("url", "")
        if ref_url:
            ref_links.append(f'<a href="{ref_url}">{ref_url}</a>')
    ref_text = ", ".join(ref_links) if ref_links else "-"
    rows.append(["References", Paragraph(ref_text, styles["Body"])])

    # Recommendation
    rows.append(["Recommendation",
                 Paragraph(sanitize_html_for_pdf(it.get("recommendation")) or "Follow OWASP best practices.",
                           styles["Body"])])

    # AI Analysis Section - keeping existing structure
    if it.get("ai_analysis"):
        ai = it.get("ai_analysis")
        rows.append(["AI Analysis", ""])  # Section header

        if ai.get("vulnerability_explanation"):
            rows.append(["Vulnerability Explanation",
                         Paragraph(sanitize_html_for_pdf(ai.get("vulnerability_explanation")),
                                   styles["Body"])])

        if ai.get("attack_scenario"):
            rows.append(["Attack Scenario",
                         Paragraph(sanitize_html_for_pdf(ai.get("attack_scenario")), styles["Body"])])

        if ai.get("impact"):
            rows.append(["Impact",
                         Paragraph(sanitize_html_for_pdf(ai.get("impact")), styles["Body"])])

        if ai.get("mitigation_steps"):
            steps = ", ".join(ai.get("mitigation_steps", [])[:3])
            rows.append(["Mitigation Steps",
                         Paragraph(sanitize_html_for_pdf(steps), styles["Body"])])

        if ai.get("code_mitigation"):
            rows.append(["Code Mitigation Example",
                         Paragraph(sanitize_code_for_pdf(ai.get("code_mitigation")), styles["BodySmall"])])

        if ai.get("tools_to_use"):
            tools = ", ".join(ai.get("tools_to_use", [])[:3])
            rows.append(["Recommended Tools",
                         Paragraph(sanitize_html_for_pdf(tools), styles["Body"])])

    # Table styling
    tbl = Table(rows, colWidths=[40 * mm, 140 * mm])
    tbl.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), BG_MAIN),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ('FONTNAME', (0, 0), (0, -1), "Helvetica-Bold"),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('TEXTCOLOR', (0, 0), (0, -1), TEXT_MUTED),
        ('TEXTCOLOR', (1, 0), (1, -1), TEXT_PRIMARY),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LINEBELOW', (0, 0), (-1, -2), 0.2, BORDER_COLOR),
    ]))

    return KeepTogether([
        Pill(sev.upper(), SEV_COLORS[sev]),
        Spacer(1, 2 * mm),
        tbl,
        Spacer(1, 8 * mm)
    ])


def to_pdf(findings: list, generated_at: str, pdf_path: str, title="Security Assessment Report"):
    """Generate a professional PDF report from findings"""

    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=A4,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
        leftMargin=15 * mm,
        rightMargin=15 * mm
    )

    story = []
    styles = _styles()

    total = len(findings)
    by_severity = Counter(sev_bucket(f.get("severity_score", 0)) for f in findings)

    # --- Executive Summary ---
    story.append(Paragraph(title, styles["H2"]))
    story.append(Paragraph(f"Generated on {generated_at}", styles["Label"]))
    story.append(Spacer(1, 10 * mm))

    if total > 0:
        risk_level = "HIGH" if by_severity.get('high', 0) > 0 else (
            "MEDIUM" if by_severity.get('medium', 0) > 0 else "LOW")
        summary_text = f"""
        This automated security assessment identified <b>{total}</b> potential vulnerabilities.
        The overall risk level is assessed as <b>{risk_level}</b>.
        The findings include {by_severity.get('high', 0)} High, {by_severity.get('medium', 0)} Medium, 
        and {by_severity.get('low', 0)} Low risk issues.
        Priority should be given to addressing high-severity issues first, followed by medium and low-severity findings.
        """
    else:
        summary_text = "No significant security vulnerabilities were identified during this automated assessment."

    story.append(Paragraph(summary_text.strip(), styles["Body"]))
    story.append(Spacer(1, 10 * mm))

    # --- Findings ---
    story.append(Paragraph("Detailed Findings", styles["H2"]))
    story.append(Spacer(1, 5 * mm))

    if not findings:
        story.append(Paragraph("No vulnerabilities were found.", styles["Body"]))
    else:
        by_category = defaultdict(list)
        for f in findings:
            cat = f.get("type", "general").split(":")[0]
            by_category[cat].append(f)

        for category, items in by_category.items():
            story.append(Paragraph(f"{category.replace('_', ' ').title()} ({len(items)})", styles["H3"]))
            story.append(Spacer(1, 3 * mm))

            # Sort by severity
            items.sort(key=lambda x: -x.get("severity_score", 0))

            for it in items:
                story.append(_create_finding_card(it, styles))

    # --- Methodology ---
    story.append(PageBreak())
    story.append(Paragraph("Methodology", styles["H2"]))
    story.append(Spacer(1, 4 * mm))

    methodology_text = """
    This assessment was conducted using an automated web application security scanner that performs:

    • <b>Passive Analysis:</b> Security header analysis, cookie security assessment, CORS policy review
    • <b>Active Testing:</b> SQL injection, Cross-Site Scripting (XSS), Local File Inclusion (LFI) testing
    • <b>Authentication Testing:</b> Session management analysis, authentication bypass attempts
    • <b>Configuration Review:</b> CSRF protection analysis, server misconfiguration detection

    All tests were performed with rate limiting to minimize impact on the target application.
    Results should be manually verified before remediation efforts begin.
    """

    story.append(Paragraph(methodology_text.strip(), styles["Body"]))

    doc.build(story, onFirstPage=_draw_header_footer, onLaterPages=_draw_header_footer)
    print(f"✅ Professional PDF generated at: {pdf_path}")
