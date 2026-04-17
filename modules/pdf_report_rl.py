from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
import html

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Image as RLImage,
    PageBreak, Table, TableStyle, HRFlowable,
)
from reportlab.platypus.flowables import Flowable
from reportlab.lib.utils import ImageReader
from reportlab.lib import colors
from reportlab.pdfgen import canvas as rl_canvas

# ── Page geometry
_LM = 2.0 * cm
_RM = 2.0 * cm
_TM = 2.4 * cm
_BM = 2.0 * cm
_PAGE_W = A4[0] - _LM - _RM

# ── Colour palette
C_BG       = colors.HexColor("#0a0d12")
C_SURFACE  = colors.HexColor("#111620")
C_SURFACE2 = colors.HexColor("#181f2e")
C_BORDER   = colors.HexColor("#1e2a3a")
C_TEXT     = colors.HexColor("#e2e8f0")
C_MUTED    = colors.HexColor("#64748b")
C_ACCENT   = colors.HexColor("#38bdf8")
C_LOW      = colors.HexColor("#22c55e")
C_MED      = colors.HexColor("#f59e0b")
C_HIGH     = colors.HexColor("#ef4444")


def _level_color(level: str) -> colors.Color:
    l = (level or "").lower()
    if l == "high":   return C_HIGH
    if l == "medium": return C_MED
    return C_LOW


def _verdict_color(verdict: str) -> colors.Color:
    v = (verdict or "").lower()
    if v == "malicious":  return C_HIGH
    if v == "suspicious": return C_MED
    if v in ("harmless", "clean"): return C_LOW
    return C_MUTED


# ── Page header/footer callback
class _PageTemplate:
    def __init__(self, risk_level: str, risk_score: int, timestamp: str):
        self.risk_level = risk_level
        self.risk_score = risk_score
        self.timestamp  = timestamp

    def __call__(self, canv: rl_canvas.Canvas, doc) -> None:
        canv.saveState()
        w, h = A4

        # ── Full page dark background
        canv.setFillColor(C_BG)
        canv.rect(0, 0, w, h, fill=1, stroke=0)

        # Header bar
        canv.setFillColor(C_SURFACE)
        canv.rect(0, h - 36, w, 36, fill=1, stroke=0)
        canv.setFillColor(C_ACCENT)
        canv.rect(0, h - 36, 4, 36, fill=1, stroke=0)
        canv.setFont("Courier-Bold", 11)
        canv.setFillColor(C_ACCENT)
        canv.drawString(_LM + 4, h - 23, "ImageAware+")
        canv.setFont("Courier", 8)
        canv.setFillColor(C_MUTED)
        canv.drawString(_LM + 90, h - 23, "Phishing Detection Engine")
        canv.drawRightString(w - _RM, h - 23, (self.timestamp[:19] or "") + " UTC")
        canv.setStrokeColor(C_BORDER)
        canv.setLineWidth(0.5)
        canv.line(0, h - 37, w, h - 37)

        # Footer bar
        canv.setFillColor(C_SURFACE)
        canv.rect(0, 0, w, 28, fill=1, stroke=0)
        canv.setStrokeColor(C_BORDER)
        canv.line(0, 28, w, 28)
        canv.setFont("Courier", 8)
        canv.setFillColor(C_MUTED)
        canv.drawString(_LM, 10, "CONFIDENTIAL — ImageAware+ Forensic Analysis Report")
        canv.drawRightString(w - _RM, 10, f"Page {doc.page}")
        canv.restoreState()


# ── Custom flowables
class SectionHeader(Flowable):
    def __init__(self, title: str, width: float = _PAGE_W):
        Flowable.__init__(self)
        self.title   = title
        self._width  = width
        self._height = 24

    def draw(self):
        c = self.canv
        c.setFillColor(C_SURFACE2)
        c.roundRect(0, 0, self._width, self._height, 3, fill=1, stroke=0)
        c.setFillColor(C_ACCENT)
        c.roundRect(0, 0, 3, self._height, 1, fill=1, stroke=0)
        c.setFont("Courier-Bold", 9)
        c.setFillColor(C_ACCENT)
        c.drawString(12, 8, self.title.upper())

    def wrap(self, *args):
        return self._width, self._height


class VerdictBlock(Flowable):
    def __init__(self, score: int, level: str, width: float = _PAGE_W):
        Flowable.__init__(self)
        self.score  = score
        self.level  = level
        self._width = width
        self._height = 72
        self._color = _level_color(level)

    def draw(self):
        c   = self.canv
        w   = self._width
        h   = self._height
        col = self._color

        c.setFillColor(C_SURFACE)
        c.roundRect(0, 0, w, h, 6, fill=1, stroke=0)
        c.setFillColor(col)
        c.roundRect(0, 0, 6, h, 3, fill=1, stroke=0)

        c.setFont("Courier-Bold", 42)
        c.setFillColor(col)
        c.drawString(22, 18, str(self.score))

        score_w = c.stringWidth(str(self.score), "Courier-Bold", 42)
        c.setFont("Courier", 12)
        c.setFillColor(C_MUTED)
        c.drawString(22 + score_w + 2, 28, "/100")

        c.setFont("Courier-Bold", 18)
        c.setFillColor(C_TEXT)
        c.drawString(22 + score_w + 50, 36, f"{self.level.upper()} RISK")

        badge_text = f"{self.level.upper()} RISK"
        badge_w = c.stringWidth(badge_text, "Courier-Bold", 9) + 24
        bx = w - badge_w - 12
        by = h // 2 - 9
        c.setStrokeColor(col)
        c.setLineWidth(1)
        c.roundRect(bx, by, badge_w, 18, 4, fill=0, stroke=1)
        c.setFont("Courier-Bold", 9)
        c.setFillColor(col)
        c.drawString(bx + 8, by + 5, badge_text)

        bar_x = 22
        bar_y = 10
        bar_w = w - 200
        bar_h = 4
        c.setFillColor(C_BORDER)
        c.roundRect(bar_x, bar_y, bar_w, bar_h, 2, fill=1, stroke=0)
        fill_w = max(4, bar_w * self.score / 100)
        c.setFillColor(col)
        c.roundRect(bar_x, bar_y, fill_w, bar_h, 2, fill=1, stroke=0)

    def wrap(self, *args):
        return self._width, self._height


class ContribBar(Flowable):
    def __init__(self, contrib: float, max_val: float = 30,
                 width: float = 80, height: float = 14):
        Flowable.__init__(self)
        self.contrib = contrib
        self.max_val = max_val
        self._width  = width
        self._height = height

    def draw(self):
        c    = self.canv
        bw   = self._width * 0.65
        fill = max(4, bw * min(self.contrib / self.max_val, 1.0))
        c.setFillColor(C_BORDER)
        c.roundRect(0, 4, bw, 4, 2, fill=1, stroke=0)
        c.setFillColor(C_ACCENT)
        c.roundRect(0, 4, fill, 4, 2, fill=1, stroke=0)
        c.setFont("Courier-Bold", 8)
        c.setFillColor(C_ACCENT)
        c.drawString(bw + 5, 2, f"+{self.contrib:.0f}")

    def wrap(self, *args):
        return self._width, self._height


# ── Styles
def _styles() -> Dict[str, ParagraphStyle]:
    body = ParagraphStyle("IABody",
        fontName="Helvetica", fontSize=9, leading=13,
        textColor=C_TEXT, spaceAfter=3,
    )
    mono = ParagraphStyle("IAMono",
        fontName="Courier", fontSize=8, leading=11,
        textColor=C_TEXT,
    )
    muted = ParagraphStyle("IAMuted",
        fontName="Courier", fontSize=8, leading=11,
        textColor=C_MUTED,
    )
    label = ParagraphStyle("IALabel",
        fontName="Courier-Bold", fontSize=8, leading=10,
        textColor=C_MUTED, spaceAfter=3,
    )
    tag = ParagraphStyle("IATag",
        fontName="Courier", fontSize=8, leading=11,
        textColor=C_ACCENT,
    )
    finding = ParagraphStyle("IAFinding",
        fontName="Helvetica", fontSize=9, leading=13,
        textColor=C_TEXT, leftIndent=8, spaceAfter=3,
    )
    url = ParagraphStyle("IAURL",
        fontName="Courier", fontSize=8, leading=10,
        textColor=C_ACCENT, wordWrap="CJK",
    )
    return dict(body=body, mono=mono, muted=muted,
                label=label, tag=tag, finding=finding, url=url)


def _table_style() -> TableStyle:
    return TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0),  C_SURFACE2),
        ("TEXTCOLOR",      (0, 0), (-1, 0),  C_MUTED),
        ("FONTNAME",       (0, 0), (-1, 0),  "Courier-Bold"),
        ("FONTSIZE",       (0, 0), (-1, 0),  8),
        ("TEXTCOLOR",      (0, 1), (-1, -1), C_TEXT),
        ("FONTNAME",       (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE",       (0, 1), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_SURFACE, C_SURFACE2]),
        ("LINEBELOW",      (0, 0), (-1, -1), 0.3, C_BORDER),
        ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",     (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 6),
        ("LEFTPADDING",    (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",   (0, 0), (-1, -1), 8),
    ])


def _kv_table_style() -> TableStyle:
    return TableStyle([
        ("FONTNAME",       (0, 0), (0, -1), "Courier-Bold"),
        ("FONTSIZE",       (0, 0), (-1,-1), 8),
        ("TEXTCOLOR",      (0, 0), (0, -1), C_MUTED),
        ("TEXTCOLOR",      (1, 0), (1, -1), C_TEXT),
        ("FONTNAME",       (1, 0), (1, -1), "Courier"),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_SURFACE, C_SURFACE2]),
        ("LINEBELOW",      (0, 0), (-1, -1), 0.3, C_BORDER),
        ("TOPPADDING",     (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 5),
        ("LEFTPADDING",    (0, 0), (-1, -1), 8),
        ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
    ])


# ── Main export
def export_pdf_from_report_json(
    report_json_path: str | Path,
    pdf_out_path: Optional[str | Path] = None,
) -> str:

    report_json_path = Path(report_json_path)
    if not report_json_path.exists():
        raise FileNotFoundError(f"Report JSON not found: {report_json_path}")

    report: Dict[str, Any] = json.loads(
        report_json_path.read_text(encoding="utf-8")
    )
    out_dir = report_json_path.parent

    if pdf_out_path is None:
        pdf_out_path = out_dir / (
            report_json_path.stem.replace("_report", "") + "_report.pdf"
        )
    pdf_out_path = Path(pdf_out_path)

    meta           = report.get("meta", {})
    ocr            = report.get("ocr", {})
    qr_data        = report.get("qr", {})
    risk           = report.get("risk", {})
    ti             = report.get("threat_intel", [])
    artifacts      = report.get("artifacts", {})
    email_data     = report.get("email")
    email_analysis = report.get("email_analysis")

    risk_score = int(risk.get("score", 0))
    risk_level = str(risk.get("level", "Low"))
    timestamp  = str(meta.get("timestamp_utc", ""))

    S  = _styles()
    kw = [_PAGE_W * 0.22, _PAGE_W * 0.78]   # key-value column widths

    page_cb = _PageTemplate(risk_level, risk_score, timestamp)

    doc = SimpleDocTemplate(
        str(pdf_out_path),
        pagesize=A4,
        leftMargin=_LM, rightMargin=_RM,
        topMargin=_TM + 10, bottomMargin=_BM + 14,
        title="ImageAware+ Forensic Analysis Report",
        author="ImageAware+",
    )

    story: List = []

    def gap(h: float = 0.3):
        story.append(Spacer(1, h * cm))

    # ═══════════════════════════════════════════════
    # PAGE 1 — Summary
    # ═══════════════════════════════════════════════

    story.append(VerdictBlock(risk_score, risk_level))
    gap(0.4)

    # Key Findings
    reasons = risk.get("reasons", [])
    if reasons:
        story.append(SectionHeader("Key Findings"))
        gap(0.15)
        for r in reasons:
            story.append(Paragraph(
                f"<font color='#38bdf8'>▸</font>  {html.escape(str(r))}",
                S["finding"],
            ))
        gap(0.3)

    # Score Breakdown
    breakdown = risk.get("breakdown", {})
    active = [(k, v) for k, v in breakdown.items()
              if v.get("contribution", 0) > 0]

    if active:
        story.append(SectionHeader("Detection Score Breakdown"))
        gap(0.15)
        cw = [_PAGE_W * 0.52, _PAGE_W * 0.10, _PAGE_W * 0.38]
        tdata = [["INDICATOR", "HITS", "CONTRIBUTION"]]
        for _, item in active:
            tdata.append([
                Paragraph(html.escape(str(item.get("label", ""))), S["body"]),
                Paragraph(str(item.get("value", "")), S["muted"]),
                ContribBar(float(item.get("contribution", 0))),
            ])
        t = Table(tdata, colWidths=cw, repeatRows=1)
        t.setStyle(_table_style())
        story.append(t)
        gap(0.4)

    # Indicator Evidence
    evidence = [(k, v) for k, v in breakdown.items() if v.get("indicators")]
    if evidence:
        story.append(SectionHeader("Indicator Evidence"))
        gap(0.15)
        for _, item in evidence:
            inds = item.get("indicators", [])
            if not inds:
                continue
            story.append(Paragraph(html.escape(str(item.get("label", ""))), S["label"]))
            line = "   ".join(f"[{html.escape(str(i))}]" for i in inds)
            story.append(Paragraph(line, S["tag"]))
            gap(0.12)
        gap(0.2)

    # Metadata
    story.append(SectionHeader("Analysis Metadata"))
    gap(0.15)
    image_name = Path(str(meta.get("image", ""))).name
    meta_rows = [
        ["FILE",          html.escape(image_name)],
        ["TIMESTAMP",     html.escape(timestamp[:26])],
        ["OCR METHOD",    html.escape(str(ocr.get("method", "N/A")))],
        ["OCR WORDS",     f"{ocr.get('kept_words', 0)} kept / {ocr.get('total_words', 0)} total"],
        ["QR FOUND",      "Yes" if qr_data.get("found") else "No"],
        ["URLS FOUND",    str(len(ocr.get("extracted_urls", [])))],
    ]
    t2 = Table(meta_rows, colWidths=kw)
    t2.setStyle(_kv_table_style())
    story.append(t2)
    gap(0.4)

    # ═══════════════════════════════════════════════
    # PAGE 2 — TI + Email + URLs
    # ═══════════════════════════════════════════════
    story.append(PageBreak())

    # Threat Intelligence
    story.append(SectionHeader(f"Threat Intelligence  ({len(ti)} URL{'s' if len(ti) != 1 else ''} Checked)"))
    gap(0.15)

    if ti:
        cw3 = [_PAGE_W * 0.55, _PAGE_W * 0.17, _PAGE_W * 0.14, _PAGE_W * 0.14]
        ti_rows = [["URL", "VERDICT", "MALICIOUS", "SUSPICIOUS"]]
        for item in ti:
            verdict  = str(item.get("verdict", "N/A")).upper()
            vcol_hex = _verdict_color(item.get("verdict", "")).hexval()
            ti_rows.append([
                Paragraph(html.escape(str(item.get("url", ""))), S["url"]),
                Paragraph(f"<font color='{vcol_hex}'>{verdict}</font>", S["mono"]),
                Paragraph(str(item.get("vt_malicious", 0)), S["muted"]),
                Paragraph(str(item.get("vt_suspicious", 0)), S["muted"]),
            ])
        t3 = Table(ti_rows, colWidths=cw3, repeatRows=1)
        t3.setStyle(_table_style())
        story.append(t3)
    else:
        story.append(Paragraph(
            "No URLs were submitted to threat intelligence services.", S["muted"]
        ))
    gap(0.4)

    # OCR URLs
    ocr_urls = ocr.get("extracted_urls", [])
    if ocr_urls:
        story.append(SectionHeader(f"OCR-Extracted URLs  ({len(ocr_urls)} Found)"))
        gap(0.15)
        for u in ocr_urls:
            story.append(Paragraph(
                f"<font color='#38bdf8'>→</font>  {html.escape(str(u))}", S["mono"]
            ))
            gap(0.05)
        gap(0.3)

    # QR
    story.append(SectionHeader("QR Code Analysis"))
    gap(0.15)
    if qr_data.get("found"):
        story.append(Paragraph(
            f"<font color='#ef4444'>QR code detected.</font>  "
            f"Data: {html.escape(str(qr_data.get('data', '')))}",
            S["body"],
        ))
    else:
        story.append(Paragraph("No QR code detected in the image.", S["muted"]))
    gap(0.4)

    # Email Analysis
    if email_analysis:
        story.append(SectionHeader("Email Security Analysis"))
        gap(0.15)

        ea_rows = []
        if email_data:
            for f in ("subject", "from", "to", "date"):
                val = str(email_data.get(f, "") or "")
                if val and val != "None":
                    ea_rows.append([f.upper(), html.escape(val)])
        ea_rows.append(["SENDER DOMAIN",
                         html.escape(str(email_analysis.get("sender_domain", "—")))])
        if email_analysis.get("reply_domain"):
            ea_rows.append(["REPLY-TO",
                             html.escape(str(email_analysis["reply_domain"]))])
        ea_rows.append(["EMAIL SCORE", str(email_analysis.get("score", 0))])

        if ea_rows:
            t_ea = Table(ea_rows, colWidths=kw)
            t_ea.setStyle(_kv_table_style())
            story.append(t_ea)
            gap(0.2)

        indicators   = email_analysis.get("indicators", [])
        auth_results = email_analysis.get("auth_results", [])

        if indicators:
            story.append(Paragraph("EMAIL INDICATORS", S["label"]))
            for ind in indicators:
                story.append(Paragraph(
                    f"<font color='#ef4444'>▸</font>  {html.escape(str(ind))}",
                    S["finding"],
                ))
            gap(0.15)

        if auth_results:
            story.append(Paragraph("AUTHENTICATION (SPF / DKIM / DMARC)", S["label"]))
            for a in auth_results:
                story.append(Paragraph(
                    f"<font color='#f59e0b'>▸</font>  {html.escape(str(a))}",
                    S["finding"],
                ))
            gap(0.15)

    # ═══════════════════════════════════════════════
    # PAGE 3 — Evidence image
    # ═══════════════════════════════════════════════
    annotated_path = artifacts.get("annotated_image") or qr_data.get("annotated_image")

    if annotated_path:
        img_path = Path(annotated_path)
        if not img_path.is_absolute():
            img_path = (out_dir / img_path).resolve()

        if img_path.exists():
            story.append(PageBreak())
            story.append(SectionHeader("Evidence Image (Annotated)"))
            gap(0.3)

            try:
                ir  = ImageReader(str(img_path))
                iw, ih = ir.getSize()
                if iw > 0 and ih > 0:
                    scale = min(_PAGE_W / float(iw), (A4[1] * 0.72) / float(ih))
                    story.append(RLImage(str(img_path),
                                         width=iw * scale, height=ih * scale))
                else:
                    story.append(Paragraph(
                        "Evidence image could not be rendered (zero dimensions).",
                        S["muted"],
                    ))
            except Exception as e:
                story.append(Paragraph(
                    f"Evidence image error: {html.escape(str(e))}", S["muted"]
                ))

    doc.build(story, onFirstPage=page_cb, onLaterPages=page_cb)
    return str(pdf_out_path)