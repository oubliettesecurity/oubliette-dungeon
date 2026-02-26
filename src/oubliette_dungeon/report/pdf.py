"""
Oubliette Dungeon - PDF Report Generator
==========================================
Professional PDF report generation for red team assessments.

Uses fpdf2 for pure-Python, cross-platform PDF generation.
"""

import io
from datetime import datetime
from typing import Optional, Dict, List

try:
    from fpdf import FPDF
except ImportError:
    FPDF = None


def _require_fpdf():
    if FPDF is None:
        raise ImportError(
            "fpdf2 package required for PDF generation. "
            "Install with: pip install fpdf2>=2.8.0"
        )


COLOR_BG_DARK = (17, 24, 39)
COLOR_BG_PANEL = (31, 41, 55)
COLOR_TEXT = (229, 231, 235)
COLOR_TEXT_MUTED = (156, 163, 175)
COLOR_RED = (239, 68, 68)
COLOR_GREEN = (34, 197, 94)
COLOR_CYAN = (34, 211, 238)
COLOR_YELLOW = (234, 179, 8)
COLOR_ORANGE = (249, 115, 22)
COLOR_PURPLE = (168, 85, 247)
COLOR_BLUE = (59, 130, 246)
COLOR_WHITE = (255, 255, 255)


class OubliettePDF(FPDF if FPDF else object):
    """Custom PDF class with Oubliette branding."""

    def __init__(self, report_title="Report", classification="CONFIDENTIAL"):
        _require_fpdf()
        super().__init__()
        self.report_title = report_title
        self.classification = classification
        self.set_auto_page_break(auto=True, margin=20)

    def header(self):
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*COLOR_RED)
        self.cell(0, 5, "OUBLIETTE SECURITY", align="L")
        self.set_text_color(*COLOR_TEXT_MUTED)
        self.cell(0, 5, self.classification, align="R", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*COLOR_RED)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(3)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(*COLOR_TEXT_MUTED)
        self.cell(0, 5, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", align="L")
        self.cell(0, 5, f"Page {self.page_no()}/{{nb}}", align="R")

    def add_cover_page(self, report_type, date_range=None):
        self.add_page()
        self.ln(40)
        self.set_font("Helvetica", "B", 28)
        self.set_text_color(*COLOR_RED)
        self.cell(0, 15, "OUBLIETTE SECURITY", align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(5)
        self.set_font("Helvetica", "", 16)
        self.set_text_color(*COLOR_WHITE)
        self.cell(0, 10, report_type, align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(10)
        self.set_font("Helvetica", "", 11)
        self.set_text_color(*COLOR_TEXT_MUTED)
        if date_range:
            self.cell(0, 8, f"Period: {date_range}", align="C", new_x="LMARGIN", new_y="NEXT")
        self.cell(0, 8, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", align="C", new_x="LMARGIN", new_y="NEXT")
        self.cell(0, 8, f"Classification: {self.classification}", align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(30)
        self.set_draw_color(*COLOR_RED)
        self.line(60, self.get_y(), 150, self.get_y())

    def section_header(self, title, color=None):
        color = color or COLOR_CYAN
        self.ln(5)
        self.set_font("Helvetica", "B", 13)
        self.set_text_color(*color)
        self.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*color)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(3)

    def stat_row(self, label, value, value_color=None):
        value_color = value_color or COLOR_WHITE
        self.set_font("Helvetica", "", 10)
        self.set_text_color(*COLOR_TEXT_MUTED)
        self.cell(80, 6, label)
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*value_color)
        self.cell(0, 6, str(value), new_x="LMARGIN", new_y="NEXT")

    def table_header(self, columns, widths):
        self.set_font("Helvetica", "B", 8)
        self.set_fill_color(31, 41, 55)
        self.set_text_color(*COLOR_CYAN)
        for col, w in zip(columns, widths):
            self.cell(w, 7, col, border=1, fill=True)
        self.ln()

    def table_row(self, cells, widths, highlight=False):
        self.set_font("Helvetica", "", 8)
        if highlight:
            self.set_fill_color(55, 20, 20)
        else:
            self.set_fill_color(255, 255, 255)
        self.set_text_color(0, 0, 0)
        for cell, w in zip(cells, widths):
            self.cell(w, 6, str(cell)[:40], border=1, fill=highlight)
        self.ln()

    def bar_chart(self, data, title="", max_width=120, bar_height=8):
        if not data:
            return
        if title:
            self.set_font("Helvetica", "B", 9)
            self.set_text_color(*COLOR_TEXT_MUTED)
            self.cell(0, 7, title, new_x="LMARGIN", new_y="NEXT")
        max_val = max(data.values()) if data.values() else 1
        colors = [COLOR_GREEN, COLOR_CYAN, COLOR_BLUE, COLOR_PURPLE, COLOR_YELLOW, COLOR_ORANGE, COLOR_RED]
        for i, (label, value) in enumerate(data.items()):
            color = colors[i % len(colors)]
            bar_w = (value / max_val) * max_width if max_val > 0 else 0
            self.set_font("Helvetica", "", 7)
            self.set_text_color(0, 0, 0)
            self.cell(45, bar_height, str(label)[:20])
            x = self.get_x()
            y = self.get_y()
            self.set_fill_color(*color)
            self.rect(x, y + 1, bar_w, bar_height - 2, "F")
            self.set_x(x + bar_w + 2)
            self.set_text_color(*color)
            self.cell(20, bar_height, str(value))
            self.ln()


class ReportGenerator:
    """Generate PDF reports for red team assessments."""

    def red_team_report(self, session_id=None, stats=None, results=None):
        _require_fpdf()

        if stats is None or results is None:
            from oubliette_dungeon.storage import RedTeamResultsDB
            import os
            db = RedTeamResultsDB(os.getenv("DUNGEON_DB_DIR", "redteam_results"))
            if stats is None:
                stats = db.get_statistics(session_id)
            if results is None:
                session_data = db.get_session(session_id) if session_id else db.get_latest_session()
                results = session_data.get("results", []) if session_data else []

        if "error" in stats:
            stats = {"total_tests": 0, "detection_rate": 0, "bypass_rate": 0,
                     "avg_confidence": 0, "by_result": {}, "by_category": {},
                     "by_difficulty": {}, "session_id": session_id or "N/A"}

        pdf = OubliettePDF("Red Team Assessment Report")
        pdf.alias_nb_pages()

        pdf.add_cover_page("Red Team Assessment Report")

        pdf.add_page()
        pdf.section_header("Executive Summary")

        detection_rate = stats.get("detection_rate", 0)
        bypass_rate = stats.get("bypass_rate", 0)

        if detection_rate >= 90:
            risk_level, risk_color = "LOW", COLOR_GREEN
        elif detection_rate >= 70:
            risk_level, risk_color = "MEDIUM", COLOR_YELLOW
        elif detection_rate >= 50:
            risk_level, risk_color = "HIGH", COLOR_ORANGE
        else:
            risk_level, risk_color = "CRITICAL", COLOR_RED

        pdf.stat_row("Session ID", stats.get("session_id", "N/A"))
        pdf.stat_row("Total Scenarios Tested", stats.get("total_tests", 0), COLOR_CYAN)
        pdf.stat_row("Detection Rate", f"{detection_rate:.1f}%",
                      COLOR_GREEN if detection_rate >= 80 else COLOR_RED)
        pdf.stat_row("Bypass Rate", f"{bypass_rate:.1f}%",
                      COLOR_RED if bypass_rate > 10 else COLOR_GREEN)
        pdf.stat_row("Average Confidence", f"{stats.get('avg_confidence', 0):.1%}", COLOR_CYAN)
        pdf.stat_row("Risk Level", risk_level, risk_color)

        pdf.section_header("Results by Outcome", COLOR_PURPLE)
        by_result = stats.get("by_result", {})
        if by_result:
            pdf.bar_chart(by_result, "Outcome Distribution")

        pdf.section_header("Results by Category", COLOR_BLUE)
        by_category = stats.get("by_category", {})
        if by_category:
            pdf.bar_chart(by_category, "Category Distribution")

        pdf.section_header("Results by Difficulty", COLOR_YELLOW)
        by_difficulty = stats.get("by_difficulty", {})
        if by_difficulty:
            pdf.bar_chart(by_difficulty, "Difficulty Distribution")

        if results:
            pdf.add_page()
            pdf.section_header("Detailed Scenario Results")
            cols = ["ID", "Name", "Category", "Difficulty", "Result", "Confidence"]
            widths = [18, 55, 30, 25, 25, 25]
            pdf.table_header(cols, widths)
            for r in results:
                is_bypass = r.get("result", "") == "bypass"
                row = [
                    r.get("scenario_id", ""),
                    r.get("scenario_name", r.get("name", ""))[:25],
                    r.get("category", ""),
                    r.get("difficulty", ""),
                    r.get("result", ""),
                    f"{r.get('confidence', 0):.0%}" if isinstance(r.get("confidence"), (int, float)) else str(r.get("confidence", "")),
                ]
                pdf.table_row(row, widths, highlight=is_bypass)

        bypassed = [r for r in (results or []) if r.get("result") == "bypass"]
        if bypassed:
            pdf.add_page()
            pdf.section_header("Critical Findings - Bypassed Scenarios", COLOR_RED)
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*COLOR_TEXT_MUTED)
            pdf.multi_cell(0, 5,
                "The following attack scenarios successfully bypassed detection. "
                "These represent the highest-priority areas for security improvement."
            )
            pdf.ln(3)
            for r in bypassed:
                pdf.set_font("Helvetica", "B", 9)
                pdf.set_text_color(*COLOR_RED)
                sid = r.get("scenario_id", "?")
                name = r.get("scenario_name", r.get("name", "Unknown"))
                pdf.cell(0, 6, f"{sid}: {name}", new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Helvetica", "", 8)
                pdf.set_text_color(0, 0, 0)
                pdf.cell(0, 5, f"  Category: {r.get('category', 'N/A')} | Difficulty: {r.get('difficulty', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
                pdf.ln(2)

        pdf.add_page()
        pdf.section_header("Recommendations")
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(0, 0, 0)

        recs = []
        if bypass_rate > 20:
            recs.append("CRITICAL: High bypass rate indicates significant detection gaps. Review pre-filter rules and ML model retraining.")
        if bypass_rate > 0:
            recs.append("Review all bypassed scenarios and add specific detection rules for their attack patterns.")
        if stats.get("total_tests", 0) < 20:
            recs.append("Expand test coverage: run more scenarios for comprehensive assessment.")
        recs.append("Schedule regular automated red team runs to track detection improvements over time.")
        recs.append("Export results as STIX bundle for integration with external threat intelligence platforms.")

        for i, rec in enumerate(recs, 1):
            pdf.multi_cell(0, 5, f"{i}. {rec}")
            pdf.ln(2)

        return bytes(pdf.output())
