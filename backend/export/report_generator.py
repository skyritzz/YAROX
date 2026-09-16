import io
from typing import Dict, List
from xml.sax.saxutils import escape

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

from models.investigation import InvestigationReport


def _p(text, style):
    return Paragraph(escape(str(text)) if text is not None else "", style)


class ReportGenerator:
    """
    Renders a persisted InvestigationReport. The PDF contains only data stored in the
    report record and the findings/evidence it references.
    """

    def generate_pdf(
        self,
        report: InvestigationReport,
        findings: List[Dict],
        evidence: Dict[str, Dict],
        compress: bool = True,
    ) -> bytes:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, pageCompression=1 if compress else 0)
        styles = getSampleStyleSheet()
        elements = []

        elements.append(_p("SOC Investigation Report", styles['Title']))
        elements.append(_p(f"Case: {report.title}", styles['Heading2']))
        elements.append(Spacer(1, 12))

        c_score = f"{report.confidence_score * 100:.0f}%" if report.confidence_score is not None else "Not available"
        details = [
            ["Report", f"v{report.version} ({report.status})"],
            ["Generated", report.generated_at.isoformat()],
            ["Severity", report.severity],
            ["Confidence", c_score],
            ["Timeline source", report.timeline_source],
        ]
        t = Table(details, colWidths=[110, 330])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 12))

        elements.append(_p("Executive Summary", styles['Heading3']))
        elements.append(_p(
            report.executive_summary if report.executive_summary else
            "Not available: the SOC Lead did not produce a validated report. Manual review required.",
            styles['Normal'],
        ))
        elements.append(Spacer(1, 12))

        elements.append(_p("Agent Runs", styles['Heading3']))
        for run in report.agent_runs:
            suffix = f" — {run['error']}" if run.get("error") else ""
            elements.append(_p(f"{run['agent']}: {run['status']}{suffix}", styles['Normal']))
        elements.append(Spacer(1, 12))

        elements.append(_p("Findings", styles['Heading3']))
        if findings:
            for f in findings:
                refs = ", ".join(c["evidence_id"][:8] for c in f["evidence"])
                elements.append(_p(f"[{f['agent']} · {f['kind']}] {f['finding']} (evidence: {refs})", styles['Normal']))
        else:
            elements.append(_p("No evidence-backed findings were recorded.", styles['Normal']))
        elements.append(Spacer(1, 12))

        elements.append(_p("Recommendations", styles['Heading3']))
        if report.recommendations:
            for r in report.recommendations:
                refs = ", ".join(e[:8] for e in r["evidence_ids"])
                elements.append(_p(f"{r['action']} (evidence: {refs})", styles['Normal']))
        else:
            elements.append(_p("No evidence-backed recommendations were produced.", styles['Normal']))
        elements.append(Spacer(1, 12))

        elements.append(_p("MITRE ATT&CK Mapping", styles['Heading3']))
        if report.mitre_techniques:
            mitre_data = [["Technique ID", "Name", "Tactic", "Source"]]
            for m in report.mitre_techniques:
                mitre_data.append([m["technique_id"], m["technique_name"], m["tactic"], m["source"]])
            t_mitre = Table(mitre_data)
            t_mitre.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            elements.append(t_mitre)
        else:
            elements.append(_p("No MITRE mappings found.", styles['Normal']))
        elements.append(Spacer(1, 12))

        elements.append(_p("Timeline", styles['Heading3']))
        for entry in report.timeline:
            elements.append(_p(f"{entry.get('time')} — {entry.get('action')}: {entry.get('details') or ''}", styles['Normal']))
        elements.append(Spacer(1, 12))

        elements.append(_p("Evidence Appendix", styles['Heading3']))
        for evidence_id in report.evidence_ids:
            e = evidence.get(evidence_id)
            if not e:
                continue
            elements.append(_p(
                f"{evidence_id} | {e['timestamp']} | {e['source']} | {e['evidence_type']} | "
                f"event {e['event_id'] or 'n/a'} | sha256 {e['event_payload_sha256'] or 'not recorded'}",
                styles['Normal'],
            ))

        doc.build(elements)
        buffer.seek(0)
        return buffer.read()


report_generator = ReportGenerator()
