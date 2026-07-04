import io
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from models.investigation import InvestigationCase

class ReportGenerator:
    def generate_pdf(self, case: InvestigationCase, evidence: list, actions: list, mitre: list) -> bytes:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []

        elements.append(Paragraph(f"SOC Investigation Report", styles['Title']))
        elements.append(Paragraph(f"Case: {case.title}", styles['Heading2']))
        elements.append(Spacer(1, 12))

        elements.append(Paragraph("Executive Summary", styles['Heading3']))
        elements.append(Paragraph(case.description or "No summary available.", styles['Normal']))
        elements.append(Spacer(1, 12))

        elements.append(Paragraph("Investigation Details", styles['Heading3']))
        
        c_score = f"{case.confidence_score * 100:.0f}%" if case.confidence_score else "N/A"
        data = [
            ["Status", case.status.value],
            ["Severity", case.severity.value],
            ["Confidence", c_score],
            ["Created At", str(case.created_at)]
        ]
        t = Table(data, colWidths=[100, 300])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 12))

        elements.append(Paragraph("MITRE ATT&CK Mapping", styles['Heading3']))
        if mitre:
            mitre_data = [["Technique ID", "Name", "Tactic"]]
            for m in mitre:
                mitre_data.append([m.technique_id, m.technique_name, m.tactic])
            t_mitre = Table(mitre_data)
            t_mitre.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            elements.append(t_mitre)
        else:
            elements.append(Paragraph("No MITRE mappings found.", styles['Normal']))
        elements.append(Spacer(1, 12))

        doc.build(elements)
        buffer.seek(0)
        return buffer.read()

report_generator = ReportGenerator()
