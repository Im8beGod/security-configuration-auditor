from io import BytesIO
from typing import Any
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def build_device_compliance_pdf(document: dict[str, Any]) -> bytes:
    """Render display-only persisted report data; no markup is interpreted."""
    stream = BytesIO(); styles = getSampleStyleSheet()
    story = [Paragraph("Device Compliance Report", styles["Title"]), Spacer(1, 12)]
    def text(value: Any) -> str:
        return str(value if value is not None else "Not available").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    audit, device = document["audit"], document["device"]
    rows = [["Device", text(device.get("display_name"))], ["Audit", text(audit.get("audit_id"))], ["Revision", text(audit.get("revision_number"))], ["Status", text(audit.get("status"))], ["Pinned profile", text(audit.get("profile"))]]
    table = Table(rows, colWidths=[110, 350]); table.setStyle(TableStyle([("GRID", (0,0), (-1,-1), .25, colors.grey), ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#e9eef2")), ("VALIGN", (0,0), (-1,-1), "TOP")]))
    story += [table, Spacer(1, 12), Paragraph("Persisted summaries", styles["Heading2"]), Paragraph(text({"verdicts": audit.get("verdict_counts"), "severities": audit.get("severity_counts"), "coverage": audit.get("coverage")}), styles["BodyText"]), PageBreak(), Paragraph("Findings", styles["Heading1"])]
    for finding in document["findings"]:
        story += [Paragraph(text(finding["title"]), styles["Heading2"]), Paragraph(text({key: finding.get(key) for key in ("verdict", "severity", "expected_state", "observed_state", "explanation", "affected_scope", "framework_references", "evidence_refs")}), styles["BodyText"])]
        remediation = finding.get("remediation")
        story.append(Paragraph("Remediation: " + text(remediation), styles["BodyText"])); story.append(Spacer(1, 8))
    SimpleDocTemplate(stream, pagesize=A4, title="Device Compliance Report", author="SIH 26155", invariant=True).build(story)
    return stream.getvalue()
