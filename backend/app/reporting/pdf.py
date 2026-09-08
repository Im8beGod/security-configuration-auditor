from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import LongTable, Paragraph, SimpleDocTemplate, Spacer, TableStyle


MISSING = "Not provided"
UNAVAILABLE = "Unavailable"


def _escape(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br/>")


def _label(value: Any) -> str:
    text = str(value).replace("_", " ").strip()
    return text[:1].upper() + text[1:] if text else text


def format_readable(value: Any, missing: str = MISSING) -> str:
    """Format persisted structured values without exposing Python/JSON syntax."""
    if value is None or value == "" or value == [] or value == {}:
        return _escape(missing)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        return "<br/>".join(format_readable(item) for item in value) or _escape(missing)
    if isinstance(value, dict):
        value_type = value.get("type")
        if value_type == "boolean" and isinstance(value.get("value"), bool):
            return f"{'Enabled' if value['value'] else 'Disabled'} / {format_readable(value['value'])}"
        if value_type == "device":
            return "Device"
        parts = []
        for key in sorted(value, key=str):
            parts.append(f"{_escape(_label(key))}: {format_readable(value[key])}")
        return "; ".join(parts) or _escape(missing)
    return _escape(str(value))


def format_counts(value: Any, *, verdict: bool = False, missing: str = MISSING) -> str:
    if not isinstance(value, dict) or not value:
        return _escape(missing)
    parts = []
    for key in sorted(value, key=str):
        label = str(key).upper() if verdict else _label(key)
        parts.append(f"{_escape(label)}: {format_readable(value[key])}")
    return "<br/>".join(parts)


def format_framework_references(value: Any, missing: str = MISSING) -> str:
    if not isinstance(value, list) or not value:
        return _escape(missing)
    parts = []
    for reference in value:
        if isinstance(reference, dict):
            framework = reference.get("framework")
            control = reference.get("control")
            if framework is not None and control is not None:
                parts.append(f"{_escape(str(framework))} - Control {_escape(str(control))}")
            else:
                parts.append(format_readable(reference))
        else:
            parts.append(format_readable(reference))
    return "<br/>".join(parts)


def build_device_compliance_pdf(document: dict[str, Any]) -> bytes:
    """Render persisted report data as a readable, display-only PDF."""
    stream = BytesIO()
    styles = getSampleStyleSheet()
    body = ParagraphStyle("ReportBody", parent=styles["BodyText"], leading=12, spaceAfter=4, wordWrap="LTR")
    small = ParagraphStyle("ReportSmall", parent=body, fontSize=8.5, leading=10)
    heading = ParagraphStyle("ReportHeading", parent=styles["Heading2"], spaceBefore=10, spaceAfter=6)
    subheading = ParagraphStyle("ReportSubheading", parent=styles["Heading3"], spaceBefore=7, spaceAfter=4)

    def scalar(value: Any, missing: str = MISSING) -> str:
        if value is None or value == "" or value == [] or value == {}:
            return missing
        return format_readable(value, missing)

    def cell(value: Any, style: ParagraphStyle = body) -> Paragraph:
        return Paragraph(str(value), style)

    def labeled_table(rows: list[tuple[str, Any]], widths: tuple[float, float] = (48 * mm, 132 * mm)) -> LongTable:
        table = LongTable([[cell(label, small), cell(value, small)] for label, value in rows], colWidths=list(widths), splitByRow=1)
        table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#aab4bd")),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e9eef2")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        return table

    def evidence_text(refs: Any) -> str:
        if not isinstance(refs, list) or not refs:
            return UNAVAILABLE
        lines = []
        for ref in refs:
            if not isinstance(ref, dict):
                lines.append(format_readable(ref))
                continue
            source = ref.get("path") or ref.get("filename") or ref.get("artifact_id") or MISSING
            start, end = ref.get("start_line"), ref.get("end_line")
            if isinstance(start, int) and isinstance(end, int) and start >= 1 and end >= start:
                location = f"lines {start}-{end}" if start != end else f"line {start}"
            else:
                location = "line range not provided"
            lines.append(f"{_escape(str(source))} ({_escape(location)})")
        return "<br/>".join(lines)

    def remediation_story(remediation: Any) -> list[Any]:
        if not isinstance(remediation, dict):
            return [Paragraph("Reviewed remediation", subheading), Paragraph(UNAVAILABLE, body)]
        status = remediation.get("status")
        if status == "not_required":
            return [Paragraph("Reviewed remediation", subheading), labeled_table([("Status", "Not required for this finding")])]
        if status not in {"applicable", "requires_parameters"}:
            return [Paragraph("Reviewed remediation", subheading), labeled_table([("Status", f"{UNAVAILABLE} ({scalar(remediation.get('reason'), 'reason not provided')})")])]
        steps = remediation.get("ordered_steps")
        if not isinstance(steps, list) or not steps:
            return [Paragraph("Reviewed remediation", subheading), labeled_table([("Status", "Applicable procedure has no ordered steps")])]
        rows = [("Status", scalar(status)), ("Procedure", scalar(remediation.get("title"))), ("Selection", scalar(remediation.get("selection_source")))]
        story = [Paragraph("Reviewed remediation", subheading), labeled_table(rows), Paragraph("Ordered guidance", styles["Heading4"])]
        for index, step in enumerate(steps, 1):
            step_text = step.get("text") if isinstance(step, dict) else None
            story.append(Paragraph(f"{index}. {scalar(step_text, UNAVAILABLE)}", body))
        return story

    audit, device = document["audit"], document["device"]
    identification = document.get("device_identification") or {}
    story: list[Any] = [
        Paragraph("Device Compliance Report", styles["Title"]),
        Spacer(1, 10),
        Paragraph("Audit summary", heading),
        labeled_table([
            ("Device", scalar(device.get("display_name"))),
            ("Audit ID", scalar(audit.get("audit_id"))),
            ("Revision", scalar(audit.get("revision_number"))),
            ("Verdict summary", format_counts(audit.get("verdict_counts"), verdict=True)),
            ("Severity summary", format_counts(audit.get("severity_counts"))),
            ("Pinned profile", scalar(audit.get("profile"))),
            ("Coverage", format_readable(audit.get("coverage"))),
            ("Assessment Pack", format_readable(audit.get("assessment"))),
        ]),
        Paragraph("Device identity", heading),
        labeled_table([
            ("Display name", scalar(identification.get("display_name"))),
            ("Hostname", scalar(identification.get("hostname"))),
            ("Vendor", scalar(identification.get("vendor"))),
            ("Product family", scalar(identification.get("product_family"))),
            ("OS / platform", scalar(identification.get("os"))),
            ("Software version", scalar(identification.get("os_version"))),
            ("Device type / class", scalar(identification.get("device_class"))),
            ("Model", scalar(identification.get("model"))),
            ("Serial number", scalar(identification.get("serial_number"))),
            ("Asset tag", scalar(identification.get("asset_tag"))),
        ]),
        Spacer(1, 12),
        Paragraph("Findings", styles["Heading1"]),
    ]

    for index, finding in enumerate(document.get("findings") or [], 1):
        story.extend([
            Paragraph(f"{index}. {scalar(finding.get('title'))}", heading),
            labeled_table([
                ("Verdict", scalar(finding.get("verdict"))),
                ("Severity", scalar(finding.get("severity"))),
                ("Framework references", format_framework_references(finding.get("framework_references"))),
                ("Source / evidence lines", evidence_text(finding.get("evidence_refs"))),
                ("Expected", format_readable(finding.get("expected_state"))),
                ("Observed", format_readable(finding.get("observed_state"))),
                ("Affected scope", format_readable(finding.get("affected_scope"))),
                ("Explanation", scalar(finding.get("explanation"))),
            ]),
        ])
        story.extend(remediation_story(finding.get("remediation")))
        story.append(Spacer(1, 8))

    if not document.get("findings"):
        story.append(Paragraph("No findings were provided for this audit.", body))

    assessment_results = document.get("assessment_results") or []
    if assessment_results:
        story.append(Paragraph("Assessment pack results", styles["Heading1"]))
        for item in assessment_results:
            story.append(labeled_table([
                ("Obligation", _escape(str(item.get("obligation_key") or MISSING))),
                ("Control", _escape(" ".join(str(value) for value in (item.get("control_id"), item.get("control_title")) if value) or MISSING)),
                ("Assessment mode", scalar(item.get("assessment_method"))),
                ("Implementation", scalar(item.get("implementation_status"))),
                ("Result", scalar(item.get("verdict"), "Manual / unimplemented")),
                ("State / evidence", format_readable((item.get("details") or {}).get("effective_state") or item.get("details"))),
            ]))

    SimpleDocTemplate(
        stream,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title="Device Compliance Report",
        author="SIH 26155",
        invariant=True,
    ).build(story)
    return stream.getvalue()
