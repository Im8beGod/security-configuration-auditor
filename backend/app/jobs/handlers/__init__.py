"""Explicit production job-handler registrations."""

from app.jobs.handlers.audit import AuditJobHandler
from app.jobs.handlers.reevaluation import handle_reevaluation
from app.jobs.handlers.system_noop import handle_system_noop
from app.jobs.handlers.pdf_generation import handle_pdf_generation
from app.jobs.handlers.mapping_validation import handle_mapping_validation

__all__ = ["AuditJobHandler", "handle_mapping_validation", "handle_pdf_generation", "handle_reevaluation", "handle_system_noop"]
