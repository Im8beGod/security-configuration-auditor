"""Explicit production job-handler registrations."""

from app.jobs.handlers.audit import AuditJobHandler
from app.jobs.handlers.system_noop import handle_system_noop
from app.jobs.handlers.pdf_generation import handle_pdf_generation

__all__ = ["AuditJobHandler", "handle_pdf_generation", "handle_system_noop"]
