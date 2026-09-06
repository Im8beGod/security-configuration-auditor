"""Explicit production job-handler registrations."""

from app.jobs.handlers.audit import AuditJobHandler
from app.jobs.handlers.system_noop import handle_system_noop

__all__ = ["AuditJobHandler", "handle_system_noop"]
