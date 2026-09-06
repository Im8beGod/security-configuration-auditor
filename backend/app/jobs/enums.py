from enum import Enum


class JobStatus(str, Enum):
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class JobType(str, Enum):
    AUDIT = "audit"
    RE_EVALUATION = "re_evaluation"
    MAPPING_VALIDATION = "mapping_validation"
    PDF_GENERATION = "pdf_generation"
    BULK_REPORT_GENERATION = "bulk_report_generation"
    SYSTEM_NOOP = "system_noop"
