from types import SimpleNamespace

from app.findings.service import MAX_EXCERPT_BYTES, _excerpt
from app.ingestion.storage import ArtifactStorageError


class Storage:
    def __init__(self, data=None, fail=False): self.data, self.fail = data, fail
    def read_prefix(self, _reference, maximum):
        assert maximum == MAX_EXCERPT_BYTES
        if self.fail: raise ArtifactStorageError("unavailable")
        return self.data


def test_line_evidence_excerpt_is_exact_and_bounded():
    artifact = SimpleNamespace(storage_reference="safe", encoding="utf-8")
    excerpt, truncated, available = _excerpt(Storage(b"one\ntwo\nthree\n"), artifact, {"start_line": 2, "end_line": 3})
    assert excerpt == "two\nthree"
    assert not truncated and available


def test_excerpt_marks_large_range_and_read_failure_unavailable():
    artifact = SimpleNamespace(storage_reference="safe", encoding="utf-8")
    data = "\n".join(str(item) for item in range(300)).encode()
    excerpt, truncated, available = _excerpt(Storage(data), artifact, {"start_line": 1, "end_line": 300})
    assert truncated and available and len(excerpt.splitlines()) == 200
    assert _excerpt(Storage(fail=True), artifact, {"start_line": 1, "end_line": 1}) == (None, False, False)
