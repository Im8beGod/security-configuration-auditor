import importlib.util
from pathlib import Path
import pytest
from app.remediation.service import RemediationError, _value
ROOT=Path(__file__).resolve().parents[3]; s=importlib.util.spec_from_file_location('b10',ROOT/'database/migrations/versions/20260909_0018_seed_multivendor_remediation.py'); B10=importlib.util.module_from_spec(s);s.loader.exec_module(B10)
def test_b10_six_safe_profile_scoped_procedures():
 assert len(B10.ROWS)==6 and len({x[0] for x in B10.ROWS})==6
 for x in B10.ROWS:
  assert x[4] and x[7] and x[8] and x[6]
  assert B10.P[x[2]]
 assert _value({'type':'integer','minimum':1,'maximum':60},'10')=='10'
 with pytest.raises(RemediationError): _value({'type':'integer','minimum':1,'maximum':60},'0')
 with pytest.raises(RemediationError): _value({'type':'enum','values':['0 4']},'0 4;reload')
