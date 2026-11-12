"""Smoke tests for the baseline-gated checks. Run: python test_apex.py"""
from unittest.mock import MagicMock
from apex.checks import check_auth_bypass, check_jwt_weak_secret, check_broken_function_auth, check_broken_object_auth


def test_auth_bypass_skips_when_endpoint_is_already_public():
    session = MagicMock()
    baseline = MagicMock(status_code=200)
    assert check_auth_bypass(session, "http://x/api", baseline) == []


def test_auth_bypass_flags_when_bad_token_bypasses_protection():
    session = MagicMock()
    session.get.return_value = MagicMock(status_code=200)
    baseline = MagicMock(status_code=401)
    findings = check_auth_bypass(session, "http://x/api", baseline)
    assert len(findings) == 2


def test_jwt_weak_secret_skips_when_endpoint_is_already_public():
    session = MagicMock()
    baseline = MagicMock(status_code=200)
    assert check_jwt_weak_secret(session, "http://x/api", baseline) == []


def test_broken_object_auth_skips_when_every_id_returns_200():
    session = MagicMock()
    session.get.return_value = MagicMock(status_code=200)
    assert check_broken_object_auth(session, "http://x/api") == []


def test_broken_object_auth_flags_real_idor():
    def fake_get(u, timeout=8):
        return MagicMock(status_code=404 if "999999999" in u else 200)
    session = MagicMock()
    session.get.side_effect = fake_get
    findings = check_broken_object_auth(session, "http://x/api")
    assert len(findings) == 3


def test_broken_function_auth_flags_open_admin_endpoint():
    session = MagicMock()
    session.get.return_value = MagicMock(status_code=200)
    findings = check_broken_function_auth(session, ["http://x/admin"])
    assert findings[0]["vuln"] == "Broken Function Level Authorization"


def test_broken_function_auth_ignores_non_admin_endpoints():
    session = MagicMock()
    session.get.return_value = MagicMock(status_code=200)
    assert check_broken_function_auth(session, ["http://x/users"]) == []


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"PASS: {t.__name__}")
    print(f"\nAll {len(tests)} smoke tests passed.")
