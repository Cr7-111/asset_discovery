from backend.app.services import ai_service


def test_use_env_proxy_defaults_to_false(monkeypatch):
    monkeypatch.delenv("AI_USE_ENV_PROXY", raising=False)

    assert ai_service._use_env_proxy() is False


def test_use_env_proxy_accepts_true_values(monkeypatch):
    monkeypatch.setenv("AI_USE_ENV_PROXY", "true")

    assert ai_service._use_env_proxy() is True


def test_build_http_session_disables_env_proxy_by_default(monkeypatch):
    monkeypatch.delenv("AI_USE_ENV_PROXY", raising=False)

    session = ai_service._build_http_session()
    try:
        assert session.trust_env is False
    finally:
        session.close()


def test_build_http_session_can_enable_env_proxy(monkeypatch):
    monkeypatch.setenv("AI_USE_ENV_PROXY", "1")

    session = ai_service._build_http_session()
    try:
        assert session.trust_env is True
    finally:
        session.close()
