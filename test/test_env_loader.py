import os
from pathlib import Path

from backend.app.core.config import load_env_file, load_project_env


def test_load_env_file_reads_key_value_pairs(monkeypatch):
    env_text = "\n".join(
        [
            "# comment",
            "AI_API_KEY=test-key",
            "AI_BASE_URL=https://api.deepseek.com/v1",
            "AI_MODEL='deepseek-chat'",
        ]
    )

    monkeypatch.delenv("AI_API_KEY", raising=False)
    monkeypatch.delenv("AI_BASE_URL", raising=False)
    monkeypatch.delenv("AI_MODEL", raising=False)
    monkeypatch.setattr(Path, "exists", lambda self: True)
    monkeypatch.setattr(Path, "read_text", lambda self, encoding="utf-8": env_text)

    assert load_env_file("mock.env") is True

    assert os.environ["AI_API_KEY"] == "test-key"
    assert os.environ["AI_BASE_URL"] == "https://api.deepseek.com/v1"
    assert os.environ["AI_MODEL"] == "deepseek-chat"


def test_load_env_file_keeps_existing_values_without_override(monkeypatch):
    monkeypatch.setenv("AI_MODEL", "deepseek-chat")
    monkeypatch.setattr(Path, "exists", lambda self: True)
    monkeypatch.setattr(Path, "read_text", lambda self, encoding="utf-8": "AI_MODEL=deepseek-reasoner")

    load_env_file("mock.env", override=False)

    assert os.environ["AI_MODEL"] == "deepseek-chat"


def test_load_project_env_reads_both_files_in_order(monkeypatch):
    paths_seen = []

    def fake_load_env_file(path, *, override=False):
        paths_seen.append((Path(path).name, override))
        return True

    monkeypatch.setattr("backend.app.core.config.load_env_file", fake_load_env_file)

    load_project_env(override=True)

    assert paths_seen == [(".env", True), (".env.local", True)]
