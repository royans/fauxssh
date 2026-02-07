import pytest
from unittest.mock import MagicMock, patch
from ssh_honeypot.core.llm import LLMInterface
from ssh_honeypot.core.universal_cache import UniversalCache


@patch("ssh_honeypot.core.llm.universal_cache")
@patch("ssh_honeypot.core.llm.config")
def test_llm_thinking_artifact_in_cache(mock_config, mock_cache):
    # Setup
    mock_config.get.return_value = "google"  # Provider
    llm = LLMInterface(api_key="fake_key")

    # Mock Cache Hit with "Thinking" artifact
    polluted_text = "Okay, here is a realistic response for your request:\nTotal 0"
    mock_cache.get.return_value = {"output_text": polluted_text}

    # Action
    response = llm.query("ls -la")

    # Assertions
    # 1. Should return the polluted text (as requested by user)
    assert response == polluted_text

    # 2. Should have called delete on the cache
    # We need to know the hash to verify exact call, but verify ANY delete is good enough for now
    assert mock_cache.delete.called
    assert mock_cache.delete.call_args[0][0] == "llm"


def test_is_thinking_artifact():
    llm = LLMInterface(api_key="fake_key")

    dataset = [
        ("Okay, here is a realistic response", True),
        ("Sure, I can help with that", True),
        ("Response:", True),
        ("**Response:**", True),
        ("root@server:~# ls -la", False),
        ("total 0", False),
        ("I cannot fulfill this request", True),
    ]

    for text, expected in dataset:
        assert llm._is_thinking_artifact(text) == expected, f"Failed for '{text}'"
