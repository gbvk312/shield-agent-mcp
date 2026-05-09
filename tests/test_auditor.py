from pathlib import Path
from unittest.mock import MagicMock, patch

from shield_agent.auditor import CloudAuditor


@patch("shield_agent.auditor.genai.Client")
def test_audit_file(mock_client_class):
    # Setup mock response
    mock_response = MagicMock()
    mock_response.text = "Mocked audit report"
    
    # Mock the client instance and its models property
    mock_client_instance = MagicMock()
    mock_client_instance.models.generate_content.return_value = mock_response
    mock_client_class.return_value = mock_client_instance
    
    auditor = CloudAuditor(api_key="fake_key")
    report = auditor.audit_file(Path("test.py"), "print('hello')")
    
    assert report == "Mocked audit report"
    mock_client_instance.models.generate_content.assert_called_once()

@patch("shield_agent.auditor.genai.Client")
def test_audit_diff(mock_client_class):
    # Setup mock response
    mock_response = MagicMock()
    mock_response.text = "Mocked diff report"
    
    # Mock the client instance and its models property
    mock_client_instance = MagicMock()
    mock_client_instance.models.generate_content.return_value = mock_response
    mock_client_class.return_value = mock_client_instance
    
    auditor = CloudAuditor(api_key="fake_key")
    report = auditor.audit_diff("diff content")
    
    assert report == "Mocked diff report"
    mock_client_instance.models.generate_content.assert_called_once()


@patch("shield_agent.auditor.genai.Client")
def test_fallback_on_rate_limit(mock_client_class):
    """Should fall back to next model on 429 / RESOURCE_EXHAUSTED."""
    mock_client_instance = MagicMock()
    mock_client_class.return_value = mock_client_instance

    # First call raises 429, second succeeds
    mock_response = MagicMock()
    mock_response.text = "Fallback report"
    mock_client_instance.models.generate_content.side_effect = [
        Exception("429 RESOURCE_EXHAUSTED"),
        mock_response,
    ]

    auditor = CloudAuditor(api_key="fake_key")
    report = auditor.audit_file(Path("test.py"), "code")

    assert report == "Fallback report"
    assert mock_client_instance.models.generate_content.call_count == 2


@patch("shield_agent.auditor.genai.Client")
def test_all_models_rate_limited(mock_client_class):
    """Should return error when all models are rate-limited."""
    mock_client_instance = MagicMock()
    mock_client_class.return_value = mock_client_instance
    mock_client_instance.models.generate_content.side_effect = Exception("429")

    auditor = CloudAuditor(api_key="fake_key")
    report = auditor.audit_file(Path("test.py"), "code")

    assert "rate-limited" in report.lower()
