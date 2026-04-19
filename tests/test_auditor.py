from unittest.mock import MagicMock, patch
from shield_agent.auditor import CloudAuditor
from pathlib import Path

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
