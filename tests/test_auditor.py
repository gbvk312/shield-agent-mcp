from unittest.mock import MagicMock, patch
from shield_agent.auditor import CloudAuditor
from pathlib import Path

@patch("google.generativeai.GenerativeModel")
def test_audit_file(mock_model):
    # Setup mock response
    mock_response = MagicMock()
    mock_response.text = "Mocked audit report"
    mock_model.return_value.generate_content.return_value = mock_response
    
    auditor = CloudAuditor(api_key="fake_key")
    report = auditor.audit_file(Path("test.py"), "print('hello')")
    
    assert report == "Mocked audit report"
    mock_model.return_value.generate_content.assert_called_once()

@patch("google.generativeai.GenerativeModel")
def test_audit_diff(mock_model):
    # Setup mock response
    mock_response = MagicMock()
    mock_response.text = "Mocked diff report"
    mock_model.return_value.generate_content.return_value = mock_response
    
    auditor = CloudAuditor(api_key="fake_key")
    report = auditor.audit_diff("diff content")
    
    assert report == "Mocked diff report"
    mock_model.return_value.generate_content.assert_called_once()
