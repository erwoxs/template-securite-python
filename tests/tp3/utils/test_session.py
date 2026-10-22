from tp3.utils.session import Session
from unittest.mock import patch, MagicMock

def test_session_init():
    # Given
    url = "http://example.com/captcha"

    # When
    session = Session(url)

    # Then
    assert session.url == url
    assert session.captcha_value == ""
    assert session.flag_value == ""
    assert session.valid_flag == ""


def test_submit_request():
    # Given
    session = Session("http://example.com/captcha")

    # When
    session.submit_request()

    # Then
    # This is a minimal test since the method doesn't do anything yet
    assert True


def test_process_response():
    # Given
    session = Session("http://example.com/captcha")

    # When
    result = session.process_response()

    # Then
    # This is a minimal test since the method doesn't do anything yet
    assert result is None


def test_get_flag():
    # Given
    session = Session("http://example.com/captcha")
    session.valid_flag = "FLAG123"

    # When
    result = session.get_flag()

    # Then
    assert result == "FLAG123"

def test_prepare_request():
    #Given
    session = Session("http://test/internal-panel")

    #When
    with patch.object(session.session, "get"), \
         patch("tp3.utils.session.Captcha") as faux_captcha:
        faux_captcha.return_value.get_value.return_value = "ABC12"
        session.prepare_request()

    #Then
    assert session.captcha_value == "ABC12"