import io
from unittest.mock import MagicMock
from PIL import Image
from tp3.utils.captcha import Captcha

def test_captcha_init():
    # Given
    url = "http://example.com/captcha"

    # When
    captcha = Captcha(url)

    # Then
    assert captcha.url == url
    assert captcha.image == ""
    assert captcha.value == ""


def test_solve():
    # Given
    captcha = Captcha("http://example.com/captcha")

    # When
    captcha.solve()

    # Then
    assert captcha.value == "FIXME"


def test_capture():
    #Given
    img = Image.new("RGB", (220, 90), "white")
    buf = io.BytesIO()
    img.save(buf, "PNG")

    session = MagicMock()
    session.get.return_value.content = buf.getvalue()

    captcha = Captcha(session, "http://test")

    #When
    captcha.capture()

    #Then
    assert captcha.image is not None
    assert captcha.image.size == (220, 90)


def test_get_value():
    # Given
    captcha = Captcha("http://example.com/captcha")
    captcha.value = "TEST123"

    # When
    result = captcha.get_value()

    # Then
    assert result == "TEST123"
