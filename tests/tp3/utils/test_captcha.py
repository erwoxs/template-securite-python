import io
from unittest.mock import MagicMock
from PIL import Image
from tp3.utils.captcha import Captcha
from unittest.mock import patch


def test_captcha_init():
    #Given / When
    captcha = Captcha(None, "http://test")

    #Then
    assert captcha.base_url == "http://test"
    assert captcha.image is None
    assert captcha.value == ""


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
    #Given
    captcha = Captcha(None, "http://test")
    captcha.value = "ABC12"

    #When
    result = captcha.get_value()

    #Then
    assert result == "ABC12"


def test_solve():
    captcha = Captcha(None, "http://test")
    captcha.image = "fausse_image"   # solve ne lit pas l'OCR est mocké

    #When
    with patch("tp3.utils.captcha.pytesseract.image_to_string", return_value="ABC12\n"):
        captcha.solve()

    #Then
    assert captcha.value == "ABC12"

