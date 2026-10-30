import io

import pytesseract
from PIL import Image


class Captcha:
    def __init__(self, session, base_url) -> None:
        """Initialise le captcha avec une session et l'URL de base."""
        self.session = session       #session
        self.base_url = base_url  #adresse du site/docker
        self.image = None #contiendra l'image
        self.value = "" #contiendra le texte extrait du captcha

    def solve(self) -> None:
        """
        Fonction permettant la résolution du captcha.
        """
        config = "--psm 7 -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" #config ocr
        self.value = pytesseract.image_to_string(self.image, config=config).strip() #recupère le texte dans l'image

    def capture(self) -> None:
        """
        Fonction permettant la capture du captcha.
        """
        r = self.session.get(f"{self.base_url}/captcha.png") #tTélécharge l'image avec un cookie de session
        self.image = Image.open(io.BytesIO(r.content))

    def get_value(self) -> str:
        """
        Fonction retournant la valeur du captcha
        """
        return self.value
