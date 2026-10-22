import requests
from tp3.utils.captcha import Captcha

class Session:
    """
    Class representing a session to solve a captcha and submit a flag.

    Attributes:
        url (str): The URL of the captcha.
        captcha_value (str): The value of the solved captcha.
        flag_value (str): The value of the flag to submit.
        valid_flag (str): The valid flag obtained after processing the response.
    """

    def __init__(self, url):
        """
        Initializes a new session with the given URL.

        Args:
            url (str): The URL of the captcha.
        """
        self.url = url
        self.session = requests.Session() #stocke le cookie de session
        self.captcha_value = ""
        self.flag_value = ""
        self.valid_flag = ""
        self.result = {}

    def prepare_request(self):
        """
        Prepares the request for sending by capturing and solving the captcha.
        """
        self.session.get(self.url) #visite la page cachée
        base = self.url.rsplit("/", 1)[0] #retire le endpoint de l'url
        captcha = Captcha(self.session, base) #crée le captcha et recupère le cookie de session
        captcha.capture()
        captcha.solve()
        self.captcha_value = captcha.get_value() #stocke la valeur du captcha

    def submit_request(self):
        """
        Sends the flag and captcha.
        """

    def process_response(self):
        """
        Processes the response.
        """

    def get_flag(self):
        """
        Returns the valid flag.

        Returns:
            str: The valid flag.
        """
        return self.valid_flag
