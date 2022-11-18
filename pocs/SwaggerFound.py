from PocUtils import PocType, Severity
from PocUtils.Http import Http
from urllib.parse import urljoin


class Poc:
    def __init__(self):
        self.poc_type = PocType.http
        self.target = ""
        self.severity = Severity.low
        self.detail = """发现swagger接口文档：<{}>"""
        self.name = "发现swagger"

    def check(self):
        return True

    def exploit(self):
        dic = [
            "",
            "/",
            "/swagger/ui/index",
            "/swagger/index.html",
        ]
        for i in dic:
            client = Http()
            client.url = urljoin(self.target, i)
            resp = client.get()
            if "swagger-ui" in resp.text:
                self.detail = self.detail.format(client.url)
                return True
        return False
