from PocUtils import PocType, Severity
from PocUtils.Http import Http
from urllib.parse import urljoin


class Poc:
    def __init__(self):
        self.poc_type = PocType.http
        self.target = ""
        self.severity = Severity.low
        self.detail = """spark主页上有网络服务相关信息"""
        self.name = "发现Spark"

    def check(self):
        return True

    def exploit(self):
        client = Http()
        client.url = self.target
        resp = client.get()
        if "Spark Jobs" in resp.text:
            return True
        else:
            return False
