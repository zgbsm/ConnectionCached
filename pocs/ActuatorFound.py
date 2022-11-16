from PocUtils import PocType, Severity
from PocUtils.Http import Http
from urllib.parse import urljoin


class Poc:
    def __init__(self):
        self.poc_type = PocType.http
        self.target = ""
        self.severity = Severity.info
        self.detail = """`/actuator/heapdump`记录了jvm内存数据，可以从中搜索密码等信息，如果可以访问`/actuator/heapdump`或`/actuator/env`则可以报中危漏洞actuator未授权访问

可以尝试提取密码以提升危害"""
        self.name = "发现Actuator"

    def check(self):
        return True

    def exploit(self):
        client = Http()
        client.url = urljoin(self.target, "/actuator/info")
        resp = client.get()
        if resp.status_code == 200:
            return True
        else:
            return False
