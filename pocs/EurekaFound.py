from PocUtils import PocType, Severity
from PocUtils.Http import Http
from urllib.parse import urljoin


class Poc:
    def __init__(self):
        self.poc_type = PocType.http
        self.target = ""
        self.severity = Severity.info
        self.detail = """Eureka记录了所有微服务节点信息，如果可以访问多个节点的`/actuator/heapdump`，则可以报高危漏洞eureka未授权访问"""
        self.name = "发现Eureka"

    def check(self):
        return True

    def exploit(self):
        client = Http()
        client.url = self.target
        resp = client.get()
        if "Instances currently registered with Eureka" in resp.text:
            return True
        else:
            return False
