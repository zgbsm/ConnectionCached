from PocUtils import PocType, Severity
from PocUtils.Http import Http


class Poc:
    def __init__(self):
        self.poc_type = PocType.http
        self.target = ""
        self.severity = Severity.info
        self.detail = """相关漏洞：
        
- 后台RCE：https://github.com/faisalfs10x/Webmin-CVE-2022-0824-revshell
- 前台RCE：https://cloud.tencent.com/developer/article/1987931
- 后台RCE：https://blog.csdn.net/weixin_45006525/article/details/116259694
- 后台RCE：https://www.anquanclub.cn/21180.html
- 后台RCE：https://blog.csdn.net/weixin_42675091/article/details/126708256

后面5个RCE感觉像是同一个洞，应该只需测试第二个和第三个即可"""
        self.name = "发现webmin"

    def check(self):
        return True

    def exploit(self):
        client = Http()
        client.url = self.target
        resp = client.get()
        if "Webmin" in resp.text:
            return True
        else:
            return False
