from PocUtils import PocType, Severity
from PocUtils.Http import Http
from urllib.parse import urljoin


class Poc:
    def __init__(self):
        self.poc_type = PocType.http
        self.target = ""
        self.severity = Severity.info
        self.detail = """YApi有NOSQL注入漏洞，可配合vm逃逸导致RCE

- https://www.cnblogs.com/zpchcbd/p/16882304.html
- https://github.com/Anthem-whisper/YApi-Exploit

注入攻击顺序：
- get_token_by_inject
- get_id_uid_by_token
- encrypt_token
- execute_command"""
        self.name = "发现YApi"

    def check(self):
        return True

    def exploit(self):
        client = Http()
        client.url = urljoin(self.target, "/")
        resp = client.get()
        if "YApi-高效、易用、功能强大的可视化接口管理平台" in resp.text:
            return True
        else:
            return False
