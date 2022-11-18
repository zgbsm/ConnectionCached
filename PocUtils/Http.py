import threading
import requests


class Http:
    cache = []
    lock = threading.Lock()
    timeout = (60, 240)

    def __init__(self):
        self.url = ""
        self.queries = {}
        self.headers = {}
        self.cookies = {}
        self.data = {}
        self.json = {}
        self.method = ""

    def __eq__(self, other):
        ue = (self.url == other.url)
        qe = (self.queries == other.queries)
        he = (self.headers == other.headers)
        ce = (self.cookies == other.cookies)
        de = (self.data == other.data)
        me = (self.method == other.method)
        je = (self.json == other.json)
        return ue and qe and he and ce and de and me and je

    def check_cache(self) -> int:
        Http.lock.acquire()
        index = 0
        for i in Http.cache:
            if i[0] == self:
                Http.lock.release()
                return index
            index += 1
        Http.lock.release()
        return -1

    def save_cache(self, resp: requests.Response):
        Http.lock.acquire()
        if len(Http.cache) > 99:
            del Http.cache[0]
        Http.cache.append((self, resp))
        Http.lock.release()

    def get(self) -> requests.Response:
        self.method = "GET"
        return self.do_request()

    def post(self) -> requests.Response:
        self.method = "POST"
        return self.do_request()

    def json_post(self) -> requests.Response:
        self.method = "JSONPOST"
        return self.do_request()

    def do_request(self) -> requests.Response:
        index = self.check_cache()
        if index != -1:
            return Http.cache[index][1]
        resp: requests.Response
        match self.method:
            case "GET":
                resp = requests.get(url=self.url, params=self.queries, headers=self.headers, cookies=self.cookies,
                                    data=self.data, verify=False, timeout=Http.timeout)
            case "POST":
                resp = requests.post(url=self.url, params=self.queries, headers=self.headers, cookies=self.cookies,
                                     data=self.data, verify=False, timeout=Http.timeout)
            case "JSONPOST":
                resp = requests.post(url=self.url, params=self.queries, headers=self.headers, cookies=self.cookies,
                                     json=self.json, verify=False, timeout=Http.timeout)
            case other:
                resp = requests.get(url=self.url, params=self.queries, headers=self.headers, cookies=self.cookies,
                                    data=self.data, verify=False, timeout=Http.timeout)
        self.save_cache(resp)
        return resp
