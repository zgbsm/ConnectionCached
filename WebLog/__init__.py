import requests
import yaml

conf_file = open("weblog.yaml")
conf_str = conf_file.read()
conf_file.close()
conf = yaml.load(conf_str, yaml.SafeLoader)
create_url = "http://{}:{}/create".format(conf['ip'], conf['web_port'])
get_url = "http://{}:{}/get".format(conf['ip'], conf['web_port'])
rev_url = "http://{}:{}".format(conf['ip'], conf['listener_port'])


class Result:
    def __init__(self):
        self.start = ''
        self.rule = ''
        self.requested = False
        self.requests = []


def create(rule: str) -> str:
    if not conf['enable']:
        return ''
    resp = requests.post(create_url, data={'rule': rule}).json()
    return resp['message']


def get(code: str) -> Result:
    if not conf['enable']:
        return Result()
    resp = requests.get(get_url, params={"c": code}).json()
    if resp['success']:
        res = Result()
        message = resp['message']
        res.start = message['start']
        res.rule = message['rule']
        res.requested = message['requested']
        res.requests = message['requests']
        return res
    else:
        return Result()
