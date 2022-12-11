import importlib
import os
import socket
import threading
import uuid
import socks
import yaml
from PocUtils import PocType
import markdown
from alive_progress import alive_bar
from queue import Queue
import urllib3

urllib3.disable_warnings()
url_queue = Queue()
ip_queue = Queue()


def invoke_pocs(fn: str, is_url: bool, target: str):
    if not fn.endswith(".py"):
        return
    poc = importlib.import_module("pocs." + fn.replace(".py", ""))
    poc_obj = poc.Poc()
    if poc_obj.poc_type == PocType.http and is_url:
        poc_obj.target = target
    elif poc_obj.poc_type != PocType.http and not is_url:
        poc_obj.target = target
    else:
        return
    try:
        if poc_obj.check():
            if poc_obj.exploit():
                exts = ['markdown.extensions.extra', 'markdown.extensions.codehilite', 'markdown.extensions.tables',
                        'markdown.extensions.toc']
                f = open("template.html", encoding="utf-8")
                temp = f.read()
                f.close()
                temp = temp.replace("{{name}}", poc_obj.name)
                temp = temp.replace("{{severity}}", poc_obj.severity)
                temp = temp.replace("{{target}}", poc_obj.target)
                temp = temp.replace("{{detail}}", markdown.markdown(poc_obj.detail, extensions=exts))
                f = open("reports/{}_{}_{}.html".format(poc_obj.severity, poc_obj.name, uuid.uuid4()), "w", encoding="utf-8")
                f.write(temp)
                f.close()
    except Exception as e:
        pass


def worker(poc_list: list, is_url: bool, p_bar):
    while True:
        target = ''
        try:
            if is_url:
                target = url_queue.get(block=False)
            else:
                target = ip_queue.get(block=False)
        except Exception:
            pass
        if target == '':
            return
        target = target.replace("\r", "")
        target = target.replace("\n", "")
        for index in poc_list:
            invoke_pocs(index, is_url, target)
        p_bar()


if __name__ == "__main__":
    targets = open("urls.txt")
    urls = targets.readlines()
    targets.close()
    targets = open("ips.txt")
    ips = targets.readlines()
    targets.close()
    pocs = os.listdir("pocs")
    proxy = open("proxy.yaml")
    socks_proxy = proxy.read()
    proxy.close()
    socks_conf = yaml.load(socks_proxy, yaml.SafeLoader)
    if socks_conf["socks5"]["host"] != "":
        socks.set_default_proxy(socks.SOCKS5, socks_conf["socks5"]["host"], socks_conf["socks5"]["port"])
        socket.socket = socks.socksocket
    for i in urls:
        url_queue.put(i)
    for i in ips:
        ip_queue.put(i)
    thread_pool = []
    with alive_bar(len(urls) + len(ips)) as bar:
        for i in range(50):
            thread = threading.Thread(target=worker, args=[pocs, True, bar])
            thread.start()
            thread_pool.append(thread)
        for i in range(50):
            thread = threading.Thread(target=worker, args=[pocs, False, bar])
            thread.start()
            thread_pool.append(thread)
        for i in thread_pool:
            i.join()
    print("done")
