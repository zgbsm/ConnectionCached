import importlib
import os
import uuid
from PocUtils import PocType
import markdown
from alive_progress import alive_bar


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
    if poc_obj.check():
        if poc_obj.exploit():
            f = open("template.html", encoding="utf-8")
            temp = f.read()
            f.close()
            temp = temp.replace("{{name}}", poc_obj.name)
            temp = temp.replace("{{severity}}", poc_obj.severity)
            temp = temp.replace("{{target}}", poc_obj.target)
            temp = temp.replace("{{detail}}", markdown.markdown(poc_obj.detail))
            f = open("reports/{}_{}_{}.html".format(poc_obj.severity, poc_obj.name, uuid.uuid4()), "w")
            f.write(temp)
            f.close()


if __name__ == "__main__":
    targets = open("urls.txt")
    urls = targets.readlines()
    targets.close()
    targets = open("ips.txt")
    ips = targets.readlines()
    targets.close()
    pocs = os.listdir("pocs")
    with alive_bar(len(urls) + len(ips)) as bar:
        for i in urls:
            t = i.replace("\r", "")
            t = t.replace("\n", "")
            for j in pocs:
                invoke_pocs(j, True, t)
            bar()
        for i in ips:
            t = i.replace("\r", "")
            t = t.replace("\n", "")
            for j in pocs:
                invoke_pocs(j, False, t)
            bar()
    print("done")
