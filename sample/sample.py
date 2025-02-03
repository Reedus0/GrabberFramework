import os
import json

import requests
import pyzipper

from ..logs.logger import log

def save_file(name, data):
    log("Saving sample: " + name + "...")
    with open("./samples/" + name + ".zip", "wb") as sample:
        sample.write(data)
        sample.close()
    with pyzipper.AESZipFile("./samples/" + name + ".zip", "r", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zip_ref:
        zip_ref.extractall("./samples/", pwd="infected".encode())
    os.remove("./samples/" + name + ".zip")

def download_sample(hash):
    log("Downloading sample: " + hash + "...")
    headers = {"Auth-Key": os.environ["ABUSE_API_KEY"]}

    data = {
        "query": "get_file",
        "sha256_hash": hash,
    }

    r = requests.post("https://mb-api.abuse.ch/api/v1/", headers=headers, data=data)
    try:
        json.loads(r.text)
        r = requests.post("https://yaraify-api.abuse.ch/api/v1/", headers=headers, json=data)
        try:
            json.loads(r.text)
        except:
            save_file(hash, r.content)
    except:
        save_file(hash, r.content)