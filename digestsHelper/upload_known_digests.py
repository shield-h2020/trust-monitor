import requests
import json

KNOWN_DIGESTS_URI = "https://TRUST_MONITOR_BASE_URL_OR_IP/known_digests/"
with open("digests.json") as f:
    data = json.load(f)

digests_list = data["digests"]

for digest in digests_list:

    for key in digest.keys():
        if key != "instance":
            print("POST request for digest: " + key +
                  " with value: " + digest[key])
            jsonObject = {"pathFile": key, "digest": digest[key]}

            r = requests.post(KNOWN_DIGESTS_URI, data=jsonObject, verify=False)
            print(r.status_code, r.reason)
