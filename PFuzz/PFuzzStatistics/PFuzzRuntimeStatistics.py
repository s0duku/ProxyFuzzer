import json
import requests

class PFuzzRuntimeStatistics:
    def __init__(self):
        pass
    def submitCoverageToWeb(self,val):
        payload = json.dumps(val)
        requests.post('http://127.0.0.1:5000/coverage/submit',data=payload)