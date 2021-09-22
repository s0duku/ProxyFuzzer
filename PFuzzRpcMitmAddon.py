from mitmproxy import ctx
from mitmproxy import http

from PFuzz.Config import PFuzzConfig
from PFuzz.PFuzzManagerClient import PFuzzManagerClient

import requests

# PFuzz XML RPC Connection
PFuzzConn = PFuzzManagerClient()

query_payloads = {'a':['hello','world'],'xxxx':[]}
header_payloads = {'user-agenta':['chrome','safari'],'accept':['text','json']}
body_payloads = ["reboot",'echo']



RuntimeFuzzConfig = {
    'FUZZ_TYPE':PFuzzConfig.HTTP_FUZZ_BODY|PFuzzConfig.HTTP_FUZZ_QUERY|PFuzzConfig.HTTP_FUZZ_HEADER|PFuzzConfig.HTTP_FUZZ_CROSS,
    'FUZZ_ARGS':{
        PFuzzConfig.QUERY_FUZZ_ARGS:query_payloads,
        PFuzzConfig.HEADER_FUZZ_ARGS:header_payloads,
        PFuzzConfig.BODY_FUZZ_ARGS:body_payloads
    }
}

def PFuzzMitmReqToRequest(req:http.Request):
    # build Request from mitmproxy request
    try:
        # our request url will not contain query string
        url = req.path[:req.path.index('?')]
    except:
        url = req.path
    
    
    method = req.method
    params = dict()
    for key,value in req.query.items():
        params[key] = value
    data = req.content.decode(PFuzzConfig.HTTP_ENCODE_TYPE)
    headers = dict()
    for key,value in req.headers.items():
        headers[key.lower()] = value
    
    return requests.Request(method=method,url=url,params=params,headers=headers,data=data)



class PFuzzRpcMitmproxyAddon:

    def request(self,flow: http.HTTPFlow):
        # mitmproxt event hook

        req = PFuzzMitmReqToRequest(flow.request)
        if flow.request.scheme == 'https':
            proto = PFuzzConfig.PROTOCOL_HTTPS
        else:
            proto = PFuzzConfig.PROTOCOL_HTTP

        # XML RPC will convert Request into dict at server.  
        PFuzzConn.addHttpTarget(proto,RuntimeFuzzConfig['FUZZ_TYPE'],req,RuntimeFuzzConfig['FUZZ_ARGS'])


addons = [
    PFuzzRpcMitmproxyAddon()
]

if __name__ == "__main__":
    print("""

""")