import time
from PFuzz.PFuzzManagerServer import PFuzzManagerServer
from PFuzz.Logger import PFuzzLog

def send_wait():
    # send after 0.1 seconds
    time.sleep(0.1)

def show_info():
    print("""
\033[35mPassive WEB Fuzzer Based on Mitmproxy\033[0m
\033[33m[Module]\033[0m \033[34mFuzz Manager\033[0m

\033[31m--exit\033[0m ctrl^c
""")

app = PFuzzManagerServer(send_wait=send_wait)

@app.addHttpMutationHook()
def replaceHook(key,value,payload):
    return payload 

@app.addHttpRequestFilter()
def postFilter(req):
    if req.headers.get('content-type') and req.headers['content-type'].startswith('application/multipart'):
        return True
    return False

#PFuzzLog.openLogFile()

if __name__ == '__main__':

    show_info()
    app.run()
