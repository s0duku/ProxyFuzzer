

# The PFuzzManager is the main code you need to modify for fuzzing your target
# This code is to start the fuzz server

import time
import json
from PFuzz.PFuzzManagerServer import PFuzzManagerServer
from MyFuzzCoverage import MyFuzzCoverage
from PFuzz.Logger import PFuzzLog

def send_wait():
    # send after 0.1 seconds
    time.sleep(0.1)


# Build self-defined coverage infomation collector
cover_info = MyFuzzCoverage()
app = PFuzzManagerServer(send_wait=send_wait,cov_based=cover_info)



@app.addHttpMutationHook()
def replaceHook(key,value,payload):
    # this function simply change the value to the payload
    return payload

@app.addHttpMutationHook()
def appendHook(key,value,payload):
    # this function used for append the payload to value
    try:
        return value+payload 
    except:
        return value

@app.addHttpRequestFilter()
def postFilter(req):
    # this function used to check content-type
    if req.headers.get('content-type') and req.headers['content-type'].startswith('application/multipart'):
        return True
    return False

@app.addHttpRequestFilter()
def hostFilter(req):
    # this function used to check host
    if req.headers.get('host') and (not req.headers['host'].startswith('127.0.0.1') ):
        return True
    return False

# 
PFuzzLog.openLogFile()

if __name__ == '__main__':

    app.run()
