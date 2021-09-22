from PFuzz.Config import PFuzzConfig
import threading
import time

from .Logger import PFuzzLog
from .Mutation import HttpPassiveMutation
from .Utils import HttpDatagramToRequest,HttpMakeResponseDatagram,HttpEncodeHeaderValue
from xmlrpc.server import SimpleXMLRPCServer,SimpleXMLRPCRequestHandler
import requests

# disable the request warning
requests.packages.urllib3.disable_warnings()

def PFuzzNoFilter(req):
    # fuzz request without any filter
    return False

def PFuzzNoWaitSend():
    # fuzz request without any waiting
    return



class PFuzzRequestFuzzSingleThreadServer(threading.Thread):

    """
    Single Thread Fuzzer, fuzz each mutation in mutations queue 
    """
    def __init__(self):
        super(PFuzzRequestFuzzSingleThreadServer,self).__init__()
        self.mutations_queue = []
        self.mutations_queue_lock = threading.Lock()

    def acquireLock(self):
        self.mutations_queue_lock.acquire()
    
    def releaseLock(self):
        self.mutations_queue_lock.release()

    def getMutationsQueue(self):
        return self.mutations_queue

    def setMutationsQueue(self,mq):
        self.mutations_queue = mq

    def getMutations(self):
        mutations = None
        self.acquireLock()
        if len(self.mutations_queue) > 0:
            mutations = self.mutations_queue[0]
            self.mutations_queue = self.mutations_queue[1:]
        self.releaseLock()
        return mutations

    def addMutations(self,proto,mutations,send_wait=PFuzzNoWaitSend):
        self.acquireLock()
        self.mutations_queue.append((proto,mutations,send_wait))
        self.releaseLock()

    def run(self):
        mts = None
        while not PFuzzLog.isExit():
            mts = self.getMutations()
            if mts == None:
                continue
            info = "\n\033[35m[Mutations Http]\033[32m\n{}\n{}\n\n\033[34m{}\n\033[35m[Mutations End]\033[0m\n"
            for data in mts[1]:
                
                if PFuzzLog.isExit():
                    return

                try:
                    #pass
                #except:
                    #pass
                #if True:
                    req = HttpDatagramToRequest(data)
                #try:
                    #pass
                except:
                    resp_log = "\n\033[35m[Mutations Http]\n\033[31mRequest Parse Error!\n\033[35m[Mutations End]\033[0m\n"
                    PFuzzLog.Info(resp_log)
                    continue
                req.url = "{}://{}{}".format(mts[0],req.headers['host'],req.url)
                try:
                    mts[2]()
                    now_time = '[{}]'.format(time.strftime("%Y/%m/%d %H:%M:%S", time.localtime()))
                #except:
                    #pass
                
                #if True:
                    resp = requests.request(method=req.method,url=req.url,
                                    params=req.params,headers=req.headers,data=req.data,verify=False)
                    resp_log = HttpMakeResponseDatagram(status=resp.status_code,header=HttpEncodeHeaderValue(resp.headers),body=resp.text)
                    PFuzzLog.Info(info.format(now_time,data,resp_log[:]))
                #try:
                    #pass
                except:
                    now_time = '[{}]'.format(time.strftime("%Y/%m/%d %H:%M:%S", time.localtime()))
                    resp_log = "\n\033[35m[Mutations Http]\n\033[31m{}\nRequest HTTP Error!\n\033[35m[Mutations End]\033[0m\n".format(now_time)
                    PFuzzLog.Info(resp_log)



__PFuzzHttpSingleThreadServer__ = PFuzzRequestFuzzSingleThreadServer()


class PFuzzRequestFuzzThread(threading.Thread):
    def __init__(self,proto,mutations,send_wait=PFuzzNoWaitSend,singleThread=True):
        super(PFuzzRequestFuzzThread,self).__init__()
        self.proto = proto
        self.mutations = mutations
        self.singleThread = singleThread
        self.send_wait = send_wait

    def run(self):
        # single thread mode
        if self.singleThread:
            __PFuzzHttpSingleThreadServer__.addMutations(self.proto,self.mutations,self.send_wait)
            return

        info = "\n\033[35m[Mutations Http]\033[32m\n{}\n{}\n\n\033[34m{}\n\033[35m[Mutations End]\033[0m\n"
        for data in self.mutations:
            req = HttpDatagramToRequest(data)
            req.url = "{}://{}{}".format(self.proto,req.headers['host'].strip(),req.url)
            try:
                self.send_wait()
                now_time = '[{}]'.format(time.strftime("%Y/%m/%d %H:%M:%S", time.localtime()))
                resp = requests.request(method=req.method,url=req.url,
                                    params=req.params,headers=req.headers,data=req.data,verify=False)
                resp_log = HttpMakeResponseDatagram(status=resp.status_code,header=HttpEncodeHeaderValue(resp.headers),body=resp.text)
                PFuzzLog.Info(info.format(now_time,data,resp_log[:]))
            except:
                now_time = '[{}]'.format(time.strftime("%Y/%m/%d %H:%M:%S", time.localtime()))
                resp_log = "\n\033[35m[Mutations Http]\n\033[31m{}\nRequest HTTP Error!\n\033[35m[Mutations End]\033[0m\n".format(now_time)
                PFuzzLog.Info(resp_log)
            





class PFuzzManagerRequestHandler(SimpleXMLRPCRequestHandler):
    # PFuzz manager server based on XML RPC, this class is the XML RPC Handler.
    rpc_paths = ('/RPC2', '/RPC3')

def PFuzzHttpTargetFilterWrap(req_filter:list,send_wait,http_mutation_hook:list):
    # XML RPC addHttpTarget RPC call wrap function

    def addHttpTarget(proto,fuzz_type,req,fuzz_args):
        fuzz_req = requests.Request(method=req.get('method'),url=req.get('url'),params=req.get('params'),
                        headers=req.get('headers'),data=req.get('data'))

        for ft in req_filter:
            if ft(fuzz_req):
                PFuzzLog.Info('\033[33m[{}] {}{} \033[0m'.format('FILTER',fuzz_req.headers['host'],fuzz_req.url))
                return

        mutations = HttpPassiveMutation(fuzz_type,fuzz_req,fuzz_args,http_mutation_hook=[])
        mutations.set_http_mutation_hook(http_mutation_hook)
        mutations = mutations.mutations()
    

        fuzz_thread = PFuzzRequestFuzzThread(proto,mutations,send_wait)
        fuzz_thread.setDaemon(False)
        fuzz_thread.start()

    return addHttpTarget


def PFuzzNoChangeHook(key,value,payload):
    return value


class PFuzzManagerServer(SimpleXMLRPCServer):
    # PFuzz manager server based on XML RPC.
    def __init__(self,host=PFuzzConfig.MANAGER_SERVER_HOST,port=PFuzzConfig.MANAGER_SERVER_PORT,send_wait=PFuzzNoWaitSend):
        super(PFuzzManagerServer,self).__init__((host,port),requestHandler=PFuzzManagerRequestHandler,allow_none=True)
        self.http_mutation_hook = []
        self.req_filter = []
        self.send_wait = send_wait
        

    
    def addHttpMutationHook(self):
        def addHook(func):
            self.http_mutation_hook.append(func)
        return addHook

    def addHttpRequestFilter(self):
        def addFilter(func):
            self.req_filter.append(func)
        return addFilter



    def run(self):
        PFuzzLog.start()
        if len(self.http_mutation_hook) == 0:
            self.http_mutation_hook.append(PFuzzNoChangeHook)
        if len(self.req_filter) == 0:
            self.req_filter.append(PFuzzNoFilter)
        self.register_function(PFuzzHttpTargetFilterWrap(self.req_filter,self.send_wait,self.http_mutation_hook),'addHttpTarget')
        if not __PFuzzHttpSingleThreadServer__.is_alive():
            __PFuzzHttpSingleThreadServer__.start()
        ret = super().serve_forever()
        return ret