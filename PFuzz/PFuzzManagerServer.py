from PFuzz.Config import PFuzzConfig
from PFuzz.PFuzzReqCov import PFuzzReqCov
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
                    req = HttpDatagramToRequest(data)
                except:
                    resp_log = "\n\033[35m[Mutations Http]\n\033[31mRequest Parse Error!\n\033[35m[Mutations End]\033[0m\n"
                    print(resp_log)
                    PFuzzLog.Info(resp_log)
                    PFuzzLog.Exit()

                req.url = "{}://{}{}".format(mts[0],req.headers.get('host'),req.url)
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


class PFuzzRequestPreFuzzSingleThreadServer(PFuzzRequestFuzzSingleThreadServer):

    """
    Single Preprocessing Fuzzing Thread, Prepare tbe Fuzzing arguments 
    """

    def __init__(self):
        super(PFuzzRequestPreFuzzSingleThreadServer,self).__init__()
        self.req_filter_lock = threading.Lock()
        self.http_mutation_hook_lock = threading.Lock()
        self.req_filter = []
        self.http_mutation_hook = []
        self.cov_based = None

    
    def addFuzzHook(self,hook):
        self.http_mutation_hook_lock.acquire()
        self.http_mutation_hook.append(hook)
        self.http_mutation_hook_lock.release()

    def addFuzzFilter(self,filter):
        self.req_filter_lock.acquire()
        self.req_filter.append(filter)
        self.req_filter_lock.release()

    def setCoverage(self,cov:PFuzzReqCov):
        self.cov_based = cov

    def getFuzzFilter(self):
        self.req_filter_lock.acquire()
        ft = self.req_filter
        self.req_filter_lock.release()
        return ft

    def getFuzzHook(self):
        self.http_mutation_hook_lock.acquire()
        hook = self.http_mutation_hook
        self.http_mutation_hook_lock.release()
        return hook


    def getFuzzReq(self):
        mutations = None
        self.acquireLock()
        if len(self.mutations_queue) > 0:
            mutations = self.mutations_queue[0]
            self.mutations_queue = self.mutations_queue[1:]
        self.releaseLock()
        return mutations

    def addFuzzReq(self,proto,fuzz_type,req,fuzz_args,send_wait=PFuzzNoWaitSend):
        self.acquireLock()
        self.mutations_queue.append((proto,fuzz_type,req,fuzz_args,send_wait))
        self.releaseLock()



    def run(self):
        origin_req = None

        while not PFuzzLog.isExit():
            origin_req = self.getFuzzReq()
            if origin_req == None:
                continue
            proto,fuzz_type,req,fuzz_args,send_wait = origin_req

            fuzz_req = requests.Request(method=req.get('method'),url=req.get('url'),params=req.get('params'),
                        headers=req.get('headers'),data=req.get('data'))
            
            cov_based = self.cov_based
            req_filter = self.getFuzzFilter()
            http_mutation_hook = self.getFuzzHook()

            # check filters
            isFilter = False
            for ft in req_filter:
                try:
                    fres = ft(fuzz_req)
                except:
                    print("\033[31m[FILTER ERROR] filter check error: {}\n\033[31m\033[0m".format(ft.__name__))
                    PFuzzLog.Exit(-1)
                if fres:
                    PFuzzLog.Info('\033[33m[{}] {} {}{} \033[0m'.format('FILTER',ft.__name__,fuzz_req.headers.get('host'),fuzz_req.url))
                    isFilter = True
                    break
            
            if isFilter:
                continue
            
            # check Coverage
            if cov_based != None:
                try:
                    req_sig = cov_based.genReqSig(fuzz_req)
                except:
                    print("\033[31m[Coverage ERROR] sig generation error: {}\n\033[31m\033[0m".format(fuzz_req.url))
                    PFuzzLog.Exit(-1)
                try:
                    hasSig = cov_based.hasCovSig(fuzz_req,req_sig)
                except:
                    print("\033[31m[Coverage ERROR] sig check error: {}\n\033[31m\033[0m".format(fuzz_req.url))
                    PFuzzLog.Exit(-1)
                if hasSig:
                    PFuzzLog.Info('\033[33m[{}] {}{} \033[0m'.format('Coverage',fuzz_req.headers.get('host'),fuzz_req.url))
                    continue
                else:
                    try:
                        cov_based.addCovSig(fuzz_req,req_sig)
                    except:
                        print("\033[31m[Coverage ERROR] sig add error: {}\n\033[31m\033[0m".format(fuzz_req.url))
                        PFuzzLog.Exit(-1)
        

            mutations = HttpPassiveMutation(fuzz_type,fuzz_req,fuzz_args,http_mutation_hook=[])
            mutations.set_http_mutation_hook(http_mutation_hook)
            mutations = mutations.mutations()
    

            fuzz_thread = PFuzzRequestFuzzThread(proto,mutations,send_wait)
            fuzz_thread.setDaemon(False)
            fuzz_thread.start()



__PFuzzHttpSingleThreadServer__ = PFuzzRequestFuzzSingleThreadServer()
__PFuzzPreHttpSingleThreadServer__ = PFuzzRequestPreFuzzSingleThreadServer()


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
            req.url = "{}://{}{}".format(self.proto,req.headers.get('host').strip(),req.url)
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

def PFuzzHttpTargetFilterWrap(send_wait):
    # XML RPC addHttpTarget RPC call wrap function

    def addHttpTarget(proto,fuzz_type,req,fuzz_args):
        global __PFuzzPreHttpSingleThreadServer__
        __PFuzzPreHttpSingleThreadServer__.addFuzzReq(proto,fuzz_type,req,fuzz_args,send_wait)
        
    return addHttpTarget


def PFuzzNoChangeHook(key,value,payload):
    return value

def PFuzzShowInfo():
    print("""
\033[35mPassive WEB Fuzzer Based on Mitmproxy\033[0m
\033[33m[Module]\033[0m \033[34mFuzz Manager\033[0m

\033[31m--exit\033[0m ctrl^c
""")


class PFuzzManagerServer(SimpleXMLRPCServer):
    # PFuzz manager server based on XML RPC.
    def __init__(self,host=PFuzzConfig.MANAGER_SERVER_HOST,port=PFuzzConfig.MANAGER_SERVER_PORT,send_wait=PFuzzNoWaitSend,cov_based:PFuzzReqCov=None):
        super(PFuzzManagerServer,self).__init__((host,port),requestHandler=PFuzzManagerRequestHandler,allow_none=True)
        self.cov_based = cov_based
        PFuzzLog.setCoverage(cov_based)
        self.http_mutation_hook = []
        self.req_filter = []
        self.send_wait = send_wait
        

    
    def addHttpMutationHook(self):
        def addHook(func):
            __PFuzzPreHttpSingleThreadServer__.addFuzzHook(func)
        return addHook

    def addHttpRequestFilter(self):
        def addFilter(func):
            __PFuzzPreHttpSingleThreadServer__.addFuzzFilter(func)
        return addFilter



    def run(self):
        PFuzzLog.start()
        PFuzzShowInfo()
        if len(__PFuzzPreHttpSingleThreadServer__.http_mutation_hook) == 0:
            __PFuzzPreHttpSingleThreadServer__.addFuzzHook(PFuzzNoChangeHook)
        if len(__PFuzzPreHttpSingleThreadServer__.req_filter) == 0:
            __PFuzzPreHttpSingleThreadServer__.addFuzzFilter(PFuzzNoFilter)
        __PFuzzPreHttpSingleThreadServer__.setCoverage(self.cov_based)
        self.register_function(PFuzzHttpTargetFilterWrap(self.send_wait),'addHttpTarget')
        if not __PFuzzPreHttpSingleThreadServer__.is_alive():
            __PFuzzPreHttpSingleThreadServer__.start()
        if not __PFuzzHttpSingleThreadServer__.is_alive():
            __PFuzzHttpSingleThreadServer__.start()
        ret = super().serve_forever()
        return ret