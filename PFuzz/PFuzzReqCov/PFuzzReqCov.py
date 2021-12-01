


import threading


class PFuzzReqCov:
    def __init__(self):
        self.pass_sig = set()
        self.cov = {}
        self.cov_cache = {}
        self.pass_sig_lock = threading.Lock()
        self.cov_lock = threading.Lock()
        self.cov_cache_lock = threading.Lock()

    def genReqSig(self,req)->str:
        return '{}:{}'.format(req.method,req.url)
    
    def addCov(self,req):
        sig = self.genReqSig(req)
        self.addCovSig(req,sig)

    def addCovSig(self,req,sig):
        host = req.headers.get('host')
        if not host:
            return
        self.cov_lock.acquire()
        if self.cov.get(host):
            self.cov.get(host).append(sig)
        else:
            self.cov[host] = [sig]
        self.cov_lock.release()

    def dismissSig(self,sig):
        res = False
        self.pass_sig_lock.acquire()
        if sig in self.pass_sig:
            res = True
        else:
            res = False
        self.pass_sig_lock.release()
        return res

    def addDismissSig(self,sig):
        self.pass_sig_lock.acquire()
        self.pass_sig.add(sig)
        self.pass_sig_lock.release()
        

    def setReqCache(self,req):
        self.cov_cache_lock.acquire()
        self.cov_cache[self.genCacheSig(req)] = req
        self.cov_cache_lock.release()

    def getReqCache(self,sig):
        self.cov_cache_lock.acquire()
        ch = self.cov_cache.get(sig)
        self.cov_cache_lock.release()
        return ch

    def genCacheSig(self,req):
        sig = self.genReqSig(req)
        return '{}:{}'.format(req.headers.get('host'),sig)

    def getHostsCoverage(self):
        return self.cov
    

    def hasCov(self,req):
        sig = self.genReqSig(req)
        return self.hasCovSig(req,sig)

    def hasCovSig(self,req,sig):
        if self.dismissSig(sig):
            return False
        host = req.headers.get('host')
        if not host:
            return
        self.cov_lock.acquire()
        tmp = self.cov.get(host)
        self.cov_lock.release()
        if tmp:
            if sig in tmp:
                return True
        else:
            return False


