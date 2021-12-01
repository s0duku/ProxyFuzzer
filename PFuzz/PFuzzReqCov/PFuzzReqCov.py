


import threading


class PFuzzReqCov:
    def __init__(self):
        self.cov = {}
        self.cov_lock = threading.Lock()
        pass

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

    def getHostsCoverage(self):
        return self.cov
    

    def hasCov(self,req):
        sig = self.genReqSig(req)
        return self.hasCovSig(req,sig)

    def hasCovSig(self,req,sig):
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


