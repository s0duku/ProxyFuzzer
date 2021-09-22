import threading
import signal
import pickle
import time

from .Config import PFuzzConfig

__PFUZZ_EXIT__ = False

def PFuzzLogExitHandler(signum,frame):
    global __PFUZZ_EXIT__
    __PFUZZ_EXIT__ = True
    print("\033[31m[Info] PFuzz Exit\033[0m")
    exit(0)

signal.signal(signal.SIGINT,PFuzzLogExitHandler)
signal.signal(signal.SIGTERM,PFuzzLogExitHandler)


class PFuzzLogReader(list):
    def __init__(self,fname):
        with open(fname,'rb') as fd:
            super(PFuzzLogReader,self).__init__(pickle.load(fd))
    
    def getLog(self,idx):
        return super()[idx%len(super())]
    
    def printLog(self,idx):
        print(super()[idx%len(super())])


class PFuzzLogger(threading.Thread):
    """
    PFuzzLogger, check whether exit
    """
    def __init__(self,logfile=False):
        super(PFuzzLogger,self).__init__()
        self.msg_queue = []
        self.msg_queue_lock = threading.Lock()
        self.log_queue = []
        self.fuzz_start_time = int(time.time())
        if logfile:
            self.logfd = open("{}_{}".format(PFuzzConfig.LOGFILE_NAME,self.fuzz_start_time),'wb')
        else:
            self.logfd = None

    def openLogFile(self):
        if not self.getLogFd():
            self.logfd = open("{}_{}".format(PFuzzConfig.LOGFILE_NAME,self.fuzz_start_time),'wb')

    def getStartTime(self):
        return self.fuzz_start_time

    def getMsgQueue(self):
        return self.msg_queue

    def getLogQueue(self):
        return self.log_queue

    def setMsqQueue(self,msgq):
        self.msg_queue = msgq

    def acquireLock(self):
        self.msg_queue_lock.acquire()

    def releaseLock(self):
        self.msg_queue_lock.release()

    def Info(self,msg:str):
        self.acquireLock()
        self.msg_queue.append(msg)
        self.releaseLock()

    def Log(self,msg:str):
        self.acquireLock()
        self.msg_queue.append(msg)
        self.releaseLock()

    def getMsg(self):
        self.acquireLock()
        msg = None
        if len(self.msg_queue)>0:
            msg = self.msg_queue[0]
            self.msg_queue = self.msg_queue[1:]
        self.releaseLock()
        return msg

    def getLogFd(self):
        return self.logfd

    def closeLogFd(self):
        return self.logfd.close()

    def isExit(self):
        global __PFUZZ_EXIT__
        return __PFUZZ_EXIT__

    def run(self):
        while not self.isExit():
            msg = self.getMsg()
            if msg == None:
                continue
            print(msg)
            self.getLogQueue().append(msg)
        if self.getLogFd():
            pickle.dump(self.getLogQueue(),self.getLogFd())
            self.closeLogFd()

PFuzzLog = PFuzzLogger()