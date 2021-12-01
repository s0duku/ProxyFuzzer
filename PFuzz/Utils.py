
from .Config import PFuzzConfig
import requests


def PFuzzBuildMatrix(row,line):
    return [[0 for k in range(line)] for l in range(row)]

def PFuzzFindCommonSubstr(X,Y):
    m = len(X)
    n = len(Y)
    
    LCSuff = PFuzzBuildMatrix(m+1,n+1)
 
    result = 0
    sublen = 0
 
    for i in range(m + 1):
        for j in range(n + 1):
            if (i == 0 or j == 0):
                LCSuff[i][j] = 0
            elif (X[i-1] == Y[j-1]):
                LCSuff[i][j] = LCSuff[i-1][j-1] + 1
                if LCSuff[i][j] > result:
                    result = LCSuff[i][j]
                    sublen = i
            else:
                LCSuff[i][j] = 0
    return X[:sublen][-result:]

def PFuzzSplitStrCommon(X,Y):
    if not X or not Y:
        return []
    splitF = []
    splitB = []

    comStr = PFuzzFindCommonSubstr(X,Y)

    if comStr:
        Xf = X[:X.index(comStr)]
        Xb = X[X.index(comStr)+len(comStr):]
        Yf = Y[:Y.index(comStr)]
        Yb = Y[Y.index(comStr)+len(comStr):]

        splitF += PFuzzSplitStrCommon(Xf,Yf)
        splitB += PFuzzSplitStrCommon(Xb,Yb)

        return splitF + [comStr] + splitB
    
    return []


def PFuzzMitmReqToRequest(req):
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


def HttpDecodeQueryValue(data:str):
    # decode query string into dict
    value = {}
    if not data:
        return value
    for pair in data.split('&'):
        tmp = pair.split('=')
        value[tmp[0]] = tmp[1]
    return value


def HttpEncodeQueryValue(data:dict):
    # encode dict to query string
    if not data:
        return ''
    tmp = []
    for key,value in data.items():
        tmp.append(key+'='+value)
    return '&'.join(tmp)


def HttpEncodeHeaderValue(data:dict):
    # encode dict to header string
    tmp = []
    for key,value in data.items():
        tmp.append(key+': '+value)
    return '\r\n'.join(tmp)

def HttpMakeRequestDatagram(method:str,url:str,query:str='',header:str='',body:str=''):
    # build request datagram from Request
    return '{} {} {}\r\n{}\r\n\r\n{}'.format(method,url+query,PFuzzConfig.HTTP_VERSION,header,body)


def HttpMakeResponseDatagram(status:str,header:str='',body:str=''):
    # build response datagram 
    return '{} {}\r\n{}\r\n\r\n{}'.format(PFuzzConfig.HTTP_VERSION,status,header,body)


def HttpDatagramToRequest(req_data:str):
    # build Request from http datagram
    
    datagram = req_data.split('\r\n')
    method,path,version = datagram[0].split(' ')

    try:
        url = path[:path.index('?')]
        query_str = path[path.index('?')+1:]
    except:
        url = path
        query_str = ''
    
    params = HttpDecodeQueryValue(query_str)
    headers = {}
    idx = 1
    
    while datagram[idx]:

        key,value = datagram[idx][:datagram[idx].index(':')],datagram[idx][datagram[idx].index(':')+1:]
        headers[key.lower()] = value.strip()
        idx += 1
    
    data = datagram[idx+1]
    
    return requests.Request(method=method,url=url,params=params,
            headers=headers,data=data)
    
    
