
from .Config import PFuzzConfig
import requests


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
    
    
