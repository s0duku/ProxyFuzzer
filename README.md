
# ProxyFuzzer 

<img align="right" src="https://github.com/s0duku/ProxyFuzzer/blob/main/examples/0.png?raw=true" alt="AFL++ Logo">   

ProxyFuzzer 是基于 mitmproxy 插件开发的 WEB Fuzzer  
通过配置HTTP/HTTPS代理实现对目标的被动式 Fuzz 。   

---  

![2](https://github.com/s0duku/ProxyFuzzer/blob/main/examples/1.png?raw=true)  

---  

支持的请求体类型:  
* URLENCODED  
* JSON  

支持的变异策略:   
* url查询字符串变异  
* http header 变异  
* http body 变异  
* 交叉变异 http 请求各部分  
* 单个参数字段依次变异  
* 选定参数字段依次变异  
* 通过hook自定义字典值变异的方式  




## Install

Require:   
* Python3  
* mitmproxy

```
pip install mitmproxy

```  

## Usage

```
cd ProxyFuzzer

mitmproxy -s .\PFuzzRpcMitmAddon.py -p 8080 -k

python3 PFuzzManager.py

``` 

## API

### PFuzzRpcMitmAddon.py

```
# mitmproxy Fuzz 插件

# Fuzz 字典，列表表示全参数Fuzz，字典是按键名Fuzz值

query_payloads = ['hello','world']
header_payloads = {'user-agent':['chrome','safari'],'accept':['text','json']}
body_payloads = ["reboot",'echo']

RuntimeFuzzConfig = {
    # Fuzz Body 内容，Fuzz URL 查询字符串，Fuzz HTTP Header，交叉变异模式
    'FUZZ_TYPE':PFuzzConfig.HTTP_FUZZ_BODY|PFuzzConfig.HTTP_FUZZ_QUERY|PFuzzConfig.HTTP_FUZZ_HEADER|PFuzzConfig.HTTP_FUZZ_CROSS,
    # Fuzz 参数
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

        # 像Fuzz管理服务发起Fuzz请求  
        PFuzzConn.addHttpTarget(proto,RuntimeFuzzConfig['FUZZ_TYPE'],req,RuntimeFuzzConfig['FUZZ_ARGS'])

```


### PFuzz.PFuzzConfig

````
PFuzz 全局配置

````


### PFuzz.Logger.PFuzzLog

````
# 开启日志持久化
PFuzzLog.openLogFile()

````


### PFuzz.PFuzzManagerServer.PFuzzManagerServer 


PFuzzManagerServer(host,port,send_wait=PFuzzNoWaitSend)   

```
host: Fuzz管理服务启动地址
port: Fuzz管理服务启动端口
send_wait: Fuzz请求之间的hook
PFuzzNoWaitSend 不做任何处理，等待的占位函数
```

```
app = PFuzzManagerServer()

# addHttpMutationHook 装饰器，添加键值对变异时hook，返回值将作为变异的值，key: 当前编译的键, value: 原始键的值, payload: 当前字典考虑的值
@app.addHttpMutationHook()
def replaceHook(key,value,payload):
    return payload

# addHttpRequestFilter 装饰器, 更据请求选择是否过滤
@app.addHttpRequestFilter()
def postFilter(req):
    if req.method == "POST":
        return True
    return False

# 启动 Fuzz 管理服务（一个Python进程环境只启动一个）
app.run()

```

