
# ProxyFuzzer 

<img align="right" src="https://github.com/s0duku/ProxyFuzzer/blob/main/examples/0.png?raw=true" alt="AFL++ Logo">   

ProxyFuzzer 被动式 WEB Fuzz 引擎, 用户可自行基于不同的代理服务器实现 Fuzz 前端，使用引擎提供的接口将请求包转发给 Fuzz 引擎即可对目标进行被动式 Fuzz 测试。

## 目前提供的代理插件实现
* mitmproxy

## 更新开发进度  

### 支持的请求体类型  
* URLENCODED  
* JSON  

### 基于签名的请求包覆盖检测
* 默认签名方式，三元组 (host,method,url)
* 支持自定签名，针对特定目标扩展

### 支持的变异策略   
* url查询字符串变异  
* http header 变异  
* http body 变异  
* 交叉变异 http 请求各部分  
* 单个参数字段依次变异  
* 选定参数字段依次变异  
* 通过自定义hook强化字典值变异的方式 (可实现替换值或附加等等)    
* 基于上下文差异提取变异

### 完善数据统计信息
* 基于Flask实现 WEB UI 展示请求覆盖信息
* 展示每个host下覆盖到的请求包签名
* 修复日志存储到文件，多线程下不完整的Bug

### 架构
* 优化代理端到Fuzz段的请求处理
* 添加Fuzz预处理中间层线程


![2](https://github.com/s0duku/ProxyFuzzer/blob/main/examples/1.png?raw=true)  


## 架构介绍

### Fuzz 工作流程

![3](https://raw.githubusercontent.com/s0duku/ProxyFuzzer/main/examples/2.jpg) 

### 数据包变异策略

![3](https://raw.githubusercontent.com/s0duku/ProxyFuzzer/main/examples/3.png)    

![3](https://raw.githubusercontent.com/s0duku/ProxyFuzzer/main/examples/4.png)

  
## 安装

Require:   
* Python3  
* mitmproxy

```
pip install mitmproxy

```  

## 使用

### 启动 Fuzz 引擎

```
cd ProxyFuzzer

mitmproxy -s .\PFuzzRpcMitmAddon.py -p 8080 -k

python3 PFuzzManager.py

``` 

### Fuzz Multipart 或其他自定义类型请求包

* 使用 Burp 抓取第一次请求包   
    ![3](https://raw.githubusercontent.com/s0duku/ProxyFuzzer/main/examples/multi_fuzz_0.png)  
* 如果我们希望 Fuzz name, filename 字段，修改这两个字段的值和原来不同，这里直接置空，发出请求  
    ![3](https://raw.githubusercontent.com/s0duku/ProxyFuzzer/main/examples/multi_fuzz_1.png)  
* 数据成功变异  
    ![3](https://raw.githubusercontent.com/s0duku/ProxyFuzzer/main/examples/multi_fuzz_2.png)  
    ![3](https://raw.githubusercontent.com/s0duku/ProxyFuzzer/main/examples/multi_fuzz_3.png)  
    

## 开发接口

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

        # 向Fuzz管理服务发起Fuzz请求  
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

