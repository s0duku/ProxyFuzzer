from .Utils import HttpDecodeQueryValue,HttpEncodeQueryValue,HttpEncodeHeaderValue,HttpMakeRequestDatagram
from .Config import PFuzzConfig
import json

def ReplaceMutationHook(key,value,mvalue):
    return mvalue


def QueryValueDfsMutation(fuzz_args,data:dict,mutation_hook:list):
    if not fuzz_args or not data:
        yield HttpEncodeQueryValue(data)
        return

    if isinstance(fuzz_args,list):
        for key,value in data.items():
            saved = value
            for payload in fuzz_args:
                for hook in mutation_hook:
                    data[key] = hook(key,data[key],payload)
                    yield HttpEncodeQueryValue(data)
            data[key] = saved
    elif isinstance(fuzz_args,dict):
        for key,value in fuzz_args.items():
            if data.get(key) == None:
                continue

            saved = data[key]

            if not data:
                data[key] = saved
                yield HttpEncodeQueryValue(data)
                continue
            for payload in value:
                for hook in mutation_hook:
                    data[key] = hook(key,data[key],payload)
                    yield HttpEncodeQueryValue(data)
            data[key] = saved


def JsonValueDfsMutation(json_fuzz_arg,root_node,par_node,key:str,cur_node,mutation_hook):
    if not json_fuzz_arg:
        yield json.dumps(root_node)
        return
    if isinstance(cur_node,list):
        for next_node in cur_node:
            obj = JsonValueDfsMutation(json_fuzz_arg,root_node,par_node,key,next_node,mutation_hook)
            for res in obj:
                yield res
    elif isinstance(cur_node,dict):
        for next_key,next_node in cur_node.items():
            saved = cur_node[next_key]
            obj = JsonValueDfsMutation(json_fuzz_arg,root_node,cur_node,next_key,next_node,mutation_hook)
            for res in obj:
                yield res
            cur_node[next_key] = saved
    else:
        if root_node == par_node:
            for payload in json_fuzz_arg:
                for hook in mutation_hook:
                    par_node[key] = hook(key,par_node[key],payload)
                    yield json.dumps(root_node) 
        if isinstance(json_fuzz_arg,list):
            for payload in json_fuzz_arg:
                for hook in mutation_hook:
                    par_node[key] = hook(key,par_node[key],payload)
                    yield json.dumps(root_node)
        elif isinstance(json_fuzz_arg,dict) and (json_fuzz_arg.get(key) != None):
            if not json_fuzz_arg.get(key):
                yield json.dumps(root_node)
                return
            for payload in json_fuzz_arg.get(key):
                for hook in mutation_hook:
                    par_node[key] = hook(key,par_node[key],payload)
                    yield json.dumps(root_node)


class PFuzzMutation:

    def __init__(self,http_mutation_hook,*kargs,**kwargs):
        self.http_mutation_hook = http_mutation_hook

    def mutations(self,default_value=0):
        return

    def get_http_mutation_hook(self)->list:
        return self.http_mutation_hook

    def http_mutation_hook(self,hook):
        self.get_http_mutation_hook().append(hook)

    def set_http_mutation_hook(self,hook:list):
        self.http_mutation_hook = hook



class JsonValueMutation(PFuzzMutation):

    def __init__(self,json_template,json_fuzz_arg,*kargs,**kwargs):
        super(JsonValueMutation,self).__init__(*kargs,**kwargs)
        self.root_node = json_template
        self.json_fuzz_arg = json_fuzz_arg

    def mutations(self, default_value=0):
        return JsonValueDfsMutation(self.json_fuzz_arg,self.root_node,self.root_node,None,self.root_node,self.http_mutation_hook)


class BodyValueMutation(PFuzzMutation):

    def __init__(self,body_template,body_fuzz_args,*kargs,**kwargs):
        super(BodyValueMutation,self).__init__(*kargs,**kwargs)
        self.body_value = body_template
        self.body_fuzz_args = body_fuzz_args

    def mutations(self, default_value=0):
        return QueryValueDfsMutation(self.body_fuzz_args,self.body_value,self.http_mutation_hook)




class ContentTypeBasedMutation(PFuzzMutation):

    CONTENT_TYPE_TEXT = 0
    CONTENT_TYPE_JSON = 1
    

    def __init__(self,req_content_type,req_body,content_fuzz_args,*kargs,**kwargs):
        super(ContentTypeBasedMutation,self).__init__(*kargs,**kwargs)
        self.req_content_type = req_content_type
        self.req_body = req_body
        self.content_fuzz_args = content_fuzz_args
    
    def mutations(self, default_value=0):
        if self.req_content_type == ContentTypeBasedMutation.CONTENT_TYPE_TEXT:
            return BodyValueMutation(HttpDecodeQueryValue(self.req_body),self.content_fuzz_args,http_mutation_hook=self.http_mutation_hook).mutations(default_value)
        elif self.req_content_type == ContentTypeBasedMutation.CONTENT_TYPE_JSON:
            return JsonValueMutation(json.loads(self.req_body),self.content_fuzz_args,http_mutation_hook=self.http_mutation_hook).mutations(default_value)


class UrlParamMutation(PFuzzMutation):

    def __init__(self,url_params,url_param_fuzz_args,*kargs,**kwargs):
        super(UrlParamMutation,self).__init__(*kargs,**kwargs)
        self.url_params = url_params
        self.url_param_fuzz_args = url_param_fuzz_args

    def mutations(self, default_value=0):
        for mt in QueryValueDfsMutation(self.url_param_fuzz_args,self.url_params,self.http_mutation_hook):
            if not mt:
                yield mt
            else:
                yield '?' + mt

class HeaderValueMutation(PFuzzMutation):

    def __init__(self,header_template,header_fuzz_args,*kargs,**kwargs):
        super(HeaderValueMutation,self).__init__(*kargs,**kwargs)
        self.header_template = header_template
        self.fuzz_args = header_fuzz_args

    def mutations(self, default_value=0):
        if not self.fuzz_args:
            yield HttpEncodeHeaderValue(self.header_template)
            return
        if isinstance(self.fuzz_args,list):
            for key,value in self.header_template.items():
                saved = value
                for payload in self.fuzz_args:
                    self.header_template[key] = payload
                    yield HttpEncodeHeaderValue(self.header_template)
                self.header_template[key] = saved
        elif isinstance(self.fuzz_args,dict):
            for key,value in self.fuzz_args.items():
                if self.header_template.get(key) == None:
                    continue
                saved = self.header_template[key]
                if not value:
                    self.header_template[key] = saved
                    yield HttpEncodeHeaderValue(self.header_template)
                    continue
                for payload in value:
                    self.header_template[key] = payload
                    yield HttpEncodeHeaderValue(self.header_template)
                self.header_template[key] = saved

class HttpPassiveMutation(PFuzzMutation):

    HTTP_FUZZ_BODY = 1
    HTTP_FUZZ_QUERY = 2
    HTTP_FUZZ_HEADER = 4

    def __init__(self,http_fuzz_type,http_req,http_fuzz_args:dict,*kargs,**kwargs):
        super(HttpPassiveMutation,self).__init__(*kargs,**kwargs)
        self.http_req = http_req
        self.http_fuzz_args = http_fuzz_args
        self.http_fuzz_type = http_fuzz_type

    def mutations(self, default_value=0):
        if self.http_fuzz_type & PFuzzConfig.HTTP_FUZZ_CROSS:
            return self.cross_mutations()
        else:
            return self.ncross_mutaitons()

    
    def cross_mutations(self):

        for query in UrlParamMutation(self.http_req.params,
                            self.http_fuzz_args.get(PFuzzConfig.QUERY_FUZZ_ARGS),http_mutation_hook=self.http_mutation_hook).mutations():
            for header in HeaderValueMutation(self.http_req.headers,
                            self.http_fuzz_args[PFuzzConfig.HEADER_FUZZ_ARGS],http_mutation_hook=self.http_mutation_hook).mutations():

                if not self.http_req.headers.get('content-length'):
                    
                    yield HttpMakeRequestDatagram(self.http_req.method,self.http_req.url,
                            query,HttpEncodeHeaderValue(self.http_req.headers),self.http_req.data)
                    continue
                    
                if self.http_req.headers['content-type'].startswith(PFuzzConfig.CONTENT_TYPE_JSON):
                    content_type = ContentTypeBasedMutation.CONTENT_TYPE_JSON
                elif self.http_req.headers['content-type'].startswith(PFuzzConfig.CONTENT_TYPE_TEXT):
                    content_type = ContentTypeBasedMutation.CONTENT_TYPE_TEXT
                elif self.http_req.headers['content-type'].startswith(PFuzzConfig.CONTENT_TYPE_URLENCODED):
                    content_type = ContentTypeBasedMutation.CONTENT_TYPE_TEXT
                else:
                    return
                
                for body in ContentTypeBasedMutation(content_type,self.http_req.data,
                            self.http_fuzz_args[PFuzzConfig.BODY_FUZZ_ARGS],http_mutation_hook=self.http_mutation_hook).mutations():
                    yield HttpMakeRequestDatagram(self.http_req.method,self.http_req.url,
                            query,header,body) 
            

    
    def ncross_mutaitons(self):
        if self.http_fuzz_type & PFuzzConfig.HTTP_FUZZ_QUERY:
            header = HttpEncodeHeaderValue(self.http_req.headers)
            body = self.http_req.data
            for query in UrlParamMutation(self.http_req.params,
                            self.http_fuzz_args[PFuzzConfig.QUERY_FUZZ_ARGS],http_mutation_hook=self.http_mutation_hook).mutations():
                yield HttpMakeRequestDatagram(self.http_req.method,self.http_req.url,
                            query,header,body)
        
        if self.http_fuzz_type & PFuzzConfig.HTTP_FUZZ_HEADER:
            if self.http_req.params:
                query = '?'+HttpEncodeQueryValue(self.http_req.params)
            else:
                query = ''
            body = self.http_req.data
            #print(self.http_fuzz_args)
            for header in HeaderValueMutation(self.http_req.headers,
                            self.http_fuzz_args[PFuzzConfig.HEADER_FUZZ_ARGS],http_mutation_hook=self.http_mutation_hook).mutations():
                yield HttpMakeRequestDatagram(self.http_req.method,self.http_req.url,
                            query,header,body)
        
        if self.http_fuzz_type & PFuzzConfig.HTTP_FUZZ_BODY:
            if self.http_req.params:
                query = '?'+HttpEncodeQueryValue(self.http_req.params)
            else:
                query = ''

            if not self.http_req.headers.get('content-length'):
                yield HttpMakeRequestDatagram(self.http_req.method,self.http_req.url,
                            query,HttpEncodeHeaderValue(self.http_req.headers),self.http_req.data)
                return
                            
            if self.http_req.headers['content-type'].startswith(PFuzzConfig.CONTENT_TYPE_JSON):
                content_type = ContentTypeBasedMutation.CONTENT_TYPE_JSON
            elif self.http_req.headers['content-type'].startswith(PFuzzConfig.CONTENT_TYPE_TEXT):
                content_type = ContentTypeBasedMutation.CONTENT_TYPE_TEXT
            elif self.http_req.headers['content-type'].startswith(PFuzzConfig.CONTENT_TYPE_URLENCODED):
                content_type = ContentTypeBasedMutation.CONTENT_TYPE_TEXT
            else:
                yield HttpMakeRequestDatagram(self.http_req.method,self.http_req.url,
                            query,HttpEncodeHeaderValue(self.http_req.headers),self.http_req.data)
                return
                

            saved_length = self.http_req.headers.get('content-length')
            
            for body in ContentTypeBasedMutation(content_type,self.http_req.data,
                            self.http_fuzz_args[PFuzzConfig.BODY_FUZZ_ARGS],http_mutation_hook=self.http_mutation_hook).mutations():
                self.http_req.headers['content-length'] = str(len(body))
                header = HttpEncodeHeaderValue(self.http_req.headers)
                yield HttpMakeRequestDatagram(self.http_req.method,self.http_req.url,
                            query,header,body)
            self.http_req.headers['content-length'] = saved_length
        


        