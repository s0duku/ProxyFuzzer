
from flask import Flask
from flask import render_template
from flask import json,jsonify
from flask import request
from .PFuzzWebConfig import PFuzzWebConfig


class PFuzzWebApp(Flask):

    def __init__(self,*kargs,**kwargs):
        super(PFuzzWebApp,self).__init__(__name__,*kargs,**kwargs)
        self.coverage = {}
        self.initRouter()

    
    def initRouter(self):
        @self.route(PFuzzWebConfig.ROUTE_INDEX)
        def PFuzzWebRouteIndex():
            return render_template('index.html',coverage=self.coverage)

        @self.route(PFuzzWebConfig.ROUTE_COVERAGE_SUBMIT,methods=['POST'])
        def PFuzzWebRouteCoverageSubmit():
            data = json.loads(request.get_data(as_text=True))
            host = data.get('host')
            if host:
                covers = data.get('covers')
                if isinstance(covers,list):
                    if self.coverage.get(host):
                        for val in covers:
                            self.coverage[host].add(val)
                    else:
                        self.coverage[host] = set()
                        for val in covers:
                            self.coverage[host].add(val)
            print(self.coverage)
            return jsonify({'status':'0','errmsg':''})

        @self.route(PFuzzWebConfig.ROUTE_COVERAGE_REQUEST)
        def PFuzzWebRouteCoverageRequest():
            return 'request'


    def run(self,*kargs,**kwargs):
        if not kwargs.get('host'):
            kwargs['host'] = PFuzzWebConfig.PFUZZ_WEB_HOST
        if not kwargs.get('port'):
            kwargs['port'] = PFuzzWebConfig.PFUZZ_WEB_PORT
    
        super(PFuzzWebApp,self).run(*kargs,**kwargs)



    