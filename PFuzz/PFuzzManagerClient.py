from .Config import PFuzzConfig
from xmlrpc.client import ServerProxy

class PFuzzManagerClient(ServerProxy):
    """
    PFuzzManagerClient for adding request to PFuzzManagerServer
    """
    def __init__(self,host=PFuzzConfig.MANAGER_SERVER_HOST,port=PFuzzConfig.MANAGER_SERVER_PORT):
        super(PFuzzManagerClient,self).__init__('http://{}:{}'.format(host,port),allow_none=True)