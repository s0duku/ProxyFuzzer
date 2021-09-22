


class PFuzzConfig:
    
    # support protocol, no need to modify this
    PROTOCOL_HTTP = "http"
    PROTOCOL_HTTPS = "https"

    HTTP_VERSION = "HTTP/1.1"
    LOGFILE_NAME = "PFuzz_log_dump"


    # fuzz options, no need to modify this
    HTTP_FUZZ_BODY = 1
    HTTP_FUZZ_QUERY = 2
    HTTP_FUZZ_HEADER = 4
    HTTP_FUZZ_CROSS = 8

    # content-type pattern for content mutation
    CONTENT_TYPE_TEXT = "text/html"
    CONTENT_TYPE_URLENCODED = "application/x-www-form-urlencoded"
    CONTENT_TYPE_JSON = "application/json"

    # fuzz args key, no need to modify this
    
    HEADER_FUZZ_ARGS = 'HEADER_FUZZ_ARGS'
    BODY_FUZZ_ARGS = 'BODY_FUZZ_ARGS'
    QUERY_FUZZ_ARGS = 'QUERY_FUZZ_ARGS'

    # fuzz manager server option
    MANAGER_SERVER_HOST = "127.0.0.1"
    MANAGER_SERVER_PORT = 7056


    # html encode
    HTTP_ENCODE_TYPE = 'utf-8'