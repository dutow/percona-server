from kmip.services.server import KmipServer
#from kmip.services.server import server

server = KmipServer(
     hostname='127.0.0.1',
     port=5696,
     certificate_path='/home/dutow/pykmip/cert',
     key_path='/home/dutow/pykmip/cert.key',
     ca_path='/home/dutow/pykmip/rootCA.crt',
     auth_suite='Basic',
     config_path='/home/dutow/pykmip/server.conf',
     log_path='/tmp/pykmip.server.log',
     policy_path='/home/dutow/pykmip/policies',
     enable_tls_client_auth=False,
     tls_cipher_suites='TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
     logging_level='DEBUG',
     database_path='/tmp/pykmip.db'
     )

server.start()

import time
time.sleep(10000)
