f = open("..\\keys\\ca.crt", "r")
ca_crt = f.read()
f.close()
f = open("..\\keys\\ssl_client.crt", "r")
ssl_client_crt = f.read()
f.close()
f = open("keys.c", "w")
f.write(
'#include <inc\keys.h>\n'
+ 'char *CA_Cert ="' + ca_crt.replace('\n', '') + '";\n'
+ 'char *Client_Cert = "' + ssl_client_crt.replace('\n', '') + '";\n'
)
f.close()
