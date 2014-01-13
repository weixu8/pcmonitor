def read_crt_lines(path):
    lines = []
    f = open(path, "r")
    while 1:
        l = f.readline()
        if l == '':
            break
        lines.append(l)
    f.close()
    return lines
   

ca_lines = read_crt_lines("..\\keys\\ca.crt")
client_lines = read_crt_lines("..\\keys\\ssl_client.crt")

f = open("keys.c", "w")
f.write('#include <inc\keys.h>\n')
f.write('char *CA_Cert =\n')
for l in ca_lines:
    f.write('"' + l.replace('\n', '') + '\\r\\n"\n')
f.write(";\n");
f.write('char *Client_Cert =\n')
for l in client_lines:
    f.write('"' + l.replace('\n', '') + '\\r\\n"\n')
f.write(";\n");
f.close()
