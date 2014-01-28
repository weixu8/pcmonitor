def read_dll(path):
    f = open(path, "rb")
    data = f.read()
    f.close()
    return data

data = read_dll("..\\build\\x64\\Release\\kdll.dll")
f = open("kdll.c", "w")
f.write('#include <inc\kdll.h>\n')
f.write('char g_kdll_data[] = {')
for c in data:
    f.write(hex(ord(c)) + ',')
f.write('};\n');

f.write('char *kdll_data() { return g_kdll_data;}\n');
f.write('size_t kdll_data_size() { return sizeof(g_kdll_data);}\n');

f.close()

#f.write('char *Client_Cert =\n')
#for l in client_lines:
#    f.write('"' + l.replace('\n', '') + '\\r\\n"\n')
#f.write(";\n");
#f.close()
