def read_dll(path):
    f = open(path, "rb")
    data = f.read()
    f.close()
    return data

data = read_dll("..\\build\\x64\\Win7 Release\\kdriver.sys")
f = open("kdriver.cpp", "w")
f.write('#include "kdriver.h"\n')
f.write('char g_kdrv_data[] = {')
for c in data:
    f.write(hex(ord(c)) + ',')
f.write('};\n');

f.write('char *kdrv_data() { return g_kdrv_data;}\n');
f.write('size_t kdrv_data_size() { return sizeof(g_kdrv_data);}\n');

f.close()
