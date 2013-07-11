# -*- coding: utf-8 -*-
# Echo server program
import socket

if __name__ == '__main__':
    HOST = ''                 # Symbolic name meaning all available interfaces
    PORT = 40008              # Arbitrary non-privileged port
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    while 1:
        s.listen(1)
        conn, addr = s.accept()
        print 'accepted', addr
        while 1:
            data = conn.recv(1024)
            if not data: break
            print data
        conn.close()


