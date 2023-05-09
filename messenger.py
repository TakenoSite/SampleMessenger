import socket 
import base64
import select
import re
import sys

class UTIL:
    def __init__(self):
        pass 
    
    def tagformat(self,body:str, tagname:str)->str:
        try:
            startTag = "<"+str(tagname)+">"
            endTag = "</"+str(tagname)+">"
            return re.split(endTag, re.split(startTag, body)[1])[0]
        except:
            return None
        pass 
    
    def base64encode(self,body:str) -> str:
        return base64.b64encode(body.encode())
        pass 

    def base64decode(self, body:str) -> str:
        try:
            return base64.b64decode(body).decode()
        except:
            return None
        pass 
    
    def lognline(self, text:str)->str:
        return "-"*15 + text + "-"*15
        pass
    
    def print_lognline(self, test:str):
        print(self.lognline(test))
        return
        pass 
    
    def response_print(self, data:str, addr:list):
        rformat = "addr : {a}\nencode_body : {e}\ndecode_body : {d}".format(a=addr, e=data, d=self.base64decode(data))
        print(rformat)
        return 
        pass
    
    def char_to_bool(self, bools:str)->bool:
        
        ustr = upper(bools)
        if ustr == "TRUE":
            return True

        elif ustr == "FALSE":
            return False

        else:
            return None

        pass 


class USERCMDTABLE:
    def __init__(self):
        self.util = UTIL()
        pass 

    def cmd_showtable(self)->list:
        cmd_body    = "<CMD><SHOWTABLE></SHOWTABLE></CMD>"
        main_body   = "<EN41>{cmd}</EN41>".format(cmd=cmd_body)
        return self.util.base64encode(main_body), main_body
        pass 

    def cmd_help(self)->list:
        cmd_body    = "<CMD><HELP></HELP></CMD>"
        main_body   = "<EN41>{cmd}</EN41>".format(cmd=cmd_body)
        return self.util.base64encode(main_body), main_body
        pass 

    def cmd_nodequery(self)->list:
        set_ip      = "{ip}".format(ip="127.0.0.1")
        cmd_body    = "<CMD><NODEQUERY>{i}</NODEQUERY></CMD>".format(i=set_ip)
        main_body   = "<EN41>{cmd}</EN41>".format(cmd=cmd_body)
        return self.util.base64encode(main_body), main_body
        pass 
        

class SOCKET:
    def __init__(self, addr:list):
        self.addr   = addr
        self.sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sockfd.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        pass 

    def udp_sock(self):
        return self.sockfd 
        pass 
    
    def udp_sockclose(self):
        self.sockfd.close()
        return
        pass 

    def udp_socktimeout(self, t:int):
        self.sockfd.settimeout(t)
        return
        pass 
    
    def udp_sender(self, payload:str):
        #self.sockfd.sendto(bytes(payload, encoding="utf-8"), self.addr)
        self.sockfd.sendto(payload, self.addr)
        return
        pass 
    
    def udp_bind(self):
        self.sockfd.bind(self.addr)

    def udp_recv(self)->list:
        data, addr = self.sockfd.recvfrom(2048)
        return data, addr
        pass 
 

class PROTOCOLTABLE:
    def __init__(self):
        self.util = UTIL()
        pass 

    def protocol_bind(self, ntype:str, sport=None)->list:
        set_nodetype    = "<NODE_TYPE>{t}</NODE_TYPE>".format(t=ntype)
        
        protocol_body = None
        if ntype == "PORT0":
            protocol_body   = "<BIND>{s}</BIND>".format(s=set_nodetype)
        
        elif ntype == "RAW":
            set_sport       = "<SPORT>{s}</SPORT>".format(s=sport)
            protocol_body   = "<BIND>{s}{p}</BIND>".format(s=set_nodetype, p=set_sport)

        main_body = "<EN41>{proto}</EN41>".format(proto=protocol_body)
        
        return self.util.base64encode(main_body), main_body
        pass
    
    def protocol_disconect(self)->list:
        protocol_body   = "<DELETE></DELETE>"
        main_body       = "<EN41>{proto}</EN41>".format(proto=protocol_body)
        return self.util.base64encode(main_body), main_body
        pass 


    def protocol_send(self, host:str, msg:str)->list:
        set_datalen     = "<DATA_LEN>{dlen}</DATA_LEN>".format(dlen=len(msg))
        set_datatype    = "<DATA_TYPE>{dtype}</DATA_TYPE>".format(dtype="text")
        set_msg         = "<MSG>{msg}</MSG>".format(msg=msg)
        set_host        = "<HOST>{host}</HOST>".format(host=host)
        
        header_body     = "<HEADER>{dlen}{dtype}</HEADER>".format(dlen=set_datalen, dtype=set_datatype)
        protocol_body   = "<SEND>{msg}{host}</SEND>".format(msg=set_msg, host=set_host)
        main_body       = "<EN41>{header}{proto}</EN41>".format(header=header_body, proto=protocol_body)

        return self.util.base64encode(main_body), main_body
        pass 

    def protocol_rawsend(self, shost:str, msg:str)->list:
        set_datatype    = "<DATA_TYPE>{dtype}</DATA_TYPE>".format(dtype="text")
        set_srchost     = "<SRCHOST>{shost}</SRCHOST>".format(shost=shost)
        set_msg         = "<MSG><BODY>{body}</BODY></MSG>".format(body=msg)

        header_body     = "<HEADER>{dtype}{shost}</HEADER>".format(dtype=set_datatype, shost=set_srchost)
        protocol_body   = "<SEND>{s}</SEND>".format(s=set_msg)
        main_body       = "<EN41>{header}{proto}</EN41>".format(header=header_body, proto=protocol_body)
        

        return self.util.base64encode(main_body),main_body
        pass 

    def protocol_ipinfo(self)->list:
        protocol_body   = "<IPINFO></IPINFO>"
        main_body       = "<EN41>{proto}</EN41>".format(proto=protocol_body)
        
        return self.util.base64encode(main_body),main_body
        pass 




class CTL:
    def __init__(self, saddr:list):
        self.user_cmd   = USERCMDTABLE() 
        self.proto      = PROTOCOLTABLE()
        self.util       = UTIL()

        self.saddr = saddr
        pass 
    
    def request_close(self):
        ssocket = SOCKET(self.saddr)
        proto_msg = self.proto.protocol_disconect()
        ssocket.udp_sender(proto_msg[0])
        ssocket.udp_sockclose() 
    
    
    def request_msgsend(self, msg:str, userlist:list):
        ssocket = SOCKET(self.saddr)
        
        for user in userlist[1]:
            if user == "" or user == "None":
                break
            proto_msg = self.proto.protocol_send(user, msg)
            ssocket.udp_sender(proto_msg[0])

        ssocket.udp_sockclose()
        
        for raw_user in userlist[2]:
            if raw_user == "" or raw_user == "None":
                break
            
            addrinfo = raw_user.split(":")
            addr = None
            
            if len(addrinfo) == 2:
                shost = addrinfo[0]
                sport = addrinfo[1]
                addr = (str(shost), int(sport))
            
            else:
                continue
            
            sockfd = SOCKET(addr)       
            proto_msg = self.proto.protocol_rawsend(shost, msg)
            
            sockfd.udp_sender(proto_msg[0])
            sockfd.udp_sockclose()
        return
        pass 

    def request_userlist(self)->list:
        ssocket = SOCKET(self.saddr)
        
        proto_msg = self.user_cmd.cmd_showtable()
        ssocket.udp_sender(proto_msg[0])
        
        ssocket.udp_socktimeout(3)

        raw_node_list = None
        port0_node_list = None
        
        while True:
            try:
                data,addr = ssocket.udp_recv()
            except:
                print("[!] request userlist :: timeout :(")
                break # goto END
            
            decode_msg = self.util.base64decode(data)
            if decode_msg == None:
                print("[!] response userlist ::invalid dataformat")
                break # goto END
            
            if self.util.tagformat(decode_msg, "EN41") != None  and self.util.tagformat(decode_msg, "CMD") == "SHOWTABLE":
                raw_node_list = self.util.tagformat(decode_msg, "RAW").split("\r\n")
                port0_node_list = self.util.tagformat(decode_msg, "PORT0").split("\r\n")
                pass 
            else:
                print("[!] response userlist :: invalid dataformat 2")
                break
            
            ssocket.udp_sockclose()
            return decode_msg, port0_node_list, raw_node_list
        
        # END
        ssocket.udp_sockclose()
        return None
    

    def request_help(self)->str:
        ssocket = SOCKET(self.saddr)
        proto_msg = self.user_cmd.cmd_help()
        ssocket.udp_sender(proto_msg[0])
        
        ssocket.udp_socktimeout(3)

        while True:
            try:
                data,addr = ssocket.udp_recv()
            except:
                print("[!] request help :: timeout :(")
                break

            decode_msg = self.util.base64decode(data)
            if decode_msg == None:
                print("[!] response help ::invalid dataformat")
                break
            
            ssocket.udp_sock.close()
            return decode_msg 
        
        ssocket.udp_sockclose()
        return None
            
    
    def request_nodequery(self, host:str)->bool:
        ssocket = SOCKET(self.saddr)
        proto_msg = self.user_cmd.cmd_nodequery()
        ssocket.udp_sender(proto_msg[0])
         
        ssocket.udp_socktimeout(3)

        while True:
            try:
                data,addr = ssocket.udp_recv()

            except:
                print("[!] request nodequery :: timeout :(")
                break

            decode_msg = self.util.base64decode(data)
            if decode_msg == None:
                print("[!] response nodequery ::invalid dataformat :(")
                break
            
            if self.util.tagformat(decode_msg, "EN41") !=None and self.util.tagformat(decode_msg, "RESOLVE") != None:
                                
                valu = self.util.tagformat(decode_msg, "RESOLVE")
                to_bool = self.util.char_to_bool(valu)
                if to_bool == None:
                    print("[!] response nodequery ::invalid dataformat :(")
                    break

                ssocket.udp_sockclose()
                return to_bool
            
            else:
                print("[!] response nodequery ::invalid dataformat :(") 
                break

        
        ssocket.udp_sockclose()
        return None
        pass 


    def request_ipinfo(self)->str:
        ssocket = SOCKET(self.saddr);
        proto_msg = self.proto.protocol_ipinfo()
        ssocket.udp_sender(proto_msg[0])
        
        ssocket.udp_socktimeout(3)
        
        while True:
            try:
                data,addr = ssocket.udp_recv()
            except:
                print("[!] request ipinfo :: timeout :(")
                break
            
            decode_msg = self.util.base64decode(data)
            if decode_msg == None:
                print("[!] response ipinfo ::invalid dataformat :(")
                break
            
            if self.util.tagformat(decode_msg, "EN41") != None and self.util.tagformat(decode_msg, "GHOST") != None:
                 ssocket.udp_sockclose()   
                 return self.util.tagformat(decode_msg, "GHOST")
            else:
                print("[!] response ipinfo ::invalid dataformat2 :(") 
                break
            
        ssocket.udp_sockclose()   
        return None


class CONNECTOR:
    def __init__(self, addr:list, ntype:str, sport=None):
        self.socket = SOCKET(addr)
        self.util   = UTIL()
        self.ctl    = CTL(addr)
        self.proto  = PROTOCOLTABLE()
        self.ntype  = ntype
        self.ipinfo = None
        self.sport  = sport
        pass 

    def connect(self):
        self.socket.udp_sender(self.proto.protocol_bind(self.ntype, self.sport)[0])
        self.socket.udp_socktimeout(3)
        try:
            res = self.socket.udp_recv()
            self.socket.udp_socktimeout(None) 
        except:
            print("[!] connected timeout.. :(") 
            return None

        res_decode = self.util.base64decode(res[0])
        if res_decode != None and self.util.tagformat(res_decode, "EN41") != None and self.util.tagformat(res_decode, "RES") == "true":
            self.ipinfo = self.ctl.request_ipinfo()
            if self.ipinfo == None:
                print("[!] request ipinfo : error :(")
                return None 
            
            print("[*] conected :)")
            return self.socket.udp_sock()
        else :
            print("[!] can't conected :(")
            return None
        pass 
   
   
    def disconnect(slef):
        self.socket.udp_sender(self.proto.protocol_disconect()[0])
        res = self.socket.udp_recv()
        res_decode = self.util.base64decode(res)

        if res_decode != None and self.util.tagformat(res_decode, "EN41") != None and self.util.tagformat(res_decode, "RES") != None:
            print("[*] success :)")
            return 0
        else :
            print("[!] problem occured :(")
            return None
        pass 
    

    
    def session(self):
        ssock = None
        if self.ntype == "PORT0":
            # Relay 
            #   IRC 
            print("[*] PORT0NODE SOCKET")
            ssock  = self.socket 
             

        elif self.ntype == "RAW":
            # P2P
            #   IPC
            print("[*] RAWNODE SOCKET")
            my_addr = (self.ipinfo, self.sport)
            ssock = SOCKET(my_addr)
            ssock.udp_bind()
            pass 
        
        
        while(True):
            data,addr = ssock.udp_recv()
            decode_msg = self.util.base64decode(data)
            
            if decode_msg != None and self.util.tagformat(decode_msg, "EN41") != None:
                if self.util.tagformat(decode_msg, "KEEPALIVE") != None: 
                    #print("[+] sys :: alive") #debug 
                    continue

                elif self.util.tagformat(decode_msg, "ACC_KEEPALIVE") != None:
                    #print("[+] sys :: acc keepalive") #debug 
                    ssock.udp_sender(data);
                    continue

                elif self.util.tagformat(decode_msg, "MSG") != None:
                    msgbody = self.util.tagformat(decode_msg, "BODY")
                    dtype   = self.util.tagformat(decode_msg, "DATA_TYPE") 
                    shost   = self.util.tagformat(decode_msg, "SRCHOST")

                    if dtype == "text":
                        print("{s} :> {t}".format(s=shost,t=msgbody))
                        continue
                     
                    else:
                        print("[+] {s} :: default dtype :: {d}".format(s=shost, d=dtype)) #debug
                        continue
                else:
                    #print("[+] sys :: proto default")  #debug 
                    #default
                    pass 
        return

# end
