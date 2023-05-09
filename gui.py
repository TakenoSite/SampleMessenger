import sys 
from messenger import UTIL, CONNECTOR, USERCMDTABLE, SOCKET, CTL
import PySimpleGUI as sg
import threading as th

sg.theme("DarkAmber")
    

class MESSENFER_GUI:
    def __init__(self):
        self.session_addr = None
        self.sockinfo     = None
        
        self.util        = UTIL()
        self.connector   = None
        self.ctl         = None
        
        self.userlist = []
         
        pass 

    def initial_config_from(self):
        configframesize = (80, 20)
        
        default_session_addr    = ("127.0.0.1", "12345")
        default_node_type       = "PORT0" 
        default_lport_type      = 4444

        layout = [
                [sg.Output(size=configframesize)],
                [sg.Text("Set Session Host : "), sg.InputText(default_session_addr[0], key="VALU1")],
                [sg.Text("Set Session Port  : "), sg.InputText(default_session_addr[1], key="VALU2")],
                [sg.Text("Set Node Type     : "), sg.InputText(default_node_type, key="VALU3")],
                [sg.Text("RawType Only (lport): "), sg.InputText(default_lport_type, key="VALU4")],
                [sg.Button("Connecting")]
                ]
        windows = sg.Window("Sample Chat GUI", layout)
        
        while True:
            event, values = windows.read()
            if event == sg.WIN_CLOSED:
                break
            
            elif event == "Connecting":
                get_valu1 = values["VALU1"]
                get_valu2 = values["VALU2"]
                get_valu3 = values["VALU3"]
                get_valu4 = values["VALU4"]
                 
                try:
                    shost = str(get_valu1)
                    sport = int(get_valu2)
                    ntype = str(get_valu3).upper()
                    lhost = int(get_valu4)
                    
                except:
                    print("[!] input in ip address and port format")
                    continue
                    pass 

                if ntype == "RAW" or ntype == "PORT0":
                    pass 
                else:
                    print("[!] Please ntype form is input in RAW or PORT0 ")
                    continue


                self.session_addr = (shost, sport)
                
                if ntype == "PORT0":
                    self.connector = CONNECTOR(self.session_addr,ntype)
                
                elif ntype == "RAW":
                    self.connector = CONNECTOR(self.session_addr, ntype, sport=lhost)
                
                
                print("[*] connection...")
                connection = self.connector.connect()
                if connection == None:
                    continue
                 
                self.ctl = CTL(self.session_addr)
                self.userlist = self.ctl.request_userlist()
                if self.userlist == None:
                    print("[!] can't get table")
                    continue
                

                self.sockinfo = connection.getsockname() 
                windows.close()
                self.messenger_gui()
                break
                pass 
        windows.close()
        pass


    def setting_form(self):
        chatframesize   = (80, 10)
        username        = "User : "
        old_config      = "0.0.0.0:12345"

        layout = [
                [sg.Text("old session host : "),sg.Text(old_config)],
                [sg.Text("new session host : "), sg.InputText(key="FORM")],
                [sg.Button("SET"), sg.Button("Close")],
                [sg.Text("", key="STATUS")]
                ]

        window = sg.Window("Sample Chat GUI", layout)
        while True:
            event, values = window.read()
            if event == sg.WIN_CLOSED or event == "Close":
                break
            
            elif event == "SET":
                getvalu = values["FORM"]
                body    = "Setting :: {s}".format(s=getvalu)
                window["STATUS"].update(body)
                pass 
        window.close()

        
    
    def userlist_form(self):
        userlistframesize = (50, 80)
        
        layout = [
                [sg.Button("Update")],
                [sg.Output(size=userlistframesize, key="USERLIST")],
                [sg.Button("Close")]
                ]
         
        window = sg.Window("Simple Chat GUI", layout)
        while True:
            event, values = window.read()
            if event == sg.WIN_CLOSED or event == "Close":
                break
            
            elif event == "Update":
                self.userlist = self.ctl.request_userlist()
                if self.userlist == None:
                    print("[!] can't get table")
                    continue
                
                window["USERLIST"].update(value="")
                print("*"*15, "port0", "*"*15)
                for i in self.userlist[1]:
                    print(i)
                
                print("*"*15, "raw", "*"*15)
                for i in self.userlist[2]:
                    print(i)

                pass 
        window.close()


    def messenger_gui(self):
        
        msgsession_t = th.Thread(target=self.connector.session)
        msgsession_t.start() 

        chatframesize   = (80, 20)
        username        = "User : "
        
        layout = [
                [sg.Output(size=chatframesize)],
                [sg.Text(username), sg.InputText(key="VALU"), sg.Button("Send")],
                [sg.Button("Setting"),sg.Button("UserList"),sg.Button("Exit")]
                ]
    
        window = sg.Window("Sample Chat GUI", layout)
        while True:
            event, values = window.read()
            if event == sg.WIN_CLOSED or event == "Exit":
                self.ctl.request_close()
                break
          
            elif event == "Send":
                getvalu = values["VALU"]
                syscmd = getvalu.split("/")
                if len(list(getvalu)) < 1:
                    continue
                # command 
                if len(syscmd) == 2 and syscmd[0] == "":
                    syscmd = syscmd
                    print(syscmd)

                # normal msg    
                else:
                    self.userlist = self.ctl.request_userlist()
                    if self.userlist == None:
                        print("[!] can't get table")
                        continue

                    self.ctl.request_msgsend(getvalu, self.userlist)
                pass 
            elif event == "Setting":
                self.setting_form()

            elif event == "UserList":
                self.userlist_form()    

        window.close()
        
if __name__ == "__main__":
    
    messenger_gui = MESSENFER_GUI() 
    messenger_gui.initial_config_from()

    pass 
