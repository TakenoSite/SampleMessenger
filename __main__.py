import sys

# Messenger lib
from messenger import UTIL, CONNECTOR 


ntype = ["RAW", "PORT0"]

if __name__ == "__main__":
    # SESSION ADDR 
    HOST    = "127.0.0.1"
    PORT    = 12345
    
    # RAWNODE ONLY
    SPORT = 4444

    addr    = (HOST, PORT)
    
    # SESSION CONNECTION
    NODE_TYPE   = ntype[1] # port0 or raw 
    
    if NODE_TYPE == "PORT0":
        connector   = CONNECTOR(addr, NODE_TYPE)
    if NODE_TYPE == "RAW":
        connector   = CONNECTOR(addr, NODE_TYPE, SPORT)
    
    connection  = connector.connect()
    

    if connection == None:
        sys.exit() 
        pass 
    
    sockinfo = connection.getsockname() # (host, port)
    
    # RUN IT 
    connector.session()
    
    pass 

