import _thread
import time
import socket

def newclient( clientName, requeststr):
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect(('localhost', 18888))
  s.send(bytes(requeststr.encode("ascii")))
  response = []
  while True:
    data = s.recv(1024)
    if data:
      response += data
    else:
      break
  
  s.close()
  print(clientName, bytes(response[:21]).decode("ascii"))
  print()
  print()



# Create two threads as follows
try:
   _thread.start_new_thread( newclient, ("Client-1", "GET /hypertext/WWW/TheProject.html HTTP/1.0\r\nHost: info.cern.ch\r\n\r\n") )
   _thread.start_new_thread( newclient, ("Client-2", "GET eng.alexu.edu.eg/ HTTP/1.0\r\n\r\n") )
   _thread.start_new_thread( newclient, ("Client-3", "GET eng.alexu.edu.eg/ HTTP/1.0\r\n\r\n") )
   _thread.start_new_thread( newclient, ("Client-4", "GET /hypertext/WWW/TheProject.html HTTP/1.0\r\nHost: info.cern.ch\r\n\r\n") )
   _thread.start_new_thread( newclient, ("Client-5", "GET /hypertext/WWW/TheProject.html HTTP/1.0\r\nHost: info.cern.ch\r\n\r\n") )

except:
   print("Error: unable to start thread")

while 1:
   pass