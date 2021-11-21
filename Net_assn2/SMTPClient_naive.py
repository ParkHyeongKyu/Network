import ssl
from socket import *
import base64

username = 'hyeongkyu@postech.ac.kr'
password = ''              # IMPORTANT NOTE!!!!!!!!!!: PLEASE REMOVE THIS FIELD WHEN YOU SUBMIT!!!!!

subject = 'Computer Network Assignment2 - Email Client'
from_ = 'hyeongkyu@postech.ac.kr'
to_ = 'hyeongkyu@postech.ac.kr'
content = 'It is so hard for me!!!'

# Message to send
endmsg = '\r\n.\r\n'

# Choose a mail server (e.g. Google mail server) and call it mailserver
mailserver = 'smtp.office365.com'
port = 587

# 1. Establish a TCP connection with a mail server [2pt]
clientSocket = socket(AF_INET, SOCK_STREAM)
receiveserver = (mailserver, port)
clientSocket.connect(receiveserver)

# 2. Dialogue with the mail server using the SMTP protocol. [2pt]
recv = clientSocket.recv(1024)
print(recv.decode())
if recv.decode()[:3] != '220':
    print('220 reply not reveived from server.')

heloCommand = 'HELO hyeongkyu\r\n'
clientSocket.send(heloCommand.encode())
recv1 = clientSocket.recv(1024)
print(recv1.decode())
if recv1.decode()[:3] != '250':
    print('250 reply not received from server.')

# 3. Login using SMTP authentication using your postech account. [5pt]

# HINT: Send STARTTLS
clientSocket.send('STARTTLS\r\n'.encode())
recv_ST = clientSocket.recv(1024)
print(recv_ST.decode())
if recv_ST.decode()[:3] != '220':
    print('220 reply not reveived from server.')

# HINT: Wrap socket using ssl.PROTOCOL_SSLv23
wrappedSocket = ssl.wrap_socket(clientSocket, ssl_version = ssl.PROTOCOL_SSLv23)

# HINT: Send EHLO
wrappedSocket.send('EHLO smtp.office365.com\r\n'.encode())
recv_el = wrappedSocket.recv(1024)
print(recv_el.decode())
if recv_el.decode()[:3] != '250':
    print('250 reply not received from server')
    
wrappedSocket.send('AUTH LOGIN\r\n'.encode())
recv_au = wrappedSocket.recv(1024)
print(recv_au.decode())
if recv_au.decode()[:3] != '334':
    print('334 reply not received from server')
   
# HINT: Use base64.b64encode for the username and password
un = base64.b64encode(username.encode())
wrappedSocket.send(un)
wrappedSocket.send('\r\n'.encode())
recv_un = wrappedSocket.recv(1024)
print(recv_un.decode())
if recv_un.decode()[:3] != '334':
    print('334 reply not received from server')

upwd = base64.b64encode(password.encode())
wrappedSocket.send(upwd)
wrappedSocket.send('\r\n'.encode())
recv_upwd = wrappedSocket.recv(1024)
print(recv_upwd.decode())
if recv_upwd.decode()[:3] != '235':
    print('235 reply not received from server')

# 4. Send a e-mail to your POSTECH mailbox. [5pt]
mailFrom = "MAIL FROM: " + from_ + "\r\n"
wrappedSocket.send(mailFrom.encode())
recv_MF = wrappedSocket.recv(1024)
print(recv_MF.decode())
if recv_MF.decode()[:3] != '250':
    print('250 reply not received from server.')

rcptTo = "RCPT TO: " + to_ + "\r\n"
wrappedSocket.send(rcptTo.encode())
recv_rT = wrappedSocket.recv(1024)
print(recv_rT.decode())
if recv_rT.decode()[:3] != '250':
    print('250 reply not received from server.')

data = "DATA\r\n"
wrappedSocket.send(data.encode())
recv_data = wrappedSocket.recv(1024)
print(recv_data.decode())
if recv_data.decode()[:3] != '354':
    print('354 reply not received from server.')

Sub = 'Subject: ' + subject + '\r\n\r\n'
wrappedSocket.send(Sub.encode())
wrappedSocket.send(content.encode())
wrappedSocket.send(endmsg.encode())
recv_msg = wrappedSocket.recv(1024)
print(recv_msg.decode())
if recv_msg.decode()[:3] != '250':
    print('250 reply not received from server.')

# 5. Destroy the TCP connection [2pt]
wrappedSocket.send("QUIT\r\n".encode())
recv_q = wrappedSocket.recv(1024)
print (recv_q.decode())
if recv_q.decode()[:3] != '221':
    print('221 reply not received from server.')

clientSocket.close()
