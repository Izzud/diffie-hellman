import socket
import sys
import time
import threading
import math
from Crypto.Util import number
import DESu

#prime, base = 30490749266330389392595715717294135890580836955093867999251611818450650607285816060329388005481680302895750792234614822315643249838238669419979524647091832305567572205614736763908039667286382570664240267758075816928465592223865159904157526579524306768829520446450509533251360281931769490875123321161816479401075540746951478460346114143472684379318955492903666864885714968889366434949770653403757329663715536834703400545434459489056736910528503900935892695782550578171140107252596041472235162352264124223747097296313535215400324379396683429178824582682444776952340943961278098017593074510852441676910972633534243654869, 1409451149971487071565020033223786426774842343

prime, base, B = 0, 0, 0

key = '0'

# generate random prime number
private = number.getPrime(128)


class Server(threading.Thread):

    def run(self):

        des = DESu.DES()

        self.sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

        print ("Server started successfully\n")

        hostname='0.0.0.0'
        port=54732

        # starts listening server
        self.sock.bind((hostname,port))
        self.sock.listen(1)

        print ("Listening on port %d\n" %port )       

        # waiting peer to connect
        (clientname,address) = self.sock.accept()

        print ("Incoming connection from %s\n" % str(address))

        global prime, base, key, B

        if prime == 0:
            chunk = clientname.recv(4096)
            print(chunk.decode('utf-8'))
            prime = int(chunk.decode('utf-8'))
            
            chunk = clientname.recv(4096)
            base = int(chunk.decode('utf-8'))
            print(chunk.decode('utf-8'))

        # get g^b mod n and key
        chunk = clientname.recv(4096)
        B = int(chunk.decode('utf-8'))

        key = str(pow(B, private, prime))

        # print('Key: ' + key + '\n')

        print('Key get!\n')


        while 1:
            chunk = clientname.recv(4096)

            if len(chunk) == 0:
                exit()

            chunk = chunk.decode('utf-8')

            print(str(address) + ' sent: ' + chunk)
            print("(Hex): {}".format(chunk.encode('utf-8').hex()))

            # decrypt
            decrypted = des.decrypt(key, chunk)

            if(decrypted == 'exit'):
                break
                        
            print ('decrypted: ' + decrypted + '\n')

class Client(threading.Thread):    

    def connect(self,host,port):
        self.sock.connect((host,port))

    def client(self,host,port,msg):
        smg = bytes(msg, encoding = 'utf-8')
        sent = self.sock.send(smg)           
        print ("Message sent\n")

    def run(self):

        des = DESu.DES()

        self.sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)

        try:
            host = input("Enter the hostname\n>>")            
            port = int(input("Enter the port\n>>"))
        except EOFError:
            print ("Error connecting to peer")
            return 1

        # connect to peer
        print ("\nConnecting..\n")
        self.connect(host,port)
        print ("Connected\n")


        # generate prime(n) and base(g) and send it to peer
        global prime, base
        if prime == 0:
            prime = number.getPrime(2048)
            base = number.getPrime(256)

            msg = str(prime)
            self.client(host, port, msg)

            msg = str(base)
            self.client(host, port, msg)

        A = pow(base, private, prime)

        msg = str(A)
        self.client(host, port, msg)

        while key == '0':
            print('Waiting for peer to connect...\n')
            time.sleep(2)

        while 1:            
            plain = input()

            cipher_text = des.encrypt(key, plain)

            if plain == 'exit':
                self.client(host, port, cipher_text)
                break

            if cipher_text=='':
                continue

            print ("{} {} to peer..".format('Sending', cipher_text))

            self.client(host,port,cipher_text)

        return(1)

if __name__=='__main__':

    srv = Server()
    srv.daemon = True

    print ("Starting server..")
    srv.start()

    time.sleep(2)

    print ("Starting client..")
    cli = Client()

    cli.start()