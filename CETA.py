# _______  _______  _______  _______ 
#|       ||       ||       ||   _   |
#|       ||    ___||_     _||  |_|  |
#|       ||   |___   |   |  |       |
#|      _||    ___|  |   |  |       |
#|     |_ |   |___   |   |  |   _   |
#|_______||_______|  |___|  |__| |__|
#CIRCLE ENCRYPTION TRANSFER ALGORITHM
#v3.0 by Scelesto 2013-2014

#GET OTHER MODULES:
import pickle,random,os,logging,shutil,sys,time

#PRIMARY CLASS
class CETA:
    #BASIC FUNCTIONS:
    r=random.randint #CETA.r(a,b): random integer between a and b
    fc="" #current contents of temporary transfer file
    def tobyte(s): #converts "" to b""
        o=b''
        for c in s:
            o+=bytes([ord(c)])
        return o
    def tostr(b): #converts b"" to ""
        o=''
        for c in b:
            o+=chr(c)
        return o
    def s(e): #serialization:  converts an object into a string
        return CETA.tostr(pickle.dumps(e))
    def u(e): #the inverse of CETA.s
        return pickle.loads(CETA.tobyte(e))
    def ko(g,n,c,a=False): #returns a key object based on parameters
        if a==False:
            return {'g':g,'n':n,'c':c}
        return {'g':g,'n':n,'c':c,'a':a}
    hx=['0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'] #Allows conversion of integer to hexadecimal character (e.g. 14->'E')
    def exm(s,e,m): #equivalent to (s**e)%m, but much faster
        n=m #n is set as a clone of the modulus
        #the euler phi function for m is calculated:
        q=1
        u=1
        for i in range(2,int(n/2)):
            while n%i==0:
                if u%i!=0: #if i is a unique prime factor of m
                    q*=i-1
                    u*=i
                n=int(n/i)
            if n<i: #if no more prime factors are possible
                break
        if n>2 and u%n!=0:
            q*=n-1
            u*=n
        p=int((m*q)/u) #phi(m)
        return (s%m)**(e%p))%m
    def shx(s): #converts each character in a string to two hexadecimal characters
        o=""
        h=CETA.hx
        for c in s:
            b=format(ord(c),'b') #converts the character to binary
            b='0'*(8-len(b))+b #makes sure the binary is 8 bits long
            o+=h[int(b[:4],2)]+h[int(b[4:],2)] #splits the binary in two and takes the hexadecimal character for each half
        return o
    def hxs(h): #the inverse of CETA.shx
        o=""
        x=CETA.hx
        for i in range(0,int(len(h)/2)):
            a=format(x.index(h[i*2]),'b') #converts the first hexadecimal character to binary
            b=format(x.index(h[i*2+1]),'b') #converts the second character to binary
            o+=chr(int('0'*(4-len(a))+a+'0'*(4-len(b))+b,2)) #turns the combined binary into a normal character
        return o
    def caesar(hx,mv): #shifts each hexadecimal character in a caesar cipher
        h=CETA.hx
        o=""
        for c in hx:
            o+=h[(h.index(c)+mv)%16]
        return o
    def matsq(a): #treating an array as a square matrix, squares it
        l=int(len(a)**(1/2)) #length of each side
        f=[]
        for i in range(0,len(a)):
            y=i%l #y coordinate in matrix
            x=int(i/l) #x coordinate in matrix
            cy=[]
            cx=[]
            r=0
            for j in range(0,len(a)): #get other numbers with coordinates
                if j%l==y:
                    cy.append(a[j])
                if int(j/l)==x:
                    cx.append(a[j])
            for j in range(0,len(cy)): #multiply and add
                r+=cy[j]*cx[j]
            f.append(r) #place in new matrix
        return f #return resultiing array

    #STORAGE FUNCTIONS:
    fname='ceta_tmp' #the default temp file name
    uname=""
    tname=""
    def enc(e): #encrypts and stores an object
        fname=CETA.fname
        if os.path.isfile(fname): #if the file exists, get rid of it
            os.remove(fname)
        t=CETA.shx(CETA.s(e)) #the object is serialized, then the serialized string is made hexadecimal
        CETA.fc=t #the current file contents is reset to the new object
        return open(fname,'a').write(t) #the encrypted object is put in the file
    def uenc(): #the inverse of CETA.enc
        fname=CETA.fname
        return CETA.u(CETA.hxs(open(fname,'r').read()))
    def rfile(): #if the file exists, get rid of it
        fname=CETA.fname
        if os.path.isfile(fname):
            os.remove(fname)
    def wait(f): #wait for the other system to do its job
        c=False
        fname=CETA.fname
        while c==False:
            if os.path.isfile(fname): #if the file exists
                r=open(fname,'r').read()
                if r!=CETA.fc: #if the contents of the file have changed
                    c=True #the other system is done.  time to work.
                CETA.fc=r #sets the current file contents
            time.sleep(0.1) #makes it less likely for more than one process to access the file simultaneously
        return f() #runs the next part of the algorithm

    #THE CIRCLE ENCRYPTION TRANSFER ALGORITHM:
    #A whole lot of keys are generated throughout the next two steps.
    #Each key is created by sending a lot of random numbers across in a simple version of the discrete logarithm:
    #   On the sender's end:
    #       g, n, and a are random integers
    #       c=(g**a)%n
    #       g, n, and c are sent to the receiver
    #   On the reciever's end:
    #       b is a random integer
    #       d=(g**b)%n
    #       d is sent to the sender
    #   k=(c**b)%n=(d**a)%n
    #   k is used to encode and decode in several ways
    #
    #A hundred sets of "encryptions" are generated.  Each one of these 100 contains the following:
    #   {g,n,a,b,c,d}=>k1 for adding bits to the beggining of a bit string
    #   {g,n,a,b,c,d}=>k2 for adding bits between each bit in a bit string
    #   {g,n,a,b,c,d}=>k3 for caesar ciphering hexadecimals
    #   Each bit is also shifted (mod 2) based on keys selected by modulo out of the possible 300
    #The pack (CETA.d) contains 'e', with the 100 encryption sets, but also involves 'k':
    #   {g,n,a,b,c,d}=>k1 for the number of encryptions to skip before encrypting
    #   {g,n,a,b,c,d}=>k2 for the number of encryptions to skip between each encryption
    def p1(s): #A string is selected and the {g,n,c} sets are sent by the sender
        p={'e':[],'k':[],'p':CETA.uname} #the pack to be sent
        CETA.d={'s':s+'\xa9','e':[],'k':[]} #the pack to be stored
        r=CETA.r #rand
        e=CETA.exm #exp mod
        k=CETA.ko #key obj
        #variables are randomly generated:
        for i in range(0,100):
            g1=r(100,1000)
            n1=r(1000,10000)
            a1=r(1000,10000)
            c1=e(g1,a1,n1)
            g2=r(100,1000)
            n2=r(1000,10000)
            a2=r(1000,10000)
            c2=e(g2,a2,n2)
            g3=r(100,1000)
            n3=r(1000,10000)
            a3=r(1000,10000)
            c3=e(g3,a3,n3)
            s1=[k(g1,n1,c1),k(g2,n2,c2),k(g3,n3,c3)]
            s2=[k(g1,n1,c1,a1),k(g2,n2,c2,a2),k(g3,n3,c3,a3)]
            p['e'].append(s1)
            CETA.d['e'].append(s2)
        g1=r(100,1000)
        n1=r(2,10)
        a1=r(1000,10000)
        c1=e(g1,a1,n1)
        g2=r(100,1000)
        n2=r(20,50)
        a2=r(1000,10000)
        c2=e(g2,a2,n2)
        p['k']=[k(g1,n1,c1),k(g2,n2,c2)]
        CETA.d['k']=[k(g1,n1,c1,a1),k(g2,n2,c2,a2)]
        enc=CETA.enc
        return enc(p) #the pack is encrypted and sent
    def p2(): #the {g,n,c} sets are recieved by the receiver and the {d} sets are sent
        p=CETA.uenc() #the pack is decrypted
        if p['p']!=CETA.tname: #checks for correct connection
            CETA.enc({'p':CETA.uname})
            return False
        CETA.d=CETA.uenc()
        r=CETA.r #rand
        e=CETA.exm #exp mod
        #the variables are randomly generated
        for i in range(0,100):
            d=CETA.d['e'][i]
            c=p['e'][i]
            d[0]['b']=r(1000,10000)
            d[0]['d']=e(d[0]['g'],d[0]['b'],d[0]['n'])
            c[0]=d[0]['d']
            d[1]['b']=r(1000,10000)
            d[1]['d']=e(d[1]['g'],d[1]['b'],d[1]['n'])
            c[1]=d[1]['d']
            d[2]['b']=r(1000,10000)
            d[2]['d']=e(d[2]['g'],d[2]['b'],d[2]['n'])
            c[2]=d[2]['d']
        d=CETA.d['k']
        c=p['k']
        d[0]['b']=r(1000,10000)
        d[0]['d']=e(d[0]['g'],d[0]['b'],d[0]['n'])
        c[0]=d[0]['d']
        d[1]['b']=r(1000,10000)
        d[1]['d']=e(d[1]['g'],d[1]['b'],d[1]['n'])
        c[1]=d[1]['d']
        p['p']=CETA.uname
        return CETA.enc(p) #the pack is encrypted and sent
    #Functions for bit-shifting (used in the next two steps):
    def bitshift(bit,index): #shift a bit based on a key selected using the bit location
        bit=int(bit) #the bit from the string is made an integer 0 or 1.
        kd=CETA.d['e'][index%3][index%100]%2 #the offset is chosen based on the bit's location
        return str((bit+kd)%2) #the offset is added to the bit and returned
    def unbitshift(bit,index): #the inverse of CETA.bitshift
        bit=int(bit)
        kd=CETA.d['e'][index%3][::-1][index%100]%2
        return str((2+bit-kd)%2)
    def p3(): #using the pack of {d} sets, the keys are generated by the sender and the string is encoded
        p=CETA.uenc() #the pack of {d} sets is decrypted
        if p['p']!=CETA.tname: #checks for correct connection
            return False
        e=CETA.exm #exp mod
        d=CETA.d #the stored {a} values
        g=d['k'] #global keys
        h=CETA.hx
        r=CETA.r #rand
        s=d['s'] #the string
        y=CETA.caesar
        c=False
        k1=e(p['k'][0],g[0]['a'],g[0]['n']) #the encryption start offset key
        k2=20+int(e(p['k'][1],g[1]['a'],g[1]['n'])*20/g[1]['n']) #the encryption intermittent offset key
        a=0
        k1s=[]
        k2s=[]
        k3s=[]
        for i in range(0,100): #generate all 300 keys
            sk1=[p['e'][i][0],d['e'][i][0]]
            k1s.append(e(sk1[0],sk1[1]['a'],sk1[1]['n'])) #the string start offset key
            sk2=[p['e'][i][1],d['e'][i][1]]
            k2s.append(e(sk2[0],sk2[1]['a'],sk2[1]['n'])) #the string intermittent offset key
            sk3=[p['e'][i][2],d['e'][i][2]]
            k3s.append(e(sk3[0],sk3[1]['a'],sk3[1]['n'])) #the string caesar cipher key
        #combine key values for resulting keys
        k1s=CETA.matsq(k1s)
        k2s=CETA.matsq(k2s)
        k3s=CETA.matsq(k3s)
        CETA.d['e']=[k1s,k2s,k3s]
        for i in range(0,100): #encrypt the string
            if i<(101-k1) and (99-i-k1)%(k2+1)==0: #if the current encryption fits the parameters defined around the encryption offset keys
                a+=1
                #get the encryption keys
                sk1=k1s[i]%50
                sk2=k2s[i]%5
                sk3=k3s[i]
                bs=''
                q=len(s)
                if c==True: #if the string is hexadecimal, it is caesar cyphered
                    s=y(s,sk3)
                for j in range(0,q): #the string is converted to binary
                    b=format(ord(s[j]),'b')
                    b='0'*(8-len(b))+b
                    bs+=b
                s=''
                for j in range(0,len(bs)):
                    s+=CETA.bitshift(bs[j],j) #each bit in the string is shifted based on its location
                    if i<100-k1:
                        for k in range(0,sk2): #each bit is offset by random bits
                            s+=str(r(0,1))
                if len(s)%4!=0: #make sure the string can be converted to hexadecimal form
                    for i in range(0,4-len(s)%4):
                        s+=str(r(0,1))
                for j in range(0,sk1): #add an offset of random bits to the beginning of the string
                    s=str(r(0,1))+s
                o=""
                for j in range(0,int(len(s)/4)): #the bit string is made hexadecimal
                    o+=h[int((s[4*j:4*j+4]),2)]
                s=o
                c=True #the string is verified as hexadecimal
        return CETA.enc(s) #the encoded string is also encrypted
    def p4(): #the keys are generated by the receiver and the received encoded string is decoded
        s=CETA.uenc() #the string is decrypted
        e=CETA.exm #exp mod
        d=CETA.d #the stored {b} values
        g=d['k'] #global keys
        h=CETA.hx
        r=CETA.r #rand
        c=False
        y=CETA.caesar
        k1=e(g[0]['c'],g[0]['b'],g[0]['n']) #the encryption start offset key
        k2=20+int(e(g[1]['c'],g[1]['b'],g[1]['n'])*20/g[1]['n']) #the encryption intermittent offset key
        k1s=[]
        k2s=[]
        k3s=[]
        for i in range(0,100): #generate all 300 keys
            sk1=d['e'][i][0]
            k1s.append(e(sk1['c'],sk1['b'],sk1['n'])) #the string start offset key
            sk2=d['e'][i][1]
            k2s.append(e(sk2['c'],sk2['b'],sk2['n'])) #the string intermittent offset key
            sk3=d['e'][i][2]
            k3s.append(e(sk3['c'],sk3['b'],sk3['n'])) #the string caesar cipher key
        #combine key values for resulting keys, and the order of the encryptions is reversed (so that the encryptions can be removed in reverse order)
        k1s=CETA.matsq(k1s)[::-1]
        k2s=CETA.matsq(k2s)[::-1]
        k3s=CETA.matsq(k3s)[::-1]
        CETA.d['e']=[k1s,k2s,k3s]
        for i in range(0,100): #decrypt the string
            if i>(k1-1) and (i-k1)%(k2+1)==0:  #if the current encryption fits the parameters defined around the encryption offset keys
                #get the encryption keys
                sk1=k1s[i]%50
                sk2=k2s[i]%5
                sk3=k3s[i]
                bs=''
                for j in range(0,len(s)): #the hexadecimal string is made binary
                    a=format(h.index(s[j]),'b')
                    bs+='0'*(4-len(a))+a
                s=''
                ta=0
                for j in range(0,len(bs[sk1:])):
                    if j%(sk2+1)==0: #for each of the "real" bits (defined by the offset keys):
                        s+=CETA.unbitshift(bs[sk1:][j],ta) #remove the bit shift
                        ta+=1
                o=''
                for j in range(0,int(len(s)/8)): #convert the resulting binary to characters
                    a=chr(int(s[j*8:j*8+8],2))
                    if i<100-k2: #if proper, remove the caesar cipher
                        a=y(a,1600-sk3)
                    o+=a
                s=o
        if s[-1]=='\xa9': #added to the end of all strings because some key combinations remove the last character during the encryption
            s=s[:-1] #remove it if it is the last character
        return s #return the sent string to the receiver

    #SYSTEM FUNCTIONS
    def send(s=False): #run all the parts for the sender
        if(s==False):
            string=input("String to send: ")
        else:
            string=s
        CETA.p1(string)
        e=CETA.wait(CETA.p3)
        if e==False: #if incorrect password
            print("\nSENDING FAILED")
            CETA.rfile()
            return
        print("\nSTRING SENT")
    def receive(): #run all the parts for the receiver
        e=CETA.wait(CETA.p2)
        if e==False: #if incorrect password
            print("\nTRANSFER FAILED")
            return
        print("\nThe string sent was",'"{0}"'.format(CETA.wait(CETA.p4)))
        CETA.rfile()
    xt=False
    def exit(): #exit the interface
        CETA.xt=True
    def update(): #get the latest version of CETA (UNIX ONLY)
        p=sys.path
        for i in p:
            if i.find('.zip')!=-1 or i=="":
                p.remove(i)
        os.system('wget tiny.cc/CETA')
        os.rename('CETA','CETA.py')
        os.remove(p[0]+'/CETA.py')
        shutil.move('CETA.py',p[0])
        print('RELOAD CETA TO CONTINUE')
        os.system('/python3')
    def setup():
        CETA.fname='ceta_tmp_'+input('CONNECTION NAME: ')
        CETA.uname=input('YOUR USERNAME: ')
        CETA.tname=input('CONNECT TO: ')
    def sys(): #get a system command
        cv={'send':CETA.send,'receive':CETA.receive,'help':CETA.help,'exit':CETA.exit,'update':CETA.update,'setup':CETA.setup} #the functions corresponding to system commands
        cmd=input("CETA >>> ") #get the system command
        if cmd.split(' ')[0] in cv: #if the command exists
            if len(cmd.split(' '))>1: #if there is more than one word in the command, pass the content after the first word to the function
                cv[cmd.split(' ')[0].lower()](' '.join(cmd.split(' ')[1:]))
            else:
                cv[cmd.split(' ')[0].lower()]()
        else: #throw an error
            logging.basicConfig(format='%(levelname)s:	%(message)s')
            logging.error('COMMAND NOT FOUND.  TRY "HELP" FOR A LIST OF VALID COMMANDS.')
        print("")
    def help(): #give a list of all valid commands
        print('______\n|HELP|\n******************\n"SEND": send a message to another window\n"RECEIVE": get a message from another window\n"HELP": get help on functions\n"EXIT": exit CETA interface\n"UPDATE": update CETA (UNIX systems only)\n"SETUP": establishes a unique connection')
def init(): #start the system
    CETA.rfile()
    print(" _______  _______  _______  _______ \n|       ||       ||       ||   _   |\n|       ||    ___||_     _||  |_|  |\n|       ||   |___   |   |  |       |\n|      _||    ___|  |   |  |       |\n|     |_ |   |___   |   |  |   _   |\n|_______||_______|  |___|  |__| |__|\nCIRCLE ENCRYPTION TRANSFER ALGORITHM\nv3.0 by Scelesto 2013-2014\n(type 'help' for commands)\n\n")
    while(CETA.xt==False): #if the user does not type "exit"
        CETA.sys() #get a system command
init() #begin CETA code (so that the user only needs to type "import CETA" to begin the system)
