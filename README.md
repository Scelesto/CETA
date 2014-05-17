 _______  _______  _______  _______ 
|       ||       ||       ||   _   |
|       ||    ___||_     _||  |_|  |
|       ||   |___   |   |  |       |
|      _||    ___|  |   |  |       |
|     |_ |   |___   |   |  |   _   |
|_______||_______|  |___|  |__| |__|
CIRCLE ENCRYPTION TRANSFER ALGORITHM
v3.0 by Scelesto 2013-2014

README:

CETA sends a very secure message between users.
WHAT CETA DOES DO:
  Is secure against other users on the server
WHAT CETA DOES NOT DO:
  Save messages anywhere
  Protect against the NSA or other people that can access your computer's outgoing connections

Run the program on a shared server.
Enter commands by typing and pressing enter.
You can view all commands by entering "help".
Commands are case-insensitive.
Commands:
"Send":
  Securely sends a message to another person
  Examples:
    CETA >>> send
    String to send: Hello, World!
    
    STRING SENT
    
    CETA >>> send Hello, World!
    
    STRING SENT
"Receive":
  Receives a secure message
  Examples:
    CETA >>> receive
    
    The string sent was "Hello, World!"
"Help":
  Gets help on commands
"Exit":
  Stops CETA from running.  It can be relaunched from python with CETA.init()
"Update":
  If you've installed CETA on a UNIX server, update to the most recent version.
"Setup":
  For added security, connect to one specific user
  Agree with another user beforehand on:
    a. A Connection Name
    b. Usernames for both of you
  Examples:
    CETA >>> setup
    CONNECTION NAME: fight_club_73
    YOUR USERNAME: Brad_Pitt
    CONNECT TO: Edward_Norton
    
    CETA >>> send
    String to send: 11:00 Monday.
    
    STRING SENT
    
    (say here username John_Wayne tried to access your message)
    
    CETA >>> send
    String to send: Make it 11:45.
    
    SENDING FAILED
    
    (say you tried to connect to a message with an attempted interception)
    
    CETA >>> receive
    
    TRANSFER FAILED
You can install CETA on a shared server with SSH access.
Instructions:
install an SSH client (I recommend Bitvise) and connect to a server both you and another person have access to.
Enter the following commands:
------------- Install Python 3.3
sudo apt-get install build-essential
sudo apt-get install libsqlite3-dev
sudo apt-get install sqlite3
sudo apt-get install bzip2 libbz2-dev
wget http://www.python.org/ftp/python/3.3.5/Python-3.3.5.tar.xz
tar xJf ./Python-3.3.5.tar.xz
cd ./Python-3.3.5
./configure --prefix=/opt/python3.3
make && sudo make install
mkdir ~/bin
ln -s /opt/python3.3/bin/python3.3 ~/bin/py
cp /opt/python3.3/bin/python3 /python
-------------
------------- Install CETA
/python
import sys,os,shutil
os.system('wget tiny.cc/CETA')
os.rename('CETA','CETA.py')
shutil.move('CETA.py','/opt/python3.3/lib/python3.3')
-------------
Both you and the other person need to open CETA.
------------- Launch CETA
/python
import CETA
-------------
