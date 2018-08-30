import getpass
import sys
import telnetlib

def fetch(file):
    file = open("fetch.txt","r")
    a = []
    for site in file :
        a.append(site)
    return a

def phase_1(tn ,sites):
    tn.write(b"end \n")
    tn.write(b"conf t \n")

    prio = input("Chose Priority of protection suite <1-10000> :")
    tn.write(b"crypto isakmp policy "+prio.encode('ascii') + b"\n")    
    tn.write(b"authentication pre-share\n")
    pre_sh = input("pre-share key :")
    print("[+] authentication pre-share")
    tn.write(b"hash sha" + b"\n") 
    print("[+] Hash SHA ")
    tn.write(b" encryption aes 128 " + b"\n") 
    tn.write(b"group 2 " + b"\n") 
    tn.write(b"lifetime 3600 " + b"\n")
    tn.write(b"exit" + b"\n") 
    
    for site in sites:
        tn.write(b"crypto isakmp key "+ pre_sh.encode('ascii')+ b" address "+ site.encode('ascii')+b"\n")

       
def trans(tn):
    tn.write(b"end \n")
    tn.write(b"conf t \n")
    name = input("transform set name :" )   
    tn.write(b"crypto ipsec transform-set " + name.encode('ascii') + b" esp-aes 128 esp-sha-hmac \n")
    return name 

def ipsecprofile(tn ,TS):
    tn.write(b"end \n")
    tn.write(b"conf t \n")
    name = input("ipsec Profile name :")
    tn.write(b"crypto ipsec profile "+ name.encode('ascii')+ b"\n")
    tn.write(b"set transform-set " + TS.encode('ascii')+b"\n")
    return name 

def accessListe(tn):
    tn.write(b"end \n")
    tn.write(b"conf t \n")

    name =input("name the ACL :")
    tn.write(b"access-list " + name.encode('ascii') +b" permit ip  10.0.0.0 0.255.255.255 10.0.0.0 0.255.255.255  \n")
    
    return name

def login(HOST):
    
    print("Loging ro HOST  >> ",HOST)
    tel = telnetlib.Telnet(HOST)
    user = input(" [ HOST 1 ]>> Enter your telnet user name :")
    password= getpass.getpass()
    tel.read_until(b"Username:")
    tel.write(user.encode('ascii')+ b"\n")
    tel.read_until(b"Password:")
    tel.write(password.encode('ascii')+b"\n")
    return tel 

def rsa_labl(tn):
    tn.write(b"end \n")
    tn.write(b"conf t \n")
    name = input("name the labl : ")
    tn.write(b"crypto key generate rsa modulus 2048 label "+ name.encode('ascii')+ b" exportable\n")
    return name 

def GETVPNgroup(tn ,idnum ,HOST ,profile ,acl ,lable , KS):
    tn.write(b"end \n")
    tn.write(b"conf t \n")

    name = input("GDOI group name : ")
    tn.write(b"crypto gdoi group "+name.encode('ascii')+ b"\n")
    tn.write(b"identity number "+idnum.encode('ascii') +b"\n")

    tn.write(b"server local "+ b"\n")

    tn.write(b"addr ipv4 "+ KS[0].encode('ascii') + b"\n")
    tn.write(b"sa ipsec 1 "+ b"\n")
    tn.write(b"profile "+profile.encode('ascii') +b"\n")
    tn.write(b"match address ipv4 "+ acl.encode('ascii')+ b"\n")
    change= input("mulitcast mode is defualt would like to overwrite it (y/n) :")
    
    if change == 'y' :
        tn.write(b"rekey transport unicast "+ b"\n")
        tn.write(b"rekey authentication mypubkey rsa " +lable.encode('ascii') + b"  \n")
        tn.write(b"rekey algorithm aes 128 "+ b"\n")
        tn.write(b"end"+ b"\n")

    return name 

def Cmap(tn ,groupe):
    tn.write(b"end \n")
    tn.write(b"conf t \n")

    name =input("Crypto Map name :")
    tn.write(b"crypto map "+ name.encode('ascii')+ b" 1 gdoi\n")
    tn.write(b"set group "+groupe.encode('ascii')+ b"\n")
    
    return name

def CmapGM(tn ,groupe ,name):
    tn.write(b"end \n")
    tn.write(b"conf t \n")
    tn.write(b"crypto map "+ name.encode('ascii')+ b" 1 gdoi\n")
    tn.write(b"set group "+groupe.encode('ascii')+ b"\n")
    
    return name

