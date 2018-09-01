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

        

def trans(tn ,trans_seted):
    tn.write(b"end \n")
    tn.write(b"conf t \n")
    if trans_seted:
        tn.write(b"crypto ipsec transform-set " + trans_seted.encode('ascii') + b" esp-aes 128 esp-sha-hmac \n")
    else:
        name = input("transform set name :" )   
        tn.write(b"crypto ipsec transform-set " + name.encode('ascii') + b" esp-aes 128 esp-sha-hmac \n")
    return name 

def ipsecprofile(tn ,TS ,profile_seted):
    tn.write(b"end \n")
    tn.write(b"conf t \n")
    if profile_seted :
        tn.write(b"crypto ipsec profile "+profile_seted.encode('ascii')+ b"\n")
        tn.write(b"set transform-set " + TS.encode('ascii')+b"\n")
    else:
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
   


def exportkey(tn ,label):
    tn.write(b"end \n")
    tn.write(b"conf t \n")

    tn.write(b"crypto key export rsa " + label.encode('ascii') + b" pem terminal 3des DEFAULT \n")
    tn.write(b"end \n")
    tn.write(b"exit \n")

def importkey(tn ,label):
    tn.write(b"end \n")
    tn.write(b"conf t \n")

    tn.write(b"crypto key import rsa " + label.encode('ascii') + b"  terminal  DEFAULT \n")
    tn.write(b"end \n")
    tn.write(b"exit \n")
   

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
def redendancy(server1 ,server2 ,group):
    hubs = [server1 , server2]
    for i in range(2) :
        hub_tn=login(hubs[i])
        hub_tn.write(b"end \n")
        hub_tn.write(b"conf t \n")
        hub_tn.write(b"crypto gdoi group " + group.encode('ascii') +b" \n")
        hub_tn.write(b"server local  \n")
        hub_tn.write(b"redundancy  \n")
        priority = input("server priority :")
        hub_tn.write(b"local priority "+ priority.encode('ascii')+ b"\n")
        hub_tn.write(b"peer address ipv4 " + hubs[int(not i ) ].encode('ascii') +b" \n")
        hub_tn.write(b"end \n")
        hub_tn.write(b"exit \n")

def importkeys(host1,host2):
    ks = login(host1)
    ks.write(b"conf t \n")
    ks.write(b"crypto key export rsa  ll pem terminal 3des password\n")
    ks.write(b"end \n")
    ks.write(b"exit \n")
    keys = ks.read_all()
    keys = keys.decode('utf-8')
    begin_pub = keys.find("-----BEGIN PUBLIC KEY-----")
    end_pub = keys.find("-----END PUBLIC KEY-----")+ len("-----END PUBLIC KEY-----")
    begin_pr = keys.find("-----BEGIN RSA PRIVATE KEY-----")
    end_pr = keys.find("-----END RSA PRIVATE KEY-----") + len("-----END RSA PRIVATE KEY-----")
    
    cp = login(host2)
    print (" [-] importing ...")
    cp.write(b"conf t \n")
    cp.write(b"crypto key import rsa ll pem terminal password\n")
    cp.write(keys[begin_pub:end_pub].encode('ascii') + b"\n")
    cp.write(b"\n")
    cp.write(keys[begin_pr:end_pr].encode('ascii') + b"\n")
    cp.write(b"quit\n")
    cp.write(b"end \n")
    cp.write(b"exit \n")
    sho = cp.read_all()
    sho = sho.decode('utf-8')

    state = sho.find("% Key pair import succeeded.")
    if state == -1 :
        print("importing field !!!!")
    else:
        return sho[state:]
print(importkeys("10.1.0.100","10.1.0.200"))

