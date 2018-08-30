from secmodule import *

SERVER = ['10.1.0.100']
sites = fetch("fetch.txt")
KEYS = ['24.0.0.1']

transform_set =''
ipsec_profile =''

TN = login(SERVER[0])
phase_1(TN ,sites)
lable = rsa_labl(TN)
transform_set = trans(TN )
ipsec_profile = ipsecprofile(TN ,transform_set )
acl = accessListe(TN)
groupe = GETVPNgroup(TN , " 11111 " ,SERVER[0] ,ipsec_profile ,acl ,lable ,KEYS)
cryptoMap =Cmap(TN ,groupe)

TN.write(b"end" + b"\n")
TN.write(b"exit" + b"\n")
a = TN.read_all()
print(a.decode('utf-8'))


for site in sites :
    GM = login(site)
    phase_1(GM ,KEYS)
    GM.write(b"crypto gdoi group "+groupe.encode('ascii')+ b"\n")
    GM.write(b"identity number "+b" 11111\n")
    GM.write(b"server address ipv4 " +KEYS[0].encode('ascii') + b" \n")
    cryptoMapGM =CmapGM(GM ,groupe ,cryptoMap)
    GM.write(b"int f 0/0 \n")
    GM.write(b"crypto map "+cryptoMapGM.encode('ascii')+b"\n")
    GM.write(b"end" + b"\n")
    GM.write(b"exit" + b"\n")
    x = GM.read_all()
    print(x.decode('utf-8')) 
    #commited frome github
