from secmodule import *

sites = fetch("fetch.txt")
KEYS = ['24.0.0.1']
COOP =['23.0.0.1']
  
transform_set =''

ipsec_profile =''

#configuring key server 
TN = login(KEYS[0])

phase_1(TN ,sites)

lable = rsa_labl(TN)

transform_set = trans(TN ,transform_set)

ipsec_profile = ipsecprofile(TN ,transform_set ,ipsec_profile)

acl = accessListe(TN)

groupe = GETVPNgroup(TN , " 11111 " ,KEYS[0] ,ipsec_profile ,acl ,lable ,KEYS)

cryptoMap =Cmap(TN ,groupe)

TN.write(b"end" + b"\n")
TN.write(b"exit" + b"\n")
a = TN.read_all()
print(a.decode('utf-8'))

#configuring coop server 

importkeys(KEYS[0] ,COOP[0])
CP = login(COOP[0])
phase_1(CP ,KEYS)

trans(CP ,transform_set)
ipsecprofile(CP , transform_set , ipsec_profile)

accessListe(CP)

GETVPNgroup(CP ," 11111 " ,COOP[0] ,ipsec_profile ,acl ,lable ,COOP[0])

Cmap(CP ,groupe) 

#ADDING REDENDANCY 
redendancy(KEYS[0] ,COOP[0] , groupe)

#Configuring GMs

for site in sites :
    GM = login(site)
    phase_1(GM ,KEYS)
    GM.write(b"crypto gdoi group "+groupe.encode('ascii')+ b"\n")
    GM.write(b"identity number "+b" 11111\n")
    GM.write(b"server address ipv4 " +KEYS[0].encode('ascii') + b" \n")
    GM.write(b"server address ipv4 " +COOP[0].encode('ascii') + b" \n")
    cryptoMapGM =CmapGM(GM ,groupe ,cryptoMap)
    GM.write(b"int f 0/0 \n")
    GM.write(b"crypto map "+cryptoMapGM.encode('ascii')+b"\n")
    GM.write(b"end" + b"\n")
    GM.write(b"exit" + b"\n")
    x = GM.read_all()
    print(x.decode('utf-8')) 