# -*- coding: utf-8 -*-
"""
Created on Fri Apr 17 13:44:40 2020

@author: Mr ABBAS-TURKI
"""



import hashlib
import binascii

def home_mod_expnoent(x, y, n):  # exponentiation modulaire
    (res1,res2)=(1,x)
    while y>0:
        if y%2==1:
            res1=(res1*res2)%n
        res2=(res2*res2)%n
        y=y//2
    return res1

def home_crt(x, d, n, p, q):
    inverse_de_q = home_ext_euclide(q,1)
    dq = home_mod_expnoent(d,1,q-1)
    dp = home_mod_expnoent(d,1,p-1)
    mq = home_mod_expnoent(x,dq,q)
    mp = home_mod_expnoent(x,dp,p)
    h = home_mod_expnoent(((mp-mq)*inverse_de_q),1,p)
    return home_mod_expnoent(mq+ h*q,1,n)

def home_ext_euclide(y, b):  # algorithme d'euclide étendu pour la recherche de l'exposant secret
    (r,nouvr,t,nouvt)=(y,b,0,1)
    while nouvr>1:
        quotient=r//nouvr
        (r, nouvr) = (nouvr, r-quotient*nouvr)
        (t, nouvt) = (nouvt, t-quotient*nouvt)
    return nouvt%y

def home_pgcd(a,b): #recherche du pgcd
    if(b==0): 
        return a 
    else: 
        return home_pgcd(b,a%b)

def home_string_to_int(x): # pour transformer un string en int
    z=0
    for i in reversed(range(len(x))):
        z=int(ord(x[i]))*pow(2,(8*i))+z
    return(z)


def home_int_to_string(x): # pour transformer un int en string
    txt=''
    res1=x
    while res1>0:
        res=res1%(pow(2,8))
        res1=(res1-res)//(pow(2,8))
        txt=txt+chr(res)
    return txt


def mot_taille_max(x1, x2): #entrer le secret
	multiplication = x1*x2
	i = 1
	while(2**i <= multiplication):
		i++
    secret=input("donner un secret de",i/8 ," caractères au maximum : ")
    while (len(secret)>i):
        secret=input("c'est beaucoup trop long,", i/8," caractères S.V.P : ")
    return(secret)
    

#voici les éléments de la clé d'Alice
x1a=7257076010836042774303355278059096448845578496737019090706736221505999323147059280196454206687792743500261374286062653088939444374460843226875563467334228581861626617922669437777542770565225370897008751760858542286570446338115484067652059802246762227608959 #p
x2a=98946588385329343825040137164932730421819843632409099852898524370547800995945556204090966391409048145819588916214643673189056544371683461259232657063447671453647292279822206602926993063878743170010634756931635850602311195355216650745434224241398995280420421 #q
na=x1a*x2a  #n
phia=((x1a-1)*(x2a-1))//home_pgcd(x1a-1,x2a-1)
ea=65537 #exposant public
da=home_ext_euclide(phia,ea) #exposant privé
#voici les éléments de la clé de bob
x1b=7769605967691994716434401820632845628438588820208556892547503109121813233251501520931262183977342003977160199344170946704469448377983550694051820836809087187917441817625928896200470101679929021735032561443994428140500126376007124607937542992512326306161807 #p
x2b=22969204215646651009808423100639403221098867921147976879037222854124904110320743532434867868549264335853563757596004492377463646813930291226643458447706909312781587361449716597023340877850816683700568939660946861164217889672858832849207732271268788414051529 #q
nb=x1b*x2b # n
phib=((x1b-1)*(x2b-1))//home_pgcd(x1b-1,x2b-1)
eb=65537 # exposants public
db=home_ext_euclide(phib,eb) #exposant privé



print("Vous êtes Bob, vous souhaitez envoyer un secret à Alice")
print("voici votre clé publique que tout le monde a le droit de consulter")
print("n =",nb)
print("exposant :",eb)
print("voici votre précieux secret")
print("d =",db)
print("*******************************************************************")
print("Voici aussi la clé publique d'Alice que tout le monde peut conslter")
print("n =",na)
print("exposent :",ea)
print("*******************************************************************")
print("il est temps de lui envoyer votre secret ")
print("*******************************************************************")
x=input("appuyer sur entrer")
secret=mot_taille_max(x1b, x2b)
print("*******************************************************************")
print("voici la version en nombre décimal de ",secret," : ")
num_sec=home_string_to_int(secret)
print(num_sec)
print("voici le message chiffré avec la publique d'Alice : ")
chif=home_mod_expnoent(num_sec, ea, na)
print(chif)
print("*******************************************************************")
print("On utilise la fonction de hashage SHA256 pour obtenir le hash du message",secret)
Bhachis0=hashlib.sha256(secret.encode(encoding='UTF-8',errors='strict')).digest() #MD5 du message
print("voici le hash en nombre décimal ")
Bhachis1=binascii.b2a_uu(Bhachis0)
Bhachis2=Bhachis1.decode() #en string
Bhachis3=home_string_to_int(Bhachis2)
print(Bhachis3)
print("voici la signature avec la clé privée de Bob du hachis")
signe=home_mod_expnoent(Bhachis3, db, nb)
print(signe)
print("*******************************************************************")
print("Bob envoie \n \t 1-le message chiffré avec la clé public d'Alice \n",chif,"\n \t 2-et le hash signé \n",signe)
print("*******************************************************************")
x=input("appuyer sur entrer")
print("*******************************************************************")
print("Alice déchiffre le message chiffré \n",chif,"\nce qui donne ")
dechif=home_int_to_string(home_crt(chif, da, na, x1a, x2a))
print(dechif)
print("*******************************************************************")
print("Alice déchiffre la signature de Bob \n",signe,"\n ce qui donne  en décimal")
designe= home_crt(signe, eb, nb, x1b, x2b)
print(designe)
print("Alice vérifie si elle obtient la même chose avec le hash de ",dechif)
Ahachis0=hashlib.sha256(dechif.encode(encoding='UTF-8',errors='strict')).digest()
Ahachis1=binascii.b2a_uu(Ahachis0)
Ahachis2=Ahachis1.decode()
Ahachis3=home_string_to_int(Ahachis2)
print(Ahachis3)
print("La différence =",Ahachis3-designe)
if (Ahachis3-designe==0):
    print("Alice : Bob m'a envoyé : ",dechif)
else:
    print("oups")