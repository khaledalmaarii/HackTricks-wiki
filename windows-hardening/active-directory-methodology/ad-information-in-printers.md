<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks क्लाउड ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 ट्विटर 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ ट्विच 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 यूट्यूब 🎥</strong></a></summary>

- क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी को HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS की नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करने की आवश्यकता है? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!

- खोजें [**The PEASS परिवार**](https://opensea.io/collection/the-peass-family), हमारा विशेष संग्रह [**NFTs**](https://opensea.io/collection/the-peass-family)

- प्राप्त करें [**आधिकारिक PEASS और HackTricks swag**](https://peass.creator-spring.com)

- **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में या मुझे **ट्विटर** पर **फ़ॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **अपने हैकिंग ट्रिक्स को [hacktricks रेपो](https://github.com/carlospolop/hacktricks) और [hacktricks-cloud रेपो](https://github.com/carlospolop/hacktricks-cloud) में पीआर जमा करके साझा करें।**

</details>


इंटरनेट पर कई ब्लॉग हैं जो **LDAP के साथ कॉन्फ़िगर किए गए प्रिंटरों को छोड़ने के खतरों को हाइलाइट करते हैं**।
इसका कारण है कि एक हमलावर **प्रिंटर को धोखा दे सकता है और एक रूग LDAP सर्वर के खिलाफ प्रमाणित करने के लिए** (आमतौर पर `nc -vv -l -p 444` पर्याप्त होता है) और प्रिंटर **क्रियाओं को साफ-पाठ में कैप्चर करने के लिए प्रमाणित करने के लिए**।

इसके अलावा, कई प्रिंटर में **उपयोगकर्ता नामों के साथ लॉग** होते हैं या वे डोमेन कंट्रोलर से **सभी उपयोगकर्ता नामों को डाउनलोड करने के लिए सक्षम** हो सकते हैं।

इस **संवेदनशील जानकारी** और सामान्य **सुरक्षा की कमी** के कारण हमलावरों के लिए प्रिंटर बहुत रोचक होते हैं।

इस विषय पर कुछ ब्लॉग:

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

**निम्नलिखित जानकारी** [**https://grimhacker.com/2018/03/09/just-a-printer/**](https://grimhacker.com/2018/03/09/just-a-printer/) से कॉपी की गई थी

# LDAP सेटिंग्स

Konica Minolta प्रिंटरों पर एक LDAP सर्वर को कनेक्ट करने के लिए कॉन्फ़िगर करना संभव है, साथ ही प्रमाणित करने के लिए क्रेडेंशियल्स। इन उपकरणों के फर्मवेयर के पहले संस्करणों में मैंने सुना है कि पृष्ठ के HTML स्रोत को पढ़कर क्रेडेंशियल्स को पुनर्प्राप्त करना संभव है। हालांकि, अब क्रेडेंशियल्स इंटरफ़ेस में वापस नहीं लौटते हैं, इसलिए हमें थोड़ा अधिक मेहनत करनी होगी।

LDAP सर्वरों की सूची नेटवर्क > LDAP सेटिंग > LDAP सेटिंग सेटिंग के तहत है

इंटरफ़ेस को LDAP सर्वर को संशोधित करने की अनुमति है बिना पुनः प्रवेश क्रेडेंशियल्स दर्ज किए जाएंगे जो इस्तेमाल किए जाएंगे। मुझे यह समझना है कि यह एक सरल उपयोगकर्ता अनुभव के लिए है, लेकिन इससे हमलावर को प्रिंटर के मास्टर से डोमेन पर एक टो होल्ड करने का एक अवसर मिलता है।

हम एक मशीन को नियंत्रण करने के लिए LDAP सर्वर पता सेटिंग को पुनर्कॉन्फ़िगर कर सकते हैं, और सहायक "परीक्षण कनेक्शन" कार्यक्षमता के साथ एक कनेक्शन को ट्रिगर कर सकते हैं।

# अच्छी चीजों के लिए सुनना

## नेटकैट

यदि मेरी तुलना में आपको अच्छी भाग्य होता है, तो आप एक सरल नेटकैट सुनने के साथ बच सकते हैं:
```
sudo nc -k -v -l -p 386
```
मुझे [@\_castleinthesky](https://twitter.com/\_castleinthesky) द्वारा यह आश्वासन दिया गया है कि यह अधिकांश समय काम करता है, हालांकि मुझे अभी तक इतनी आसानी से छुटकारा नहीं मिला है।

## Slapd

मुझे पता चला है कि प्रिंटर को पहले एक पूर्ण LDAP सर्वर की आवश्यकता होती है, जहां प्रिंटर पहले एक नल बाइंड का प्रयास करता है और फिर उपलब्ध जानकारी का प्रश्न करता है, केवल यदि ये कार्रवाई सफल होती है तो वह प्रमाणीकरण के साथ बाइंड करता है।

मैंने एक सरल LDAP सर्वर खोजा जो आवश्यकताओं को पूरा करता है, हालांकि वहां सीमित विकल्प थे। अंत में मैंने एक खुला LDAP सर्वर सेटअप करने का विकल्प चुना और स्लैपडी डीबग सर्वर सेवा का उपयोग करके कनेक्शन स्वीकार करने और प्रिंटर से संदेश प्रिंट करने का उपयोग किया। (यदि आपको कोई आसान विकल्प पता हो, तो मुझे खुशी होगी उसके बारे में सुनने की)

### स्थापना

(नोट: इस खंड को यहां [https://www.server-world.info/en/note?os=Fedora\_26\&p=openldap](https://www.server-world.info/en/note?os=Fedora\_26\&p=openldap) के गाइड का हल्का संशोधित संस्करण है)

रूट टर्मिनल से:

**OpenLDAP स्थापित करें,**
```
#> dnf install -y install openldap-servers openldap-clients

#> cp /usr/share/openldap-servers/DB_CONFIG.example /var/lib/ldap/DB_CONFIG

#> chown ldap. /var/lib/ldap/DB_CONFIG
```
**एक OpenLDAP व्यवस्थापक पासवर्ड सेट करें (आपको इसे शीघ्र ही फिर से आवश्यक होगा)**
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
**मूल स्कीमा आयात करें**
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
**LDAP डीबी पर अपने डोमेन नाम सेट करें।**
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

**एसएसएल प्रमाणपत्र बनाएं**
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
**SSL /TLS के लिए Slapd को कॉन्फ़िगर करें**

To configure Slapd for SSL/TLS, follow the steps below:

1. Generate a self-signed certificate or obtain a valid SSL/TLS certificate from a trusted certificate authority (CA).

2. Copy the certificate and private key files to the appropriate directory on the server. The default directory is usually `/etc/ldap/ssl/`.

3. Set the correct permissions for the certificate and private key files to ensure only the LDAP server can access them. Use the following commands:

   ```bash
   chmod 600 /etc/ldap/ssl/cert.pem
   chmod 600 /etc/ldap/ssl/key.pem
   ```

4. Edit the Slapd configuration file, usually located at `/etc/ldap/slapd.conf`, and add the following lines:

   ```bash
   TLSCACertificateFile /etc/ldap/ssl/cert.pem
   TLSCertificateFile /etc/ldap/ssl/cert.pem
   TLSCertificateKeyFile /etc/ldap/ssl/key.pem
   ```

   Make sure to replace `/etc/ldap/ssl/cert.pem` and `/etc/ldap/ssl/key.pem` with the actual paths to your certificate and private key files.

5. Restart the Slapd service to apply the changes:

   ```bash
   systemctl restart slapd
   ```

6. Verify that Slapd is now using SSL/TLS by connecting to the LDAP server using the `ldapsearch` command with the `-ZZ` option:

   ```bash
   ldapsearch -x -H ldap://localhost -ZZ -b "dc=example,dc=com" -D "cn=admin,dc=example,dc=com" -W
   ```

   If the connection is successful, it means that Slapd is now configured to use SSL/TLS.

By following these steps, you can configure Slapd to use SSL/TLS for secure communication.
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
**लोकल फ़ायरवॉल के माध्यम से LDAP को अनुमति दें**
```
firewall-cmd --add-service={ldap,ldaps}
```
## भुगतान

एक बार जब आपने अपनी LDAP सेवा को स्थापित और कॉन्फ़िगर कर लिया है, तो आप इसे निम्नलिखित कमांड के साथ चला सकते हैं:

> ```
> slapd -d 2
> ```

नीचे दिए गए स्क्रीनशॉट में एक उदाहरण दिखाया गया है जब हम प्रिंटर पर कनेक्शन टेस्ट चलाते हैं। जैसा कि आप देख सकते हैं, उपयोगकर्ता नाम और पासवर्ड LDAP क्लाइंट से सर्वर को पास किए जाते हैं।

![slapd टर्मिनल आउटपुट जिसमें उपयोगकर्ता नाम "MyUser" और पासवर्ड "MyPassword" हैं](https://i1.wp.com/grimhacker.com/wp-content/uploads/2018/03/slapd\_output.png?resize=474%2C163\&ssl=1)

# यह कितना खराब हो सकता है?

यह बहुत अधिक उन प्रमाणित को निर्धारित करता है जो कॉन्फ़िगर किए गए हैं।

यदि न्यूनतम अधिकार के सिद्धांत का पालन किया जा रहा है, तो आपको संगठन के कुछ तत्वों के लिए केवल पठनीय पहुंच मिल सकती है। यह अक्सर महत्वपूर्ण होता है क्योंकि आप उस जानकारी का उपयोग करके और अधिक सटीक हमलों को तैयार करने के लिए उसका उपयोग कर सकते हैं।

सामान्यतः आपको डोमेन उपयोगकर्ता समूह में एक खाता मिलेगा जिससे संवेदनशील जानकारी तक पहुंच मिल सकती है या अन्य हमलों के लिए पूर्वापेक्षित प्रमाणीकरण दिया जा सकता है।

या, मेरी तरह, आपको एक LDAP सर्वर स्थापित करने के लिए पुरस्कृत किया जा सकता है और आपको एक डोमेन व्यवस्थापक खाता स्वर्ण प्लेटर पर हाथ में दिया जा सकता है।


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- क्या आप एक **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी कंपनी को **HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आप **PEASS के नवीनतम संस्करण का उपयोग करना चाहते हैं या HackTricks को PDF में डाउनलोड करना चाहते हैं**? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!

- खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष [**NFT**](https://opensea.io/collection/the-peass-family) संग्रह

- प्राप्त करें [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या मुझे **ट्विटर** पर **फ़ॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **अपने हैकिंग ट्रिक्स को [hacktricks रेपो](https://github.com/carlospolop/hacktricks) और [hacktricks-cloud रेपो](https://github.com/carlospolop/hacktricks-cloud) में पीआर जमा करके अपना योगदान दें।**

</details>
