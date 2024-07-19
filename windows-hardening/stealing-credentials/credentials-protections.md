# Windows Credentials Protections

## Credentials Protections

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

## WDigest

Protokol [WDigest](https://technet.microsoft.com/pt-pt/library/cc778868\(v=ws.10\).aspx?f=255\&MSPPError=-2147217396), uveden sa Windows XP, dizajniran je za autentifikaciju putem HTTP protokola i je **omogućen po defaultu na Windows XP do Windows 8.0 i Windows Server 2003 do Windows Server 2012**. Ova podrazumevana postavka rezultira u **čuvanju lozinki u običnom tekstu u LSASS** (Local Security Authority Subsystem Service). Napadač može koristiti Mimikatz da **izvuče ove kredencijale** izvršavanjem:
```bash
sekurlsa::wdigest
```
Da biste **isključili ili uključili ovu funkciju**, registri _**UseLogonCredential**_ i _**Negotiate**_ unutar _**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ moraju biti postavljeni na "1". Ako su ovi ključevi **odsutni ili postavljeni na "0"**, WDigest je **onemogućen**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA zaštita

Počevši od **Windows 8.1**, Microsoft je poboljšao bezbednost LSA da **blokira neovlašćene čitanja memorije ili injekcije koda od strane nepouzdanih procesa**. Ovo poboljšanje ometa tipično funkcionisanje komandi kao što je `mimikatz.exe sekurlsa:logonpasswords`. Da bi se **omogućila ova poboljšana zaštita**, vrednost _**RunAsPPL**_ u _**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ treba prilagoditi na 1:
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Bypass

Moguće je zaobići ovu zaštitu koristeći Mimikatz drajver mimidrv.sys:

![](../../.gitbook/assets/mimidrv.png)

## Credential Guard

**Credential Guard**, funkcija ekskluzivna za **Windows 10 (Enterprise i Education edicije)**, poboljšava sigurnost mašinskih kredencijala koristeći **Virtual Secure Mode (VSM)** i **Virtualization Based Security (VBS)**. Iskorišćava CPU virtuelizacione ekstenzije da izoluje ključne procese unutar zaštićenog memorijskog prostora, daleko od dometa glavnog operativnog sistema. Ova izolacija osigurava da čak ni kernel ne može pristupiti memoriji u VSM, efikasno štiteći kredencijale od napada poput **pass-the-hash**. **Local Security Authority (LSA)** funkcioniše unutar ovog sigurnog okruženja kao trustlet, dok **LSASS** proces u glavnom OS-u deluje samo kao komunikator sa VSM-ovim LSA.

Podrazumevano, **Credential Guard** nije aktivan i zahteva ručnu aktivaciju unutar organizacije. Ključno je za poboljšanje sigurnosti protiv alata poput **Mimikatz**, koji su ometeni u svojoj sposobnosti da izvuku kredencijale. Međutim, ranjivosti se i dalje mogu iskoristiti dodavanjem prilagođenih **Security Support Providers (SSP)** za hvatanje kredencijala u čistom tekstu tokom pokušaja prijavljivanja.

Da biste proverili status aktivacije **Credential Guard**, može se pregledati registracioni ključ _**LsaCfgFlags**_ pod _**HKLM\System\CurrentControlSet\Control\LSA**_. Vrednost "**1**" označava aktivaciju sa **UEFI zaključavanjem**, "**2**" bez zaključavanja, a "**0**" označava da nije omogućeno. Ova registraciona provera, iako je jak pokazatelj, nije jedini korak za omogućavanje Credential Guard-a. Detaljna uputstva i PowerShell skripta za omogućavanje ove funkcije dostupni su online.
```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Za sveobuhvatno razumevanje i uputstva o omogućavanju **Credential Guard** u Windows 10 i njegovoj automatskoj aktivaciji u kompatibilnim sistemima **Windows 11 Enterprise i Education (verzija 22H2)**, posetite [Microsoftovu dokumentaciju](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Dalji detalji o implementaciji prilagođenih SSP-ova za hvatanje kredencijala su navedeni u [ovom vodiču](../active-directory-methodology/custom-ssp.md).

## RDP RestrictedAdmin Mode

**Windows 8.1 i Windows Server 2012 R2** su uveli nekoliko novih bezbednosnih funkcija, uključujući _**Restricted Admin mode za RDP**_. Ovaj režim je dizajniran da poboljša bezbednost smanjenjem rizika povezanih sa [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/) napadima.

Tradicionalno, kada se povežete na udaljeni računar putem RDP-a, vaši kredencijali se čuvaju na ciljnim mašinama. Ovo predstavlja značajan bezbednosni rizik, posebno kada se koriste računi sa povišenim privilegijama. Međutim, uvođenjem _**Restricted Admin mode**_, ovaj rizik je značajno smanjen.

Kada započnete RDP vezu koristeći komandu **mstsc.exe /RestrictedAdmin**, autentifikacija na udaljeni računar se vrši bez čuvanja vaših kredencijala na njemu. Ovaj pristup osigurava da, u slučaju infekcije malverom ili ako zlonameran korisnik dobije pristup udaljenom serveru, vaši kredencijali nisu kompromitovani, jer nisu sačuvani na serveru.

Važno je napomenuti da u **Restricted Admin mode**, pokušaji pristupa mrežnim resursima iz RDP sesije neće koristiti vaše lične kredencijale; umesto toga, koristi se **identitet mašine**.

Ova funkcija predstavlja značajan korak napred u obezbeđivanju veza sa udaljenim desktopom i zaštiti osetljivih informacija od izlaganja u slučaju bezbednosnog proboja.

![](../../.gitbook/assets/RAM.png)

Za detaljnije informacije posetite [ovaj resurs](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Cached Credentials

Windows obezbeđuje **domen kredencijale** putem **Local Security Authority (LSA)**, podržavajući procese prijavljivanja sa bezbednosnim protokolima kao što su **Kerberos** i **NTLM**. Ključna karakteristika Windows-a je njegova sposobnost da kešira **poslednjih deset domen prijava** kako bi osigurao da korisnici i dalje mogu pristupiti svojim računarima čak i ako je **domen kontroler van mreže**—što je korisno za korisnike laptopova koji često nisu u mreži svoje kompanije.

Broj keširanih prijava se može prilagoditi putem specifičnog **registry ključa ili grupne politike**. Da biste pregledali ili promenili ovu postavku, koristi se sledeća komanda:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Access to these cached credentials is tightly controlled, with only the **SYSTEM** account having the necessary permissions to view them. Administrators needing to access this information must do so with SYSTEM user privileges. The credentials are stored at: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** can be employed to extract these cached credentials using the command `lsadump::cache`.

For further details, the original [source](http://juggernaut.wikidot.com/cached-credentials) provides comprehensive information.

## Protected Users

Membership in the **Protected Users group** introduces several security enhancements for users, ensuring higher levels of protection against credential theft and misuse:

* **Delegacija kredencijala (CredSSP)**: Čak i ako je postavka Grupa politika za **Dozvoli delegiranje podrazumevanih kredencijala** omogućena, plain text kredencijali za Zaštićene korisnike neće biti keširani.
* **Windows Digest**: Počevši od **Windows 8.1 i Windows Server 2012 R2**, sistem neće keširati plain text kredencijale Zaštićenih korisnika, bez obzira na status Windows Digest-a.
* **NTLM**: Sistem neće keširati plain text kredencijale Zaštićenih korisnika ili NT jednosmerne funkcije (NTOWF).
* **Kerberos**: Za Zaštićene korisnike, Kerberos autentifikacija neće generisati **DES** ili **RC4 ključeve**, niti će keširati plain text kredencijale ili dugoročne ključeve nakon inicijalne akvizicije Ticket-Granting Ticket (TGT).
* **Offline prijavljivanje**: Zaštićeni korisnici neće imati keširan verifikator kreiran prilikom prijavljivanja ili otključavanja, što znači da offline prijavljivanje nije podržano za ove naloge.

Ove zaštite se aktiviraju u trenutku kada se korisnik, koji je član **grupe Zaštićenih korisnika**, prijavi na uređaj. Ovo osigurava da su kritične mere bezbednosti na mestu kako bi se zaštitili od različitih metoda kompromitacije kredencijala.

For more detailed information, consult the official [documentation](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).

**Table from** [**the docs**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

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
