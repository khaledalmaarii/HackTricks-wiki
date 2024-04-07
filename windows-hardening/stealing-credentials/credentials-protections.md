# Zaštita Windows akreditacija

## Zaštita akreditacija

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## WDigest

Protokol [WDigest](https://technet.microsoft.com/pt-pt/library/cc778868\(v=ws.10\).aspx?f=255\&MSPPError=-2147217396), predstavljen sa Windows XP-om, dizajniran je za autentifikaciju putem HTTP protokola i **podrazumevano je omogućen na Windows XP-u do Windows 8.0 i Windows Server 2003 do Windows Server 2012**. Ovo podrazumevano podešavanje rezultira **skladištenjem lozinki u tekstualnom formatu u LSASS-u** (Local Security Authority Subsystem Service). Napadač može koristiti Mimikatz da **izvuče ove akreditacije** izvršavanjem:
```bash
sekurlsa::wdigest
```
Da biste **uključili ili isključili ovu funkciju**, registarski ključevi _**UseLogonCredential**_ i _**Negotiate**_ unutar _**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ moraju biti postavljeni na "1". Ako ovi ključevi **nedostaju ili su postavljeni na "0"**, WDigest je **onemogućen**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## Zaštita LSA

Počevši od **Windows 8.1**, Microsoft je poboljšao sigurnost LSA-e kako bi **blokirao neovlašćeno čitanje memorije ili ubacivanje koda od nepoverenih procesa**. Ovo poboljšanje ometa tipično funkcionisanje komandi poput `mimikatz.exe sekurlsa:logonpasswords`. Da biste **omogućili ovu poboljšanu zaštitu**, vrednost _**RunAsPPL**_ u _**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ treba podešena na 1:
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Bypass

Moguće je zaobići ovu zaštitu korišćenjem Mimikatz drajvera mimidrv.sys:

![](../../.gitbook/assets/mimidrv.png)

## Zaštita akreditiva

**Zaštita akreditiva**, funkcija ekskluzivna za **Windows 10 (Enterprise i Education izdanja)**, poboljšava sigurnost mašinskih akreditiva korišćenjem **Virtual Secure Mode (VSM)** i **Virtualization Based Security (VBS)**. Koristi proširenja za virtualizaciju CPU-a kako bi izolovala ključne procese unutar zaštićenog memorijskog prostora, daleko od dosega glavnog operativnog sistema. Ova izolacija osigurava da čak ni jezgro ne može pristupiti memoriji u VSM-u, efikasno štiteći akreditive od napada poput **pass-the-hash**. **Local Security Authority (LSA)** funkcioniše unutar ovog sigurnog okruženja kao trustlet, dok proces **LSASS** u glavnom OS-u deluje samo kao komunikator sa LSA-om VSM-a.

Po podrazumevanim podešavanjima, **Zaštita akreditiva** nije aktivna i zahteva ručno aktiviranje unutar organizacije. Ključno je za poboljšanje sigurnosti protiv alata poput **Mimikatz**, koji su ometeni u sposobnosti izvlačenja akreditiva. Međutim, ranjivosti i dalje mogu biti iskorišćene dodavanjem prilagođenih **Security Support Providers (SSP)** za hvatanje akreditiva u čistom tekstu tokom pokušaja prijavljivanja.

Za proveru statusa aktivacije **Zaštite akreditiva**, može se pregledati registarski ključ _**LsaCfgFlags**_ pod _**HKLM\System\CurrentControlSet\Control\LSA**_. Vrednost "**1**" označava aktivaciju sa **UEFI zaključavanjem**, "**2**" bez zaključavanja, a "**0**" označava da nije omogućeno. Ova provera registra, iako snažan pokazatelj, nije jedini korak za omogućavanje Zaštite akreditiva. Detaljno uputstvo i PowerShell skripta za omogućavanje ove funkcije dostupni su na mreži.
```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Za sveobuhvatno razumevanje i uputstva o omogućavanju **Credential Guard**-a u Windows 10 i njegovoj automatskoj aktivaciji na kompatibilnim sistemima **Windows 11 Enterprise i Education (verzija 22H2)**, posetite [Microsoftovu dokumentaciju](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Dodatne detalje o implementaciji prilagođenih SSP-ova za hvatanje akreditiva pružene su u [ovom vodiču](../active-directory-methodology/custom-ssp.md).

## RDP RestrictedAdmin režim

**Windows 8.1 i Windows Server 2012 R2** su uveli nekoliko novih sigurnosnih funkcija, uključujući _**Restricted Admin režim za RDP**_. Ovaj režim je dizajniran da poboljša sigurnost smanjenjem rizika povezanih sa [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/) napadima.

Tradiconalno, prilikom povezivanja sa udaljenim računarom putem RDP-a, vaše akreditacije se čuvaju na ciljnom računaru. Ovo predstavlja značajan sigurnosni rizik, posebno prilikom korišćenja naloga sa povišenim privilegijama. Međutim, sa uvođenjem _**Restricted Admin režima**_, ovaj rizik je značajno smanjen.

Prilikom pokretanja RDP veze korišćenjem komande **mstsc.exe /RestrictedAdmin**, autentikacija ka udaljenom računaru se vrši bez čuvanja vaših akreditacija na njemu. Ovaj pristup osigurava da, u slučaju infekcije malverom ili ako zlonamerni korisnik dobije pristup udaljenom serveru, vaše akreditacije nisu kompromitovane, jer nisu sačuvane na serveru.

Važno je napomenuti da u **Restricted Admin režimu**, pokušaji pristupa mrežnim resursima iz RDP sesije neće koristiti vaše lične akreditacije; umesto toga, koristi se **identitet mašine**.

Ova funkcija predstavlja značajan korak napred u obezbeđivanju sigurnosti veza sa udaljenim radnim površinama i zaštiti osetljivih informacija od izlaganja u slučaju sigurnosnog propusta.

![](../../.gitbook/assets/RAM.png)

Za detaljnije informacije posetite [ovaj resurs](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Keširane akreditacije

Windows obezbeđuje **domenske akreditacije** putem **Local Security Authority (LSA)**, podržavajući procese prijavljivanja sigurnosnim protokolima poput **Kerberos** i **NTLM**. Ključna karakteristika Windows-a je njegova sposobnost keširanja **poslednjih deset domenskih prijava** kako bi se osiguralo da korisnici i dalje mogu pristupiti svojim računarima čak i ako je **kontroler domena offline**—prednost za korisnike laptopova koji su često van mreže svoje kompanije.

Broj keširanih prijava se može podešavati putem određenog **registarskog ključa ili grupe pravila**. Za pregled ili promenu ovog podešavanja koristi se sledeća komanda:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Pristup ovim keširanim akreditacijama strogo je kontrolisan, pri čemu samo **SYSTEM** nalog ima neophodne dozvole da ih pregleda. Administratori koji trebaju pristupiti ovim informacijama moraju to učiniti sa privilegijama korisnika SYSTEM. Akreditacije se čuvaju na: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** se može koristiti za izvlačenje ovih keširanih akreditacija korišćenjem komande `lsadump::cache`.

Za dalje detalje, originalni [izvor](http://juggernaut.wikidot.com/cached-credentials) pruža sveobuhvatne informacije.

## Zaštićeni korisnici

Članstvo u **Zaštićenim korisnicima grupi** uvodi nekoliko bezbednosnih poboljšanja za korisnike, osiguravajući više nivoa zaštite od krađe i zloupotrebe akreditacija:

* **Delegiranje akreditacija (CredSSP)**: Čak i ako je postavka Grupe politika za **Dozvoli delegiranje podrazumevanih akreditacija** omogućena, tekstualne akreditacije Zaštićenih korisnika neće biti keširane.
* **Windows Digest**: Počevši od **Windows 8.1 i Windows Server 2012 R2**, sistem neće keširati tekstualne akreditacije Zaštićenih korisnika, bez obzira na status Windows Digest-a.
* **NTLM**: Sistem neće keširati tekstualne akreditacije ili NT jednosmjerne funkcije (NTOWF) Zaštićenih korisnika.
* **Kerberos**: Za Zaštićene korisnike, Kerberos autentifikacija neće generisati **DES** ili **RC4 ključeve**, niti će keširati tekstualne akreditacije ili dugoročne ključeve izvan početnog dobijanja Ticket-Granting Ticket (TGT).
* **Offline prijava**: Zaštićeni korisnici neće imati keširan verifikator kreiran prilikom prijave ili otključavanja, što znači da offline prijava nije podržana za ove naloge.

Ove zaštite se aktiviraju čim se korisnik, koji je član **Zaštićenih korisnika grupe**, prijavi na uređaj. Ovo osigurava da su kritične bezbednosne mere na snazi kako bi se zaštitili od različitih metoda kompromitovanja akreditacija.

Za detaljnije informacije, konsultujte zvaničnu [dokumentaciju](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).

**Tabela iz** [**dokumenata**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

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
