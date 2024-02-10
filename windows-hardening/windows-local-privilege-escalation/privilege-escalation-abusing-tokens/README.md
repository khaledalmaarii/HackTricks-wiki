# Zloupotreba tokena

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Radite li u **kompaniji za kibernetičku bezbednost**? Želite li da vidite svoju **kompaniju reklamiranu na HackTricks-u**? Ili želite da imate pristup **najnovijoj verziji PEASS-a ili preuzmete HackTricks u PDF formatu**? Proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili me **pratite** na **Twitter-u** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na [hacktricks repo](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Tokeni

Ako **ne znate šta su Windows Access Tokeni**, pročitajte ovu stranicu pre nego što nastavite:

{% content-ref url="../access-tokens.md" %}
[access-tokens.md](../access-tokens.md)
{% endcontent-ref %}

**Možda ćete moći da eskalirate privilegije zloupotrebom tokena koje već imate**

### SeImpersonatePrivilege

Ovo je privilegija koju poseduje svaki proces koji omogućava impersonaciju (ali ne i kreiranje) bilo kog tokena, pod uslovom da se može dobiti ručka za njega. Privilegovani token može se dobiti od Windows servisa (DCOM) induciranjem NTLM autentifikacije protiv eksploatacije, čime se omogućava izvršavanje procesa sa SYSTEM privilegijama. Ovu ranjivost mogu iskoristiti razni alati, kao što su [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (koji zahteva onemogućavanje winrm-a), [SweetPotato](https://github.com/CCob/SweetPotato) i [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

{% content-ref url="../roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](../roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="../juicypotato.md" %}
[juicypotato.md](../juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege

Veoma je slična **SeImpersonatePrivilege**, koristi **isti metod** za dobijanje privilegovanog tokena.\
Onda, ova privilegija omogućava **dodeljivanje primarnog tokena** novom/suspendovanom procesu. Sa privilegovanim impersonation tokenom možete izvesti primarni token (DuplicateTokenEx).\
Sa tokenom, možete kreirati **novi proces** sa 'CreateProcessAsUser' ili kreirati proces suspendovan i **postaviti token** (uopšteno, ne možete menjati primarni token pokrenutog procesa).

### SeTcbPrivilege

Ako imate omogućen ovaj token, možete koristiti **KERB\_S4U\_LOGON** da biste dobili **impersonation token** za bilo koji drugi korisnik, a da ne znate akreditive, **dodajte proizvoljnu grupu** (admins) tokenu, postavite **nivo integriteta** tokena na "**medium**" i dodelite ovaj token **trenutnom thread-u** (SetThreadToken).

### SeBackupPrivilege

Sistem je primoran da **dodeli sve dozvole za čitanje** kontrole bilo kojoj datoteci (ograničeno na operacije čitanja) putem ovog privilegovanja. Koristi se za **čitanje heševa lozinki lokalnih Administrator** naloga iz registra, nakon čega se mogu koristiti alati poput "**psexec**" ili "**wmicexec**" sa hešom (Pass-the-Hash tehnika). Međutim, ova tehnika ne uspeva u dva slučaja: kada je lokalni Administrator nalog onemogućen ili kada je primenjena politika koja uklanja administratorska prava od lokalnih administratora koji se povezuju na daljinu.\
Ovo privilegovanje možete **zloupotrebiti** sa:

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* prateći **IppSec** u [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)
* Ili kako je objašnjeno u odeljku **escalating privileges with Backup Operators**:

{% content-ref url="../../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### SeRestorePrivilege

Ovo privilegovanje omogućava **pisanje pristupa** bilo kojoj sistemskoj datoteci, bez obzira na Access Control List (ACL) datoteke. Otvorene su brojne mogućnosti za eskalaciju, uključujući mogućnost **izmene servisa**, izvođenje DLL Hijacking-a i postavljanje **debuggera** putem Image File Execution Options, među raznim drugim tehnikama.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege je moćna dozvola, posebno korisna kada korisnik ima mogućnost impersonacije tokena, ali i u odsustvu SeImpersonatePrivilege. Ova sposobnost se oslanja na mogućnost impersonacije tokena koji predstavlja istog korisnika i čiji nivo integriteta ne prelazi nivo integriteta trenutnog procesa.

**Ključne tačke:**
- **Impersonacija bez SeImpersonatePrivilege:** Moguće je iskoristiti SeCreateTokenPrivilege za EoP putem impersonacije tokena pod određenim uslovima.
- **Uslovi za impersonaciju tokena:** Uspesna impersonacija zahteva da ciljni token pripada istom korisniku i ima nivo integriteta koji je manji ili jednak nivou integriteta procesa koji pokušava da izvrši impersonaciju.
- **Kreiranje i modifikacija impersonation tokena:** Korisnici mogu kreirati impersonation token i unaprediti ga dodavanjem SID-a (Security Identifier) privilegovane grupe.

### SeLoadDriverPrivilege

Ovo privilegovanje omogućava **učitavanje i isključivanje drajvera uređaja** sa kreiranjem unosa u registar sa specifičnim vrednostima za `ImagePath` i `Type`. Pošto je direktni pristup pisanju u `HKLM` (HKEY_LOCAL_MACHINE) ograničen, umesto toga se mor
```python
# Example Python code to set the registry values
import winreg as reg

# Define the path and values
path = r'Software\YourPath\System\CurrentControlSet\Services\DriverName' # Adjust 'YourPath' as needed
key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
reg.SetValueEx(key, "ImagePath", 0, reg.REG_SZ, "path_to_binary")
reg.SetValueEx(key, "Type", 0, reg.REG_DWORD, 0x00000001)
reg.CloseKey(key)
```
Još načina za zloupotrebu ovih privilegija možete pronaći na [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Ovo je slično kao i **SeRestorePrivilege**. Njegova osnovna funkcija omogućava procesu da **preuzme vlasništvo nad objektom**, zaobilazeći zahtev za eksplicitnim pristupom putem pružanja prava pristupa WRITE_OWNER. Proces uključuje prvo obezbeđivanje vlasništva nad odgovarajućim registarskim ključem u svrhu pisanja, a zatim izmenu DACL-a kako bi se omogućile operacije pisanja.
```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant <your_username>:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```
### SeDebugPrivilege

Ovo ovlašćenje omogućava **debugiranje drugih procesa**, uključujući čitanje i pisanje u memoriju. Različite strategije za ubrizgavanje memorije, sposobne da izbegnu većinu antivirusnih i host intrusion prevention rešenja, mogu se koristiti uz ovo ovlašćenje.

#### Dump memorije

Možete koristiti [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) iz [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) da **zabeležite memoriju procesa**. Konkretno, ovo se može primeniti na proces **Local Security Authority Subsystem Service ([LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service))**, koji je odgovoran za čuvanje korisničkih podataka nakon što se korisnik uspešno prijavi na sistem.

Zatim možete učitati ovaj dump u mimikatz-u da biste dobili lozinke:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Ako želite da dobijete `NT SYSTEM` shell, možete koristiti:

* ****[**SeDebugPrivilegePoC**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)****
* ****[**psgetsys.ps1**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)****
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
## Provera privilegija

To determine the privileges of a user, you can use the following methods:

### 1. Whoami

The `whoami` command displays the current user and group information, including the privileges associated with the user.

```plaintext
whoami /priv
```

### 2. Systeminfo

The `systeminfo` command provides detailed information about the system, including the privileges of the current user.

```plaintext
systeminfo
```

### 3. PowerShell

You can use PowerShell to check the privileges of a user. The following command displays the privileges associated with the current user:

```plaintext
whoami /priv
```

### 4. AccessChk

AccessChk is a command-line tool that shows the effective permissions for files, registry keys, services, processes, and more. You can use it to check the privileges of a user.

```plaintext
accesschk.exe -a <username>
```

### 5. Process Explorer

Process Explorer is a graphical tool that provides detailed information about running processes. It also displays the privileges associated with each process.

### 6. Task Manager

Task Manager is a built-in Windows utility that provides information about running processes. It also displays the privileges associated with each process.

By using these methods, you can easily check the privileges of a user and identify potential privilege escalation opportunities.
```
whoami /priv
```
**Tokeni koji se pojavljuju kao onemogućeni** mogu biti omogućeni, i zapravo možete zloupotrebiti _Omogućene_ i _Onemogućene_ tokene.

### Omogućavanje svih tokena

Ako imate onemogućene tokene, možete koristiti skriptu [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) da omogućite sve tokene:
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Ili **skriptu** ugrađenu u ovaj [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabela

Potpuna lista privilegija tokena nalazi se na [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), u nastavku će biti navedeni samo direktni načini iskorišćavanja privilegija radi dobijanja administratorske sesije ili čitanja osetljivih fajlova.

| Privilegija                | Uticaj      | Alat                    | Put izvršenja                                                                                                                                                                                                                                                                                                                                      | Napomene                                                                                                                                                                                                                                                                                                                       |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | Alat treće strane       | _"Omogućava korisniku da se predstavlja kao token i dobije privilegije nt sistema koristeći alate kao što su potato.exe, rottenpotato.exe i juicypotato.exe"_                                                                                                                                                                                        | Hvala [Aurélien Chalot](https://twitter.com/Defte\_) na ažuriranju. Pokušaću da to preformulišem na nešto nalik receptu.                                                                                                                                                                                                         |
| **`SeBackup`**             | **Pretnja** | _**Ugrađene komande**_  | Čitanje osetljivih fajlova pomoću `robocopy /b`                                                                                                                                                                                                                                                                                                    | <p>- Može biti interesantno ako možete čitati %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (i robocopy) nije koristan kada je u pitanju otvaranje fajlova.<br><br>- Robocopy zahteva i SeBackup i SeRestore privilegije da bi radio sa /b parametrom.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | Alat treće strane       | Kreiranje proizvoljnog tokena uključujući lokalne administratorske privilegije pomoću `NtCreateToken`.                                                                                                                                                                                                                                           |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Dupliciranje tokena `lsass.exe`.                                                                                                                                                                                                                                                                                                                   | Skripta se može pronaći na [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | Alat treće strane       | <p>1. Učitajte problematični kernel drajver kao što je <code>szkg64.sys</code><br>2. Iskoristite ranjivost drajvera<br><br>Alternativno, privilegija se može koristiti za uklanjanje drajvera vezanih za bezbednost pomoću ugrađene komande <code>ftlMC</code>. npr.: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. Ranjivost <code>szkg64</code> je navedena kao <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. Kod za iskorišćavanje ranjivosti <code>szkg64</code> je kreirao <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Pokrenite PowerShell/ISE sa prisutnom privilegijom SeRestore.<br>2. Omogućite privilegiju pomoću <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Preimenujte utilman.exe u utilman.old<br>4. Preimenujte cmd.exe u utilman.exe<br>5. Zaključajte konzolu i pritisnite Win+U</p> | <p>Napad može biti otkriven od strane nekih AV softvera.</p><p>Alternativna metoda se oslanja na zamenu binarnih fajlova servisa smeštenih u "Program Files" koristeći istu privilegiju</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Ugrađene komande**_  | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Preimenujte cmd.exe u utilman.exe<br>4. Zaključajte konzolu i pritisnite Win+U</p>                                                                                                                                       | <p>Napad može biti otkriven od strane nekih AV softvera.</p><p>Alternativna metoda se oslanja na zamenu binarnih fajlova servisa smeštenih u "Program Files" koristeći istu privilegiju.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | Alat treće strane       | <p>Manipulacija tokenima kako bi se uključile lokalne administratorske privilegije. Može zahtevati SeImpersonate.</p><p>Treba proveriti.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Reference

* Pogledajte ovu tabelu koja definiše Windows tokene: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* Pogledajte [**ovaj rad**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt) o iskorišćavanju privilegija tokena. 

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **cybersecurity kompaniji**? Želite li da vidite **vašu kompaniju reklamiranu na HackTricks**? Ili želite da imate pristup **najnovijoj verziji PEASS-a ili preuzmete HackTricks u PDF formatu**? Proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili me **pratite** na **Twitteru** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na [hacktricks repo](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
