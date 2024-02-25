# Kudhuru Vitambulisho

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Unataka kuona **kampuni yako ikitangazwa kwenye HackTricks**? au unataka kupata upatikanaji wa **toleo jipya la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **nifuata** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Vitambulisho

Ikiwa **hujui ni nini Vitambulisho vya Kufikia Windows** soma ukurasa huu kabla ya kuendelea:

{% content-ref url="../access-tokens.md" %}
[access-tokens.md](../access-tokens.md)
{% endcontent-ref %}

**Labda unaweza kuwa na uwezo wa kudhuru vitambulisho unavyo tayari**

### SeImpersonatePrivilege

Hii ni haki ambayo inashikiliwa na mchakato wowote inaruhusu uigaji (lakini sio uumbaji) wa kifungo chochote, ikitoa kwamba kushughulikia kwake kunaweza kupatikana. Kifungo cha kifahari kinaweza kupatikana kutoka kwa huduma ya Windows (DCOM) kwa kuiwezesha kufanya uthibitishaji wa NTLM dhidi ya shambulio, kisha kuruhusu utekelezaji wa mchakato na mamlaka ya SYSTEM. Udhaifu huu unaweza kutumiwa kwa kutumia zana mbalimbali, kama vile [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (inayohitaji winrm iwe imezimwa), [SweetPotato](https://github.com/CCob/SweetPotato), na [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

{% content-ref url="../roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](../roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="../juicypotato.md" %}
[juicypotato.md](../juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege

Ni sawa sana na **SeImpersonatePrivilege**, itatumia **njia ile ile** kupata kifungo cha kifahari.\
Kisha, haki hii inaruhusu **kuweka kifungo cha msingi** kwa mchakato mpya/uliosimamishwa. Kwa kifungo cha uigaji cha kifahari unaweza kuzalisha kifungo cha msingi (DuplicateTokenEx).\
Kwa kifungo, unaweza kuunda **mchakato mpya** na 'CreateProcessAsUser' au kuunda mchakato uliosimamishwa na **kuweka kifungo** (kwa ujumla, huwezi kurekebisha kifungo cha msingi cha mchakato unaofanya kazi).

### SeTcbPrivilege

Ikiwa umewezesha kifungo hiki unaweza kutumia **KERB\_S4U\_LOGON** kupata **kifungo cha uigaji** kwa mtumiaji mwingine yeyote bila kujua siri, **kuongeza kikundi cha aina yoyote** (wasimamizi) kwenye kifungo, kuweka **kiwango cha usalama** cha kifungo kuwa "**wa kati**", na kuweka kifungo hiki kwa **mnyororo wa sasa** (SetThreadToken).

### SeBackupPrivilege

Mfumo unalazimishwa **kutoa udhibiti wa kusoma** kwa faili yoyote (iliyopunguzwa kwa shughuli za kusoma) kupitia kwa haki hii. Inatumika kwa **kusoma vibonye vya nywila za akaunti za Wasimamizi wa Mitaa** kutoka kwa usajili, kufuatia ambayo, zana kama "**psexec**" au "**wmicexec**" zinaweza kutumika na kibonye hicho (mbinu ya Pass-the-Hash). Walakini, mbinu hii inashindwa chini ya hali mbili: wakati akaunti ya Msimamizi wa Mitaa imelemazwa, au wakati sera inawekwa ambayo inaondoa haki za utawala kutoka kwa Wasimamizi wa Mitaa wanaounganisha kijijini.\
Unaweza **kudhuru haki hii** na:

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* kufuata **IppSec** katika [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)
* Au kama ilivyoelezwa katika sehemu ya **kudhuru haki za Backup Operators** ya:

{% content-ref url="../../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### SeRestorePrivilege

Ruhusa ya **upatikanaji wa kuandika** kwa faili yoyote ya mfumo, bila kujali Orodha ya Kudhibiti ya Upatikanaji (ACL) ya faili hiyo, inatolewa na haki hii. Inafungua fursa nyingi za kudhuru, ikiwa ni pamoja na uwezo wa **kurekebisha huduma**, kutekeleza DLL Hijacking, na kuweka **wadukuzi** kupitia Chaguo za Utekelezaji wa Faili ya Picha kati ya mbinu mbalimbali.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege ni ruhusa yenye nguvu, hasa inayofaa wakati mtumiaji ana uwezo wa kudai vitambulisho, lakini pia bila SeImpersonatePrivilege. Uwezo huu unategemea uwezo wa kudai kifungo kinachowakilisha mtumiaji huyo huyo na ambaye kiwango chake cha usalama hakiendi zaidi ya mchakato wa sasa.

**Muhimu:**
- **Uigaji bila SeImpersonatePrivilege:** Inawezekana kutumia SeCreateTokenPrivilege kwa EoP kwa kudai vitambulisho chini ya hali maalum.
- **Hali za Uigaji wa Kifungo:** Uigaji mafanikio unahitaji kifungo cha lengo kuwa cha mtumiaji huyo huyo na kiwango cha usalama ambacho ni kidogo au sawa na kiwango cha usalama wa mchakato unaojaribu uigaji.
- **Uundaji na Kubadilisha Vitambulisho vya Uigaji:** Watumiaji wanaweza kuunda kifungo cha uigaji na kukiimarisha kwa kuongeza SID ya kikundi cha kifahari.

### SeLoadDriverPrivilege

Haki hii inaruhusu **kupakia na kufuta madereva ya kifaa** kwa kuunda kuingiza ya usajili na thamani maalum kwa `ImagePath` na `Type`. Kwa kuwa upatikanaji wa kuandika moja kwa moja kwa `HKLM` (HKEY_LOCAL_MACHINE) umepunguzwa, `HKCU` (HKEY_CURRENT_USER) lazima itumike badala yake. Walakini, ili kufanya `HKCU` itambulike na kernel kwa usanidi wa dereva, njia maalum lazima ifuatwe.

Njia hii ni `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, ambapo `<RID>` ni Kitambulisho cha Kihusishi cha mtumiaji wa sasa. Ndani ya `HKCU`, njia nzima hii lazima iundwe, na thamani mbili zinahitaji kuwekwa:
- `ImagePath`, ambayo ni njia ya utekelezaji wa binary
- `Type`, na thamani ya `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Hatua za Kufuata:**
1. Fikia `HKCU` badala ya `HKLM` kutokana na upatikanaji mdogo wa kuandika.
2. Unda njia `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` ndani ya `HKCU`, ambapo `<RID>` inawakilisha Kitambulisho cha Kihusishi cha mtumiaji wa sasa.
3. Weka `ImagePath` kwa njia ya utekelezaji wa binary.
4. Weka `Type` kama `SERVICE_KERNEL_DRIVER` (`0x00000001`).
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
Njia zaidi za kutumia haki hii kwa [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Hii inafanana na **SeRestorePrivilege**. Kazi yake kuu inaruhusu mchakato kuchukua **umiliki wa kitu**, kuzunguka mahitaji ya ufikiaji wa hiari kupitia utoaji wa haki za ufikiaji wa WRITE_OWNER. Mchakato huu unahusisha kwanza kusimika umiliki wa funguo ya usajili inayokusudiwa kwa madhumuni ya kuandika, kisha kubadilisha DACL kuruhusu operesheni za kuandika.
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

Haki hii inaruhusu **kudebugi michakato mingine**, ikiwa ni pamoja na kusoma na kuandika kwenye kumbukumbu. Mikakati mbalimbali ya kuingiza kumbukumbu, inayoweza kuepuka zaidi ya programu za kupambana na virusi na ufumbuzi wa kuzuia uvamizi wa mwenyeji, inaweza kutumika na haki hii.

#### Pindua kumbukumbu

Unaweza kutumia [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) kutoka [Suite ya SysInternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) kwa **kukamata kumbukumbu ya mchakato**. Hasa, hii inaweza kutumika kwa **Mchakato wa Huduma ya Subsystem ya Usalama wa Mitaa ([LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service))**, ambao unahusika na kuhifadhi siri za mtumiaji mara tu mtumiaji anapofanikiwa kuingia kwenye mfumo.

Kisha unaweza kupakia pindu hili kwenye mimikatz ili upate nywila:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Ikiwa unataka kupata kifaa cha `NT SYSTEM` unaweza kutumia:

- ****[**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)****
- ****[**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)****
- ****[**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)****
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
## Angalia mamlaka
```
whoami /priv
```
**Vidakuzi vinavyoonekana kama Vilivyozimwa** vinaweza kuwezeshwa, kwa kweli unaweza kutumia vidakuzi vilivyo **Vilivyowezeshwa** na **Vilivyozimwa**.

### Wezesha Vidakuzi Vyote

Ikiwa una vidakuzi vilivyozimwa, unaweza kutumia skripti [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) kuwezesha vidakuzi vyote:
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Au **script** uliowekwa katika [**chapisho hili**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Jedwali

Mwongozo kamili wa mizania ya ruhusa ya token unapatikana kwa [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), muhtasari hapa chini utaorodhesha njia za moja kwa moja za kutumia ruhusa hiyo kwa kupata kikao cha msimamizi au kusoma faili nyeti.

| Ruhusa                    | Athari      | Zana                    | Njia ya utekelezaji                                                                                                                                                                                                                                                                                                                                | Maelezo                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Msimamizi**_ | Zana ya tatu          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Asante [Aurélien Chalot](https://twitter.com/Defte\_) kwa sasisho. Nitajaribu kubadilisha maneno kuwa kama mapishi hivi karibuni.                                                                                                                                                                                        |
| **`SeBackup`**             | **Tishio**  | _**Amri zilizojengwa**_ | Soma faili nyeti kwa kutumia `robocopy /b`                                                                                                                                                                                                                                                                                                             | <p>- Inaweza kuwa ya kuvutia zaidi ikiwa unaweza kusoma %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (na robocopy) haifai linapokuja kufungua faili.<br><br>- Robocopy inahitaji SeBackup na SeRestore kufanya kazi na /b parameter.</p>                                                                      |
| **`SeCreateToken`**        | _**Msimamizi**_ | Zana ya tatu          | Unda token ya kupindukia ikiwa ni pamoja na ruhusa za msimamizi wa ndani kwa kutumia `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Msimamizi**_ | **PowerShell**          | Nakili token ya `lsass.exe`.                                                                                                                                                                                                                                                                                                                   | Script inapatikana kwa [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Msimamizi**_ | Zana ya tatu          | <p>1. Pakia dereva dhaifu wa kernel kama vile <code>szkg64.sys</code><br>2. Tumia udhaifu wa dereva<br><br>Kwa upande mwingine, ruhusa inaweza kutumika kufuta dereva zinazohusiana na usalama kwa kutumia amri ya kujengwa ya <code>ftlMC</code>. yaani: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. Udhaifu wa <code>szkg64</code> umetajwa kama <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. Msimbo wa udhaifu wa <code>szkg64</code> ulibuniwa na <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Msimamizi**_ | **PowerShell**          | <p>1. Anzisha PowerShell/ISE na ruhusa ya SeRestore ikiwepo.<br>2. Wezesha ruhusa hiyo kwa kutumia <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Badilisha utilman.exe kuwa utilman.old<br>4. Badilisha cmd.exe kuwa utilman.exe<br>5. Funga konsoli na bonyeza Win+U</p> | <p>Shambulio linaweza kugunduliwa na programu fulani za AV.</p><p>Njia mbadala inategemea kubadilisha programu za huduma zilizohifadhiwa katika "Program Files" kwa kutumia ruhusa hiyo hiyo</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Msimamizi**_ | _**Amri zilizojengwa**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Badilisha cmd.exe kuwa utilman.exe<br>4. Funga konsoli na bonyeza Win+U</p>                                                                                                                                       | <p>Shambulio linaweza kugunduliwa na programu fulani za AV.</p><p>Njia mbadala inategemea kubadilisha programu za huduma zilizohifadhiwa katika "Program Files" kwa kutumia ruhusa hiyo hiyo.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Msimamizi**_ | Zana ya tatu          | <p>Tumia mizania kuwa na ruhusa za msimamizi wa ndani zilizojumuishwa. Inaweza kuhitaji SeImpersonate.</p><p>Kuthibitishwa.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Marejeo

* Angalia jedwali hili linaloelezea vidole vya Windows: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* Angalia [**karatasi hii**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt) kuhusu privesc na vidole.
