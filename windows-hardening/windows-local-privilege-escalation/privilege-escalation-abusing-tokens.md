# Kudhuru Vitambulisho

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Unataka kuona **kampuni yako ikionyeshwa kwenye HackTricks**? au unataka kupata upatikanaji wa **toleo jipya la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **nifuata** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Vitambulisho

Ikiwa **hujui ni nini Vitambulisho vya Kufikia Windows** soma ukurasa huu kabla ya kuendelea:

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

**Labda unaweza kuwa na uwezo wa kudhuru vitambulisho unavyo tayari**

### SeImpersonatePrivilege

Hii ni haki inayoshikiliwa na mchakato wowote inayoruhusu uigaji (lakini sio uumbaji) wa vitambulisho vyovyote, ikizingatiwa kwamba kushika kwa hicho kunaweza kupatikana. Vitambulisho vilivyo na haki vinaweza kupatikana kutoka kwa huduma ya Windows (DCOM) kwa kuchochea kufanya uthibitishaji wa NTLM dhidi ya shambulio, kisha kuruhusu utekelezaji wa mchakato na haki za SYSTEM. Udhaifu huu unaweza kutumiwa kwa kutumia zana mbalimbali, kama vile [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (ambayo inahitaji winrm iwe imelemazwa), [SweetPotato](https://github.com/CCob/SweetPotato), na [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="juicypotato.md" %}
[juicypotato.md](juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege

Ni sawa sana na **SeImpersonatePrivilege**, itatumia **njia ile ile** kupata vitambulisho vilivyo na haki.\
Kisha, haki hii inaruhusu **kuweka kipaumbele cha vitambulisho** kwa mchakato mpya/uliosimamishwa. Kwa vitambulisho vya uigaji vilivyo na haki unaweza kuzalisha kipaumbele cha msingi (DuplicateTokenEx).\
Kwa kutumia vitambulisho, unaweza kuunda **mchakato mpya** na 'CreateProcessAsUser' au kuunda mchakato uliosimamishwa na **kuweka kipaumbele cha vitambulisho** (kwa ujumla, huwezi kurekebisha kipaumbele cha msingi cha mchakato unaotumika).

### SeTcbPrivilege

Ikiwa umewezesha kibali hiki unaweza kutumia **KERB\_S4U\_LOGON** kupata **vitambulisho vya uigaji** kwa mtumiaji mwingine yeyote bila kujua siri, **kuongeza kikundi cha aina yoyote** (wasimamizi) kwenye kibali, kuweka **kiwango cha usalama** cha kibali kuwa "**wa kati**", na kuweka kibali hiki kwa **mnyororo wa sasa** (SetThreadToken).

### SeBackupPrivilege

Mfumo unahimizwa kutoa **ufikiaji wa kusoma wote** kwa faili yoyote (mdogo kwa shughuli za kusoma) kwa kibali hiki. Hutumiwa kwa **kusoma nywila za wakala wa Msimamizi wa Mitaa** kutoka kwa usajili, kufuatia ambayo, zana kama "**psexec**" au "**wmicexec**" zinaweza kutumika na hash (mbinu ya Pass-the-Hash). Walakini, mbinu hii inashindwa chini ya hali mbili: wakati akaunti ya Msimamizi wa Mitaa imelemazwa, au wakati sera inawekwa ambayo inaondoa haki za usimamizi kutoka kwa Msimamizi wa Mitaa anayeunganisha kijijini.\
Unaweza **kudhuru kibali hiki** na:

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* kufuata **IppSec** katika [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)
* Au kama ilivyoelezwa katika sehemu ya **kudhuru vitambulisho na waendeshaji wa Nakala za Kurejesha** ya:

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### SeRestorePrivilege

Kibali cha **ufikiaji wa kuandika** kwa faili yoyote ya mfumo, bila kujali Orodha ya Kudhibiti ya Ufikiaji (ACL) ya faili hiyo, kinatolewa na kibali hiki. Hii inafungua fursa nyingi za kudhuru, ikiwa ni pamoja na uwezo wa **kurekebisha huduma**, kutekeleza DLL Hijacking, na kuweka **wadukuzi** kupitia Chaguo za Utekelezaji wa Faili ya Picha kati ya mbinu mbalimbali.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege ni kibali chenye nguvu, hasa muhimu wakati mtumiaji ana uwezo wa kudai vitambulisho, lakini pia bila SeImpersonatePrivilege. Uwezo huu unategemea uwezo wa kudai vitambulisho vinavyowakilisha mtumiaji huyo huyo na ambao kiwango chake cha usalama hakiendi zaidi ya kiwango cha sasa cha mchakato.

**Mambo Muhimu:**

* **Uigaji bila SeImpersonatePrivilege:** Inawezekana kutumia SeCreateTokenPrivilege kwa EoP kwa kudai vitambulisho chini ya hali maalum.
* **Hali za Uigaji wa Vitambulisho:** Uigaji mafanikio unahitaji vitambulisho vya lengo kuwa vya mtumiaji huyo huyo na kuwa na kiwango cha usalama ambacho ni kidogo au sawa na kiwango cha usalama cha mchakato unaojaribu uigaji.
* **Uundaji na Marekebisho ya Vitambulisho vya Uigaji:** Watumiaji wanaweza kuunda vitambulisho vya uigaji na kuviboresha kwa kuongeza SID ya kikundi cha haki.

### SeLoadDriverPrivilege

Kibali hiki kuruhusu **kupakia na kufuta madereva ya kifaa** kwa kuunda kuingiza usajili na thamani maalum kwa `ImagePath` na `Aina`. Kwa kuwa ufikiaji wa kuandika moja kwa moja kwa `HKLM` (HKEY\_LOCAL\_MACHINE) umepunguzwa, `HKCU` (HKEY\_CURRENT\_USER) lazima itumike badala yake. Walakini, ili kufanya `HKCU` iweze kutambulika na kernel kwa usanidi wa dereva, njia maalum lazima ifuatwe.

Njia hii ni `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, ambapo `<RID>` ni Kitambulisho cha Kihusishi cha mtumiaji wa sasa. Ndani ya `HKCU`, njia nzima hii lazima iundwe, na thamani mbili zinahitaji kuwekwa:

* `ImagePath`, ambayo ni njia ya utekelezaji wa binary
* `Aina`, na thamani ya `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Hatua za Kufuata:**

1. Fikia `HKCU` badala ya `HKLM` kutokana na ufikiaji mdogo wa kuandika.
2. Unda njia `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` ndani ya `HKCU`, ambapo `<RID>` inawakilisha Kitambulisho cha Kihusishi cha mtumiaji wa sasa.
3. Weka `ImagePath` kuwa njia ya utekelezaji wa binary.
4. Weka `Aina` kama `SERVICE_KERNEL_DRIVER` (`0x00000001`).
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

Hii inafanana na **SeRestorePrivilege**. Kazi yake kuu ni kuruhusu mchakato kuchukua **umiliki wa kitu**, kuzunguka mahitaji ya ufikiaji wa hiari kupitia utoaji wa haki za ufikiaji wa WRITE\_OWNER. Mchakato huanza kwa kwanza kusimika umiliki wa funguo ya usajili inayokusudiwa kwa madhumuni ya kuandika, kisha kubadilisha DACL kuruhusu operesheni za kuandika.
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

Unaweza kutumia [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) kutoka [Suite ya SysInternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) kwa **kukamata kumbukumbu ya mchakato**. Hasa, hii inaweza kutumika kwa mchakato wa **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local\_Security\_Authority\_Subsystem\_Service)**)**, ambao unahusika na kuhifadhi sifa za mtumiaji mara tu mtumiaji anapofanikiwa kuingia kwenye mfumo.

Kisha unaweza kupakia pindu hili kwenye mimikatz ili upate nywila:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Ikiwa unataka kupata kifaa cha `NT SYSTEM` unaweza kutumia:

* [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
* [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
* [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
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

Mwongozo kamili wa mbinu za kukiuka haki za token unaweza kupatikana hapa [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), muhtasari hapa chini utaorodhesha njia za moja kwa moja za kutumia haki hiyo kwa lengo la kupata kikao cha msimamizi au kusoma faili nyeti.

| Haki                      | Athari      | Zana                    | Njia ya utekelezaji                                                                                                                                                                                                                                                                                                                                  | Maelezo                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Msimamizi**_ | Zana ya tatu          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Asante [Aurélien Chalot](https://twitter.com/Defte\_) kwa sasisho. Nitajaribu kubadilisha maneno kuwa kama mapishi hivi karibuni.                                                                                                                                                                                        |
| **`SeBackup`**             | **Tishio**  | _**Amri zilizojengwa**_ | Soma faili nyeti kwa kutumia `robocopy /b`                                                                                                                                                                                                                                                                                                             | <p>- Inaweza kuwa ya kuvutia zaidi ikiwa unaweza kusoma %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (na robocopy) haifai linapokuja suala la kufungua faili.<br><br>- Robocopy inahitaji SeBackup na SeRestore kufanya kazi na parameta /b.</p>                                                                      |
| **`SeCreateToken`**        | _**Msimamizi**_ | Zana ya tatu          | Unda token ya kupindukia ikiwa ni pamoja na haki za msimamizi wa ndani kwa kutumia `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Msimamizi**_ | **PowerShell**          | Nakili token ya `lsass.exe`.                                                                                                                                                                                                                                                                                                                   | Script inapatikana kwenye [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Msimamizi**_ | Zana ya tatu          | <p>1. Pakia dereva dhaifu wa kernel kama vile <code>szkg64.sys</code><br>2. Tumia udhaifu wa dereva<br><br>Kwa upande mwingine, haki hiyo inaweza kutumika kufuta dereva zinazohusiana na usalama kwa kutumia amri ya kujengwa ya <code>ftlMC</code>. yaani: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. Udhaifu wa <code>szkg64</code> umetajwa kama <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. Msimbo wa kudanganya wa <code>szkg64</code> ulibuniwa na <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Msimamizi**_ | **PowerShell**          | <p>1. Anzisha PowerShell/ISE na haki ya SeRestore ikiwepo.<br>2. Wezesha haki hiyo kwa kutumia <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Badilisha jina la utilman.exe kuwa utilman.old<br>4. Badilisha jina la cmd.exe kuwa utilman.exe<br>5. Funga konsoli na bonyeza Win+U</p> | <p>Shambulio linaweza kugunduliwa na programu fulani za AV.</p><p>Njia mbadala inategemea kubadilisha programu za huduma zilizohifadhiwa katika "Program Files" kwa kutumia haki hiyo hiyo</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Msimamizi**_ | _**Amri zilizojengwa**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Badilisha jina la cmd.exe kuwa utilman.exe<br>4. Funga konsoli na bonyeza Win+U</p>                                                                                                                                       | <p>Shambulio linaweza kugunduliwa na programu fulani za AV.</p><p>Njia mbadala inategemea kubadilisha programu za huduma zilizohifadhiwa katika "Program Files" kwa kutumia haki hiyo hiyo.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Msimamizi**_ | Zana ya tatu          | <p>Tumia mbinu za kudanganya kuwa na haki za msimamizi wa ndani zilizojumuishwa. Inaweza kuhitaji SeImpersonate.</p><p>Kuthibitishwa.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Marejeo

* Angalia jedwali hili linaloelezea token za Windows: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* Angalia [**karatasi hii**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt) kuhusu kukiuka haki za token.
