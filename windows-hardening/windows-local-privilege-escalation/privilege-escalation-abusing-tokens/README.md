# Kudhuru Vitambulisho

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwenye [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Vitambulisho

Ikiwa **hujui ni nini Vitambulisho vya Kupata Windows**, soma ukurasa huu kabla ya kuendelea:

{% content-ref url="../access-tokens.md" %}
[access-tokens.md](../access-tokens.md)
{% endcontent-ref %}

**Labda unaweza kuweza kuongeza mamlaka kwa kudukua vitambulisho ulivyonavyo tayari**

### SeImpersonatePrivilege

Hii ni mamlaka ambayo inashikiliwa na mchakato wowote inaruhusu uwakilishi (lakini sio uundaji) wa vitambulisho vyovyote, ikitoa kuwa kushughulikia kwake kunaweza kupatikana. Vitambulisho vyenye mamlaka vinaweza kupatikana kutoka kwa huduma ya Windows (DCOM) kwa kuchochea uwakilishi wa NTLM dhidi ya shambulio, kisha kuruhusu utekelezaji wa mchakato na mamlaka ya SYSTEM. Udhaifu huu unaweza kutumiwa kwa kutumia zana mbalimbali, kama vile [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (ambayo inahitaji winrm kuwa imezimwa), [SweetPotato](https://github.com/CCob/SweetPotato), na [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

{% content-ref url="../roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](../roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="../juicypotato.md" %}
[juicypotato.md](../juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege

Ni sawa sana na **SeImpersonatePrivilege**, itatumia **njia ile ile** ya kupata vitambulisho vyenye mamlaka.\
Kisha, mamlaka hii inaruhusu **kuweka kichwa cha msingi** kwa mchakato mpya/uliosimamishwa. Kwa kutumia vitambulisho vya uwakilishi vyenye mamlaka unaweza kuzaliana kichwa cha msingi (DuplicateTokenEx).\
Kwa kutumia kichwa cha msingi, unaweza kuunda **mchakato mpya** na 'CreateProcessAsUser' au kuunda mchakato uliosimamishwa na **kuweka kichwa cha msingi** (kwa ujumla, huwezi kubadilisha kichwa cha msingi cha mchakato unaotumika).

### SeTcbPrivilege

Ikiwa umewezesha vitambulisho hivi unaweza kutumia **KERB\_S4U\_LOGON** kupata **kichwa cha msingi cha uwakilishi** kwa mtumiaji mwingine yeyote bila kujua sifa, **kuongeza kikundi cha kiholela** (waendeshaji) kwenye kichwa cha msingi, kuweka **kiwango cha uadilifu** cha kichwa cha msingi kuwa "**kiwango cha kati**", na kuweka kichwa hiki kwenye **mchakato wa sasa** (SetThreadToken).

### SeBackupPrivilege

Mfumo unaruhusiwa **kutoa udhibiti wa upatikanaji wa kusoma** kwa faili yoyote (imezuiliwa kwa shughuli za kusoma tu) kwa kutumia mamlaka haya. Inatumika kusoma misimbuko ya nywila za akaunti za Msimamizi wa Mitaa kutoka kwenye usajili, kisha zana kama "**psexec**" au "**wmicexec**" zinaweza kutumika na misimbuko (njia ya "Pass-the-Hash"). Walakini, mbinu hii inashindwa chini ya hali mbili: wakati akaunti ya Msimamizi wa Mitaa imelemazwa, au wakati sera imewekwa ambayo inaondoa haki za utawala kutoka kwa Waendeshaji wa Mitaa wanaounganisha kijijini.\
Unaweza **kudukua mamlaka haya** na:

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* kwa kufuata **IppSec** katika [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)
* Au kama ilivyoelezwa katika sehemu ya **kuongeza mamlaka na Waendeshaji wa Kuhifadhi** katika:

{% content-ref url="../../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### SeRestorePrivilege

Ruhusa ya **upatikanaji wa kuandika** kwa faili yoyote ya mfumo, bila kujali Orodha ya Kudhibiti Upatikanaji (ACL) ya faili hiyo, inatolewa na mamlaka haya. Inafungua fursa nyingi za kudukua, ikiwa ni pamoja na uwezo wa **kurekebisha huduma**, kutekeleza DLL Hijacking, na kuweka **wadukuzi** kupitia Chaguo za Utekelezaji wa Faili ya Picha kati ya mbinu mbalimbali.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege ni idhini yenye nguvu, hasa inayofaa wakati mtumiaji ana uwezo wa uwakilishi wa vitambulisho, lakini pia wakati hakuna SeImpersonatePrivilege. Uwezo huu unategemea uwezo wa uwakilishi wa kichwa cha msingi kinachowakilisha mtumiaji huyo na kiwango chake cha uadilifu hakizidi kiwango cha sasa cha mchakato.

**Mambo
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

Hii ni sawa na **SeRestorePrivilege**. Kazi yake kuu ni kuruhusu mchakato kuchukua umiliki wa kitu, kwa kuzingatia mahitaji ya upatikanaji wa kibali kupitia utoaji wa haki za upatikanaji wa WRITE_OWNER. Mchakato huu unahusisha kwanza kusimika umiliki wa funguo ya usajili inayokusudiwa kwa madhumuni ya kuandika, kisha kubadilisha DACL ili kuwezesha shughuli za kuandika.
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

Haki hii inaruhusu **kudukua michakato mingine**, ikiwa ni pamoja na kusoma na kuandika kwenye kumbukumbu. Mikakati mbalimbali ya kuingiza kumbukumbu, inayoweza kuepuka zana za antivirus na ufumbuzi wa kuzuia uingizaji wa mwenyeji, inaweza kutumika na haki hii.

#### Pindua kumbukumbu

Unaweza kutumia [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) kutoka [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) ili **kupata kumbukumbu ya michakato**. Hasa, hii inaweza kutumika kwa **Local Security Authority Subsystem Service ([LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service))** ambayo inahusika na kuhifadhi vibali vya mtumiaji mara tu mtumiaji anapofanikiwa kuingia kwenye mfumo.

Kisha unaweza kupakia pindu hii kwenye mimikatz ili kupata nywila:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Ikiwa unataka kupata kikoa cha `NT SYSTEM` unaweza kutumia:

* ****[**SeDebugPrivilegePoC**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)****
* ****[**psgetsys.ps1**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)****
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
## Angalia mamlaka

To check the privileges of a user, you can use the following methods:

### Method 1: Using the `whoami` command

The `whoami` command displays the username of the current user. By default, it also shows the group memberships of the user, which can give you an idea of the privileges they have.

```plaintext
whoami
```

### Method 2: Using the `net user` command

The `net user` command provides detailed information about a user account, including their group memberships and privileges.

```plaintext
net user <username>
```

Replace `<username>` with the name of the user you want to check.

### Method 3: Using the `whoami /priv` command

The `whoami /priv` command displays the privileges held by the current user. This can help you identify any elevated privileges that the user may have.

```plaintext
whoami /priv
```

### Method 4: Using the `secpol.msc` GUI

You can also use the `secpol.msc` GUI (Local Security Policy) to check the privileges of a user. Follow these steps:

1. Press `Win + R` to open the Run dialog box.
2. Type `secpol.msc` and press Enter.
3. In the Local Security Policy window, navigate to Security Settings > Local Policies > User Rights Assignment.
4. Double-click on any privilege to view the users and groups that have been granted that privilege.

These methods will help you determine the privileges of a user, which is crucial for identifying potential privilege escalation opportunities.
```
whoami /priv
```
**Vidakuzi ambavyo vinaonekana kuwa vimelemazwa** vinaweza kuwezeshwa, na kwa kweli unaweza kutumia vidakuzi vilivyo **wezeshwa** na **vilivyo lemezwa**.

### Wezesha Vidakuzi Vyote

Ikiwa una vidakuzi vilivyolemazwa, unaweza kutumia skripti [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) kuwezesha vidakuzi vyote:
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Au **script** imewekwa katika [**chapisho**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) hii.

## Jedwali

Cheatsheet kamili ya haki za tokeni inapatikana kwenye [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), muhtasari hapa chini utaorodhesha njia za moja kwa moja za kutumia haki za kupata kikao cha msimamizi au kusoma faili nyeti.

| Haki                       | Athari      | Zana                    | Njia ya Utekelezaji                                                                                                                                                                                                                                                                                                                               | Maelezo                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | Zana ya tatu            | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Asante [Aurélien Chalot](https://twitter.com/Defte\_) kwa sasisho. Nitajaribu kubadilisha maneno ili iwe kama mapishi hivi karibuni.                                                                                                                                                                                        |
| **`SeBackup`**             | **Tishio**  | _**Amri zilizojengwa**_ | Soma faili nyeti na `robocopy /b`                                                                                                                                                                                                                                                                                                             | <p>- Inaweza kuwa ya kuvutia zaidi ikiwa unaweza kusoma %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (na robocopy) haifai linapokuja kufungua faili.<br><br>- Robocopy inahitaji SeBackup na SeRestore kufanya kazi na kipengele cha /b.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | Zana ya tatu            | Unda tokeni isiyo na kikomo ikiwa ni pamoja na haki za msimamizi wa ndani na `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Nakili tokeni ya `lsass.exe`.                                                                                                                                                                                                                                                                                                                   | Skripti inapatikana kwenye [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | Zana ya tatu            | <p>1. Pakia dereva dhaifu wa kerneli kama vile <code>szkg64.sys</code><br>2. Tumia udhaifu wa dereva<br><br>Kwa njia mbadala, haki inaweza kutumika kuondoa dereva zinazohusiana na usalama kwa kutumia amri ya ndani ya <code>ftlMC</code>. yaani: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. Udhaifu wa <code>szkg64</code> umetajwa kama <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. Kanuni ya udanganyifu wa <code>szkg64</code> iliumbwa na <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Anzisha PowerShell/ISE na haki ya SeRestore ikiwepo.<br>2. Wezesha haki hiyo na <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Badilisha utilman.exe kuwa utilman.old<br>4. Badilisha cmd.exe kuwa utilman.exe<br>5. Funga konsoli na bonyeza Win+U</p> | <p>Shambulio linaweza kugunduliwa na programu fulani za AV.</p><p>Njia mbadala inategemea kubadilisha faili za huduma zilizohifadhiwa katika "Program Files" kwa kutumia haki hiyo hiyo</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Amri zilizojengwa**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Badilisha cmd.exe kuwa utilman.exe<br>4. Funga konsoli na bonyeza Win+U</p>                                                                                                                                       | <p>Shambulio linaweza kugunduliwa na programu fulani za AV.</p><p>Njia mbadala inategemea kubadilisha faili za huduma zilizohifadhiwa katika "Program Files" kwa kutumia haki hiyo hiyo.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | Zana ya tatu            | <p>Dhibiti tokeni ili iwe na haki za msimamizi wa ndani. Inaweza kuhitaji SeImpersonate.</p><p>Kuthibitishwa.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Marejeo

* Angalia jedwali hili linaloelezea tokeni za Windows: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* Angalia [**karatasi hii**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt) kuhusu privesc na tokeni.

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je! Unafanya kazi katika **kampuni ya usalama wa mtandao**? Je! Unataka kuona **kampuni yako inatangazwa katika HackTricks**? au unataka kupata upatikanaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuate** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
