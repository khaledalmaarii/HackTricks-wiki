# Nadużywanie tokenów

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie z branży cyberbezpieczeństwa**? Chcesz zobaczyć, jak Twoja **firma jest reklamowana na HackTricks**? lub chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Tokeny

Jeśli **nie wiesz, co to są tokeny dostępu w systemie Windows**, przeczytaj tę stronę przed kontynuacją:

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

**Być może będziesz w stanie eskalować uprawnienia, nadużywając tokenów, które już posiadasz**

### SeImpersonatePrivilege

To uprawnienie, które jest przypisane do dowolnego procesu, umożliwia impersonację (ale nie tworzenie) dowolnego tokenu, pod warunkiem uzyskania do niego uchwytu. Uprawniony token można uzyskać od usługi systemowej Windows (DCOM), wywołując autentykację NTLM przeciwko exploitowi, umożliwiając następnie wykonanie procesu z uprawnieniami SYSTEM. Tę podatność można wykorzystać za pomocą różnych narzędzi, takich jak [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (który wymaga wyłączenia winrm), [SweetPotato](https://github.com/CCob/SweetPotato) i [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="juicypotato.md" %}
[juicypotato.md](juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege

Jest bardzo podobne do **SeImpersonatePrivilege**, będzie używać **tej samej metody** do uzyskania uprawnionego tokenu.\
Następnie to uprawnienie pozwala **przypisać token podstawowy** do nowego/zawieszonego procesu. Dzięki uprawnionemu tokenowi do impersonacji można wygenerować token podstawowy (DuplicateTokenEx).\
Z tym tokenem można utworzyć **nowy proces** za pomocą 'CreateProcessAsUser' lub utworzyć proces zawieszony i **ustawić token** (zazwyczaj nie można modyfikować podstawowego tokenu działającego procesu).

### SeTcbPrivilege

Jeśli masz włączone to uprawnienie, możesz użyć **KERB\_S4U\_LOGON** do uzyskania **tokena impersonacji** dla dowolnego innego użytkownika bez znajomości poświadczeń, **dodać dowolną grupę** (administratorów) do tokenu, ustawić **poziom integralności** tokenu na "**średni**" i przypisać ten token do **bieżącego wątku** (SetThreadToken).

### SeBackupPrivilege

System jest zmuszony do **udzielenia pełnego dostępu do odczytu** do dowolnego pliku (ograniczonego do operacji odczytu) za pomocą tego uprawnienia. Jest ono wykorzystywane do **odczytywania skrótów haseł kont lokalnych Administratora** z rejestru, po czym narzędzia takie jak "**psexec**" lub "**wmicexec**" mogą być użyte z hasłem (technika Pass-the-Hash). Jednak ta technika zawodzi w dwóch przypadkach: gdy konto Lokalnego Administratora jest wyłączone lub gdy istnieje polityka, która usuwa prawa administracyjne od Lokalnych Administratorów łączących się zdalnie.\
Możesz **nadużyć to uprawnienie** za pomocą:

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* śledząc **IppSec** na [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)
* Lub zgodnie z **eskalacją uprawnień z operatorami kopii zapasowych** opisaną w sekcji:

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### SeRestorePrivilege

Uprawnienie do **zapisu do dowolnego pliku systemowego**, niezależnie od listy kontroli dostępu (ACL) pliku, jest udzielane przez to uprawnienie. Otwiera to wiele możliwości eskalacji, w tym możliwość **modyfikacji usług**, wykonywania DLL Hijacking oraz ustawiania **debuggerów** za pomocą opcji wykonania pliku obrazu, między innymi różne techniki.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege to potężne uprawnienie, szczególnie przydatne, gdy użytkownik posiada zdolność do impersonacji tokenów, ale także w przypadku braku SeImpersonatePrivilege. Ta zdolność opiera się na możliwości impersonacji tokenu reprezentującego tego samego użytkownika, którego poziom integralności nie przekracza poziomu integralności bieżącego procesu.

**Kluczowe punkty:**

* **Impersonacja bez SeImpersonatePrivilege:** Możliwe jest wykorzystanie SeCreateTokenPrivilege do EoP poprzez impersonację tokenów w określonych warunkach.
* **Warunki impersonacji tokenów:** Skuteczna impersonacja wymaga, aby docelowy token należał do tego samego użytkownika i miał poziom integralności mniejszy lub równy poziomowi integralności procesu próbującego dokonać impersonacji.
* **Tworzenie i modyfikacja tokenów impersonacji:** Użytkownicy mogą tworzyć token impersonacji i ulepszać go, dodając identyfikator SID (Security Identifier) uprzywilejowanej grupy.

### SeLoadDriverPrivilege

To uprawnienie pozwala na **ładowanie i usuwanie sterowników urządzeń** poprzez utworzenie wpisu rejestru z określonymi wartościami dla `ImagePath` i `Type`. Ponieważ bezpośredni zapis do `HKLM` (HKEY\_LOCAL\_MACHINE) jest ograniczony, należy zamiast tego użyć `HKCU` (HKEY\_CURRENT\_USER). Jednakże, aby sprawić, żeby `HKCU` był rozpoznawalny przez jądro do konfiguracji sterownika, należy podążać za określoną ścieżką.

Ta ścieżka to `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, gdzie `<RID>` to względny identyfikator bieżącego użytkownika. Wewnątrz `HKCU` należy utworzyć całą tę ścieżkę i ustawić dwie wartości:

* `ImagePath`, czyli ścieżka do binariów do wykonania
* `Type`, z wartością `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Kroki do wykonania:**

1. Uzyskaj dostęp do `HKCU` zamiast `HKLM` ze względu na ograniczony dostęp do zapisu.
2. Utwórz ścieżkę `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` w `HKCU`, gdzie `<RID>` reprezentuje względny identyfikator bieżącego użytkownika.
3. Ustaw `ImagePath` na ścieżkę wykonania binariów.
4. Przypisz `Type` jako `SERVICE_KERNEL_DRIVER` (`0x00000001`).
```python
# Example Python code to set the registry values
import winreg as reg

# Define the path and values
path = r'Software\YourPath\System\CurrentControlSet\Services\DriverName' # Adjust 'YourPath' as needed
key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
reg.SetValueEx(key, "ImagePath", 0, reg.REG_SZ, "path_to_binary")
reg.SetValueEx(key, "Type", 0, reg.REG_DWORD, 0x00000001)
reg.CloseKey(key)
```
Więcej sposobów na nadużycie tego uprawnienia można znaleźć w [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

To jest podobne do **SeRestorePrivilege**. Jego główna funkcja pozwala procesowi **przyjąć własność obiektu**, omijając konieczność uzyskania wyraźnego dostępu dyskrecyjnego poprzez udzielenie praw dostępu WRITE\_OWNER. Proces polega na najpierw zabezpieczeniu własności zamierzonego klucza rejestru w celu zapisu, a następnie zmianie DACL w celu umożliwienia operacji zapisu.
```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant <your_username>:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```
### SeDebugPrivilege

To uprawnienie pozwala na **debugowanie innych procesów**, w tym odczyt i zapis w pamięci. Można zastosować różne strategie wstrzykiwania pamięci, zdolne do unikania większości programów antywirusowych i rozwiązań zapobiegających intruzji na hostingu.

#### Zrzut pamięci

Możesz użyć [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) z pakietu [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite), aby **przechwycić pamięć procesu**. W szczególności dotyczy to procesu **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local\_Security\_Authority\_Subsystem\_Service)**)**, który jest odpowiedzialny za przechowywanie poświadczeń użytkownika po pomyślnym zalogowaniu się do systemu.

Następnie można załadować ten zrzut do mimikatz, aby uzyskać hasła:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Jeśli chcesz uzyskać powłokę `NT SYSTEM`, możesz użyć:

* [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
* [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
* [**psgetsys.ps1 (Skrypt Powershell)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
## Sprawdź uprawnienia
```
whoami /priv
```
**Tokeny, które są oznaczone jako Wyłączone** mogą zostać włączone, co pozwala na nadużycie tokenów _Włączonych_ i _Wyłączonych_.

### Włącz wszystkie tokeny

Jeśli masz tokeny wyłączone, możesz użyć skryptu [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1), aby włączyć wszystkie tokeny:
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
lub **skrypt** osadzony w tym [**poście**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabela

Pełny cheatsheet uprawnień tokenów dostępny pod adresem [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), poniższe podsumowanie zawiera tylko bezpośrednie sposoby wykorzystania uprawnienia do uzyskania sesji administratora lub odczytu poufnych plików.

| Uprawnienie                | Wpływ       | Narzędzie               | Ścieżka wykonania                                                                                                                                                                                                                                                                                                                                   | Uwagi                                                                                                                                                                                                                                                                                                                          |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | Narzędzie zewnętrzne    | _"Pozwala użytkownikowi na podszycie się pod tokeny i eskalację uprawnień do systemu nt za pomocą narzędzi takich jak potato.exe, rottenpotato.exe i juicypotato.exe"_                                                                                                                                                                                 | Dziękuję [Aurélienowi Chalot](https://twitter.com/Defte\_) za aktualizację. Spróbuję wkrótce przefrazować to w bardziej przepisowy sposób.                                                                                                                                                                                        |
| **`SeBackup`**             | **Zagrożenie** | _**Polecenia wbudowane**_ | Odczytaj poufne pliki za pomocą `robocopy /b`                                                                                                                                                                                                                                                                                                      | <p>- Może być bardziej interesujące, jeśli można odczytać %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (i robocopy) nie są pomocne przy otwieraniu plików.<br><br>- Robocopy wymaga zarówno uprawnień SeBackup, jak i SeRestore, aby działać z parametrem /b.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | Narzędzie zewnętrzne    | Utwórz dowolny token, w tym lokalne uprawnienia administratora za pomocą `NtCreateToken`.                                                                                                                                                                                                                                                           |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Zduplikuj token `lsass.exe`.                                                                                                                                                                                                                                                                                                                       | Skrypt można znaleźć na stronie [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                             |
| **`SeLoadDriver`**         | _**Admin**_ | Narzędzie zewnętrzne    | <p>1. Załaduj błędny sterownik jądra, taki jak <code>szkg64.sys</code><br>2. Wykorzystaj podatność sterownika<br><br>Alternatywnie, uprawnienie to może być użyte do wyłączenia sterowników związanych z bezpieczeństwem za pomocą wbudowanego polecenia <code>ftlMC</code>. np.: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. Podatność <code>szkg64</code> jest wymieniona jako <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. Kod eksploatacyjny <code>szkg64</code> został stworzony przez <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Uruchom PowerShell/ISE z obecnością uprawnienia SeRestore.<br>2. Włącz uprawnienie za pomocą <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Zmień nazwę utilman.exe na utilman.old<br>4. Zmień nazwę cmd.exe na utilman.exe<br>5. Zablokuj konsolę i naciśnij Win+U</p> | <p>Atak może być wykryty przez niektóre oprogramowania AV.</p><p>Alternatywna metoda polega na zastąpieniu binarnych plików usługi przechowywanych w "Program Files" tym samym uprawnieniem</p>                                                                                                                                    |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Polecenia wbudowane**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Zmień nazwę cmd.exe na utilman.exe<br>4. Zablokuj konsolę i naciśnij Win+U</p>                                                                                                                                       | <p>Atak może być wykryty przez niektóre oprogramowania AV.</p><p>Alternatywna metoda polega na zastąpieniu binarnych plików usługi przechowywanych w "Program Files" tym samym uprawnieniem.</p>                                                                                                                                      |
| **`SeTcb`**                | _**Admin**_ | Narzędzie zewnętrzne    | <p>Manipuluj tokenami, aby zawierały lokalne uprawnienia administratora. Może wymagać SeImpersonate.</p><p>Do weryfikacji.</p>                                                                                                                                                                                                                   |                                                                                                                                                                                                                                                                                                                                |

## Odnośniki

* Zapoznaj się z tą tabelą definiującą tokeny systemu Windows: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* Przeczytaj [**ten artykuł**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt) o eskalacji uprawnień za pomocą tokenów.
