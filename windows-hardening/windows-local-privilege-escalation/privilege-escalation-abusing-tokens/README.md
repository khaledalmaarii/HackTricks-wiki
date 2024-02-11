# Wykorzystywanie tokenów

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć reklamę swojej **firmy na HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do repozytorium [hacktricks](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Tokeny

Jeśli **nie wiesz, czym są tokeny dostępu w systemie Windows**, przeczytaj tę stronę, zanim przejdziesz dalej:

{% content-ref url="../access-tokens.md" %}
[access-tokens.md](../access-tokens.md)
{% endcontent-ref %}

**Możliwe, że będziesz w stanie podnieść uprawnienia, wykorzystując już posiadane tokeny**

### SeImpersonatePrivilege

To uprawnienie, które posiada każdy proces, umożliwia podmianę (ale nie tworzenie) dowolnego tokenu, pod warunkiem, że można uzyskać do niego uchwyt. Uprawniony token można uzyskać z usługi systemu Windows (DCOM), wywołując uwierzytelnianie NTLM przeciwko wykorzystaniu, co umożliwia wykonanie procesu z uprawnieniami SYSTEM. Tę podatność można wykorzystać za pomocą różnych narzędzi, takich jak [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (które wymaga wyłączenia winrm), [SweetPotato](https://github.com/CCob/SweetPotato) i [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

{% content-ref url="../roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](../roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="../juicypotato.md" %}
[juicypotato.md](../juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege

Jest bardzo podobne do **SeImpersonatePrivilege**, użyje **tej samej metody** do uzyskania uprzywilejowanego tokenu.\
Następnie, to uprawnienie pozwala **przypisać podstawowy token** do nowego/zawieszonego procesu. Z uprzywilejowanego tokenu impersonacji można utworzyć podstawowy token (DuplicateTokenEx).\
Z tym tokenem można utworzyć **nowy proces** za pomocą 'CreateProcessAsUser' lub utworzyć proces zawieszony i **ustawić token** (zazwyczaj nie można modyfikować podstawowego tokenu działającego procesu).

### SeTcbPrivilege

Jeśli masz włączone to uprawnienie, możesz użyć **KERB\_S4U\_LOGON**, aby uzyskać **token impersonacji** dla dowolnego innego użytkownika, nie znając poświadczeń, **dodać dowolną grupę** (administratorzy) do tokenu, ustawić **poziom integralności** tokenu na "**średni**" i przypisać ten token do **bieżącego wątku** (SetThreadToken).

### SeBackupPrivilege

System jest zmuszony do **udzielenia wszystkim plikom** (ograniczone do operacji odczytu) kontroli dostępu do odczytu za pomocą tego uprawnienia. Jest ono wykorzystywane do **odczytywania skrótów haseł kont lokalnych Administratora** z rejestru, a następnie można użyć narzędzi takich jak "**psexec**" lub "**wmicexec**" z tym skrótem (technika Pass-the-Hash). Jednak ta technika nie działa w dwóch przypadkach: gdy konto lokalnego Administratora jest wyłączone lub gdy obowiązuje zasada, która usuwa prawa administracyjne od Administratorów lokalnych łączących się zdalnie.\
Możesz **wykorzystać to uprawnienie** za pomocą:

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* śledząc **IppSec** w [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)
* lub zgodnie z wyjaśnieniem w sekcji **podnoszenie uprawnień z operatorami kopii zapasowych** w:

{% content-ref url="../../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### SeRestorePrivilege

To uprawnienie umożliwia **zapis do dowolnego pliku systemowego**, niezależnie od listy kontroli dostępu (ACL) pliku. Otwiera to wiele możliwości eskalacji, w tym możliwość **modyfikacji usług**, wykonywania DLL Hijackingu i ustawiania **debuggerów** za pomocą Image File Execution Options oraz wiele innych technik.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege to potężne uprawnienie, szczególnie przydatne, gdy użytkownik ma możliwość podmiany tokenów, ale także w przypadku braku uprawnienia SeImpersonatePrivilege. Ta zdolność opiera się na możliwości podmiany tokenu, który reprezentuje tego samego użytkownika i którego poziom integralności nie przekracza poziomu integralności bieżącego procesu.

**Kluczowe punkty:**
- **Podmiana tożsamości bez uprawnienia SeImpersonatePrivilege:** Możliwe jest wykorzystanie uprawnienia SeCreateTokenPrivilege do podniesienia uprawnień poprzez podmianę tokenów w określonych warunkach.
- **Warunki podmiany tokenów:** Aby podmiana była udana, token docelowy musi należeć do tego samego użytkownika i mieć poziom integralności mniejszy lub równy poziomowi integralności procesu próbującego dokonać podmiany.
- **Tworzenie i modyfikacja tokenów podmiany:** Użytkownicy mogą tworzyć token podmiany i ulepszać go, dodając identyfikator zabezpieczeń (SID) uprzywilejowanej grupy.

### SeLoadDriverPrivilege

To uprawnienie umożliwia **ładowanie i usuwanie sterowników urządzeń**
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
Więcej sposobów na wykorzystanie tej uprzywilejowanej roli znajduje się na stronie [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

To jest podobne do **SeRestorePrivilege**. Jego główna funkcja pozwala procesowi **przejmować własność obiektu**, omijając wymaganie udzielania jawnego dostępu dyskrecjonalnego poprzez zapewnienie praw dostępu WRITE_OWNER. Proces polega na najpierw zabezpieczeniu własności zamierzonego klucza rejestru w celu zapisu, a następnie zmianie DACL w celu umożliwienia operacji zapisu.
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

Ta uprawnienie umożliwia **debugowanie innych procesów**, w tym odczyt i zapis w pamięci. Można zastosować różne strategie wstrzykiwania pamięci, które są w stanie uniknąć większości programów antywirusowych i rozwiązań do zapobiegania intruzji na hosta.

#### Zrzut pamięci

Możesz użyć [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) z [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite), aby **przechwycić pamięć procesu**. W szczególności dotyczy to procesu **Local Security Authority Subsystem Service ([LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service))**, który jest odpowiedzialny za przechowywanie poświadczeń użytkownika po pomyślnym zalogowaniu do systemu.

Następnie możesz załadować ten zrzut do mimikatz, aby uzyskać hasła:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Jeśli chcesz uzyskać powłokę `NT SYSTEM`, możesz użyć:

* ****[**SeDebugPrivilegePoC**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)****
* ****[**psgetsys.ps1**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)****
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
## Sprawdź uprawnienia

To determine the privileges of the current user, you can use the following methods:

### 1. Whoami

The `whoami` command displays the username and group membership of the current user.

```plaintext
whoami
```

### 2. Net user

The `net user` command provides detailed information about user accounts, including their group memberships and privileges.

```plaintext
net user <username>
```

Replace `<username>` with the name of the user you want to check.

### 3. Systeminfo

The `systeminfo` command displays detailed information about the system, including the privileges of the current user.

```plaintext
systeminfo
```

### 4. PowerShell

You can also use PowerShell to check the privileges of the current user. Run the following command:

```plaintext
whoami /priv
```

This will display a list of privileges assigned to the current user.

Remember that these methods will only show the privileges of the current user. To check the privileges of other users, you may need administrative access or specific permissions.
```
whoami /priv
```
**Tokeny, które są wyłączone**, można włączyć, a tak naprawdę można nadużywać tokenów _Włączonych_ i _Wyłączonych_.

### Włącz wszystkie tokeny

Jeśli masz wyłączone tokeny, możesz użyć skryptu [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1), aby włączyć wszystkie tokeny:
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Lub **skrypt** osadzony w tym [**poście**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabela

Pełna ściąga uprawnień tokenów dostępna pod adresem [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), poniżej znajdują się tylko bezpośrednie sposoby wykorzystania uprawnień w celu uzyskania sesji administratora lub odczytu poufnych plików.

| Uprawnienie                | Wpływ       | Narzędzie               | Ścieżka wykonania                                                                                                                                                                                                                                                                                                                                 | Uwagi                                                                                                                                                                                                                                                                                                                          |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | Narzędzie firm trzecich | _"Pozwala użytkownikowi na podszywanie się pod tokeny i eskalację uprawnień do nt system przy użyciu narzędzi takich jak potato.exe, rottenpotato.exe i juicypotato.exe"_                                                                                                                                                                              | Dziękuję [Aurélienowi Chalot](https://twitter.com/Defte\_) za aktualizację. Postaram się wkrótce przepisać to na coś bardziej przypominającego przepis.                                                                                                                                                                        |
| **`SeBackup`**             | **Zagrożenie**  | _**Wbudowane polecenia**_ | Odczytaj poufne pliki za pomocą `robocopy /b`                                                                                                                                                                                                                                                                                                             | <p>- Może być bardziej interesujące, jeśli można odczytać %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (i robocopy) nie są pomocne przy otwieraniu plików.<br><br>- Robocopy wymaga zarówno uprawnień SeBackup, jak i SeRestore, aby działać z parametrem /b.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | Narzędzie firm trzecich | Utwórz dowolny token, w tym z lokalnymi uprawnieniami administratora za pomocą `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Zduplikuj token `lsass.exe`.                                                                                                                                                                                                                                                                                                                   | Skrypt można znaleźć pod adresem [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | Narzędzie firm trzecich | <p>1. Załaduj wadliwy sterownik jądra, tak jak <code>szkg64.sys</code><br>2. Wykorzystaj podatność sterownika<br><br>Alternatywnie, uprawnienie to może być używane do wyładowania sterowników związanych z zabezpieczeniami za pomocą wbudowanego polecenia <code>ftlMC</code>. np.: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. Podatność <code>szkg64</code> jest wymieniona jako <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. Kod eksploitacji <code>szkg64</code> został stworzony przez <a href="https://twitter.com/parvezghh">Parveza Anwara</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Uruchom PowerShell/ISE z obecnością uprawnienia SeRestore.<br>2. Włącz uprawnienie za pomocą <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Zmień nazwę utilman.exe na utilman.old<br>4. Zmień nazwę cmd.exe na utilman.exe<br>5. Zablokuj konsolę i naciśnij Win+U</p> | <p>Atak może być wykryty przez niektóre oprogramowanie antywirusowe.</p><p>Alternatywna metoda polega na zastąpieniu binarnych plików usług przechowywanych w "Program Files" przy użyciu tego samego uprawnienia</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Wbudowane polecenia**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Zmień nazwę cmd.exe na utilman.exe<br>4. Zablokuj konsolę i naciśnij Win+U</p>                                                                                                                                       | <p>Atak może być wykryty przez niektóre oprogramowanie antywirusowe.</p><p>Alternatywna metoda polega na zastąpieniu binarnych plików usług przechowywanych w "Program Files" przy użyciu tego samego uprawnienia.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | Narzędzie firm trzecich | <p>Zmieniaj tokeny, aby zawierały lokalne uprawnienia administratora. Może wymagać SeImpersonate.</p><p>Do weryfikacji.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Odnośniki

* Zapoznaj się z tą tabelą definiującą tokeny systemu Windows: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* Przeczytaj [**ten artykuł**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt) na temat eskalacji uprawnień za pomocą tokenów.

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć **reklamę swojej firmy w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR do repozytorium [hacktricks](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
