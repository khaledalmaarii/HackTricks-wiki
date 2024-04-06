# Access Tokens

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Tokeny dostępu

Każdy **zalogowany użytkownik** na systemie **posiada token dostępu z informacjami o zabezpieczeniach** dla tej sesji logowania. System tworzy token dostępu, gdy użytkownik się loguje. **Każdy proces wykonany** w imieniu użytkownika **ma kopię tokenu dostępu**. Token identyfikuje użytkownika, grupy użytkownika i uprawnienia użytkownika. Token zawiera również SID logowania (Security Identifier), który identyfikuje bieżącą sesję logowania.

Możesz zobaczyć te informacje wykonując polecenie `whoami /all`

```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

lub używając _Process Explorer_ z Sysinternals (wybierz proces i przejdź do zakładki "Security"):

![](<../../.gitbook/assets/image (321).png>)

### Lokalny administrator

Kiedy lokalny administrator loguje się, **tworzone są dwa tokeny dostępu**: jeden z uprawnieniami administratora i drugi z normalnymi uprawnieniami. **Domyślnie**, gdy ten użytkownik uruchamia proces, używany jest token z **zwykłymi** (nieadministrator) **uprawnieniami**. Gdy ten użytkownik próbuje **wykonać** cokolwiek **jako administrator** (np. "Uruchom jako administrator"), zostanie użyty **UAC**, aby poprosić o zgodę.\
Jeśli chcesz [**dowiedzieć się więcej o UAC, przeczytaj tę stronę**](../authentication-credentials-uac-and-efs/#uac)**.**

### Impersonacja użytkownika z użyciem poświadczeń

Jeśli masz **ważne poświadczenia innego użytkownika**, możesz **utworzyć nową sesję logowania** z tymi poświadczeniami:

```
runas /user:domain\username cmd.exe
```

**Token dostępu** ma również **odwołanie** do sesji logowania wewnątrz **LSASS**, co jest przydatne, jeśli proces musi uzyskać dostęp do niektórych obiektów sieciowych.\
Możesz uruchomić proces, który **korzysta z innych poświadczeń do dostępu do usług sieciowych** za pomocą:

```
runas /user:domain\username /netonly cmd.exe
```

To jest przydatne, jeśli masz użyteczne poświadczenia dostępu do obiektów w sieci, ale te poświadczenia nie są ważne wewnątrz bieżącego hosta, ponieważ będą one używane tylko w sieci (w bieżącym hoście będą używane twoje bieżące uprawnienia użytkownika).

### Rodzaje tokenów

Dostępne są dwa rodzaje tokenów:

* **Token podstawowy**: Służy jako reprezentacja poświadczeń bezpieczeństwa procesu. Tworzenie i powiązywanie tokenów podstawowych z procesami to działania, które wymagają podwyższonych uprawnień, podkreślając zasadę separacji uprawnień. Zazwyczaj za tworzenie tokenów odpowiada usługa uwierzytelniania, podczas gdy usługa logowania zajmuje się ich powiązaniem z powłoką systemu operacyjnego użytkownika. Warto zauważyć, że procesy dziedziczą token podstawowy swojego procesu nadrzędnego podczas tworzenia.
* **Token personifikacji**: Umożliwia aplikacji serwerowej tymczasowe przyjęcie tożsamości klienta w celu uzyskania dostępu do bezpiecznych obiektów. Ten mechanizm jest warstwowo podzielony na cztery poziomy działania:
* **Anonimowy**: Zapewnia dostęp serwera podobny do dostępu niezidentyfikowanego użytkownika.
* **Identyfikacja**: Pozwala serwerowi zweryfikować tożsamość klienta bez wykorzystywania jej do dostępu do obiektów.
* **Personifikacja**: Umożliwia serwerowi działanie w ramach tożsamości klienta.
* **Delegacja**: Podobne do personifikacji, ale obejmuje możliwość rozszerzenia tego założenia tożsamości na zdalne systemy, z którymi serwer współdziała, zapewniając zachowanie poświadczeń.

#### Personifikacja tokenów

Korzystając z modułu _**incognito**_ w metasploicie, jeśli masz wystarczające uprawnienia, możesz łatwo **wyświetlić** i **personifikować** inne **tokeny**. Może to być przydatne do wykonywania **działań tak, jakbyś był innym użytkownikiem**. Możesz również **podwyższyć uprawnienia** za pomocą tej techniki.

### Uprawnienia tokenów

Dowiedz się, które **uprawnienia tokenów mogą być wykorzystane do podwyższania uprawnień:**

{% content-ref url="privilege-escalation-abusing-tokens.md" %}
[privilege-escalation-abusing-tokens.md](privilege-escalation-abusing-tokens.md)
{% endcontent-ref %}

Zapoznaj się z [**wszystkimi możliwymi uprawnieniami tokenów i niektórymi definicjami na tej zewnętrznej stronie**](https://github.com/gtworek/Priv2Admin).

## Odnośniki

Dowiedz się więcej o tokenach w tych samouczkach: [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) i [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

<details>

<summary><strong>Dowiedz się o hakowaniu AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Czy pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Uzyskaj [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR do repozytorium** [**hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
