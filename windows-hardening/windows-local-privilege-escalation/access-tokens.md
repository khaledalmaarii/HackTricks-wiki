# Access Tokens

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}


## Access Tokens

Każdy **użytkownik zalogowany** do systemu **posiada token dostępu z informacjami o bezpieczeństwie** dla tej sesji logowania. System tworzy token dostępu, gdy użytkownik się loguje. **Każdy proces wykonywany** w imieniu użytkownika **ma kopię tokena dostępu**. Token identyfikuje użytkownika, grupy użytkownika oraz uprawnienia użytkownika. Token zawiera również SID logowania (Identifikator Bezpieczeństwa), który identyfikuje bieżącą sesję logowania.

Możesz zobaczyć te informacje, wykonując `whoami /all`
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
or using _Process Explorer_ from Sysinternals (select process and access"Security" tab):

![](<../../.gitbook/assets/image (772).png>)

### Lokalny administrator

Gdy lokalny administrator się loguje, **tworzone są dwa tokeny dostępu**: jeden z uprawnieniami administratora i drugi z normalnymi uprawnieniami. **Domyślnie**, gdy ten użytkownik uruchamia proces, używany jest ten z **zwykłymi** (nie-administratorskimi) **uprawnieniami**. Gdy ten użytkownik próbuje **wykonać** cokolwiek **jako administrator** ("Uruchom jako administrator" na przykład), **UAC** zostanie użyty do zapytania o pozwolenie.\
Jeśli chcesz [**dowiedzieć się więcej o UAC, przeczytaj tę stronę**](../authentication-credentials-uac-and-efs/#uac)**.**

### Uwierzytelnianie użytkownika

Jeśli masz **ważne dane uwierzytelniające innego użytkownika**, możesz **utworzyć** **nową sesję logowania** z tymi danymi:
```
runas /user:domain\username cmd.exe
```
**Token dostępu** ma również **referencję** sesji logowania wewnątrz **LSASS**, co jest przydatne, jeśli proces musi uzyskać dostęp do niektórych obiektów w sieci.\
Możesz uruchomić proces, który **używa różnych poświadczeń do uzyskiwania dostępu do usług sieciowych** za pomocą:
```
runas /user:domain\username /netonly cmd.exe
```
To jest przydatne, jeśli masz użyteczne poświadczenia do uzyskania dostępu do obiektów w sieci, ale te poświadczenia nie są ważne w bieżącym hoście, ponieważ będą używane tylko w sieci (w bieżącym hoście będą używane uprawnienia bieżącego użytkownika).

### Typy tokenów

Dostępne są dwa typy tokenów:

* **Token główny**: Służy jako reprezentacja poświadczeń bezpieczeństwa procesu. Tworzenie i przypisywanie tokenów głównych do procesów to działania wymagające podwyższonych uprawnień, co podkreśla zasadę separacji uprawnień. Zazwyczaj usługa uwierzytelniania jest odpowiedzialna za tworzenie tokenów, podczas gdy usługa logowania zajmuje się ich przypisaniem do powłoki systemu operacyjnego użytkownika. Warto zauważyć, że procesy dziedziczą token główny swojego procesu macierzystego w momencie tworzenia.
* **Token impersonacji**: Umożliwia aplikacji serwerowej tymczasowe przyjęcie tożsamości klienta w celu uzyskania dostępu do zabezpieczonych obiektów. Mechanizm ten jest podzielony na cztery poziomy działania:
* **Anonimowy**: Przyznaje dostęp serwera podobny do tego, który ma nieznany użytkownik.
* **Identyfikacja**: Pozwala serwerowi zweryfikować tożsamość klienta bez wykorzystania jej do uzyskania dostępu do obiektów.
* **Impersonacja**: Umożliwia serwerowi działanie pod tożsamością klienta.
* **Delegacja**: Podobna do impersonacji, ale obejmuje możliwość rozszerzenia tej tożsamości na zdalne systemy, z którymi serwer wchodzi w interakcje, zapewniając zachowanie poświadczeń.

#### Tokeny impersonacji

Używając modułu _**incognito**_ w metasploit, jeśli masz wystarczające uprawnienia, możesz łatwo **wylistować** i **imponować** innymi **tokenami**. Może to być przydatne do wykonywania **działań tak, jakbyś był innym użytkownikiem**. Możesz również **eskalować uprawnienia** za pomocą tej techniki.

### Uprawnienia tokenów

Dowiedz się, które **uprawnienia tokenów mogą być nadużywane do eskalacji uprawnień:**

{% content-ref url="privilege-escalation-abusing-tokens.md" %}
[privilege-escalation-abusing-tokens.md](privilege-escalation-abusing-tokens.md)
{% endcontent-ref %}

Zobacz [**wszystkie możliwe uprawnienia tokenów i niektóre definicje na tej zewnętrznej stronie**](https://github.com/gtworek/Priv2Admin).

## Referencje

Dowiedz się więcej o tokenach w tych samouczkach: [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) i [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)


{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
