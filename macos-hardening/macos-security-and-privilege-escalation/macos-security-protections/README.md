# Ochrona macOS

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Gatekeeper

Gatekeeper to zazwyczaj odnosi się do kombinacji **Quarantine + Gatekeeper + XProtect**, 3 modułów bezpieczeństwa macOS, które będą próbować **zapobiec uruchamianiu potencjalnie złośliwego oprogramowania pobranego przez użytkowników**.

Więcej informacji:

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## Ograniczenia procesów

### SIP - System Integrity Protection

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### Sandbox

Piaskownica macOS **ogranicza działanie aplikacji** uruchamianych wewnątrz piaskownicy do **dozwolonych działań określonych w profilu piaskownicy**, z jakim aplikacja jest uruchamiana. Pomaga to zapewnić, że **aplikacja będzie miała dostęp tylko do oczekiwanych zasobów**.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** to framework bezpieczeństwa. Został zaprojektowany do **zarządzania uprawnieniami** aplikacji, w szczególności regulującym ich dostęp do funkcji ochrony prywatności i kontroli danych osobowych, takich jak **usługi lokalizacyjne, kontakty, zdjęcia, mikrofon, kamera, dostępność i pełny dostęp do dysku**. TCC zapewnia, że aplikacje mogą uzyskać dostęp do tych funkcji tylko po uzyskaniu wyraźnej zgody użytkownika, wzmacniając tym samym prywatność i kontrolę nad danymi osobowymi.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### Ograniczenia uruchamiania/środowiska i pamięć podręczna zaufania

Ograniczenia uruchamiania w macOS to funkcja bezpieczeństwa, która **reguluje inicjację procesu**, określając, **kto może uruchomić** proces, **jak** i **skąd**. Wprowadzone w macOS Ventura, kategoryzują binarne pliki systemowe w kategoriach ograniczeń w ramach **pamięci podręcznej zaufania**. Każdy plik wykonywalny ma określone **zasady** dotyczące jego **uruchamiania**, w tym ograniczenia **własne**, **rodzica** i **odpowiedzialne**. Rozszerzone na aplikacje firm trzecich jako Ograniczenia **środowiskowe** w macOS Sonoma, te funkcje pomagają łagodzić potencjalne wykorzystania systemu, regulując warunki uruchamiania procesu.

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - Narzędzie do usuwania złośliwego oprogramowania

Narzędzie do usuwania złośliwego oprogramowania (MRT) to kolejna część infrastruktury bezpieczeństwa macOS. Jak wskazuje nazwa, główną funkcją MRT jest **usuwanie znanego złośliwego oprogramowania z zainfekowanych systemów**.

Po wykryciu złośliwego oprogramowania na komputerze Mac (zarówno przez XProtect, jak i za pomocą innych środków), MRT może być używane do automatycznego **usunięcia złośliwego oprogramowania**. MRT działa w tle i zazwyczaj uruchamia się za każdym razem, gdy system jest aktualizowany lub gdy pobierana jest nowa definicja złośliwego oprogramowania (wygląda na to, że reguły, według których MRT wykrywa złośliwe oprogramowanie, znajdują się wewnątrz binarnego pliku).

Podczas gdy zarówno XProtect, jak i MRT są częścią środków bezpieczeństwa macOS, pełnią one różne funkcje:

* **XProtect** to narzędzie zapobiegawcze. **Sprawdza pliki podczas ich pobierania** (za pośrednictwem określonych aplikacji) i jeśli wykryje jakiekolwiek znane typy złośliwego oprogramowania, **uniemożliwia otwarcie pliku**, tym samym zapobiegając zainfekowaniu systemu przez złośliwe oprogramowanie.
* **MRT** natomiast jest **narzędziem reaktywnym**. Działa po wykryciu złośliwego oprogramowania na systemie, mając na celu usunięcie szkodliwego oprogramowania w celu oczyszczenia systemu.

Aplikacja MRT znajduje się w **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Zarządzanie zadaniami w tle

**macOS** teraz **informuje** za każdym razem, gdy narzędzie używa dobrze znanego **sposobu na utrwalenie wykonywania kodu** (takiego jak elementy logowania, demony...), dzięki czemu użytkownik lepiej wie, **które oprogramowanie jest trwałe**.

<figure><img src="../../../.gitbook/assets/image (711).png" alt=""><figcaption></figcaption></figure>

Działa to z **demona** znajdującego się w `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` oraz **agenta** w `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`

Sposób, w jaki **`backgroundtaskmanagementd`** wie, że coś jest zainstalowane w trwałym folderze, polega na **otrzymywaniu zdarzeń FSEvents** i tworzeniu odpowiednich **handlerów** dla nich.

Ponadto, istnieje plik plist, który zawiera **dobrze znane aplikacje**, które często są trwałe i są utrzymywane przez Apple, znajdujący się pod adresem: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
```json
[...]
"us.zoom.ZoomDaemon" => {
"AssociatedBundleIdentifiers" => [
0 => "us.zoom.xos"
]
"Attribution" => "Zoom"
"Program" => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
"ProgramArguments" => [
0 => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
]
"TeamIdentifier" => "BJ4HAAB9B3"
}
[...]
```
### Wyliczanie

Możliwe jest **wyliczenie wszystkich** skonfigurowanych elementów tła za pomocą narzędzia Apple CLI:
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Ponadto, możliwe jest również wylistowanie tych informacji za pomocą [**DumpBTM**](https://github.com/objective-see/DumpBTM).
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Ta informacja jest przechowywana w **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** i Terminal potrzebuje FDA.

### Mieszanie z BTM

Gdy zostanie znalezione nowe trwałe zdarzenie typu **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Więc, jakakolwiek metoda **uniemożliwiająca** wysłanie tego **zdarzenia** lub **powiadomienia użytkownika przez agenta** pomoże atakującemu w _**ominięciu**_ BTM.

* **Resetowanie bazy danych**: Uruchomienie następującej komendy zresetuje bazę danych (powinna być odbudowana od podstaw), jednak z jakiegoś powodu po jej uruchomieniu **nie zostaną wyświetlone żadne nowe trwałe zdarzenia, dopóki system nie zostanie ponownie uruchomiony**.
* Wymagane jest **root**.
```bash
# Reset the database
sfltool resettbtm
```
* **Zatrzymaj agenta**: Możliwe jest wysłanie sygnału zatrzymania do agenta, aby **nie powiadamiał użytkownika**, gdy zostaną znalezione nowe wykrycia.
```bash
# Get PID
pgrep BackgroundTaskManagementAgent
1011

# Stop it
kill -SIGSTOP 1011

# Check it's stopped (a T means it's stopped)
ps -o state 1011
T
```
* **Błąd**: Jeśli **proces, który utworzył trwałość, zakończy się szybko po tym**, demon spróbuje **uzyskać informacje** na jego temat, **nie powiedzie się** i **nie będzie w stanie wysłać zdarzenia** wskazującego, że coś nowego jest trwałe.

Odnośniki i **więcej informacji na temat BTM**:

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
