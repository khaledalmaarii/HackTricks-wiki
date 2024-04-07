# Zabezpieczenia macOS

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>

## Gatekeeper

Gatekeeper to zazwyczaj odnosi się do kombinacji **Kwarantanna + Gatekeeper + XProtect**, 3 modułów bezpieczeństwa macOS, które będą próbować **zapobiec użytkownikom uruchamiania potencjalnie złośliwego oprogramowania pobranego**.

Więcej informacji w:

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## Ograniczenia procesów

### SIP - Ochrona Integralności Systemu

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### Piaskownica

Piaskownica macOS **ogranicza działanie aplikacji** uruchamianych wewnątrz piaskownicy do **dozwolonych akcji określonych w profilu piaskownicy**, z którą aplikacja jest uruchamiana. Pomaga to zapewnić, że **aplikacja będzie uzyskiwać dostęp tylko do oczekiwanych zasobów**.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **Przejrzystość, Zgoda i Kontrola**

**TCC (Przejrzystość, Zgoda i Kontrola)** to framework bezpieczeństwa. Został zaprojektowany do **zarządzania uprawnieniami** aplikacji, regulując ich dostęp do wrażliwych funkcji. Obejmuje elementy takie jak **usługi lokalizacyjne, kontakty, zdjęcia, mikrofon, kamera, dostępność i pełny dostęp do dysku**. TCC zapewnia, że aplikacje mogą uzyskać dostęp do tych funkcji dopiero po uzyskaniu wyraźnej zgody użytkownika, wzmacniając tym samym prywatność i kontrolę nad danymi osobowymi.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### Ograniczenia uruchamiania/środowiska i pamięć podręczna zaufania

Ograniczenia uruchamiania w macOS to funkcja bezpieczeństwa, która **reguluje inicjowanie procesu**, określając **kto może uruchomić** proces, **jak** i **skąd**. Wprowadzone w macOS Ventura, kategoryzują binaria systemowe do kategorii ograniczeń w ramach **pamięci podręcznej zaufania**. Każdy wykonywalny binarny plik ma określone **zasady** dla swojego **uruchomienia**, w tym ograniczenia **własne**, **rodzicielskie** i **odpowiedzialne**. Rozszerzone na aplikacje innych firm jako Ograniczenia **Środowiskowe** w macOS Sonoma, te funkcje pomagają zmniejszyć potencjalne wykorzystania systemu, regulując warunki uruchamiania procesu.

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - Narzędzie do Usuwania Złośliwego Oprogramowania

Narzędzie do usuwania złośliwego oprogramowania (MRT) to kolejna część infrastruktury bezpieczeństwa macOS. Jak sugeruje nazwa, główną funkcją MRT jest **usuwanie znanego złośliwego oprogramowania z zainfekowanych systemów**.

Gdy złośliwe oprogramowanie zostanie wykryte na Macu (zarówno przez XProtect, jak i innymi środkami), MRT może być używane do automatycznego **usunięcia złośliwego oprogramowania**. MRT działa w tle i zazwyczaj uruchamia się za każdym razem, gdy system jest aktualizowany lub gdy pobierana jest nowa definicja złośliwego oprogramowania (wygląda na to, że reguły, według których MRT wykrywa złośliwe oprogramowanie, znajdują się wewnątrz binariów).

Podczas gdy zarówno XProtect, jak i MRT są częścią środków bezpieczeństwa macOS, pełnią różne funkcje:

* **XProtect** jest narzędziem zapobiegawczym. **Sprawdza pliki podczas pobierania** (za pośrednictwem określonych aplikacji) i jeśli wykryje jakiekolwiek znane typy złośliwego oprogramowania, **zapobiega otwarciu pliku**, uniemożliwiając tym samym zainfekowanie systemu przez złośliwe oprogramowanie na samym początku.
* **MRT** natomiast jest **narzędziem reaktywnym**. Działa po wykryciu złośliwego oprogramowania na systemie, z celem usunięcia szkodliwego oprogramowania w celu oczyszczenia systemu.

Aplikacja MRT znajduje się w **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Zarządzanie Zadaniami W Tle

**macOS** teraz **informuje** za każdym razem, gdy narzędzie wykorzystuje dobrze znaną **technikę trwałego wykonywania kodu** (taką jak Elementy logowania, Daemony...), dzięki czemu użytkownik lepiej **wie, które oprogramowanie jest trwałe**.

<figure><img src="../../../.gitbook/assets/image (1180).png" alt=""><figcaption></figcaption></figure>

Działa to za pomocą **demona** znajdującego się w `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` oraz **agenta** w `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`

Sposób, w jaki **`backgroundtaskmanagementd`** wie, że coś jest zainstalowane w trwałym folderze, polega na **uzyskiwaniu zdarzeń FSEvents** i tworzeniu pewnych **obsług** dla nich.

Co więcej, istnieje plik plist zawierający **dobrze znane aplikacje**, które często są trwałe, utrzymywane przez Apple, znajdujący się pod adresem: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
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
### Wyliczenie

Możliwe jest **wyliczenie wszystkich** skonfigurowanych elementów tła za pomocą narzędzia wiersza poleceń Apple:
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Ponadto istnieje możliwość wylistowania tych informacji za pomocą [**DumpBTM**](https://github.com/objective-see/DumpBTM).
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Te informacje są przechowywane w **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** i Terminal potrzebuje FDA.

### Bawienie się z BTM

Kiedy zostanie znalezione nowe trwałe zdarzenie typu **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Więc, każdy sposób na **zapobieżenie** wysłania tego **zdarzenia** lub **powiadomienia agenta** użytkownika pomoże atakującemu w _**obejściu**_ BTM.

* **Resetowanie bazy danych**: Uruchomienie poniższej komendy zresetuje bazę danych (powinna ją odbudować od nowa), jednakże, z jakiegoś powodu, po jej uruchomieniu, **żadne nowe trwałe zdarzenia nie będą powiadamiane aż do ponownego uruchomienia systemu**.
* Wymagane jest **root**.
```bash
# Reset the database
sfltool resettbtm
```
* **Zatrzymaj agenta**: Możliwe jest wysłanie sygnału zatrzymania do agenta, dzięki czemu **nie będzie on alarmował użytkownika**, gdy zostaną znalezione nowe wykrycia.
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
* **Błąd**: Jeśli **proces, który utworzył trwałość, istnieje szybko po tym**, demon spróbuje **uzyskać informacje** na jego temat, **zawiódł** i **nie będzie w stanie wysłać zdarzenia** wskazującego, że coś nowego jest trwałe.

Odnośniki i **więcej informacji o BTM**:

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Kup [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
