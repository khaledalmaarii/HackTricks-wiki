# Systemowe rozszerzenia macOS

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów GitHub.

</details>

## Systemowe rozszerzenia / Framework Endpoint Security

W przeciwieństwie do rozszerzeń jądra, **systemowe rozszerzenia działają w przestrzeni użytkownika** zamiast w przestrzeni jądra, co zmniejsza ryzyko awarii systemu spowodowanej nieprawidłowym działaniem rozszerzenia.

<figure><img src="../../../.gitbook/assets/image (1) (3) (1) (1).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Istnieją trzy rodzaje systemowych rozszerzeń: Rozszerzenia **DriverKit**, Rozszerzenia **Network** i Rozszerzenia **Endpoint Security**.

### **Rozszerzenia DriverKit**

DriverKit to zastępstwo dla rozszerzeń jądra, które **zapewniają obsługę sprzętu**. Pozwala sterownikom urządzeń (takim jak sterowniki USB, szeregowe, NIC i HID) działać w przestrzeni użytkownika zamiast w przestrzeni jądra. Framework DriverKit zawiera **wersje przestrzeni użytkownika niektórych klas I/O Kit**, a jądro przekazuje normalne zdarzenia I/O Kit do przestrzeni użytkownika, oferując bezpieczniejsze środowisko dla tych sterowników.

### **Rozszerzenia Network**

Rozszerzenia Network umożliwiają dostosowywanie zachowań sieciowych. Istnieje kilka rodzajów rozszerzeń sieciowych:

* **App Proxy**: Służy do tworzenia klienta VPN, który implementuje protokół VPN oparty na przepływach. Oznacza to, że obsługuje ruch sieciowy na podstawie połączeń (lub przepływów), a nie pojedynczych pakietów.
* **Packet Tunnel**: Służy do tworzenia klienta VPN, który implementuje protokół VPN oparty na pakietach. Oznacza to, że obsługuje ruch sieciowy na podstawie pojedynczych pakietów.
* **Filter Data**: Służy do filtrowania "przepływów" sieciowych. Może monitorować lub modyfikować dane sieciowe na poziomie przepływu.
* **Filter Packet**: Służy do filtrowania pojedynczych pakietów sieciowych. Może monitorować lub modyfikować dane sieciowe na poziomie pakietu.
* **DNS Proxy**: Służy do tworzenia niestandardowego dostawcy DNS. Może być używany do monitorowania lub modyfikowania żądań i odpowiedzi DNS.

## Framework Endpoint Security

Endpoint Security to framework dostarczany przez Apple w macOS, który zapewnia zestaw interfejsów API do zabezpieczeń systemowych. Jest przeznaczony do użytku przez **dostawców zabezpieczeń i programistów w celu budowania produktów, które mogą monitorować i kontrolować aktywność systemu** w celu identyfikacji i ochrony przed działaniami szkodliwymi.

Ten framework zapewnia **zbiór interfejsów API do monitorowania i kontrolowania aktywności systemu**, takich jak wykonywanie procesów, zdarzenia systemu plików, zdarzenia sieciowe i jądra.

Rdzeń tego frameworka jest zaimplementowany w jądrze jako rozszerzenie jądra (KEXT) znajdujące się w **`/System/Library/Extensions/EndpointSecurity.kext`**. KEXT ten składa się z kilku kluczowych komponentów:

* **EndpointSecurityDriver**: Działa jako "punkt wejścia" do rozszerzenia jądra. Jest głównym punktem interakcji między systemem operacyjnym a frameworkiem Endpoint Security.
* **EndpointSecurityEventManager**: Odpowiada za implementację haków jądra. Haki jądra pozwalają frameworkowi monitorować zdarzenia systemowe poprzez przechwytywanie wywołań systemowych.
* **EndpointSecurityClientManager**: Zarządza komunikacją z klientami przestrzeni użytkownika, śledząc, które klienty są podłączone i wymagają otrzymywania powiadomień o zdarzeniach.
* **EndpointSecurityMessageManager**: Wysyła wiadomości i powiadomienia o zdarzeniach do klientów przestrzeni użytkownika.

Zdarzenia, które framework Endpoint Security może monitorować, są kategoryzowane jako:

* Zdarzenia plików
* Zdarzenia procesów
* Zdarzenia gniazd
* Zdarzenia jądra (takie jak ładowanie/odładowanie rozszerzenia jądra lub otwieranie urządzenia I/O Kit)

### Architektura frameworka Endpoint Security

<figure><img src="../../../.gitbook/assets/image (3) (8).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

Komunikacja **przestrzeni użytkownika** z frameworkiem Endpoint Security odbywa się za pomocą klasy IOUserClient. Używane są dwie różne podklasy, w zależności od rodzaju wywołującego:

* **EndpointSecurityDriverClient**: Wymaga uprawnienia `com.apple.private.endpoint-security.manager`, które posiada tylko proces systemowy `endpointsecurityd`.
* **EndpointSecurityExternalClient**: Wymaga uprawnienia `com.apple.developer.endpoint-security.client`. Zazwyczaj jest to używane przez oprogramowanie zewnętrznych dostawców zabezpieczeń, które musi współdziałać z frameworkiem Endpoint Security.

Rozszerzenia Endpoint Security:**`libEndpointSecurity.dylib`** to biblioteka C, którą rozszerzenia systemowe używają do komunikacji z jądrem. Ta biblioteka korzysta z I/O Kit (`IOKit`) do komunikacji z rozszerzeniem Endpoint Security KEXT.

**`endpointsecurityd`** to kluczowy demon systemowy odpowiedzialny za zarządzanie i uruchamianie rozszerzeń systemowych związanych z bezpieczeństwem punktu końcowego, zwłaszcza podczas wczesnego procesu uruchamiania. **Tylko rozszerzenia systemowe** oznaczone jako **`NSEndpointSecurityEarlyBoot`** w pliku `Info.plist` otrzymują to wczesne traktowanie podczas uruchamiania.

Inny demon systemowy, **`sysextd`**, **sprawdza poprawność rozszerzeń systemowych** i przenosi je do odpowiednich lokalizacji systemowych. Następnie prosi odpowiedniego demona o załadowanie rozszerzenia. **`SystemExtensions.framework`** jest odpowiedzialny za aktywowanie i dezaktywowanie rozszerzeń systemowych.

## Omijanie ESF

ESF jest używany przez narzędzia zabezpieczeń, które próbują wykryć red teamera, więc jakiekolwiek informacje na temat tego, jak można tego uniknąć, brzmią interesująco.

### CVE-2021-30965

Rzecz w tym, że aplikacja zabezpieczająca musi mieć **pełny dostęp do dysku**. Jeśli atakujący mógłby to usunąć, mógłby zapobiec uruchomieniu oprogramowania:
```bash
tccutil reset All
```
Dla **więcej informacji** na temat tego obejścia i powiązanych obejść, sprawdź prezentację [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Na końcu problem ten został naprawiony poprzez nadanie nowego uprawnienia **`kTCCServiceEndpointSecurityClient`** aplikacji zabezpieczeń zarządzanej przez **`tccd`**, dzięki czemu `tccutil` nie będzie usuwał jej uprawnień, co uniemożliwia jej uruchomienie.

## Referencje

* [**OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
* [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
