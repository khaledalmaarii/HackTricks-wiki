# macOS MDM

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

**Aby dowiedzieć się więcej o macOS MDM, sprawdź:**

* [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
* [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Podstawy

### **Przegląd MDM (Mobile Device Management)**
[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) jest wykorzystywane do zarządzania różnymi urządzeniami końcowymi, takimi jak smartfony, laptopy i tablety. Szczególnie dla platform Apple (iOS, macOS, tvOS) obejmuje zestaw specjalistycznych funkcji, interfejsów API i praktyk. Działanie MDM opiera się na kompatybilnym serwerze MDM, który jest dostępny komercyjnie lub jako oprogramowanie open-source i musi obsługiwać [Protokół MDM](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Kluczowe punkty obejmują:

- Skoncentrowana kontrola nad urządzeniami.
- Zależność od serwera MDM, który przestrzega protokołu MDM.
- Możliwość wysyłania różnych poleceń do urządzeń przez serwer MDM, na przykład zdalne usuwanie danych lub instalacja konfiguracji.

### **Podstawy DEP (Device Enrollment Program)**
[Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) oferowany przez Apple ułatwia integrację Mobile Device Management (MDM), umożliwiając konfigurację urządzeń bez konieczności interwencji użytkownika lub administratora. DEP automatyzuje proces rejestracji, umożliwiając urządzeniom natychmiastowe uruchomienie po wyjęciu z pudełka, z minimalnym zaangażowaniem użytkownika lub administratora. Istotne aspekty obejmują:

- Pozwala urządzeniom na samodzielne zarejestrowanie się na predefiniowanym serwerze MDM podczas pierwszej aktywacji.
- Przede wszystkim korzystne dla nowych urządzeń, ale także stosowane dla urządzeń poddawanych rekonfiguracji.
- Ułatwia prostą konfigurację, dzięki czemu urządzenia są gotowe do użycia w organizacji szybko.

### **Uwagi dotyczące bezpieczeństwa**
Należy zauważyć, że łatwość rejestracji zapewniana przez DEP, choć korzystna, może również wiązać się z ryzykiem bezpieczeństwa. Jeśli nie są odpowiednio egzekwowane środki ochrony podczas rejestracji MDM, atakujący mogą wykorzystać ten uproszczony proces, aby zarejestrować swoje urządzenie na serwerze MDM organizacji, podszywając się pod urządzenie korporacyjne.

{% hint style="danger" %}
**Ostrzeżenie o bezpieczeństwie**: Uproszczona rejestracja DEP może potencjalnie umożliwić nieautoryzowaną rejestrację urządzenia na serwerze MDM organizacji, jeśli nie są wdrożone odpowiednie zabezpieczenia.
{% endhint %}

### Podstawy Co to jest SCEP (Simple Certificate Enrolment Protocol)?

* Relatywnie stary protokół, stworzony przed rozpowszechnieniem się TLS i HTTPS.
* Daje klientom standaryzowany sposób wysyłania **żądania podpisania certyfikatu** (CSR) w celu uzyskania certyfikatu. Klient prosi serwer o podpisanie certyfikatu.

### Czym są profile konfiguracji (znane również jako mobileconfigs)?

* Oficjalny sposób Apple na **ustawianie/wymuszanie konfiguracji systemu**.
* Format pliku, który może zawierać wiele ładunków.
* Oparte na listach właściwości (rodzaj XML).
* "mogą być podpisane i zaszyfrowane w celu potwierdzenia ich pochodzenia, zapewnienia integralności i ochrony ich zawartości." Podstawy — Strona 70, iOS Security Guide, styczeń 2018.

## Protokoły

### MDM

* Połączenie APNs (**serwery Apple**) + RESTful API (**serwery dostawców MDM**)
* **Komunikacja** odbywa się między **urządzeniem** a serwerem związanym z **produktem zarządzania urządzeniami**.
* **Polecenia** są dostarczane z serwera MDM do urządzenia w formie **słowników zakodowanych w formacie plist**.
* Wszystko odbywa się przez **HTTPS**. Serwery MDM mogą być (i zazwyczaj są) przypinane.
* Apple przyznaje dostawcy MDM **certyfikat APNs** do uwierzytelniania.

### DEP

* **3 interfejsy API**: 1 dla sprzedawców, 1 dla dostawców MDM, 1 dla tożsamości urządzenia (nieudokumentowane):
* Tak zwane [API "usługi chmurowej" DEP](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Jest to używane przez serwery MDM do powiązania profili DEP z konkretnymi urządzeniami.
* [API DEP używane przez autoryzowanych sprzedawców Apple](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) do rejestracji urządzeń, sprawdzania statusu rejestracji i sprawdzania statusu transakcji.
* Nieudokumentowane prywatne API DEP. Jest to używane przez urządzenia Apple do żądania swojego profilu DEP. W systemie macOS za komunikację za pomocą tego interfejsu odpowiada plik binarny `cloudconfigurationd`.
* Bardziej nowoczesne i oparte na **JSON** (w przeciwieństwie do plist).
* Apple przyznaje dostawcy MDM **token OAuth**.

**API "usługi chmurowej" DEP**

* RESTful
* synchronizuje rekordy urządzeń z Apple na serwer MDM
* synchronizuje "profile DEP" z serwera MDM do Apple (dostarczane przez Apple do urządzenia w późniejszym czasie)
* Profil DEP zawiera:
* Adres URL serwera dostawcy MDM
* Dodatkowe zaufane certyfikaty dla adresu URL serwera (opcjonalne przypinanie)
* Dodatkowe ustawienia (np. które ekrany pominąć w Asystencie konfiguracji)

## Numer seryjny

Urządzenia Apple wyprodukowane po 2010 roku zazwyczaj mają **12-znakowe alfanumeryczne** numery seryjne, gdzie **pierwsze trzy cyfry oznaczają miejsce produkcji**, kolejne **dwie** wskazują **rok** i **tydzień** produkcji, następne **trzy** cyfry stanowią **unikalny identyfikator**, a **ostatnie** **cztery** cyfry reprezentują **numer modelu**.

{% content-ref
### Krok 4: Sprawdzanie DEP - Uzyskiwanie Rekordu Aktywacji

Ten etap procesu występuje, gdy **użytkownik uruchamia Maca po raz pierwszy** (lub po pełnym wymazaniu)

![](<../../../.gitbook/assets/image (568).png>)

lub podczas wykonywania polecenia `sudo profiles show -type enrollment`

* Sprawdzenie, czy urządzenie jest włączone do DEP
* Rekord aktywacji to wewnętrzna nazwa **"profilu" DEP**
* Rozpoczyna się od momentu, gdy urządzenie jest podłączone do Internetu
* Sterowane przez **`CPFetchActivationRecord`**
* Realizowane przez **`cloudconfigurationd`** za pośrednictwem XPC. **"Asystent konfiguracji"** (gdy urządzenie jest uruchamiane po raz pierwszy) lub polecenie **`profiles`** skontaktuje się z tym demonem, aby pobrać rekord aktywacji.
* LaunchDaemon (zawsze działa jako root)

Następuje kilka kroków w celu uzyskania Rekordu Aktywacji, wykonywanych przez **`MCTeslaConfigurationFetcher`**. Proces ten wykorzystuje szyfrowanie o nazwie **Absinthe**

1. Pobierz **certyfikat**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Zainicjuj** stan na podstawie certyfikatu (**`NACInit`**)
1. Wykorzystuje różne dane specyficzne dla urządzenia (np. **Numer seryjny za pomocą `IOKit`**)
3. Pobierz **klucz sesji**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Ustanów sesję (**`NACKeyEstablishment`**)
5. Wyślij żądanie
1. POST do [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile), wysyłając dane `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. Dane JSON są szyfrowane za pomocą Absinthe (**`NACSign`**)
3. Wszystkie żądania są realizowane przez HTTPs, używane są wbudowane certyfikaty root

![](<../../../.gitbook/assets/image (566).png>)

Odpowiedź to słownik JSON zawierający kilka ważnych danych, takich jak:

* **url**: Adres URL hosta dostawcy MDM dla profilu aktywacji
* **anchor-certs**: Tablica certyfikatów DER używanych jako zaufane kotwice

### **Krok 5: Pobieranie profilu**

![](<../../../.gitbook/assets/image (567).png>)

* Wysyłane jest żądanie pod adres **url podany w profilu DEP**.
* Jeśli są dostępne, używane są **certyfikaty kotwicowe** do **oceny zaufania**.
* Przypomnienie: właściwość **anchor\_certs** profilu DEP
* **Żądanie to prosty plik .plist** z identyfikacją urządzenia
* Przykłady: **UDID, wersja systemu operacyjnego**.
* Podpisane przy użyciu **certyfikatu tożsamości urządzenia (z APNS)**
* Łańcuch certyfikatów zawiera wygasłe **Apple iPhone Device CA**

![](<../../../.gitbook/assets/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (7).png>)

### Krok 6: Instalacja profilu

* Po pobraniu, **profil jest przechowywany w systemie**
* Ten krok rozpoczyna się automatycznie (jeśli w **asystencie konfiguracji**)
* Sterowane przez **`CPInstallActivationProfile`**
* Realizowane przez mdmclient za pośrednictwem XPC
* LaunchDaemon (jako root) lub LaunchAgent (jako użytkownik), w zależności od kontekstu
* Profile konfiguracyjne mają wiele ładunków do zainstalowania
* Framework ma architekturę opartą na wtyczkach do instalowania profili
* Każdy typ ładunku jest powiązany z wtyczką
* Może to być XPC (w frameworku) lub klasyczne Cocoa (w ManagedClient.app)
* Przykład:
* Ładunki certyfikatów używają usługi CertificateService.xpc

Zazwyczaj **profil aktywacji** dostarczony przez dostawcę MDM będzie zawierał następujące ładunki:

* `com.apple.mdm`: do **zarejestrowania** urządzenia w MDM
* `com.apple.security.scep`: do bezpiecznego dostarczenia **certyfikatu klienta** do urządzenia.
* `com.apple.security.pem`: do **instalacji zaufanych certyfikatów CA** w System Keychain urządzenia.
* Instalowanie ładunku MDM równoważnego **sprawdzaniu MDM w dokumentacji**
* Ładunek **zawiera kluczowe właściwości**:
*
* Adres URL sprawdzania MDM (**`CheckInURL`**)
* Adres URL odpytywania poleceń MDM (**`ServerURL`**) + temat APNs do jego wywołania
* Aby zainstalować ładunek MDM, wysyłane jest żądanie pod adres **`CheckInURL`**
* Realizowane w **`mdmclient`**
* Ładunek MDM może zależeć od innych ładunków
* Pozwala na **przypisanie żądań do określonych certyfikatów**:
* Właściwość: **`CheckInURLPinningCertificateUUIDs`**
* Właściwość: **`ServerURLPinningCertificateUUIDs`**
* Dostarczane za pomocą ładunku PEM
* Pozwala na przypisanie urządzenia do certyfikatu tożsamości:
* Właściwość: IdentityCertificateUUID
* Dostarczane za pomocą ładunku SCEP

### **Krok 7: Nasłuchiwanie poleceń MDM**

* Po zakończeniu sprawdzania MDM, dostawca może **wysyłać powiadomienia push za pomocą APNs**
* Po otrzymaniu powiadomienia, obsługiwane przez **`mdmclient`**
* Aby odpytywać o polecenia MDM, wysyłane jest żądanie pod adres ServerURL
* Wykorzystuje wcześniej zainstalowany ładunek MDM:
* **`ServerURLPinningCertificateUUIDs`** do przypinania żądania
* **`IdentityCertificateUUID`** do certyfikatu klienta TLS

## Ataki

### Rejestrowanie urządzeń w innych organizacjach

Jak wcześniej wspomniano, aby spróbować zarejestrować urządzenie w organizacji, **wystarczy numer seryjny należący do tej organizacji**. Po zarejestrowaniu urządzenia wiele organizacji zainstaluje na nim wrażliwe dane: certyfikaty, aplikacje, hasła WiFi, konfiguracje VPN [i tak dalej](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Dlatego może to być niebezpieczne wejście dla atakujących, jeśli proces rejestracji nie jest odpowiednio chroniony:

{% content-ref url="enrolling-devices-in-other-organisations.md" %}
[enrolling-devices-in-other-organisations.md](enrolling-devices-in-other-organisations.md)
{% endcontent-ref %}


<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**,
