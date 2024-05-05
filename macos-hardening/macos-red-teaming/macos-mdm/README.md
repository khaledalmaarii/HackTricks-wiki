# macOS MDM

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

**Aby dowiedzieć się więcej o macOS MDM, sprawdź:**

* [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
* [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Podstawy

### **Przegląd MDM (Mobile Device Management)**

[Zarządzanie urządzeniami mobilnymi](https://en.wikipedia.org/wiki/Mobile\_device\_management) (MDM) jest wykorzystywane do zarządzania różnymi urządzeniami końcowymi, takimi jak smartfony, laptopy i tablety. Szczególnie dla platform Apple (iOS, macOS, tvOS) obejmuje zestaw specjalistycznych funkcji, interfejsów API i praktyk. Działanie MDM opiera się na kompatybilnym serwerze MDM, który jest dostępny komercyjnie lub jako oprogramowanie open-source, i musi obsługiwać [Protokół MDM](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Kluczowe punkty obejmują:

* Zcentralizowana kontrola nad urządzeniami.
* Zależność od serwera MDM, który przestrzega protokołu MDM.
* Możliwość serwera MDM do wysyłania różnych poleceń do urządzeń, na przykład zdalne usuwanie danych lub instalację konfiguracji.

### **Podstawy DEP (Device Enrollment Program)**

[Program rejestracji urządzeń](https://www.apple.com/business/site/docs/DEP\_Guide.pdf) (DEP) oferowany przez Apple ułatwia integrację Mobile Device Management (MDM), umożliwiając konfigurację bez interakcji użytkownika lub administratora. DEP automatyzuje proces rejestracji, umożliwiając urządzeniom być gotowym do użycia od razu po wyjęciu z pudełka, z minimalną ingerencją użytkownika lub administratora. Istotne aspekty obejmują:

* Umożliwia urządzeniom automatyczną rejestrację w predefiniowanym serwerze MDM podczas początkowej aktywacji.
* Przede wszystkim korzystne dla zupełnie nowych urządzeń, ale także stosowalne dla urządzeń poddawanych rekonfiguracji.
* Ułatwia prostą konfigurację, sprawiając, że urządzenia są gotowe do użytku organizacyjnego szybko.

### **Rozważania dotyczące bezpieczeństwa**

Należy zauważyć, że łatwość rejestracji zapewniana przez DEP, choć korzystna, może również stanowić ryzyko dla bezpieczeństwa. Jeśli środki ochronne nie są odpowiednio egzekwowane podczas rejestracji w MDM, atakujący mogą wykorzystać ten uproszczony proces do zarejestrowania swojego urządzenia na serwerze MDM organizacji, podszywając się pod korporacyjne urządzenie.

{% hint style="danger" %}
**Alert bezpieczeństwa**: Uproszczona rejestracja DEP może potencjalnie umożliwić nieautoryzowaną rejestrację urządzenia na serwerze MDM organizacji, jeśli nie są wdrożone odpowiednie zabezpieczenia.
{% endhint %}

### Podstawy Co to jest SCEP (Simple Certificate Enrolment Protocol)?

* Relatywnie stary protokół, stworzony przed rozpowszechnieniem się TLS i HTTPS.
* Zapewnia klientom standaryzowany sposób wysyłania **żądania podpisania certyfikatu** (CSR) w celu uzyskania certyfikatu. Klient prosi serwer o podpisanie certyfikatu.

### Co to są Profile Konfiguracji (znane również jako mobileconfigs)?

* Oficjalny sposób Apple na **ustawianie/wymuszanie konfiguracji systemu.**
* Format pliku, który może zawierać wiele ładunków.
* Oparte na listach właściwości (rodzaj XML).
* „mogą być podpisane i zaszyfrowane, aby zweryfikować ich pochodzenie, zapewnić integralność i chronić ich zawartość.” Podstawy — Strona 70, Przewodnik po bezpieczeństwie iOS, styczeń 2018 r.

## Protokoły

### MDM

* Kombinacja APNs (**serwery Apple**) + RESTful API (**serwery dostawców MDM**)
* **Komunikacja** zachodzi między **urządzeniem** a serwerem związanych z **produktem zarządzania urządzeniami**
* **Polecenia** dostarczane z MDM do urządzenia w formie **słowników kodowanych w plist**
* Wszystko przez **HTTPS**. Serwery MDM mogą być (i zazwyczaj są) przypięte.
* Apple przyznaje dostawcy MDM **certyfikat APNs** do uwierzytelniania

### DEP

* **3 interfejsy API**: 1 dla sprzedawców, 1 dla dostawców MDM, 1 dla tożsamości urządzenia (nieudokumentowany):
* Tak zwane [API „usługi chmury” DEP](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Jest to używane przez serwery MDM do powiązania profili DEP z konkretnymi urządzeniami.
* [API DEP używane przez autoryzowanych sprzedawców Apple](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) do rejestracji urządzeń, sprawdzania stanu rejestracji i stanu transakcji.
* Nieudokumentowane prywatne API DEP. Jest to używane przez urządzenia Apple do żądania swojego profilu DEP. Na macOS, binarny `cloudconfigurationd` jest odpowiedzialny za komunikację za pomocą tego API.
* Bardziej nowoczesne i oparte na **JSON** (w przeciwieństwie do plist)
* Apple przyznaje dostawcy MDM **token OAuth**

**API „usługi chmury” DEP**

* RESTful
* synchronizacja rekordów urządzeń z Apple do serwera MDM
* synchronizacja „profili DEP” do Apple z serwera MDM (dostarczane przez Apple do urządzenia w późniejszym czasie)
* Profil DEP zawiera:
* URL serwera dostawcy MDM
* Dodatkowe zaufane certyfikaty dla adresu URL serwera (opcjonalne przypięcie)
* Dodatkowe ustawienia (np. które ekrany pominąć w Asystencie konfiguracji)

## Numer seryjny

Urządzenia Apple wyprodukowane po 2010 roku zazwyczaj mają **12-znakowe alfanumeryczne** numery seryjne, gdzie **pierwsze trzy cyfry reprezentują lokalizację produkcji**, kolejne **dwie** wskazują **rok** i **tydzień** produkcji, następne **trzy** cyfry zapewniają **unikalny** **identyfikator**, a **ostatnie** **cztery** cyfry reprezentują **numer modelu**.

{% content-ref url="macos-serial-number.md" %}
[macos-serial-number.md](macos-serial-number.md)
{% endcontent-ref %}

## Kroki rejestracji i zarządzania

1. Tworzenie rekordu urządzenia (Sprzedawca, Apple): Tworzony jest rekord dla nowego urządzenia
2. Przypisanie rekordu urządzenia (Klient): Urządzenie jest przypisywane do serwera MDM
3. Synchronizacja rekordów urządzenia (Dostawca MDM): MDM synchronizuje rekordy urządzenia i przesyła profile DEP do Apple
4. Sprawdzanie DEP (Urządzenie): Urządzenie otrzymuje swój profil DEP
5. Pobieranie profilu (Urządzenie)
6. Instalacja profilu (Urządzenie) a. w tym ładunki MDM, SCEP i root CA
7. Wydawanie poleceń MDM (Urządzenie)

![](<../../../.gitbook/assets/image (694).png>)

Plik `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` eksportuje funkcje, które można uznać za **wysokopoziomowe "kroki"** procesu rejestracji.
### Krok 4: Sprawdzenie DEP - Pobranie Rekordu Aktywacji

Ten etap procesu zachodzi, gdy **użytkownik uruchamia Maca po raz pierwszy** (lub po pełnym wymazaniu)

![](<../../../.gitbook/assets/image (1044).png>)

lub podczas wykonywania `sudo profiles show -type enrollment`

* Określenie, czy urządzenie jest włączone do DEP
* Rekord Aktywacji to wewnętrzna nazwa dla **profilu DEP**
* Rozpoczyna się od razu po podłączeniu urządzenia do Internetu
* Sterowane przez **`CPFetchActivationRecord`**
* Wdrożone przez **`cloudconfigurationd`** za pomocą XPC. **"Asystent konfiguracji**" (gdy urządzenie jest uruchamiane po raz pierwszy) lub polecenie **`profiles`** będzie **kontaktować się z tym demonem** w celu pobrania rekordu aktywacji.
* LaunchDaemon (zawsze działa jako root)

Następuje kilka kroków w celu uzyskania Rekordu Aktywacji wykonywanego przez **`MCTeslaConfigurationFetcher`**. Ten proces wykorzystuje szyfrowanie o nazwie **Absinthe**

1. Pobierz **certyfikat**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Zainicjuj** stan z certyfikatu (**`NACInit`**)
1. Wykorzystuje różne dane specyficzne dla urządzenia (np. **Numer seryjny za pomocą `IOKit`**)
3. Pobierz **klucz sesji**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Ustanów sesję (**`NACKeyEstablishment`**)
5. Wyślij żądanie
1. POST do [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) wysyłając dane `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. Ładunek JSON jest szyfrowany za pomocą Absinthe (**`NACSign`**)
3. Wszystkie żądania są realizowane przez HTTPs, używane są wbudowane certyfikaty root

![](<../../../.gitbook/assets/image (566) (1).png>)

Odpowiedź to słownik JSON z ważnymi danymi, takimi jak:

* **url**: URL hosta dostawcy MDM dla profilu aktywacji
* **anchor-certs**: Tablica certyfikatów DER używanych jako zaufane kotwice

### **Krok 5: Pobieranie Profilu**

![](<../../../.gitbook/assets/image (444).png>)

* Żądanie wysłane do **url podanego w profilu DEP**.
* **Certyfikaty kotwicowe** są używane do **oceny zaufania**, jeśli są dostarczone.
* Przypomnienie: właściwość **anchor\_certs** profilu DEP
* **Żądanie to prosty plik .plist** z identyfikacją urządzenia
* Przykłady: **UDID, wersja OS**.
* Podpisany CMS, zakodowany DER
* Podpisany za pomocą **certyfikatu tożsamości urządzenia (z APNS)**
* **Łańcuch certyfikatów** zawiera wygasły **Apple iPhone Device CA**

![](<../../../.gitbook/assets/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Krok 6: Instalacja Profilu

* Po pobraniu, **profil jest przechowywany w systemie**
* Ten krok rozpoczyna się automatycznie (jeśli w **asystencie konfiguracji**)
* Sterowane przez **`CPInstallActivationProfile`**
* Wdrożone przez mdmclient za pomocą XPC
* LaunchDaemon (jako root) lub LaunchAgent (jako użytkownik), w zależności od kontekstu
* Profile konfiguracji mają wiele ładunków do zainstalowania
* Framework ma architekturę opartą na wtyczkach do instalowania profili
* Każdy rodzaj ładunku jest powiązany z wtyczką
* Może być XPC (w frameworku) lub klasyczne Cocoa (w ManagedClient.app)
* Przykład:
* Ładunki certyfikatów używają CertificateService.xpc

Zazwyczaj **profil aktywacji** dostarczony przez dostawcę MDM będzie **zawierał następujące ładunki**:

* `com.apple.mdm`: do **zarejestrowania** urządzenia w MDM
* `com.apple.security.scep`: do bezpiecznego dostarczenia **certyfikatu klienta** do urządzenia.
* `com.apple.security.pem`: do **zainstalowania zaufanych certyfikatów CA** w Systemowym Keychain urządzenia.
* Instalowanie ładunku MDM równoważne z **kontrolą MDM w dokumentacji**
* Ładunek zawiera kluczowe właściwości:
*
* URL Kontroli MDM (**`CheckInURL`**)
* URL Odpytywania Komend MDM (**`ServerURL`**) + temat APNs do jego wywołania
* Aby zainstalować ładunek MDM, żądanie jest wysyłane do **`CheckInURL`**
* Wdrożone w **`mdmclient`**
* Ładunek MDM może zależeć od innych ładunków
* Pozwala na **przypięcie żądań do określonych certyfikatów**:
* Właściwość: **`CheckInURLPinningCertificateUUIDs`**
* Właściwość: **`ServerURLPinningCertificateUUIDs`**
* Dostarczone za pomocą ładunku PEM
* Pozwala na przypisanie urządzenia certyfikatem tożsamości:
* Właściwość: IdentityCertificateUUID
* Dostarczone za pomocą ładunku SCEP

### **Krok 7: Nasłuchiwanie poleceń MDM**

* Po zakończeniu kontroli MDM, dostawca może **wysyłać powiadomienia push za pomocą APNs**
* Po otrzymaniu, obsługiwane przez **`mdmclient`**
* Aby odpytać o polecenia MDM, żądanie jest wysyłane do ServerURL
* Wykorzystuje wcześniej zainstalowany ładunek MDM:
* **`ServerURLPinningCertificateUUIDs`** do przypięcia żądania
* **`IdentityCertificateUUID`** do certyfikatu klienta TLS

## Ataki

### Rejestracja Urządzeń w Innych Organizacjach

Jak wcześniej wspomniano, aby spróbować zarejestrować urządzenie w organizacji, **wystarczy numer seryjny należący do tej Organizacji**. Gdy urządzenie zostanie zarejestrowane, kilka organizacji zainstaluje wrażliwe dane na nowym urządzeniu: certyfikaty, aplikacje, hasła WiFi, konfiguracje VPN [i tak dalej](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Dlatego może to być niebezpieczne wejście dla atakujących, jeśli proces rejestracji nie jest odpowiednio chroniony:

{% content-ref url="enrolling-devices-in-other-organisations.md" %}
[enrolling-devices-in-other-organisations.md](enrolling-devices-in-other-organisations.md)
{% endcontent-ref %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Kup [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
