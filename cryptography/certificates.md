# Certyfikaty

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować przepływy pracy** przy użyciu najbardziej zaawansowanych narzędzi społecznościowych na świecie.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Czym jest certyfikat

**Certyfikat klucza publicznego** to cyfrowe ID używane w kryptografii do udowodnienia, że ktoś jest właścicielem klucza publicznego. Zawiera szczegóły klucza, tożsamość właściciela (podmiotu) oraz cyfrowy podpis od zaufanego organu (wydawcy). Jeśli oprogramowanie ufa wydawcy i podpis jest prawidłowy, możliwa jest bezpieczna komunikacja z właścicielem klucza.

Certyfikaty są głównie wydawane przez [organizacje certyfikujące](https://en.wikipedia.org/wiki/Certificate_authority) (CA) w ramach [infrastruktury klucza publicznego](https://en.wikipedia.org/wiki/Public-key_infrastructure) (PKI). Inną metodą jest [sieć zaufania](https://en.wikipedia.org/wiki/Web_of_trust), w której użytkownicy bezpośrednio weryfikują klucze innych użytkowników. Powszechnym formatem certyfikatów jest [X.509](https://en.wikipedia.org/wiki/X.509), który można dostosować do konkretnych potrzeb, zgodnie z RFC 5280.

## Wspólne pola x509

### **Wspólne pola w certyfikatach x509**

W certyfikatach x509 kilka **pól** odgrywa kluczowe role w zapewnieniu ważności i bezpieczeństwa certyfikatu. Oto podział tych pól:

- **Numer wersji** oznacza wersję formatu x509.
- **Numer seryjny** jednoznacznie identyfikuje certyfikat w systemie Organizacji Certyfikującej (CA), głównie w celu śledzenia unieważnienia.
- Pole **Podmiot** reprezentuje właściciela certyfikatu, który może być maszyną, osobą fizyczną lub organizacją. Zawiera szczegółowe dane identyfikacyjne, takie jak:
- **Nazwa wspólna (CN)**: Domeny objęte certyfikatem.
- **Kraj (C)**, **Miejscowość (L)**, **Stan lub prowincja (ST, S lub P)**, **Organizacja (O)** i **Jednostka organizacyjna (OU)** dostarczają informacje geograficzne i organizacyjne.
- **Nazwa wyróżniająca (DN)** zawiera pełną identyfikację podmiotu.
- **Wydawca** podaje informacje o osobie, która zweryfikowała i podpisała certyfikat, zawierając podobne podpola jak Podmiot dla CA.
- **Okres ważności** jest oznaczony znacznikami **Nie wcześniej niż** i **Nie później niż**, zapewniając, że certyfikat nie jest używany przed określoną datą ani po niej.
- Sekcja **Klucz publiczny**, kluczowa dla bezpieczeństwa certyfikatu, określa algorytm, rozmiar i inne techniczne szczegóły klucza publicznego.
- **Rozszerzenia x509v3** zwiększają funkcjonalność certyfikatu, określając **Użycie klucza**, **Rozszerzone użycie klucza**, **Alternatywną nazwę podmiotu** i inne właściwości, aby dostosować certyfikat do konkretnego zastosowania.

#### **Użycie klucza i rozszerzenia**

- **Użycie klucza** identyfikuje kryptograficzne zastosowania klucza publicznego, takie jak podpis cyfrowy lub szyfrowanie klucza.
- **Rozszerzone użycie klucza** bardziej precyzuje przypadki użycia certyfikatu, np. do uwierzytelniania serwera TLS.
- **Alternatywna nazwa podmiotu** i **Podstawowe ograniczenie** definiują dodatkowe nazwy hostów objęte certyfikatem oraz czy jest to certyfikat CA czy jednostki końcowej.
- Identyfikatory, takie jak **Identyfikator klucza podmiotu** i **Identyfikator klucza wydawcy**, zapewniają unikalność i możliwość śledzenia kluczy.
- **Dostęp do informacji o wydawcy** i **Punkty dystrybucji listy unieważnień** dostarczają ścieżki do weryfikacji wydającego CA i sprawdzenia stanu unieważnienia certyfikatu.
- **CT Precertificate SCTs** oferują dzienniki przejrzystości, kluczowe dla publicznego zaufania do certyfikatu.
```python
# Example of accessing and using x509 certificate fields programmatically:
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Load an x509 certificate (assuming cert.pem is a certificate file)
with open("cert.pem", "rb") as file:
cert_data = file.read()
certificate = x509.load_pem_x509_certificate(cert_data, default_backend())

# Accessing fields
serial_number = certificate.serial_number
issuer = certificate.issuer
subject = certificate.subject
public_key = certificate.public_key()

print(f"Serial Number: {serial_number}")
print(f"Issuer: {issuer}")
print(f"Subject: {subject}")
print(f"Public Key: {public_key}")
```
### **Różnica między OCSP a punktami dystrybucji CRL**

**OCSP** (**RFC 2560**) polega na współpracy klienta i respondera w celu sprawdzenia, czy cyfrowy certyfikat klucza publicznego został unieważniony, bez konieczności pobierania pełnego **CRL**. Ta metoda jest bardziej wydajna niż tradycyjny **CRL**, który zawiera listę unieważnionych numerów seryjnych certyfikatów, ale wymaga pobrania potencjalnie dużego pliku. CRL może zawierać do 512 wpisów. Więcej szczegółów można znaleźć [tutaj](https://www.arubanetworks.com/techdocs/ArubaOS%206_3_1_Web_Help/Content/ArubaFrameStyles/CertRevocation/About_OCSP_and_CRL.htm).

### **Co to jest Transparentność Certyfikatów**

Transparentność Certyfikatów pomaga zwalczać zagrożenia związane z certyfikatami, zapewniając, że wydawanie i istnienie certyfikatów SSL są widoczne dla właścicieli domen, CA i użytkowników. Jej cele to:

* Zapobieganie wydawaniu certyfikatów SSL dla domeny bez wiedzy właściciela domeny.
* Ustanowienie otwartego systemu audytu do śledzenia błędnie lub złośliwie wydanych certyfikatów.
* Ochrona użytkowników przed fałszywymi certyfikatami.

#### **Rejestry Certyfikatów**

Rejestry certyfikatów to publicznie audytowalne, tylko do odczytu zapisy certyfikatów, utrzymywane przez usługi sieciowe. Rejestry te dostarczają dowodów kryptograficznych w celach audytowych. Zarówno wydawcy certyfikatów, jak i publiczność mogą przesyłać certyfikaty do tych rejestrów lub zapytać o nie w celu weryfikacji. Chociaż dokładna liczba serwerów rejestrów nie jest ustalona, oczekuje się, że będzie ich mniej niż tysiąc na całym świecie. Serwery te mogą być niezależnie zarządzane przez CA, dostawców usług internetowych lub dowolną zainteresowaną jednostkę.

#### **Zapytanie**

Aby przeglądać rejestry Transparentności Certyfikatów dla dowolnej domeny, odwiedź [https://crt.sh/](https://crt.sh).

Istnieją różne formaty przechowywania certyfikatów, z różnymi zastosowaniami i kompatybilnością. Ten podsumowanie obejmuje główne formaty i udziela wskazówek dotyczących konwersji między nimi.

## **Formaty**

### **Format PEM**
- Najczęściej używany format dla certyfikatów.
- Wymaga oddzielnych plików dla certyfikatów i kluczy prywatnych, zakodowanych w Base64 ASCII.
- Powszechnie stosowany przez serwery Apache i podobne.

### **Format DER**
- Binarny format certyfikatów.
- Nie zawiera instrukcji "BEGIN/END CERTIFICATE" znajdujących się w plikach PEM.
- Powszechne rozszerzenia: .cer, .der.
- Często używany w platformach Java.

### **Format P7B/PKCS#7**
- Przechowywany w Base64 ASCII, z rozszerzeniami .p7b lub .p7c.
- Zawiera tylko certyfikaty i łańcuchy certyfikatów, bez klucza prywatnego.
- Obsługiwany przez systemy Microsoft Windows i Java Tomcat.

### **Format PFX/P12/PKCS#12**
- Binarny format, który zawiera certyfikaty serwera, certyfikaty pośrednie i klucze prywatne w jednym pliku.
- Rozszerzenia: .pfx, .p12.
- Głównie używany w systemach Windows do importu i eksportu certyfikatów.

### **Konwersja formatów**

Konwersje **PEM** są niezbędne dla kompatybilności:

- **x509 do PEM**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
- **PEM na DER**

Aby przekonwertować plik w formacie PEM na format DER, można użyć narzędzia OpenSSL. Poniżej znajduje się polecenie, które można użyć do wykonania tej konwersji:

```plaintext
openssl x509 -outform der -in certificate.pem -out certificate.der
```

Gdzie `certificate.pem` to nazwa pliku w formacie PEM, który chcesz przekonwertować, a `certificate.der` to nazwa pliku wynikowego w formacie DER. Po wykonaniu tego polecenia, plik w formacie PEM zostanie przekonwertowany na format DER.
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
- **DER to PEM**

- **DER na PEM**
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
- **PEM na P7B**

Aby przekonwertować plik w formacie PEM na format P7B, można użyć narzędzia OpenSSL. Poniżej znajduje się polecenie, które można użyć do wykonania tej konwersji:

```plaintext
openssl crl2pkcs7 -nocrl -certfile certificate.pem -out certificate.p7b
```

Gdzie `certificate.pem` to ścieżka do pliku w formacie PEM, który chcesz przekonwertować, a `certificate.p7b` to nazwa pliku wynikowego w formacie P7B. Po wykonaniu tego polecenia, plik w formacie P7B zostanie utworzony i będzie zawierał certyfikat z pliku PEM.
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
- **PKCS7 do PEM**

Aby przekonwertować plik w formacie PKCS7 na format PEM, można użyć następującego polecenia OpenSSL:

```plaintext
openssl pkcs7 -print_certs -in input.p7b -out output.pem
```

Gdzie `input.p7b` to plik w formacie PKCS7, a `output.pem` to docelowy plik w formacie PEM, do którego zostaną zapisane certyfikaty.

Ten proces konwersji umożliwia łatwiejsze zarządzanie certyfikatami w formacie PEM, który jest bardziej powszechnie stosowany.
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**Konwersje PFX** są kluczowe dla zarządzania certyfikatami w systemie Windows:

- **PFX na PEM**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
- **PFX na PKCS#8** wymaga dwóch kroków:
1. Konwertuj PFX na PEM
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. Konwersja PEM do PKCS8

Aby przekonwertować plik w formacie PEM na format PKCS8, można użyć narzędzia OpenSSL. Poniżej przedstawiono polecenie, które można wykorzystać do wykonania tej konwersji:

```plaintext
openssl pkcs8 -topk8 -inform PEM -outform PEM -in private_key.pem -out private_key_pkcs8.pem
```

W powyższym poleceniu należy zamienić `private_key.pem` na nazwę pliku zawierającego klucz prywatny w formacie PEM, który chcemy przekonwertować. Po wykonaniu tego polecenia, zostanie utworzony plik `private_key_pkcs8.pem`, który będzie zawierał klucz prywatny w formacie PKCS8.
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
- **P7B na PFX** wymaga również dwóch poleceń:
1. Konwertuj P7B na CER
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. Konwersja pliku CER i klucza prywatnego do formatu PFX

Aby przekonwertować plik CER i klucz prywatny do formatu PFX, możemy użyć narzędzia OpenSSL. Oto jak to zrobić:

1. Upewnij się, że masz zainstalowane narzędzie OpenSSL na swoim systemie.
2. Otwórz terminal lub wiersz polecenia i przejdź do folderu, w którym znajdują się pliki CER i klucz prywatny.
3. Wykonaj następujące polecenie, aby przekonwertować plik CER i klucz prywatny do formatu PFX:

```
openssl pkcs12 -export -out certificate.pfx -inkey privatekey.key -in certificate.cer
```

4. Zostaniesz poproszony o wprowadzenie hasła dla pliku PFX. Wprowadź odpowiednie hasło i zatwierdź.
5. Po zakończeniu procesu, plik PFX zostanie utworzony w bieżącym folderze. Możesz go teraz użyć do różnych celów, takich jak importowanie certyfikatu do przeglądarki lub serwera.

Pamiętaj, że plik PFX zawiera zarówno certyfikat, jak i klucz prywatny, dlatego ważne jest, aby zachować go w bezpiecznym miejscu i nie udostępniać go publicznie.
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
***

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować przepływy pracy** przy użyciu najbardziej zaawansowanych narzędzi społecznościowych na świecie.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
