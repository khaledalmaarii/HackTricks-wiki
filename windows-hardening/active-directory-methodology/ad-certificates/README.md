# Certyfikaty AD

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Wprowadzenie

### Składniki certyfikatu

- **Podmiot** certyfikatu oznacza jego właściciela.
- **Klucz publiczny** jest powiązany z prywatnym kluczem, aby połączyć certyfikat z jego prawowitym właścicielem.
- **Okres ważności**, określony przez daty **NotBefore** i **NotAfter**, oznacza efektywny czas trwania certyfikatu.
- Unikalny **Numer seryjny**, dostarczony przez Urząd Certyfikacji (CA), identyfikuje każdy certyfikat.
- **Wydawca** odnosi się do CA, który wydał certyfikat.
- **SubjectAlternativeName** umożliwia dodatkowe nazwy dla podmiotu, zwiększając elastyczność identyfikacji.
- **Podstawowe ograniczenia** identyfikują, czy certyfikat jest dla CA czy jednostki końcowej i definiują ograniczenia użytkowania.
- **Rozszerzone zastosowania klucza (EKU)** wytyczają konkretne cele certyfikatu, takie jak podpisywanie kodu lub szyfrowanie poczty elektronicznej, za pomocą identyfikatorów obiektów (OID).
- **Algorytm podpisu** określa metodę podpisywania certyfikatu.
- **Podpis**, utworzony za pomocą prywatnego klucza wydawcy, gwarantuje autentyczność certyfikatu.

### Specjalne uwagi

- **Alternatywne nazwy podmiotu (SAN)** rozszerzają zastosowanie certyfikatu na wiele tożsamości, co jest istotne dla serwerów obsługujących wiele domen. Ważne jest, aby procesy bezpiecznego wydawania zapobiegały ryzyku podszywania się przez atakujących manipulujących specyfikacją SAN.

### Urzędy Certyfikacji (CA) w Active Directory (AD)

AD CS uznaje certyfikaty CA w lesie AD za pomocą wyznaczonych kontenerów, z których każdy pełni unikalne role:

- Kontener **Certification Authorities** przechowuje certyfikaty korzeniowe CA.
- Kontener **Enrolment Services** zawiera informacje o CA przedsiębiorstwa i ich szablonach certyfikatów.
- Obiekt **NTAuthCertificates** zawiera certyfikaty CA autoryzowane do uwierzytelniania AD.
- Kontener **AIA (Authority Information Access)** ułatwia walidację łańcucha certyfikatów za pomocą certyfikatów pośrednich i krzyżowych CA.

### Uzyskiwanie certyfikatów: Przepływ żądania certyfikatu klienta

1. Proces żądania rozpoczyna się od znalezienia przez klientów CA przedsiębiorstwa.
2. Po wygenerowaniu pary kluczy publiczny-prywatny tworzony jest CSR zawierający klucz publiczny i inne szczegóły.
3. CA ocenia CSR pod kątem dostępnych szablonów certyfikatów, wydając certyfikat na podstawie uprawnień szablonu.
4. Po zatwierdzeniu CA podpisuje certyfikat za pomocą swojego klucza prywatnego i zwraca go klientowi.

### Szablony certyfikatów

Zdefiniowane w AD, te szablony określają ustawienia i uprawnienia do wydawania certyfikatów, w tym dozwolone EKU i prawa do zapisu lub modyfikacji, co jest istotne dla zarządzania dostępem do usług certyfikatów.

## Rejestracja certyfikatów

Proces rejestracji certyfikatów jest inicjowany przez administratora, który **tworzy szablon certyfikatu**, a następnie jest **publikowany** przez Przedsiębiorczy Urząd Certyfikacji (CA). Dzięki temu szablon staje się dostępny do rejestracji klienta, co osiąga się poprzez dodanie nazwy szablonu do pola `certificatetemplates` obiektu Active Directory.

Aby klient mógł poprosić o certyfikat, muszą zostać udzielone **prawa do rejestracji**. Prawa te są określane przez deskryptory zabezpieczeń szablonu certyfikatu i samego Przedsiębiorczego CA. Uprawnienia muszą być udzielone w obu lokalizacjach, aby żądanie było udane.

### Prawa rejestracji szablonu

Te prawa są określane za pomocą wpisów kontroli dostępu (ACE), które określają uprawnienia, takie jak:
- Prawa **Certificate-Enrollment** i **Certificate-AutoEnrollment**, związane z konkretnymi GUID-ami.
- **ExtendedRights**, pozwalające na wszystkie rozszerzone uprawnienia.
- **FullControl/GenericAll**, zapewniające pełną kontrolę nad szablonem.

### Prawa rejestracji Przedsiębiorczego CA

Prawa CA są określone w deskryptorze zabezpieczeń, dostępnym za pośrednictwem konsoli zarządzania Urzędem Certyfikacji. Niektóre ustawienia pozwalają nawet użytkownikom o niskich uprawnieniach na zdalny dostęp, co może stanowić zagrożenie dla bezpieczeństwa.

### Dodatkowe kontrole wydawania

Mogą obowiązywać pewne kontrole, takie jak:
- **Zatwierdzenie przez kierownika**: Umieszcza żądania w stanie oczekiwania do momentu zatwierdzenia przez kierownika certyfikatów.
- **Agenci rejestracji i wymagane podpisy**: Określają liczbę wymaganych podpisów na CSR i wymagane identyfikatory zasad aplikacji.

### Metody żądania certyfikatów

Certyfikaty można żądać za pomocą:
1. **Protokół rejestracji certyfikatów klienta systemu Windows** (MS-WCCE), za pomocą interfejsów DCOM.
2. **Protokół zdalny ICertPassage** (MS-ICPR), za pośrednictwem nazwanych potoków lub TCP/IP.
3. **Interfejs internetowy rejestracji certyfikatów**, z zainstalowaną rolą internetowego rejestracji certyfikatów CA.
4. **Usługa rejestracji certyfikatów** (CES), we współpracy z usługą zasad rejestracji certyfikatów (CEP).
5. **Usługa rejestracji urządzeń sieciowych** (NDES) dla urządzeń sieciowych, za pomocą protokołu prostego rejestracji certyfikatów (SCEP).

Użytkownicy systemu Windows mogą również żądać certyfikatów za pomocą interfejsu graficznego (`certmgr.msc` lub `certlm.msc`) lub narzędzi wiersza poleceń (`certreq.exe` lub polecenie `Get-Certificate` w PowerShell).
```powershell
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Autoryzacja za pomocą certyfikatów

Active Directory (AD) obsługuje autoryzację za pomocą certyfikatów, głównie przy użyciu protokołów **Kerberos** i **Secure Channel (Schannel)**.

### Proces autoryzacji Kerberos

W procesie autoryzacji Kerberos, żądanie użytkownika o przyznanie biletu TGT (Ticket Granting Ticket) jest podpisane za pomocą **klucza prywatnego** certyfikatu użytkownika. To żądanie przechodzi przez kilka walidacji przez kontroler domeny, w tym **ważność**, **ścieżkę** i **status unieważnienia** certyfikatu. Walidacje obejmują również sprawdzenie, czy certyfikat pochodzi od zaufanego źródła oraz potwierdzenie obecności wystawcy w **sklepie certyfikatów NTAUTH**. Pomyślne walidacje skutkują wydaniem biletu TGT. Obiekt **`NTAuthCertificates`** w AD, znajduje się pod adresem:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
jest kluczowe dla ustanowienia zaufania dla uwierzytelniania za pomocą certyfikatów.

### Uwierzytelnianie kanału bezpiecznego (Schannel)

Schannel ułatwia bezpieczne połączenia TLS/SSL, gdzie podczas negocjacji klient prezentuje certyfikat, który po pomyślnym zweryfikowaniu autoryzuje dostęp. Przyporządkowanie certyfikatu do konta AD może obejmować funkcję **S4U2Self** Kerberosa lub **Alternatywną Nazwę Podmiotu (SAN)** certyfikatu, wśród innych metod.

### Wyliczanie usług certyfikatów AD

Usługi certyfikatów AD mogą być wyliczane za pomocą zapytań LDAP, ujawniając informacje o **Enterprise Certificate Authorities (CAs)** i ich konfiguracjach. Jest to dostępne dla dowolnego użytkownika uwierzytelnionego w domenie bez specjalnych uprawnień. Narzędzia takie jak **[Certify](https://github.com/GhostPack/Certify)** i **[Certipy](https://github.com/ly4k/Certipy)** są używane do wyliczania i oceny podatności w środowiskach AD CS.

Polecenia do korzystania z tych narzędzi obejmują:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
## Odwołania

* [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)
* [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
