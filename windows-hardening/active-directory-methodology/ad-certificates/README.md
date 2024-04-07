# Certyfikaty AD

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

## Wprowadzenie

### Składniki certyfikatu

- **Podmiot** certyfikatu oznacza jego właściciela.
- **Klucz publiczny** jest sparowany z kluczem prywatnym, aby powiązać certyfikat z jego prawowitym właścicielem.
- **Okres ważności**, określony przez daty **NotBefore** i **NotAfter**, oznacza efektywny czas trwania certyfikatu.
- Unikalny **Numer seryjny**, dostarczany przez Certyfikującego Organizatora (CA), identyfikuje każdy certyfikat.
- **Wydawca** odnosi się do CA, który wydał certyfikat.
- **SubjectAlternativeName** pozwala na dodatkowe nazwy dla podmiotu, zwiększając elastyczność identyfikacji.
- **Podstawowe ograniczenia** identyfikują, czy certyfikat jest dla CA czy jednostki końcowej i definiują ograniczenia użytkowania.
- **Rozszerzone zastosowania kluczy (EKU)** wytyczają konkretne cele certyfikatu, takie jak podpisywanie kodu lub szyfrowanie e-maili, za pomocą identyfikatorów obiektów (OID).
- **Algorytm podpisu** określa metodę podpisywania certyfikatu.
- **Podpis**, stworzony za pomocą klucza prywatnego wydawcy, gwarantuje autentyczność certyfikatu.

### Specjalne uwagi

- **Alternatywne nazwy podmiotów (SANs)** rozszerzają zastosowanie certyfikatu na wiele tożsamości, co jest istotne dla serwerów obsługujących wiele domen. Bezpieczne procesy wydawania są kluczowe, aby uniknąć ryzyka podszywania się przez atakujących manipulujących specyfikacją SAN.

### Organizacje Certyfikujące (CA) w Active Directory (AD)

AD CS uznaje certyfikaty CA w lesie AD poprzez wyznaczone kontenery, z których każdy pełni unikalne role:

- Kontener **Certification Authorities** przechowuje zaufane certyfikaty root CA.
- Kontener **Enrolment Services** zawiera szczegóły dotyczące CA przedsiębiorstwa i ich szablonów certyfikatów.
- Obiekt **NTAuthCertificates** zawiera certyfikaty CA upoważnione do uwierzytelniania w AD.
- Kontener **AIA (Authority Information Access)** ułatwia walidację łańcucha certyfikatów z certyfikatami pośrednimi i krzyżowymi CA.

### Pozyskiwanie certyfikatu: Przepływ żądania certyfikatu klienta

1. Proces żądania rozpoczyna się od znalezienia przez klientów CA przedsiębiorstwa.
2. Po wygenerowaniu pary kluczy publiczny-prywatny tworzony jest CSR zawierający klucz publiczny i inne szczegóły.
3. CA ocenia CSR w oparciu o dostępne szablony certyfikatów, wydając certyfikat na podstawie uprawnień szablonu.
4. Po zatwierdzeniu CA podpisuje certyfikat swoim kluczem prywatnym i zwraca go klientowi.

### Szablony certyfikatów

Zdefiniowane w AD, te szablony określają ustawienia i uprawnienia do wydawania certyfikatów, w tym dozwolone EKU oraz prawa do zapisu lub modyfikacji, co jest kluczowe dla zarządzania dostępem do usług certyfikatów.

## Enrolment Certyfikatu

Proces zapisywania na certyfikaty jest inicjowany przez administratora, który **tworzy szablon certyfikatu**, a następnie jest **publikowany** przez Certyfikującego Organizatora Przedsiębiorstwa (CA). Szablon staje się dostępny do zapisu przez klienta poprzez dodanie nazwy szablonu do pola `certificatetemplates` obiektu Active Directory.

Aby klient mógł poprosić o certyfikat, muszą zostać udzielone **prawa zapisu**. Te prawa są określane przez deskryptory zabezpieczeń na szablonie certyfikatu oraz samym Certyfikującym Organizatorem Przedsiębiorstwa. Uprawnienia muszą być udzielone w obu lokalizacjach, aby żądanie było udane.

### Prawa zapisu do szablonu

Te prawa są określane poprzez wpisy kontroli dostępu (ACE), określające uprawnienia takie jak:
- Prawa **Certificate-Enrollment** i **Certificate-AutoEnrollment**, związane z konkretnymi GUID-ami.
- **ExtendedRights**, pozwalające na wszystkie rozszerzone uprawnienia.
- **FullControl/GenericAll**, zapewniające pełną kontrolę nad szablonem.

### Prawa zapisu do Certyfikującego Organizatora Przedsiębiorstwa

Prawa CA są określone w jego deskryptorze zabezpieczeń, dostępnym za pośrednictwem konsoli zarządzania Certyfikującym Organizatorem. Niektóre ustawienia pozwalają nawet użytkownikom o niskich uprawnieniach na zdalny dostęp, co może stanowić zagrożenie dla bezpieczeństwa.

### Dodatkowe Kontrole Wydawania

Mogą być stosowane pewne kontrole, takie jak:
- **Zatwierdzenie przez kierownika**: Umieszcza żądania w stanie oczekiwania do zatwierdzenia przez kierownika certyfikatów.
- **Agenci zapisu i upoważnione podpisy**: Określ liczbę wymaganych podpisów na CSR oraz niezbędne identyfikatory zasad aplikacji.

### Metody żądania certyfikatów

Certyfikaty można żądać poprzez:
1. **Protokół Zapisu Certyfikatu Klienta Windows** (MS-WCCE), korzystając z interfejsów DCOM.
2. **Protokół Zdalnego Przejścia ICert** (MS-ICPR), za pośrednictwem nazwanych rur lub TCP/IP.
3. **Interfejs internetowy do zapisu certyfikatów**, z zainstalowaną rolą Internetowego Interfejsu Zapisu Certyfikatów.
4. **Usługa Zapisu Certyfikatów** (CES), w połączeniu z usługą Polityki Zapisu Certyfikatów (CEP).
5. **Usługa Zapisu Urządzeń Sieciowych** (NDES) dla urządzeń sieciowych, korzystając z Protokołu Prostego Zapisu Certyfikatów (SCEP).

Użytkownicy systemu Windows mogą również żądać certyfikatów za pomocą interfejsu graficznego (`certmgr.msc` lub `certlm.msc`) lub narzędzi wiersza poleceń (`certreq.exe` lub polecenia `Get-Certificate` w PowerShell).
```powershell
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Autoryzacja certyfikatów

Active Directory (AD) obsługuje autoryzację certyfikatów, głównie przy użyciu protokołów **Kerberos** i **Secure Channel (Schannel)**.

### Proces autoryzacji Kerberos

W procesie autoryzacji Kerberos, żądanie użytkownika o Bilet Granting Ticket (TGT) jest podpisane przy użyciu **klucza prywatnego** certyfikatu użytkownika. To żądanie przechodzi przez kilka walidacji przez kontroler domeny, w tym **ważność**, **ścieżkę** i **status unieważnienia** certyfikatu. Walidacje obejmują również sprawdzenie, czy certyfikat pochodzi z zaufanego źródła oraz potwierdzenie obecności wydawcy w magazynie certyfikatów **NTAUTH**. Pomyślne walidacje skutkują wydaniem TGT. Obiekt **`NTAuthCertificates`** w AD znajduje się pod adresem:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
jest kluczowy dla ustanowienia zaufania do uwierzytelniania za pomocą certyfikatów.

### Uwierzytelnianie kanału zabezpieczeń (Schannel)

Schannel ułatwia bezpieczne połączenia TLS/SSL, gdzie podczas ustanawiania połączenia klient prezentuje certyfikat, który po pomyślnym zweryfikowaniu autoryzuje dostęp. Odwzorowanie certyfikatu na konto AD może obejmować funkcję **S4U2Self** Kerberosa lub **Alternatywną Nazwę Podmiotu (SAN)** certyfikatu, między innymi metodami.

### Wyliczanie Usług Certyfikatów AD

Usługi certyfikatów AD mogą być wyliczone poprzez zapytania LDAP, ujawniając informacje o **Centralach Certyfikatów Przedsiębiorstwa (CA)** i ich konfiguracjach. Jest to dostępne dla każdego użytkownika uwierzytelnionego w domenie bez specjalnych uprawnień. Narzędzia takie jak **[Certify](https://github.com/GhostPack/Certify)** i **[Certipy](https://github.com/ly4k/Certipy)** są używane do wyliczania i oceny podatności w środowiskach AD CS.

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
## Odnośniki

* [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)
* [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
