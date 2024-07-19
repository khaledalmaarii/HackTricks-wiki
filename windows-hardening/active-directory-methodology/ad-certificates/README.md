# AD Certificates

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

## Wprowadzenie

### Składniki certyfikatu

- **Podmiot** certyfikatu oznacza jego właściciela.
- **Klucz publiczny** jest sparowany z kluczem prywatnym, aby powiązać certyfikat z jego prawowitym właścicielem.
- **Okres ważności**, określony przez daty **NotBefore** i **NotAfter**, oznacza czas obowiązywania certyfikatu.
- Unikalny **Numer seryjny**, dostarczony przez Urząd Certyfikacji (CA), identyfikuje każdy certyfikat.
- **Wystawca** odnosi się do CA, który wydał certyfikat.
- **SubjectAlternativeName** pozwala na dodatkowe nazwy dla podmiotu, zwiększając elastyczność identyfikacji.
- **Podstawowe ograniczenia** identyfikują, czy certyfikat jest dla CA, czy dla podmiotu końcowego oraz definiują ograniczenia użytkowania.
- **Rozszerzone zastosowania kluczy (EKU)** określają konkretne cele certyfikatu, takie jak podpisywanie kodu lub szyfrowanie e-maili, za pomocą identyfikatorów obiektów (OID).
- **Algorytm podpisu** określa metodę podpisywania certyfikatu.
- **Podpis**, stworzony za pomocą klucza prywatnego wystawcy, gwarantuje autentyczność certyfikatu.

### Specjalne uwagi

- **Alternatywne nazwy podmiotu (SAN)** rozszerzają zastosowanie certyfikatu na wiele tożsamości, co jest kluczowe dla serwerów z wieloma domenami. Bezpieczne procesy wydawania są niezbędne, aby uniknąć ryzyka podszywania się przez atakujących manipulujących specyfikacją SAN.

### Urzędy Certyfikacji (CA) w Active Directory (AD)

AD CS uznaje certyfikaty CA w lesie AD poprzez wyznaczone kontenery, z których każdy pełni unikalne role:

- Kontener **Certification Authorities** przechowuje zaufane certyfikaty głównych CA.
- Kontener **Enrolment Services** zawiera szczegóły dotyczące Enterprise CA i ich szablonów certyfikatów.
- Obiekt **NTAuthCertificates** zawiera certyfikaty CA autoryzowane do uwierzytelniania AD.
- Kontener **AIA (Authority Information Access)** ułatwia walidację łańcucha certyfikatów z certyfikatami pośrednimi i krzyżowymi CA.

### Pozyskiwanie certyfikatów: Proces żądania certyfikatu klienta

1. Proces żądania rozpoczyna się od znalezienia przez klientów Enterprise CA.
2. Tworzony jest CSR, zawierający klucz publiczny i inne szczegóły, po wygenerowaniu pary kluczy publiczno-prywatnych.
3. CA ocenia CSR w odniesieniu do dostępnych szablonów certyfikatów, wydając certyfikat na podstawie uprawnień szablonu.
4. Po zatwierdzeniu CA podpisuje certyfikat swoim kluczem prywatnym i zwraca go klientowi.

### Szablony certyfikatów

Zdefiniowane w AD, te szablony określają ustawienia i uprawnienia do wydawania certyfikatów, w tym dozwolone EKU oraz prawa do rejestracji lub modyfikacji, co jest kluczowe dla zarządzania dostępem do usług certyfikacyjnych.

## Rejestracja certyfikatów

Proces rejestracji certyfikatów inicjuje administrator, który **tworzy szablon certyfikatu**, który następnie jest **publikowany** przez Enterprise Certificate Authority (CA). To sprawia, że szablon jest dostępny do rejestracji przez klientów, co osiąga się poprzez dodanie nazwy szablonu do pola `certificatetemplates` obiektu Active Directory.

Aby klient mógł zażądać certyfikatu, muszą być przyznane **prawa rejestracji**. Prawa te są określone przez deskryptory zabezpieczeń na szablonie certyfikatu oraz samym Enterprise CA. Uprawnienia muszą być przyznane w obu lokalizacjach, aby żądanie było skuteczne.

### Prawa rejestracji szablonów

Prawa te są określone za pomocą wpisów kontroli dostępu (ACE), szczegółowo opisujących uprawnienia, takie jak:
- Prawa **Certificate-Enrollment** i **Certificate-AutoEnrollment**, z każdym związanym z określonymi GUID.
- **ExtendedRights**, pozwalające na wszystkie rozszerzone uprawnienia.
- **FullControl/GenericAll**, zapewniające pełną kontrolę nad szablonem.

### Prawa rejestracji Enterprise CA

Prawa CA są określone w jego deskryptorze zabezpieczeń, dostępnym za pośrednictwem konsoli zarządzania Urzędem Certyfikacji. Niektóre ustawienia pozwalają nawet użytkownikom o niskich uprawnieniach na zdalny dostęp, co może stanowić zagrożenie dla bezpieczeństwa.

### Dodatkowe kontrole wydawania

Mogą obowiązywać pewne kontrole, takie jak:
- **Zatwierdzenie menedżera**: Umieszcza żądania w stanie oczekiwania do zatwierdzenia przez menedżera certyfikatów.
- **Agenci rejestracji i autoryzowane podpisy**: Określają liczbę wymaganych podpisów na CSR oraz niezbędne identyfikatory polityki aplikacji OID.

### Metody żądania certyfikatów

Certyfikaty można żądać za pośrednictwem:
1. **Protokół rejestracji certyfikatów klienta Windows** (MS-WCCE), używając interfejsów DCOM.
2. **Protokół ICertPassage Remote** (MS-ICPR), przez potok nazwany lub TCP/IP.
3. **Interfejs internetowy rejestracji certyfikatów**, z zainstalowaną rolą Web Enrollment Urzędu Certyfikacji.
4. **Usługa rejestracji certyfikatów** (CES), w połączeniu z usługą polityki rejestracji certyfikatów (CEP).
5. **Usługa rejestracji urządzeń sieciowych** (NDES) dla urządzeń sieciowych, używając prostego protokołu rejestracji certyfikatów (SCEP).

Użytkownicy systemu Windows mogą również żądać certyfikatów za pośrednictwem GUI (`certmgr.msc` lub `certlm.msc`) lub narzędzi wiersza poleceń (`certreq.exe` lub polecenia PowerShell `Get-Certificate`).
```powershell
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Uwierzytelnianie za pomocą certyfikatów

Active Directory (AD) wspiera uwierzytelnianie za pomocą certyfikatów, głównie wykorzystując protokoły **Kerberos** i **Secure Channel (Schannel)**.

### Proces Uwierzytelniania Kerberos

W procesie uwierzytelniania Kerberos, żądanie użytkownika o Ticket Granting Ticket (TGT) jest podpisywane za pomocą **klucza prywatnego** certyfikatu użytkownika. To żądanie przechodzi przez kilka walidacji przez kontroler domeny, w tym **ważność**, **ścieżkę** i **status unieważnienia** certyfikatu. Walidacje obejmują również weryfikację, że certyfikat pochodzi z zaufanego źródła oraz potwierdzenie obecności wystawcy w **magazynie certyfikatów NTAUTH**. Pomyślne walidacje skutkują wydaniem TGT. Obiekt **`NTAuthCertificates`** w AD, znajdujący się pod:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
is central to establishing trust for certificate authentication.

### Secure Channel (Schannel) Authentication

Schannel ułatwia bezpieczne połączenia TLS/SSL, gdzie podczas handshake klient przedstawia certyfikat, który, jeśli zostanie pomyślnie zweryfikowany, upoważnia do dostępu. Mapowanie certyfikatu do konta AD może obejmować funkcję Kerberos **S4U2Self** lub **Subject Alternative Name (SAN)** certyfikatu, między innymi metody.

### AD Certificate Services Enumeration

Usługi certyfikatów AD można enumerować za pomocą zapytań LDAP, ujawniając informacje o **Enterprise Certificate Authorities (CAs)** i ich konfiguracjach. Jest to dostępne dla każdego użytkownika uwierzytelnionego w domenie bez specjalnych uprawnień. Narzędzia takie jak **[Certify](https://github.com/GhostPack/Certify)** i **[Certipy](https://github.com/ly4k/Certipy)** są używane do enumeracji i oceny podatności w środowiskach AD CS.

Commands for using these tools include:
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
## Odniesienia

* [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)
* [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
