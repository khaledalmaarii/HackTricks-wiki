# AD CS Trwałość domeny

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

**To jest podsumowanie technik trwałości domeny udostępnionych w [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**. Sprawdź to dla dalszych szczegółów.

## Fałszowanie certyfikatów za pomocą skradzionych certyfikatów CA - DPERSIST1

Jak można stwierdzić, czy certyfikat jest certyfikatem CA?

Można stwierdzić, że certyfikat jest certyfikatem CA, jeśli spełnione są kilka warunków:

- Certyfikat jest przechowywany na serwerze CA, a jego klucz prywatny jest zabezpieczony przez DPAPI maszyny lub przez sprzęt, takie jak TPM/HSM, jeśli system operacyjny to obsługuje.
- Zarówno pola Wydawcy, jak i Podmiotu certyfikatu odpowiadają nazwie odróżniającej CA.
- Rozszerzenie "Wersja CA" jest obecne wyłącznie w certyfikatach CA.
- Certyfikat nie zawiera pól Rozszerzonego Użycia Klucza (EKU).

Aby wyodrębnić klucz prywatny tego certyfikatu, obsługiwana metoda za pomocą wbudowanego interfejsu GUI jest narzędzie `certsrv.msc` na serwerze CA. Niemniej jednak, ten certyfikat nie różni się od innych przechowywanych w systemie; dlatego można zastosować metody takie jak technika [THEFT2](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) do jego wyodrębnienia.

Certyfikat i klucz prywatny można również uzyskać za pomocą Certipy za pomocą następującej komendy:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Po uzyskaniu certyfikatu CA i jego klucza prywatnego w formacie `.pfx`, można użyć narzędzi takich jak [ForgeCert](https://github.com/GhostPack/ForgeCert), aby wygenerować ważne certyfikaty:
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
{% hint style="warning" %}
Użytkownik, którego dotyczy fałszowanie certyfikatu, musi być aktywny i zdolny do uwierzytelnienia w Active Directory, aby proces zakończył się sukcesem. Fałszowanie certyfikatu dla specjalnych kont, takich jak krbtgt, jest nieskuteczne.
{% endhint %}

Ten sfałszowany certyfikat będzie **ważny** do określonej daty zakończenia i **tylko wtedy, gdy certyfikat CA nadrzędnego jest ważny** (zazwyczaj od 5 do **10+ lat**). Jest również ważny dla **maszyn**, więc w połączeniu z **S4U2Self** atakujący może **utrzymywać trwałość na dowolnej maszynie domeny** tak długo, jak certyfikat CA jest ważny.\
Ponadto, **wygenerowane certyfikaty** za pomocą tej metody **nie mogą zostać unieważnione**, ponieważ CA o nich nie wie.

## Ufanie sfałszowanym certyfikatom CA - DPERSIST2

Obiekt `NTAuthCertificates` jest definiowany jako zawierający jeden lub więcej **certyfikatów CA** w swoim atrybucie `cacertificate`, który wykorzystuje Active Directory (AD). Proces weryfikacji przez **kontroler domeny** polega na sprawdzeniu obiektu `NTAuthCertificates` w poszukiwaniu wpisu odpowiadającego **CA określonemu** w polu Wydawca uwierzytelniającego **certyfikatu**. Jeśli zostanie znalezione dopasowanie, uwierzytelnianie jest kontynuowane.

Atakujący może dodać samopodpisany certyfikat CA do obiektu `NTAuthCertificates`, o ile ma kontrolę nad tym obiektem AD. Zazwyczaj tylko członkowie grupy **Enterprise Admin**, wraz z **Domain Admins** lub **Administrators** w **domenie korzenia lasu**, mają uprawnienia do modyfikowania tego obiektu. Mogą edytować obiekt `NTAuthCertificates`, używając `certutil.exe` z poleceniem `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126`, lub za pomocą [**narzędzia PKI Health**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Ta możliwość jest szczególnie istotna, gdy jest używana w połączeniu z wcześniej opisaną metodą wykorzystującą ForgeCert do dynamicznego generowania certyfikatów.

## Złośliwa nieprawidłowa konfiguracja - DPERSIST3

Okazje do **trwałości** poprzez **modyfikacje deskryptorów zabezpieczeń komponentów AD CS** są liczne. Modyfikacje opisane w sekcji "[Eskalacja domeny](domain-escalation.md)" mogą być złośliwie wprowadzane przez atakującego z podwyższonym dostępem. Dotyczy to dodawania "uprawnień kontrolnych" (np. WriteOwner/WriteDACL itp.) do wrażliwych komponentów, takich jak:

- Obiekt **komputera AD serwera CA**
- Serwer **RPC/DCOM serwera CA**
- Dowolny **obiekt lub kontener potomny AD** w **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (na przykład kontener Szablony certyfikatów, kontener Certyfikujące urzędy, obiekt NTAuthCertificates itp.)
- **Grupy AD z uprawnieniami do kontrolowania AD CS** domyślnie lub przez organizację (takie jak wbudowana grupa Cert Publishers i jej członkowie)

Przykładem złośliwej implementacji byłoby dodanie uprawnienia **`WriteOwner`** do domyślnego szablonu certyfikatu **`User`**, gdzie atakujący jest właścicielem tego uprawnienia. Aby wykorzystać to, atakujący najpierw zmieniłby właściciela szablonu **`User`** na siebie. Następnie na szablonie ustawiono **`mspki-certificate-name-flag`** na **1**, aby włączyć **`ENROLLEE_SUPPLIES_SUBJECT`**, co umożliwia użytkownikowi podanie alternatywnego nazwy w żądaniu. Następnie atakujący mógłby **zarejestrować się** za pomocą **szablonu**, wybierając jako alternatywną nazwę **administratora domeny**, i wykorzystać uzyskany certyfikat do uwierzytelnienia jako DA.


<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
