# Stała obecność konta AD CS

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

**To jest małe podsumowanie rozdziałów dotyczących trwałości maszyny z niesamowitych badań z [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**


## **Zrozumienie kradzieży aktywnych poświadczeń użytkownika za pomocą certyfikatów - PERSIST1**

W scenariuszu, w którym użytkownik może poprosić o certyfikat umożliwiający uwierzytelnianie domeny, atakujący ma możliwość **poproszenia** i **ukradzenia** tego certyfikatu w celu **utrzymania trwałości** w sieci. Domyślnie szablon `User` w Active Directory umożliwia takie żądania, chociaż czasami może być wyłączony.

Za pomocą narzędzia o nazwie [**Certify**](https://github.com/GhostPack/Certify) można wyszukiwać ważne certyfikaty umożliwiające stały dostęp:
```bash
Certify.exe find /clientauth
```
Podkreśla się, że moc certyfikatu leży w jego zdolności do **uwierzytelniania jako użytkownik**, do którego należy, niezależnie od zmiany hasła, pod warunkiem, że certyfikat pozostaje **ważny**.

Certyfikaty można żądać za pomocą interfejsu graficznego przy użyciu `certmgr.msc` lub za pomocą wiersza polecenia za pomocą `certreq.exe`. Dzięki **Certify** proces żądania certyfikatu jest uproszczony i przebiega w następujący sposób:
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
Po udanym żądaniu generowany jest certyfikat wraz z kluczem prywatnym w formacie `.pem`. Aby przekonwertować go na plik `.pfx`, który można używać w systemach Windows, używa się następującej komendy:
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
Plik `.pfx` można następnie przesłać na docelowy system i użyć go z narzędziem o nazwie [**Rubeus**](https://github.com/GhostPack/Rubeus), aby poprosić o bilet Ticket Granting Ticket (TGT) dla użytkownika, przedłużając dostęp atakującego tak długo, jak długo certyfikat jest **ważny** (zazwyczaj jeden rok):
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
Ważne ostrzeżenie dotyczy tego, jak ta technika, połączona z inną metodą opisaną w sekcji **THEFT5**, umożliwia atakującemu trwałe uzyskanie **skrótu NTLM** konta bez interakcji z usługą Local Security Authority Subsystem (LSASS) i z kontekstu o niskich uprawnieniach, co zapewnia bardziej skrytą metodę długotrwałego kradzieży poświadczeń.

## **Zdobywanie trwałości maszyny za pomocą certyfikatów - PERSIST2**

Inna metoda polega na zapisaniu konta maszyny skompromitowanego systemu na certyfikat, wykorzystując domyślny szablon `Machine`, który umożliwia takie działania. Jeśli atakujący uzyska podwyższone uprawnienia na systemie, może użyć konta **SYSTEM** do żądania certyfikatów, co zapewnia formę **trwałości**:
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
Ten dostęp umożliwia atakującemu uwierzytelnienie się w **Kerberosie** jako konto maszyny i wykorzystanie **S4U2Self** do uzyskania biletów usługi Kerberos dla dowolnej usługi na hoście, co efektywnie daje atakującemu trwały dostęp do maszyny.

## **Rozszerzenie trwałości poprzez odnawianie certyfikatów - PERSIST3**

Ostatnia omawiana metoda polega na wykorzystaniu **okresów ważności** i **odnawiania** szablonów certyfikatów. Poprzez **odnawianie** certyfikatu przed jego wygaśnięciem, atakujący może utrzymać uwierzytelnienie w Active Directory bez konieczności dodatkowego zapisywania biletów, co mogłoby pozostawić ślady na serwerze Certyfikatów (CA).

Ten podejście pozwala na **rozszerzenie trwałości**, minimalizując ryzyko wykrycia poprzez mniejszą liczbę interakcji z serwerem CA i unikając generowania artefaktów, które mogłyby zwrócić uwagę administratorów na włamanie.

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
