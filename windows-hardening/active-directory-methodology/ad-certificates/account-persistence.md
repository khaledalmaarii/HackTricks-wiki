# AD CS Account Persistence

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

**To jest małe podsumowanie rozdziałów dotyczących utrzymywania maszyn w świetnym badaniu z [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**

## **Zrozumienie kradzieży poświadczeń aktywnego użytkownika za pomocą certyfikatów – PERSIST1**

W scenariuszu, w którym certyfikat umożliwiający uwierzytelnianie w domenie może być żądany przez użytkownika, atakujący ma możliwość **zażądania** i **kradzieży** tego certyfikatu, aby **utrzymać trwałość** w sieci. Domyślnie szablon `User` w Active Directory pozwala na takie żądania, chociaż czasami może być wyłączony.

Używając narzędzia o nazwie [**Certify**](https://github.com/GhostPack/Certify), można wyszukiwać ważne certyfikaty, które umożliwiają trwały dostęp:
```bash
Certify.exe find /clientauth
```
Zaznaczone jest, że moc certyfikatu polega na jego zdolności do **uwierzytelniania jako użytkownik**, do którego należy, niezależnie od jakichkolwiek zmian hasła, pod warunkiem, że certyfikat pozostaje **ważny**.

Certyfikaty można żądać za pomocą interfejsu graficznego przy użyciu `certmgr.msc` lub za pomocą wiersza poleceń z `certreq.exe`. Dzięki **Certify** proces żądania certyfikatu jest uproszczony w następujący sposób:
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
Po pomyślnym żądaniu, certyfikat wraz z jego kluczem prywatnym jest generowany w formacie `.pem`. Aby przekonwertować to na plik `.pfx`, który jest użyteczny w systemach Windows, używa się następującego polecenia:
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
Plik `.pfx` może być następnie przesłany do docelowego systemu i użyty z narzędziem o nazwie [**Rubeus**](https://github.com/GhostPack/Rubeus) do żądania Ticket Granting Ticket (TGT) dla użytkownika, przedłużając dostęp atakującego tak długo, jak certyfikat jest **ważny** (zazwyczaj przez rok):
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
An important warning is shared about how this technique, combined with another method outlined in the **THEFT5** section, allows an attacker to persistently obtain an account’s **NTLM hash** without interacting with the Local Security Authority Subsystem Service (LSASS), and from a non-elevated context, providing a stealthier method for long-term credential theft.

## **Gaining Machine Persistence with Certificates - PERSIST2**

Inna metoda polega na zarejestrowaniu konta maszyny skompromitowanego systemu dla certyfikatu, wykorzystując domyślny szablon `Machine`, który pozwala na takie działania. Jeśli atakujący uzyska podwyższone uprawnienia w systemie, może użyć konta **SYSTEM** do żądania certyfikatów, co zapewnia formę **persistence**:
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
Tożsamość ta umożliwia atakującemu uwierzytelnienie się do **Kerberos** jako konto maszyny i wykorzystanie **S4U2Self** do uzyskania biletów serwisowych Kerberos dla dowolnej usługi na hoście, co skutecznie przyznaje atakującemu trwały dostęp do maszyny.

## **Rozszerzanie trwałości poprzez odnawianie certyfikatów - PERSIST3**

Ostatnia omawiana metoda polega na wykorzystaniu **ważności** i **okresów odnawiania** szablonów certyfikatów. Poprzez **odnowienie** certyfikatu przed jego wygaśnięciem, atakujący może utrzymać uwierzytelnienie do Active Directory bez potrzeby dodatkowych rejestracji biletów, co mogłoby pozostawić ślady na serwerze Urzędu Certyfikacji (CA).

Podejście to pozwala na metodę **rozszerzonej trwałości**, minimalizując ryzyko wykrycia poprzez mniejsze interakcje z serwerem CA i unikanie generowania artefaktów, które mogłyby zaalarmować administratorów o intruzji.
