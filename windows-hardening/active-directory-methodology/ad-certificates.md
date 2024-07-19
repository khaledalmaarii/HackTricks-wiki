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

## Introduction

### Components of a Certificate

- The **Subject** of the certificate denotes its owner.
- A **Public Key** is paired with a privately held key to link the certificate to its rightful owner.
- The **Validity Period**, defined by **NotBefore** and **NotAfter** dates, marks the certificate's effective duration.
- A unique **Serial Number**, provided by the Certificate Authority (CA), identifies each certificate.
- The **Issuer** refers to the CA that has issued the certificate.
- **SubjectAlternativeName** allows for additional names for the subject, enhancing identification flexibility.
- **Basic Constraints** identify if the certificate is for a CA or an end entity and define usage restrictions.
- **Extended Key Usages (EKUs)** delineate the certificate's specific purposes, like code signing or email encryption, through Object Identifiers (OIDs).
- The **Signature Algorithm** specifies the method for signing the certificate.
- The **Signature**, created with the issuer's private key, guarantees the certificate's authenticity.

### Special Considerations

- **Subject Alternative Names (SANs)** expand a certificate's applicability to multiple identities, crucial for servers with multiple domains. Secure issuance processes are vital to avoid impersonation risks by attackers manipulating the SAN specification.

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS acknowledges CA certificates in an AD forest through designated containers, each serving unique roles:

- **Certification Authorities** container holds trusted root CA certificates.
- **Enrolment Services** container details Enterprise CAs and their certificate templates.
- **NTAuthCertificates** object includes CA certificates authorized for AD authentication.
- **AIA (Authority Information Access)** container facilitates certificate chain validation with intermediate and cross CA certificates.

### Certificate Acquisition: Client Certificate Request Flow

1. The request process begins with clients finding an Enterprise CA.
2. A CSR is created, containing a public key and other details, after generating a public-private key pair.
3. The CA assesses the CSR against available certificate templates, issuing the certificate based on the template's permissions.
4. Upon approval, the CA signs the certificate with its private key and returns it to the client.

### Certificate Templates

Defined within AD, these templates outline the settings and permissions for issuing certificates, including permitted EKUs and enrollment or modification rights, critical for managing access to certificate services.

## Certificate Enrollment

Процес реєстрації сертифікатів ініціюється адміністратором, який **створює шаблон сертифіката**, який потім **публікується** підприємницьким центром сертифікації (CA). Це робить шаблон доступним для реєстрації клієнтів, що досягається шляхом додавання імені шаблону до поля `certificatetemplates` об'єкта Active Directory.

Щоб клієнт міг запросити сертифікат, **права на реєстрацію** повинні бути надані. Ці права визначаються за допомогою дескрипторів безпеки на шаблоні сертифіката та самому підприємницькому CA. Права повинні бути надані в обох місцях, щоб запит був успішним.

### Template Enrollment Rights

Ці права визначаються через записи контролю доступу (ACE), що деталізують такі дозволи, як:
- **Certificate-Enrollment** та **Certificate-AutoEnrollment** права, кожне з яких пов'язане з конкретними GUID.
- **ExtendedRights**, що дозволяє всі розширені дозволи.
- **FullControl/GenericAll**, що надає повний контроль над шаблоном.

### Enterprise CA Enrollment Rights

Права CA викладені в його дескрипторі безпеки, доступному через консоль управління центром сертифікації. Деякі налаштування навіть дозволяють користувачам з низькими привілеями віддалений доступ, що може бути проблемою безпеки.

### Additional Issuance Controls

Деякі контролі можуть застосовуватися, такі як:
- **Manager Approval**: Поміщає запити в стан очікування до затвердження менеджером сертифікатів.
- **Enrolment Agents and Authorized Signatures**: Визначають кількість необхідних підписів на CSR та необхідні OID політики застосування.

### Methods to Request Certificates

Сертифікати можна запитувати через:
1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), використовуючи DCOM інтерфейси.
2. **ICertPassage Remote Protocol** (MS-ICPR), через іменовані канали або TCP/IP.
3. Веб-інтерфейс реєстрації сертифікатів, з встановленою роллю веб-реєстрації центру сертифікації.
4. **Certificate Enrollment Service** (CES), у поєднанні з сервісом політики реєстрації сертифікатів (CEP).
5. **Network Device Enrollment Service** (NDES) для мережевих пристроїв, використовуючи простий протокол реєстрації сертифікатів (SCEP).

Користувачі Windows також можуть запитувати сертифікати через GUI (`certmgr.msc` або `certlm.msc`) або командні інструменти (`certreq.exe` або команду PowerShell `Get-Certificate`).
```powershell
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Сертифікатна Аутентифікація

Active Directory (AD) підтримує сертифікатну аутентифікацію, в основному використовуючи протоколи **Kerberos** та **Secure Channel (Schannel)**.

### Процес Аутентифікації Kerberos

У процесі аутентифікації Kerberos запит користувача на отримання квитка на отримання квитка (TGT) підписується за допомогою **приватного ключа** сертифіката користувача. Цей запит проходить кілька перевірок доменним контролером, включаючи **дійсність** сертифіката, **шлях** та **статус відкликання**. Перевірки також включають підтвердження того, що сертифікат походить з надійного джерела, та підтвердження наявності видавця в **сховищі сертифікатів NTAUTH**. Успішні перевірки призводять до видачі TGT. Об'єкт **`NTAuthCertificates`** в AD, розташований за:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
є центральним для встановлення довіри для сертифікатної аутентифікації.

### Аутентифікація через Secure Channel (Schannel)

Schannel забезпечує безпечні TLS/SSL з'єднання, під час яких клієнт представляє сертифікат, який, якщо успішно перевірений, надає доступ. Відображення сертифіката на обліковий запис AD може включати функцію Kerberos **S4U2Self** або **Subject Alternative Name (SAN)** сертифіката, серед інших методів.

### Перерахування сертифікатних служб AD

Служби сертифікатів AD можна перерахувати через LDAP запити, що розкриває інформацію про **Enterprise Certificate Authorities (CAs)** та їх конфігурації. Це доступно будь-якому користувачу, аутентифікованому в домені, без спеціальних привілеїв. Інструменти, такі як **[Certify](https://github.com/GhostPack/Certify)** та **[Certipy](https://github.com/ly4k/Certipy)**, використовуються для перерахування та оцінки вразливостей в середовищах AD CS.

Команди для використання цих інструментів включають:
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
## References

* [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)
* [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

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
