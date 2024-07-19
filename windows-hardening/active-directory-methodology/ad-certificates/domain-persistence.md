# AD CS Domain Persistence

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

**Це резюме технік збереження домену, представлених у [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**. Перевірте його для отримання додаткових деталей.

## Підробка сертифікатів за допомогою вкрадених CA сертифікатів - DPERSIST1

Як можна визначити, що сертифікат є CA сертифікатом?

Можна визначити, що сертифікат є CA сертифікатом, якщо виконуються кілька умов:

- Сертифікат зберігається на CA сервері, а його приватний ключ захищений DPAPI машини або апаратним забезпеченням, таким як TPM/HSM, якщо операційна система це підтримує.
- Поля Issuer і Subject сертифіката збігаються з відмінним ім'ям CA.
- У сертифікатах CA присутнє розширення "CA Version" виключно.
- Сертифікат не має полів Extended Key Usage (EKU).

Щоб витягти приватний ключ цього сертифіката, підтримуваним методом є інструмент `certsrv.msc` на CA сервері через вбудований GUI. Проте цей сертифікат не відрізняється від інших, що зберігаються в системі; отже, можна застосувати методи, такі як [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) для витягнення.

Сертифікат і приватний ключ також можна отримати за допомогою Certipy з наступною командою:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Після отримання сертифіката CA та його приватного ключа у форматі `.pfx`, можна використовувати інструменти, такі як [ForgeCert](https://github.com/GhostPack/ForgeCert), для генерації дійсних сертифікатів:
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
Користувач, на якого націлено підробку сертифіката, повинен бути активним і здатним аутентифікуватися в Active Directory, щоб процес був успішним. Підробка сертифіката для спеціальних облікових записів, таких як krbtgt, є неефективною.
{% endhint %}

Цей підроблений сертифікат буде **дійсним** до дати закінчення, зазначеної в ньому, і **доки сертифікат кореневого ЦС є дійсним** (зазвичай від 5 до **10+ років**). Він також дійсний для **машин**, тому в поєднанні з **S4U2Self** зловмисник може **підтримувати стійкість на будь-якій доменній машині** доти, поки сертифікат ЦС є дійсним.\
Більше того, **сертифікати, згенеровані** цим методом, **не можуть бути відкликані**, оскільки ЦС не знає про них.

## Довіра до сертифікатів зловмисного ЦС - DPERSIST2

Об'єкт `NTAuthCertificates` визначено для містити один або кілька **сертифікатів ЦС** в атрибуті `cacertificate`, який використовує Active Directory (AD). Процес перевірки з боку **доменного контролера** включає перевірку об'єкта `NTAuthCertificates` на наявність запису, що відповідає **ЦС, зазначеному** в полі Видавець аутентифікуючого **сертифіката**. Аутентифікація продовжується, якщо знайдено відповідність.

Зловмисник може додати самопідписаний сертифікат ЦС до об'єкта `NTAuthCertificates`, якщо він має контроль над цим об'єктом AD. Зазвичай лише члени групи **Enterprise Admin**, разом з **Domain Admins** або **Administrators** в **домена кореня лісу**, мають право змінювати цей об'єкт. Вони можуть редагувати об'єкт `NTAuthCertificates`, використовуючи `certutil.exe` з командою `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126`, або за допомогою [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Ця можливість є особливо актуальною, коли використовується разом з раніше описаним методом, що включає ForgeCert для динамічної генерації сертифікатів.

## Зловмисна неправильна конфігурація - DPERSIST3

Можливості для **стійкості** через **модифікації дескрипторів безпеки компонентів AD CS** є численними. Модифікації, описані в розділі "[Domain Escalation](domain-escalation.md)", можуть бути зловмисно реалізовані зловмисником з підвищеним доступом. Це включає додавання "прав контролю" (наприклад, WriteOwner/WriteDACL/тощо) до чутливих компонентів, таких як:

- Об'єкт комп'ютера AD **сервера ЦС**
- **RPC/DCOM сервер** сервера ЦС
- Будь-який **потомок об'єкта AD або контейнера** в **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (наприклад, контейнер Шаблонів Сертифікатів, контейнер Сертифікаційних Органів, об'єкт NTAuthCertificates тощо)
- **Групи AD, яким делеговані права контролю AD CS** за замовчуванням або організацією (такі як вбудована група Cert Publishers та будь-які її члени)

Приклад зловмисної реалізації включав би зловмисника, який має **підвищені права** в домені, що додає **дозвіл `WriteOwner`** до шаблону сертифіката за замовчуванням **`User`**, при цьому зловмисник є основним для цього права. Щоб скористатися цим, зловмисник спочатку змінить право власності на шаблон **`User`** на себе. Після цього **`mspki-certificate-name-flag`** буде встановлено на **1** на шаблоні, щоб активувати **`ENROLLEE_SUPPLIES_SUBJECT`**, що дозволяє користувачу надати альтернативну назву суб'єкта в запиті. Потім зловмисник може **зареєструватися** за допомогою **шаблону**, вибравши ім'я **доменного адміністратора** як альтернативну назву, і використовувати отриманий сертифікат для аутентифікації як DA.


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
