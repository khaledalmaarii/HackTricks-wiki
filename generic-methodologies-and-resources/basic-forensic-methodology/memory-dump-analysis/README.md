# Аналіз дампа пам'яті

{% hint style="success" %}
Вивчайте та практикуйте AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) є найважливішою подією в сфері кібербезпеки в **Іспанії** та однією з найважливіших в **Європі**. З **метою просування технічних знань**, цей конгрес є гарячою точкою зустрічі для професіоналів у сфері технологій та кібербезпеки в усіх дисциплінах.

{% embed url="https://www.rootedcon.com/" %}

## Початок

Почніть **шукати** **шкідливе ПЗ** всередині pcap. Використовуйте **інструменти**, згадані в [**Аналізі шкідливого ПЗ**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Volatility є основним відкритим фреймворком для аналізу дампів пам'яті**. Цей інструмент на Python аналізує дампи з зовнішніх джерел або віртуальних машин VMware, ідентифікуючи дані, такі як процеси та паролі на основі профілю ОС дампа. Він розширюється за допомогою плагінів, що робить його дуже універсальним для судово-медичних розслідувань.

[**Знайдіть тут шпаргалку**](volatility-cheatsheet.md)

## Звіт про аварійний дамп

Коли дамп є малим (всього кілька КБ, можливо, кілька МБ), то це, ймовірно, звіт про аварійний дамп, а не дамп пам'яті.

![](<../../../.gitbook/assets/image (532).png>)

Якщо у вас встановлено Visual Studio, ви можете відкрити цей файл і прив'язати деяку базову інформацію, таку як назва процесу, архітектура, інформація про виключення та модулі, що виконуються:

![](<../../../.gitbook/assets/image (263).png>)

Ви також можете завантажити виключення та переглянути декомпільовані інструкції

![](<../../../.gitbook/assets/image (142).png>)

![](<../../../.gitbook/assets/image (610).png>)

У будь-якому випадку, Visual Studio не є найкращим інструментом для проведення глибокого аналізу дампа.

Вам слід **відкрити** його за допомогою **IDA** або **Radare** для детального огляду.

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) є найважливішою подією в сфері кібербезпеки в **Іспанії** та однією з найважливіших в **Європі**. З **метою просування технічних знань**, цей конгрес є гарячою точкою зустрічі для професіоналів у сфері технологій та кібербезпеки в усіх дисциплінах.

{% embed url="https://www.rootedcon.com/" %}

{% hint style="success" %}
Вивчайте та практикуйте AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}
