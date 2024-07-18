# Аналіз PDF файлів

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

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Використовуйте [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) для легкого створення та **автоматизації робочих процесів**, підтримуваних **найсучаснішими** інструментами спільноти.\
Отримайте доступ сьогодні:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

**Для отримання додаткової інформації перевірте:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)

Формат PDF відомий своєю складністю та потенціалом для приховування даних, що робить його центром уваги для CTF судово-медичних викликів. Він поєднує елементи простого тексту з бінарними об'єктами, які можуть бути стиснуті або зашифровані, і може включати скрипти на мовах, таких як JavaScript або Flash. Щоб зрозуміти структуру PDF, можна звернутися до [вступних матеріалів](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) Дідьє Стефенса або використовувати інструменти, такі як текстовий редактор або редактор, специфічний для PDF, наприклад, Origami.

Для глибшого дослідження або маніпуляції з PDF доступні інструменти, такі як [qpdf](https://github.com/qpdf/qpdf) та [Origami](https://github.com/mobmewireless/origami-pdf). Приховані дані в PDF можуть бути заховані в:

* Невидимих шарах
* Форматі метаданих XMP від Adobe
* Інкрементальних генераціях
* Тексті того ж кольору, що й фон
* Тексті за зображеннями або накладених зображеннях
* Непоказаних коментарях

Для індивідуального аналізу PDF можна використовувати бібліотеки Python, такі як [PeepDF](https://github.com/jesparza/peepdf), щоб створити спеціальні скрипти для парсингу. Крім того, потенціал PDF для зберігання прихованих даних настільки великий, що ресурси, такі як посібник NSA з ризиків PDF та контрзаходів, хоча більше не розміщений за своєю первісною адресою, все ще пропонують цінні відомості. [Копія посібника](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) та колекція [трюків формату PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) від Анжелі Альберті можуть надати додаткову інформацію з цього питання.

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
