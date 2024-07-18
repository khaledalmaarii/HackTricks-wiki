# Викрадення розкриття чутливої інформації з веб-сторінки

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

Якщо в якийсь момент ви знайдете **веб-сторінку, яка надає вам чутливу інформацію на основі вашої сесії**: Можливо, вона відображає куки, або друкує деталі кредитної картки або будь-яку іншу чутливу інформацію, ви можете спробувати її вкрасти.\
Ось основні способи, які ви можете спробувати для досягнення цього:

* [**CORS обход**](../pentesting-web/cors-bypass.md): Якщо ви можете обійти заголовки CORS, ви зможете вкрасти інформацію, виконуючи Ajax-запит на зловмисну сторінку.
* [**XSS**](../pentesting-web/xss-cross-site-scripting/): Якщо ви знайдете вразливість XSS на сторінці, ви зможете зловживати нею для викрадення інформації.
* [**Danging Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/): Якщо ви не можете ввести теги XSS, ви все ще можете вкрасти інформацію, використовуючи інші звичайні HTML-теги.
* [**Clickjaking**](../pentesting-web/clickjacking.md): Якщо немає захисту від цієї атаки, ви можете обманути користувача, щоб він надіслав вам чутливі дані (приклад [тут](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).

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
