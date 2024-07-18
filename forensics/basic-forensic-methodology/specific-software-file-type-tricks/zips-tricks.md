# Підступи до ZIP-файлів

{% hint style="success" %}
Вивчайте та практикуйте хакінг AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Навчання HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте хакінг GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Навчання HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Поширюйте хакерські трюки, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв GitHub.

</details>
{% endhint %}

**Командні інструменти** для управління **zip-файлами** є важливими для діагностики, відновлення та взлому zip-файлів. Ось деякі ключові утиліти:

- **`unzip`**: Розкриває причину, чому zip-файл може не розпакуватися.
- **`zipdetails -v`**: Надає детальний аналіз полів формату zip-файлу.
- **`zipinfo`**: Виводить список вмісту zip-файлу без їх видобутку.
- **`zip -F input.zip --out output.zip`** та **`zip -FF input.zip --out output.zip`**: Спробуйте відновити пошкоджені zip-файли.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Інструмент для брутфорсного взлому паролів zip, ефективний для паролів до близько 7 символів.

Специфікація формату zip-файлу надає вичерпні відомості про структуру та стандарти zip-файлів.

Важливо зауважити, що захищені паролем zip-файли **не шифрують імена файлів або розміри файлів** всередині, уразливість, яку не поділяють файли RAR або 7z, які шифрують цю інформацію. Крім того, zip-файли, зашифровані за допомогою старішого методу ZipCrypto, вразливі до **атаки на текст** у разі наявності незашифрованої копії стиснутого файлу. Ця атака використовує відомий вміст для взлому пароля zip, уразливість детально описана в [статті HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) та подальше пояснено в [цій науковій статті](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf). Однак zip-файли, захищені шифруванням **AES-256**, є невразливими до цієї атаки на текст, демонструючи важливість вибору безпечних методів шифрування для конфіденційних даних.

## Посилання
* [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)

{% hint style="success" %}
Вивчайте та практикуйте хакінг AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Навчання HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте хакінг GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Навчання HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Поширюйте хакерські трюки, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв GitHub.

</details>
{% endhint %}
