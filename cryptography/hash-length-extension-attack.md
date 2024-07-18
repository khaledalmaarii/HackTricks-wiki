{% hint style="success" %}
Вивчайте та практикуйте взлом AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Навчання HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте взлом GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Навчання HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Поширюйте хакерські трюки, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв GitHub.

</details>
{% endhint %}


# Опис атаки

Уявіть сервер, який **підписує** деякі **дані**, додаючи до відомих чітких даних **секрет** і потім хешуючи ці дані. Якщо ви знаєте:

* **Довжину секрету** (це також можна перебрати з вказаного діапазону довжини)
* **Чіткі дані**
* **Алгоритм (і він вразливий до цієї атаки)**
* **Відоме доповнення**
* Зазвичай використовується типове, тому якщо виконані інші 3 вимоги, це також
* Доповнення змінюється в залежності від довжини секрету + даних, тому потрібна довжина секрету

Тоді для **зловмисника** можливо **додати дані** та **згенерувати** дійсний **підпис** для **попередніх даних + доданих даних**.

## Як?

Основні вразливі алгоритми генерують хеші, спочатку **хешуючи блок даних**, а потім, **з** **раніше** створеного **хешу** (стану), вони **додають наступний блок даних** та **хешують його**.

Тоді уявіть, що секрет - "секрет" і дані - "дані", MD5 "секретдані" - 6036708eba0d11f6ef52ad44e8b74d5b.\
Якщо зловмисник хоче додати рядок "додати", він може:

* Згенерувати MD5 з 64 "A"
* Змінити стан раніше ініціалізованого хешу на 6036708eba0d11f6ef52ad44e8b74d5b
* Додати рядок "додати"
* Завершити хешування, і отриманий хеш буде **дійсним для "секрет" + "дані" + "доповнення" + "додати"**

## **Інструмент**

{% embed url="https://github.com/iagox86/hash_extender" %}

## Посилання

Ви можете знайти цю атаку добре поясненою за посиланням [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)


{% hint style="success" %}
Вивчайте та практикуйте взлом AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Навчання HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте взлом GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Навчання HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Поширюйте хакерські трюки, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв GitHub.

</details>
{% endhint %}
