# Weaponizing Distroless

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

## Що таке Distroless

Контейнер distroless — це тип контейнера, який **містить лише необхідні залежності для запуску конкретного застосунку**, без будь-якого додаткового програмного забезпечення або інструментів, які не є необхідними. Ці контейнери розроблені, щоб бути **легкими** та **безпечними** наскільки це можливо, і вони прагнуть **мінімізувати поверхню атаки**, видаляючи будь-які непотрібні компоненти.

Контейнери distroless часто використовуються в **виробничих середовищах, де безпека та надійність є найважливішими**.

Деякі **приклади** **контейнерів distroless**:

* Надано **Google**: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
* Надано **Chainguard**: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Озброєння Distroless

Мета озброєння контейнера distroless полягає в тому, щоб мати можливість **виконувати довільні двійкові файли та корисні навантаження, навіть з обмеженнями**, які накладає **distroless** (відсутність загальних двійкових файлів у системі), а також захистами, які зазвичай зустрічаються в контейнерах, такими як **тільки для читання** або **без виконання** в `/dev/shm`.

### Через пам'ять

Приблизно в якийсь момент 2023 року...

### Через існуючі двійкові файли

#### openssl

****[**У цьому пості,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) пояснюється, що двійковий файл **`openssl`** часто зустрічається в цих контейнерах, можливо, тому що він **потрібен** програмному забезпеченню, яке буде працювати всередині контейнера.


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
