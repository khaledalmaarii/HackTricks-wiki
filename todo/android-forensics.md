# Android Forensics

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

## Заблокований пристрій

Щоб почати витягувати дані з Android-пристрою, його потрібно розблокувати. Якщо він заблокований, ви можете:

* Перевірити, чи активовано налагодження через USB.
* Перевірити можливу [smudge attack](https://www.usenix.org/legacy/event/woot10/tech/full\_papers/Aviv.pdf)
* Спробувати [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

## Отримання даних

Створіть [android backup using adb](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) і витягніть його за допомогою [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/): `java -jar abe.jar unpack file.backup file.tar`

### Якщо є доступ до root або фізичне з'єднання з JTAG інтерфейсом

* `cat /proc/partitions` (знайдіть шлях до флеш-пам'яті, зазвичай перший запис - _mmcblk0_ і відповідає всій флеш-пам'яті).
* `df /data` (виявити розмір блоку системи).
* dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (виконайте його з інформацією, зібраною з розміру блоку).

### Пам'ять

Використовуйте Linux Memory Extractor (LiME) для витягування інформації з RAM. Це розширення ядра, яке потрібно завантажити через adb.

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
