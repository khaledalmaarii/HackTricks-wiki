# Android Forensics

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити **рекламу вашої компанії на HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Дізнайтеся про [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв.

</details>

## Заблокований пристрій

Для початку видобутку даних з Android-пристрою його потрібно розблокувати. Якщо він заблокований, ви можете:

* Перевірити, чи активовано на пристрої налагодження через USB.
* Перевірити можливість [атаки на відбитки пальців](https://www.usenix.org/legacy/event/woot10/tech/full\_papers/Aviv.pdf)
* Спробувати з [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

## Отримання даних

Створіть [резервну копію Android за допомогою adb](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) та видобудьте її за допомогою [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/): `java -jar abe.jar unpack file.backup file.tar`

### Якщо є root-доступ або фізичне підключення до інтерфейсу JTAG

* `cat /proc/partitions` (шукайте шлях до флеш-пам'яті, зазвичай першим записом є _mmcblk0_ і відповідає цілій флеш-пам'яті).
* `df /data` (Дізнайтеся розмір блоку системи).
* dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (виконайте його з інформацією, зібраною з розміру блоку).

### Пам'ять

Використовуйте Linux Memory Extractor (LiME), щоб видобути інформацію про ОЗП. Це розширення ядра, яке повинно бути завантажене через adb.
