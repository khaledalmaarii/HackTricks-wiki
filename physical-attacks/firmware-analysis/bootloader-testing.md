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

Наступні кроки рекомендуються для модифікації конфігурацій запуску пристроїв та завантажувачів, таких як U-boot:

1. **Доступ до інтерпретатора завантажувача**:
- Під час завантаження натисніть "0", пробіл або інші виявлені "магічні коди", щоб отримати доступ до інтерпретатора завантажувача.

2. **Модифікація аргументів завантаження**:
- Виконайте наступні команди, щоб додати '`init=/bin/sh`' до аргументів завантаження, що дозволяє виконання команд оболонки:
%%%
#printenv
#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh
#saveenv
#boot
%%%

3. **Налаштування TFTP сервера**:
- Налаштуйте TFTP сервер для завантаження образів через локальну мережу:
%%%
#setenv ipaddr 192.168.2.2 #локальна IP адреса пристрою
#setenv serverip 192.168.2.1 #IP адреса TFTP сервера
#saveenv
#reset
#ping 192.168.2.1 #перевірка доступу до мережі
#tftp ${loadaddr} uImage-3.6.35 #loadaddr приймає адресу для завантаження файлу та ім'я файлу образу на TFTP сервері
%%%

4. **Використання `ubootwrite.py`**:
- Використовуйте `ubootwrite.py` для запису образу U-boot та завантаження модифікованого прошивки для отримання root доступу.

5. **Перевірка функцій налагодження**:
- Перевірте, чи активовані функції налагодження, такі як детальне ведення журналу, завантаження довільних ядер або завантаження з ненадійних джерел.

6. **Обережність при апаратному втручанні**:
- Будьте обережні при підключенні одного контакту до землі та взаємодії з чіпами SPI або NAND flash під час послідовності завантаження пристрою, особливо перед розпакуванням ядра. Консультуйтеся з технічними характеристиками чіпа NAND flash перед коротким замиканням контактів.

7. **Налаштування підробленого DHCP сервера**:
- Налаштуйте підроблений DHCP сервер з шкідливими параметрами для пристрою, щоб він споживав їх під час PXE завантаження. Використовуйте інструменти, такі як допоміжний сервер DHCP Metasploit (MSF). Змініть параметр 'FILENAME' на команди ін'єкції, такі як `'a";/bin/sh;#'`, щоб перевірити валідацію введення для процедур запуску пристрою.

**Примітка**: Кроки, що передбачають фізичну взаємодію з контактами пристрою (*позначені зірочками), слід виконувати з великою обережністю, щоб уникнути пошкодження пристрою.


## References
* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)


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
