# Linux Environment Variables

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

## Глобальні змінні

Глобальні змінні **будуть** успадковані **дочірніми процесами**.

Ви можете створити глобальну змінну для вашої поточної сесії, виконавши:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Ця змінна буде доступна у ваших поточних сесіях та їх дочірніх процесах.

Ви можете **видалити** змінну, виконавши:
```bash
unset MYGLOBAL
```
## Локальні змінні

**Локальні змінні** можуть бути **доступні** лише **поточній оболонці/скрипту**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Список поточних змінних
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Загальні змінні

З: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** – дисплей, що використовується **X**. Ця змінна зазвичай встановлюється на **:0.0**, що означає перший дисплей на поточному комп'ютері.
* **EDITOR** – улюблений текстовий редактор користувача.
* **HISTFILESIZE** – максимальна кількість рядків, що містяться в файлі історії.
* **HISTSIZE** – Кількість рядків, доданих до файлу історії, коли користувач закінчує свою сесію.
* **HOME** – ваш домашній каталог.
* **HOSTNAME** – ім'я хоста комп'ютера.
* **LANG** – ваша поточна мова.
* **MAIL** – місце розташування поштового спулу користувача. Зазвичай **/var/spool/mail/USER**.
* **MANPATH** – список каталогів для пошуку сторінок довідки.
* **OSTYPE** – тип операційної системи.
* **PS1** – стандартний запит у bash.
* **PATH** – зберігає шлях до всіх каталогів, які містять бінарні файли, які ви хочете виконати, просто вказавши ім'я файлу, а не відносний або абсолютний шлях.
* **PWD** – поточний робочий каталог.
* **SHELL** – шлях до поточної командної оболонки (наприклад, **/bin/bash**).
* **TERM** – тип поточного терміналу (наприклад, **xterm**).
* **TZ** – ваш часовий пояс.
* **USER** – ваше поточне ім'я користувача.

## Цікаві змінні для хакінгу

### **HISTFILESIZE**

Змініть **значення цієї змінної на 0**, щоб, коли ви **закінчите свою сесію**, **файл історії** (\~/.bash\_history) **був видалений**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Змініть **значення цієї змінної на 0**, щоб, коли ви **закінчите свою сесію**, будь-яка команда була додана до **файлу історії** (\~/.bash\_history).
```bash
export HISTSIZE=0
```
### http\_proxy & https\_proxy

Процеси використовуватимуть **проксі**, оголошений тут, для підключення до Інтернету через **http або https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL\_CERT\_FILE & SSL\_CERT\_DIR

Процеси довірятимуть сертифікатам, вказаним у **цих змінних середовища**.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

Змініть вигляд вашого запиту.

[**Це приклад**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../.gitbook/assets/image (897).png>)

Звичайний користувач:

![](<../.gitbook/assets/image (740).png>)

Одна, дві та три фонові задачі:

![](<../.gitbook/assets/image (145).png>)

Одна фонове завдання, одне зупинене, а остання команда не завершилася правильно:

![](<../.gitbook/assets/image (715).png>)


{% hint style="success" %}
Вчіться та практикуйте AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вчіться та практикуйте GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на github.

</details>
{% endhint %}
