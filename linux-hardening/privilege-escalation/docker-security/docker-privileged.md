# Docker --privileged

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Ви працюєте в **кібербезпеці компанії**? Хочете побачити вашу **компанію рекламовану на HackTricks**? або хочете мати доступ до **останньої версії PEASS або завантажити HackTricks у PDF**? Перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* Отримайте [**офіційний PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Приєднуйтесь до** [**💬**](https://emojipedia.org/speech-balloon/) [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за мною на **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**репозиторію hacktricks**](https://github.com/carlospolop/hacktricks) **та** [**репозиторію hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Як це впливає

Коли ви запускаєте контейнер з привілейованими правами, ви вимикаєте наступні заходи захисту:

### Монтування /dev

У привілейованому контейнері всі **пристрої можна отримати доступ до `/dev/`**. Тому ви можете **вийти** за допомогою **монтування** диска хоста.

{% tabs %}
{% tab title="У стандартному контейнері" %}
```bash
# docker run --rm -it alpine sh
ls /dev
console  fd       mqueue   ptmx     random   stderr   stdout   urandom
core     full     null     pts      shm      stdin    tty      zero
```
{% endtab %}

{% tab title="Усередині привілейованого контейнера" %}
```bash
# docker run --rm --privileged -it alpine sh
ls /dev
cachefiles       mapper           port             shm              tty24            tty44            tty7
console          mem              psaux            stderr           tty25            tty45            tty8
core             mqueue           ptmx             stdin            tty26            tty46            tty9
cpu              nbd0             pts              stdout           tty27            tty47            ttyS0
[...]
```

#### Файлові системи ядра лише для читання

Файлові системи ядра надають механізм для процесу зміни поведінки ядра. Однак, коли мова йде про процеси контейнера, ми хочемо запобігти їм вносити будь-які зміни до ядра. Тому ми монтуємо файлові системи ядра як **тільки для читання** всередині контейнера, забезпечуючи, що процеси контейнера не можуть змінювати ядро.

```bash
# docker run --rm -it alpine sh
mount | grep '(ro'
sysfs on /sys type sysfs (ro,nosuid,nodev,noexec,relatime)
cpuset on /sys/fs/cgroup/cpuset type cgroup (ro,nosuid,nodev,noexec,relatime,cpuset)
cpu on /sys/fs/cgroup/cpu type cgroup (ro,nosuid,nodev,noexec,relatime,cpu)
cpuacct on /sys/fs/cgroup/cpuacct type cgroup (ro,nosuid,nodev,noexec,relatime,cpuacct)
```
{% endtab %}

{% tab title="Усередині привілейованого контейнера" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep '(ro'
```

#### Маскування файлових систем ядра

Файлова система **/proc** є вибірково записуваною, але з метою безпеки певні частини захищені від запису та читання шляхом накладання на них **tmpfs**, що гарантує, що процеси контейнера не зможуть отримати доступ до чутливих областей.

{% hint style="info" %}
**tmpfs** - це файлова система, яка зберігає всі файли у віртуальній пам'яті. tmpfs не створює жодних файлів на вашому жорсткому диску. Тому якщо відмонтувати файлову систему tmpfs, всі файли, які в ній знаходяться, будуть втрачені назавжди.
{% endhint %}

{% tabs %}
{% tab title="У стандартному контейнері" %}
```bash
# docker run --rm -it alpine sh
mount  | grep /proc.*tmpfs
tmpfs on /proc/acpi type tmpfs (ro,relatime)
tmpfs on /proc/kcore type tmpfs (rw,nosuid,size=65536k,mode=755)
tmpfs on /proc/keys type tmpfs (rw,nosuid,size=65536k,mode=755)
```
{% endtab %}

{% tab title="Усередині привілейованого контейнера" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep /proc.*tmpfs
```
{% endtab %}
{% endtabs %}

#### Linux можливості

Двигуни контейнерів запускають контейнери з **обмеженою кількістю можливостей**, щоб контролювати те, що відбувається всередині контейнера за замовчуванням. **Привілейовані** мають **всі** **можливості** доступні. Щоб дізнатися більше про можливості, прочитайте:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

```bash
# docker run --rm -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
[...]
```
{% endtab %}

{% tab title="Усередині привілейованого контейнера" %}
```bash
# docker run --rm --privileged -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: =eip cap_perfmon,cap_bpf,cap_checkpoint_restore-eip
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
[...]
```
{% endtab %}
{% endtabs %}

Ви можете маніпулювати можливостями, доступними для контейнера, не запускаючи його в режимі `--privileged`, використовуючи прапорці `--cap-add` та `--cap-drop`.

### Seccomp

**Seccomp** корисний для обмеження **системних викликів (syscalls)**, які може викликати контейнер. За замовчуванням профіль seccomp увімкнено при запуску контейнерів Docker, але в привілейованому режимі він вимкнений. Дізнайтеся більше про Seccomp тут:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

```bash
# docker run --rm -it alpine sh
grep Seccomp /proc/1/status
Seccomp:	2
Seccomp_filters:	1
```

```bash
# docker run --rm --privileged -it alpine sh
grep Seccomp /proc/1/status
Seccomp:	0
Seccomp_filters:	0
```

```bash
# You can manually disable seccomp in docker with
--security-opt seccomp=unconfined
```

Також слід зауважити, що коли Docker (або інші CRIs) використовуються в кластері Kubernetes, фільтр **seccomp вимкнений за замовчуванням**

### AppArmor

**AppArmor** - це покращення ядра для обмеження **контейнерів** до **обмеженого** набору **ресурсів** з **профілями для кожної програми**. Коли ви запускаєте з прапорцем `--privileged`, цей захист вимкнений.

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

```bash
# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined
```

### SELinux

Запуск контейнера з флагом `--privileged` вимикає **мітки SELinux**, що призводить до успадкування мітки контейнерним двигуном, зазвичай `unconfined`, надаючи повний доступ, схожий на контейнерний двигун. У режимі без кореня використовується `container_runtime_t`, тоді як у режимі кореня застосовується `spc_t`.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

```bash
# You can manually disable selinux in docker with
--security-opt label:disable
```

## Чого Не Впливає

### Простори Імен

Простори імен **НЕ піддаються впливу** прапорця `--privileged`. Навіть якщо вони не мають увімкнених обмежень безпеки, **вони не бачать всі процеси на системі або мережу хоста, наприклад**. Користувачі можуть вимкнути окремі простори імен, використовуючи прапорці двигуна контейнера **`--pid=host`, `--net=host`, `--ipc=host`, `--uts=host`**.

{% tabs %}
{% tab title="Усередині типового привілейованого контейнера" %}
```bash
# docker run --rm --privileged -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
1 root      0:00 sh
18 root      0:00 ps -ef
```
{% endtab %}

{% tab title="Усередині --pid=host Контейнера" %}
```bash
# docker run --rm --privileged --pid=host -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
1 root      0:03 /sbin/init
2 root      0:00 [kthreadd]
3 root      0:00 [rcu_gp]ount | grep /proc.*tmpfs
[...]
```
{% endtab %}
{% endtabs %}

### Простір користувача

**За замовчуванням, контейнерні двигуни не використовують простори користувачів, за винятком безкореневих контейнерів**, які потребують їх для монтування файлової системи та використання кількох UID. Простори користувачів, які є невід'ємними для безкореневих контейнерів, не можуть бути вимкнені і значно підвищують безпеку, обмежуючи привілеї.

## Посилання

* [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Ви працюєте в **кібербезпеці**? Хочете побачити вашу **компанію в рекламі на HackTricks**? або хочете мати доступ до **останньої версії PEASS або завантажити HackTricks у PDF**? Перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Дізнайтеся про [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* **Приєднуйтесь до** [**💬**](https://emojipedia.org/speech-balloon/) [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за мною на **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**репозиторію hacktricks**](https://github.com/carlospolop/hacktricks) **та** [**репозиторію hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
