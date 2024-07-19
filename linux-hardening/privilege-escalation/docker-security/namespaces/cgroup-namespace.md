# CGroup Namespace

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

## Basic Information

Cgroup namespace — це функція ядра Linux, яка забезпечує **ізоляцію ієрархій cgroup для процесів, що працюють у межах простору імен**. Cgroups, скорочено від **control groups**, є функцією ядра, яка дозволяє організовувати процеси в ієрархічні групи для управління та забезпечення **обмежень на системні ресурси** такі як ЦП, пам'ять та I/O.

Хоча cgroup namespaces не є окремим типом простору імен, як інші, про які ми говорили раніше (PID, mount, network тощо), вони пов'язані з концепцією ізоляції простору імен. **Cgroup namespaces віртуалізують вид ієрархії cgroup**, так що процеси, що працюють у cgroup namespace, мають інший вигляд ієрархії в порівнянні з процесами, що працюють на хості або в інших просторах імен.

### How it works:

1. Коли створюється новий cgroup namespace, **він починається з вигляду ієрархії cgroup, заснованого на cgroup процесу, що створює**. Це означає, що процеси, що працюють у новому cgroup namespace, будуть бачити лише підмножину всієї ієрархії cgroup, обмежену піддеревом cgroup, коренем якого є cgroup процесу, що створює.
2. Процеси в межах cgroup namespace **бачать свою власну cgroup як корінь ієрархії**. Це означає, що з точки зору процесів всередині простору імен їхня власна cgroup з'являється як корінь, і вони не можуть бачити або отримувати доступ до cgroups поза межами свого власного піддерева.
3. Cgroup namespaces не забезпечують безпосередньої ізоляції ресурсів; **вони лише забезпечують ізоляцію вигляду ієрархії cgroup**. **Контроль ресурсів та ізоляція все ще забезпечуються підсистемами cgroup** (наприклад, cpu, memory тощо).

For more information about CGroups check:

{% content-ref url="../cgroups.md" %}
[cgroups.md](../cgroups.md)
{% endcontent-ref %}

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
При монтуванні нового екземпляра файлової системи `/proc`, якщо ви використовуєте параметр `--mount-proc`, ви забезпечуєте, що новий простір монтування має **точний та ізольований вигляд інформації про процеси, специфічної для цього простору**.

<details>

<summary>Помилка: bash: fork: Не вдається виділити пам'ять</summary>

Коли `unshare` виконується без параметра `-f`, виникає помилка через те, як Linux обробляє нові PID (ідентифікатори процесів) простори. Основні деталі та рішення наведені нижче:

1. **Пояснення проблеми**:
- Ядро Linux дозволяє процесу створювати нові простори за допомогою системного виклику `unshare`. Однак процес, який ініціює створення нового PID простору (який називається "unshare" процесом), не входить до нового простору; лише його дочірні процеси входять.
- Виконання `%unshare -p /bin/bash%` запускає `/bin/bash` в тому ж процесі, що й `unshare`. Відповідно, `/bin/bash` та його дочірні процеси знаходяться в оригінальному PID просторі.
- Перший дочірній процес `/bin/bash` у новому просторі стає PID 1. Коли цей процес завершується, це викликає очищення простору, якщо немає інших процесів, оскільки PID 1 має особливу роль усиновлення сирітських процесів. Ядро Linux тоді вимкне виділення PID у цьому просторі.

2. **Наслідок**:
- Завершення PID 1 у новому просторі призводить до очищення прапора `PIDNS_HASH_ADDING`. Це призводить до того, що функція `alloc_pid` не може виділити новий PID при створенні нового процесу, що викликає помилку "Не вдається виділити пам'ять".

3. **Рішення**:
- Проблему можна вирішити, використовуючи параметр `-f` з `unshare`. Цей параметр змушує `unshare` створити новий процес після створення нового PID простору.
- Виконання `%unshare -fp /bin/bash%` забезпечує, що команда `unshare` сама стає PID 1 у новому просторі. `/bin/bash` та його дочірні процеси тоді безпечно містяться в цьому новому просторі, запобігаючи передчасному завершенню PID 1 та дозволяючи нормальне виділення PID.

Забезпечивши, що `unshare` виконується з прапором `-f`, новий PID простір правильно підтримується, що дозволяє `/bin/bash` та його підпроцесам працювати без виникнення помилки виділення пам'яті.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Перевірте, в якому просторі імен знаходиться ваш процес
```bash
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### Знайти всі простори імен CGroup

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Увійти в простір імен CGroup
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
Також ви можете **увійти в інше просторове ім'я лише якщо ви є root**. І ви **не можете** **увійти** в інше просторове ім'я **без дескриптора**, що вказує на нього (наприклад, `/proc/self/ns/cgroup`).

## References
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

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
