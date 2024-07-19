# macOS Network Services & Protocols

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

## Remote Access Services

Це загальні служби macOS для віддаленого доступу до них.\
Ви можете увімкнути/вимкнути ці служби в `System Settings` --> `Sharing`

* **VNC**, відомий як “Screen Sharing” (tcp:5900)
* **SSH**, називається “Remote Login” (tcp:22)
* **Apple Remote Desktop** (ARD), або “Remote Management” (tcp:3283, tcp:5900)
* **AppleEvent**, відомий як “Remote Apple Event” (tcp:3031)

Перевірте, чи будь-яка з них увімкнена, запустивши:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\*.88|\*.445|\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Pentesting ARD

Apple Remote Desktop (ARD) є покращеною версією [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing), адаптованою для macOS, що пропонує додаткові функції. Помітною вразливістю в ARD є його метод аутентифікації для пароля контролю екрану, який використовує лише перші 8 символів пароля, що робить його вразливим до [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) з використанням інструментів, таких як Hydra або [GoRedShell](https://github.com/ahhh/GoRedShell/), оскільки немає стандартних обмежень швидкості.

Вразливі екземпляри можна ідентифікувати за допомогою скрипта `vnc-info` **nmap**. Сервіси, що підтримують `VNC Authentication (2)`, особливо схильні до атак методом грубої сили через обрізання пароля до 8 символів.

Щоб увімкнути ARD для різних адміністративних завдань, таких як підвищення привілеїв, доступ до GUI або моніторинг користувачів, використовуйте наступну команду:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD надає різноманітні рівні контролю, включаючи спостереження, спільний контроль та повний контроль, з сесіями, які зберігаються навіть після зміни паролів користувачів. Це дозволяє надсилати команди Unix безпосередньо, виконуючи їх від імені адміністратора. Планування завдань та пошук Remote Spotlight є помітними функціями, що полегшують віддалений, маловпливовий пошук чутливих файлів на кількох машинах.

## Bonjour Protocol

Bonjour, технологія, розроблена Apple, дозволяє **пристроям в одній мережі виявляти послуги, які вони пропонують**. Відома також як Rendezvous, **Zero Configuration** або Zeroconf, вона дозволяє пристрою приєднуватися до TCP/IP мережі, **автоматично вибирати IP-адресу** та транслювати свої послуги іншим мережевим пристроям.

Zero Configuration Networking, що надається Bonjour, забезпечує, щоб пристрої могли:
* **Автоматично отримувати IP-адресу** навіть за відсутності DHCP-сервера.
* Виконувати **переклад імен на адреси** без необхідності в DNS-сервері.
* **Виявляти послуги**, доступні в мережі.

Пристрої, що використовують Bonjour, призначать собі **IP-адресу з діапазону 169.254/16** та перевірять її унікальність у мережі. Macs підтримують запис у таблиці маршрутизації для цієї підмережі, що можна перевірити за допомогою `netstat -rn | grep 169`.

Для DNS Bonjour використовує **протокол Multicast DNS (mDNS)**. mDNS працює через **порт 5353/UDP**, використовуючи **стандартні DNS-запити**, але націлюючись на **мультимовну адресу 224.0.0.251**. Цей підхід забезпечує, щоб усі прослуховуючі пристрої в мережі могли отримувати та відповідати на запити, полегшуючи оновлення своїх записів.

При приєднанні до мережі кожен пристрій самостійно вибирає ім'я, яке зазвичай закінчується на **.local**, що може бути похідним від імені хоста або випадково згенерованим.

Виявлення послуг у мережі полегшується за допомогою **DNS Service Discovery (DNS-SD)**. Використовуючи формат DNS SRV записів, DNS-SD використовує **DNS PTR записи** для можливості переліку кількох послуг. Клієнт, що шукає конкретну послугу, запитуватиме PTR запис для `<Service>.<Domain>`, отримуючи у відповідь список PTR записів у форматі `<Instance>.<Service>.<Domain>`, якщо послуга доступна з кількох хостів.

Утиліта `dns-sd` може бути використана для **виявлення та реклами мережевих послуг**. Ось кілька прикладів її використання:

### Searching for SSH Services

Щоб шукати SSH послуги в мережі, використовується наступна команда:
```bash
dns-sd -B _ssh._tcp
```
Ця команда ініціює перегляд для _ssh._tcp сервісів і виводить деталі, такі як мітка часу, прапори, інтерфейс, домен, тип сервісу та ім'я екземпляра.

### Реклама HTTP Сервісу

Щоб рекламувати HTTP сервіс, ви можете використовувати:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Ця команда реєструє HTTP-сервіс з назвою "Index" на порту 80 з шляхом `/index.html`.

Щоб потім шукати HTTP-сервіси в мережі:
```bash
dns-sd -B _http._tcp
```
Коли служба запускається, вона оголошує про свою доступність для всіх пристроїв у підмережі, мультикастуючи свою присутність. Пристрої, зацікавлені в цих службах, не повинні надсилати запити, а просто слухати ці оголошення.

Для більш зручного інтерфейсу додаток **Discovery - DNS-SD Browser**, доступний в Apple App Store, може візуалізувати служби, що пропонуються у вашій локальній мережі.

Альтернативно, можна написати власні скрипти для перегляду та виявлення служб, використовуючи бібліотеку `python-zeroconf`. Скрипт [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) демонструє створення браузера служб для `_http._tcp.local.`, виводячи додані або видалені служби:
```python
from zeroconf import ServiceBrowser, Zeroconf

class MyListener:

def remove_service(self, zeroconf, type, name):
print("Service %s removed" % (name,))

def add_service(self, zeroconf, type, name):
info = zeroconf.get_service_info(type, name)
print("Service %s added, service info: %s" % (name, info))

zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
try:
input("Press enter to exit...\n\n")
finally:
zeroconf.close()
```
### Вимкнення Bonjour
Якщо є занепокоєння щодо безпеки або інші причини для вимкнення Bonjour, його можна вимкнути за допомогою наступної команди:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Посилання

* [**Посібник хакера Mac**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)

{% hint style="success" %}
Вивчайте та практикуйте AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримати HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на github.

</details>
{% endhint %}
