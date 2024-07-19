# macOS Sandbox

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

MacOS Sandbox (спочатку називався Seatbelt) **обмежує програми**, що працюють всередині пісочниці, до **дозволених дій, зазначених у профілі пісочниці**, з яким працює програма. Це допомагає забезпечити, що **програма буде отримувати доступ лише до очікуваних ресурсів**.

Будь-яка програма з **правом** **`com.apple.security.app-sandbox`** буде виконуватися всередині пісочниці. **Бінарні файли Apple** зазвичай виконуються всередині пісочниці, і для публікації в **App Store** **це право є обов'язковим**. Тому більшість програм буде виконуватися всередині пісочниці.

Щоб контролювати, що процес може або не може робити, **пісочниця має хуки** у всіх **системних викликах** по всьому ядру. **Залежно** від **прав** програми пісочниця **дозволить** певні дії.

Деякі важливі компоненти пісочниці:

* **Розширення ядра** `/System/Library/Extensions/Sandbox.kext`
* **Приватна бібліотека** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* **Демон**, що працює в користувацькому просторі `/usr/libexec/sandboxd`
* **Контейнери** `~/Library/Containers`

Всередині папки контейнерів ви можете знайти **папку для кожної програми, виконуваної в пісочниці**, з назвою ідентифікатора пакета:
```bash
ls -l ~/Library/Containers
total 0
drwx------@ 4 username  staff  128 May 23 20:20 com.apple.AMPArtworkAgent
drwx------@ 4 username  staff  128 May 23 20:13 com.apple.AMPDeviceDiscoveryAgent
drwx------@ 4 username  staff  128 Mar 24 18:03 com.apple.AVConference.Diagnostic
drwx------@ 4 username  staff  128 Mar 25 14:14 com.apple.Accessibility-Settings.extension
drwx------@ 4 username  staff  128 Mar 25 14:10 com.apple.ActionKit.BundledIntentHandler
[...]
```
Всередині кожної папки з ідентифікатором пакету ви можете знайти **plist** та **каталог даних** програми:
```bash
cd /Users/username/Library/Containers/com.apple.Safari
ls -la
total 104
drwx------@   4 username  staff    128 Mar 24 18:08 .
drwx------  348 username  staff  11136 May 23 20:57 ..
-rw-r--r--    1 username  staff  50214 Mar 24 18:08 .com.apple.containermanagerd.metadata.plist
drwx------   13 username  staff    416 Mar 24 18:05 Data

ls -l Data
total 0
drwxr-xr-x@  8 username  staff   256 Mar 24 18:08 CloudKit
lrwxr-xr-x   1 username  staff    19 Mar 24 18:02 Desktop -> ../../../../Desktop
drwx------   2 username  staff    64 Mar 24 18:02 Documents
lrwxr-xr-x   1 username  staff    21 Mar 24 18:02 Downloads -> ../../../../Downloads
drwx------  35 username  staff  1120 Mar 24 18:08 Library
lrwxr-xr-x   1 username  staff    18 Mar 24 18:02 Movies -> ../../../../Movies
lrwxr-xr-x   1 username  staff    17 Mar 24 18:02 Music -> ../../../../Music
lrwxr-xr-x   1 username  staff    20 Mar 24 18:02 Pictures -> ../../../../Pictures
drwx------   2 username  staff    64 Mar 24 18:02 SystemData
drwx------   2 username  staff    64 Mar 24 18:02 tmp
```
{% hint style="danger" %}
Зверніть увагу, що навіть якщо символічні посилання існують для "втечі" з пісочниці та доступу до інших папок, додаток все ще повинен **мати дозволи** для їх доступу. Ці дозволи знаходяться всередині **`.plist`**.
{% endhint %}
```bash
# Get permissions
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# Binary sandbox profile
<key>SandboxProfileData</key>
<data>
AAAhAboBAAAAAAgAAABZAO4B5AHjBMkEQAUPBSsGPwsgASABHgEgASABHwEf...

# In this file you can find the entitlements:
<key>Entitlements</key>
<dict>
<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
<true/>
<key>com.apple.accounts.appleaccount.fullaccess</key>
<true/>
<key>com.apple.appattest.spi</key>
<true/>
<key>keychain-access-groups</key>
<array>
<string>6N38VWS5BX.ru.keepcoder.Telegram</string>
<string>6N38VWS5BX.ru.keepcoder.TelegramShare</string>
</array>
[...]

# Some parameters
<key>Parameters</key>
<dict>
<key>_HOME</key>
<string>/Users/username</string>
<key>_UID</key>
<string>501</string>
<key>_USER</key>
<string>username</string>
[...]

# The paths it can access
<key>RedirectablePaths</key>
<array>
<string>/Users/username/Downloads</string>
<string>/Users/username/Documents</string>
<string>/Users/username/Library/Calendars</string>
<string>/Users/username/Desktop</string>
<key>RedirectedPaths</key>
<array/>
[...]
```
{% hint style="warning" %}
Все, що створюється/модифікується пісочницею, отримає **атрибут карантину**. Це запобігатиме простору пісочниці, активуючи Gatekeeper, якщо пісочна програма намагатиметься виконати щось за допомогою **`open`**.
{% endhint %}

### Профілі пісочниці

Профілі пісочниці - це конфігураційні файли, які вказують, що буде **дозволено/заборонено** в цій **пісочниці**. Вони використовують **Мову профілів пісочниці (SBPL)**, яка базується на [**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\)) мові програмування.

Ось приклад:
```scheme
(version 1) ; First you get the version

(deny default) ; Then you shuold indicate the default action when no rule applies

(allow network*) ; You can use wildcards and allow everything

(allow file-read* ; You can specify where to apply the rule
(subpath "/Users/username/")
(literal "/tmp/afile")
(regex #"^/private/etc/.*")
)

(allow mach-lookup
(global-name "com.apple.analyticsd")
)
```
{% hint style="success" %}
Перевірте це [**дослідження**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **щоб дізнатися більше про дії, які можуть бути дозволені або заборонені.**
{% endhint %}

Важливі **системні служби** також працюють у своїх власних кастомних **пісочницях**, таких як служба `mdnsresponder`. Ви можете переглянути ці кастомні **профілі пісочниці** у:

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**&#x20;
* Інші профілі пісочниці можна перевірити на [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

Додатки з **App Store** використовують **профіль** **`/System/Library/Sandbox/Profiles/application.sb`**. Ви можете перевірити в цьому профілі, як права, такі як **`com.apple.security.network.server`**, дозволяють процесу використовувати мережу.

SIP - це профіль пісочниці, названий platform\_profile у /System/Library/Sandbox/rootless.conf

### Приклади профілів пісочниці

Щоб запустити додаток з **конкретним профілем пісочниці**, ви можете використовувати:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{% tabs %}
{% tab title="touch" %}
{% code title="touch.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```
{% endcode %}
```bash
# This will fail because default is denied, so it cannot execute touch
sandbox-exec -f touch.sb touch /tmp/hacktricks.txt
# Check logs
log show --style syslog --predicate 'eventMessage contains[c] "sandbox"' --last 30s
[...]
2023-05-26 13:42:44.136082+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) process-exec* /usr/bin/touch
2023-05-26 13:42:44.136100+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /usr/bin/touch
2023-05-26 13:42:44.136321+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
2023-05-26 13:42:52.701382+0200  localhost kernel[0]: (Sandbox) 5 duplicate reports for Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
[...]
```
{% code title="touch2.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
; This will also fail because:
; 2023-05-26 13:44:59.840002+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/bin/touch
; 2023-05-26 13:44:59.840016+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin/touch
; 2023-05-26 13:44:59.840028+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin
; 2023-05-26 13:44:59.840034+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/lib/dyld
; 2023-05-26 13:44:59.840050+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) sysctl-read kern.bootargs
; 2023-05-26 13:44:59.840061+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /
```
{% endcode %}

{% code title="touch3.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/private/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
(allow file-read-data (literal "/"))
; This one will work
```
{% endcode %}
{% endtab %}
{% endtabs %}

{% hint style="info" %}
Зверніть увагу, що **програмне забезпечення**, написане **Apple**, яке працює на **Windows**, **не має додаткових заходів безпеки**, таких як пісочниця для додатків.
{% endhint %}

Приклади обходу:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (вони можуть записувати файли за межами пісочниці, назва яких починається з `~$`).

### Профілі пісочниці MacOS

macOS зберігає профілі системної пісочниці у двох місцях: **/usr/share/sandbox/** та **/System/Library/Sandbox/Profiles**.

І якщо сторонній додаток має право _**com.apple.security.app-sandbox**_, система застосовує профіль **/System/Library/Sandbox/Profiles/application.sb** до цього процесу.

### **Профіль пісочниці iOS**

За замовчуванням профіль називається **container**, і у нас немає текстового представлення SBPL. У пам'яті ця пісочниця представлена як бінарне дерево Allow/Deny для кожного дозволу з пісочниці.

### Налагодження та обход пісочниці

На macOS, на відміну від iOS, де процеси з самого початку ізольовані ядром, **процеси повинні самостійно вибрати пісочницю**. Це означає, що на macOS процес не обмежений пісочницею, поки він активно не вирішить увійти в неї.

Процеси автоматично потрапляють у пісочницю з користувацького простору, коли вони запускаються, якщо у них є право: `com.apple.security.app-sandbox`. Для детального пояснення цього процесу дивіться:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **Перевірка привілеїв PID**

[**Згідно з цим**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), **`sandbox_check`** (це `__mac_syscall`), може перевірити, **чи дозволена операція чи ні** пісочницею для певного PID.

[**Інструмент sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) може перевірити, чи може PID виконати певну дію:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### Custom SBPL in App Store apps

Можливо, що компанії можуть змусити свої додатки працювати **з кастомними профілями пісочниці** (замість за замовчуванням). Вони повинні використовувати право **`com.apple.security.temporary-exception.sbpl`**, яке потрібно авторизувати Apple.

Можна перевірити визначення цього права в **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Це **оцінить рядок після цього права** як профіль Sandbox.

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
