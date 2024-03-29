# Пісочниця macOS

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити **рекламу вашої компанії на HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) **і** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **репозиторіїв на GitHub**.

</details>

## Основна інформація

Пісочниця MacOS (спочатку називалася Seatbelt) **обмежує додатки**, які працюють всередині пісочниці, до **дозволених дій, вказаних у профілі пісочниці**, з якою працює додаток. Це допомагає забезпечити, що **додаток буде отримувати доступ лише до очікуваних ресурсів**.

Будь-який додаток з **привілеєм** **`com.apple.security.app-sandbox`** буде виконуватися всередині пісочниці. **Бінарні файли Apple** зазвичай виконуються всередині пісочниці, і для публікації в **App Store** **цей привілей є обов'язковим**. Таким чином, більшість додатків будуть виконуватися всередині пісочниці.

Для контролю того, що процес може або не може робити, **пісочниця має гачки** в усіх **системних викликах** по всьому ядру. **Залежно** від **привілеємів** додатка пісочниця буде **дозволяти** певні дії.

Деякі важливі компоненти пісочниці:

* Розширення ядра `/System/Library/Extensions/Sandbox.kext`
* Приватний фреймворк `/System/Library/PrivateFrameworks/AppSandbox.framework`
* Демон, що працює в userland `/usr/libexec/sandboxd`
* **Контейнери** `~/Library/Containers`

У папці контейнерів ви можете знайти **папку для кожного додатка, який виконується в пісочниці** з назвою ідентифікатора пакета:
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
У кожній папці з ідентифікатором пакета ви знайдете **plist** та **каталог Data** додатка:
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
Зверніть увагу, що навіть якщо символьні посилання є там для "виходу" з пісочниці та доступу до інших папок, додатку все ще потрібно **мати дозволи** для доступу до них. Ці дозволи знаходяться всередині **`.plist`**.
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
Все створене/змінене за допомогою застосунку у пісочниці отримає атрибут **карантину**. Це запобігне виклику Gatekeeper, якщо пісочниця спробує виконати щось за допомогою **`open`**.
{% endhint %}

### Профілі пісочниці

Профілі пісочниці - це файли конфігурації, які вказують, що буде **дозволено/заборонено** в цій **пісочниці**. Вони використовують **Мову профілю пісочниці (SBPL)**, яка використовує мову програмування [**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\)).

Тут ви можете знайти приклад:
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
Перевірте це [**дослідження**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/), **щоб перевірити більше дій, які можуть бути дозволені або заборонені.**
{% endhint %}

Важливі **системні служби** також працюють у власному **індивідуальному пісочниці**, таких як служба `mdnsresponder`. Ви можете переглянути ці індивідуальні **профілі пісочниці** в:

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**&#x20;
* Інші профілі пісочниці можна перевірити за посиланням [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

Додатки **App Store** використовують **профіль** **`/System/Library/Sandbox/Profiles/application.sb`**. В цьому профілі можна перевірити, які дозволи, такі як **`com.apple.security.network.server`**, дозволяють процесу використовувати мережу.

SIP - це профіль пісочниці, який називається platform\_profile в /System/Library/Sandbox/rootless.conf

### Приклади профілів пісочниці

Для запуску додатка з **конкретним профілем пісочниці** можна використовувати:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{% tabs %}
{% tab title="доторкнутися" %}
{% code title="доторкнутися.sb" %}
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
Зверніть увагу, що **програмне забезпечення, розроблене Apple**, яке працює на **Windows**, **не має додаткових заходів безпеки**, таких як ізоляція додатків.
{% endhint %}

Приклади обхідів:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (їм вдалося записати файли поза пісочницею, ім'я яких починається на `~$`).

### Профілі пісочниці MacOS

macOS зберігає системні профілі пісочниці в двох місцях: **/usr/share/sandbox/** та **/System/Library/Sandbox/Profiles**.

І якщо сторонній додаток має entitlement _**com.apple.security.app-sandbox**_, система застосовує профіль **/System/Library/Sandbox/Profiles/application.sb** до цього процесу.

### **Профіль пісочниці iOS**

Стандартний профіль називається **container**, і у нас немає текстового представлення SBPL. У пам'яті ця пісочниця представлена як дерево бінарних дозволів/заборон для кожного дозволу з пісочниці.

### Налагодження та обхід пісочниці

На macOS, на відміну від iOS, де процеси з початку ізольовані ядром, **процеси повинні самі вибирати пісочницю**. Це означає, що на macOS процес не обмежується пісочницею, поки він активно не вирішить увійти в неї.

Процеси автоматично входять в пісочницю з userland при запуску, якщо вони мають entitlement: `com.apple.security.app-sandbox`. Для докладного пояснення цього процесу перегляньте:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **Перевірка привілеїв PID**

[**Згідно з цим**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), **`sandbox_check`** (це `__mac_syscall`) може перевірити, **чи дозволена операція чи ні** пісочницею в певному PID.

Інструмент [**sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) може перевірити, чи може PID виконати певну дію:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### Користувацький SBPL в додатках App Store

Для компаній можливо зробити так, щоб їх додатки працювали **з користувацькими профілями пісочниці** (замість стандартного). Для цього вони повинні використовувати entitlement **`com.apple.security.temporary-exception.sbpl`**, який повинен бути схвалений Apple.

Можливо перевірити визначення цього entitlement у **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Це **оцінить рядок після цього дозволу** як профіль пісочниці.

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити свою **компанію в рекламі на HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв GitHub.

</details>
