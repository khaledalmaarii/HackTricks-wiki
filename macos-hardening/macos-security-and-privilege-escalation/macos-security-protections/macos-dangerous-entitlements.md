# macOS Dangerous Entitlements & TCC perms

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

{% hint style="warning" %}
Зверніть увагу, що права, які починаються з **`com.apple`**, недоступні для третіх осіб, лише Apple може їх надати.
{% endhint %}

## High

### `com.apple.rootless.install.heritable`

Права **`com.apple.rootless.install.heritable`** дозволяють **обійти SIP**. Перевірте [це для отримання додаткової інформації](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Права **`com.apple.rootless.install`** дозволяють **обійти SIP**. Перевірте[ це для отримання додаткової інформації](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (раніше називався `task_for_pid-allow`)**

Ці права дозволяють отримати **порт завдання для будь-якого** процесу, за винятком ядра. Перевірте [**це для отримання додаткової інформації**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

Ці права дозволяють іншим процесам з правами **`com.apple.security.cs.debugger`** отримати порт завдання процесу, запущеного бінарним файлом з цими правами, і **впроваджувати код у нього**. Перевірте [**це для отримання додаткової інформації**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Додатки з правами інструменту налагодження можуть викликати `task_for_pid()`, щоб отримати дійсний порт завдання для незахищених і сторонніх додатків з правами `Get Task Allow`, встановленими на `true`. Однак, навіть з правами інструменту налагодження, налагоджувач **не може отримати порти завдання** процесів, які **не мають прав `Get Task Allow`**, і які, отже, захищені захистом цілісності системи. Перевірте [**це для отримання додаткової інформації**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

Ці права дозволяють **завантажувати фрейми, плагіни або бібліотеки без підпису Apple або підпису з тим же ідентифікатором команди**, як основний виконуваний файл, тому зловмисник може зловживати завантаженням довільної бібліотеки для впровадження коду. Перевірте [**це для отримання додаткової інформації**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Ці права дуже схожі на **`com.apple.security.cs.disable-library-validation`**, але **замість** **прямого відключення** перевірки бібліотек, вони дозволяють процесу **викликати системний виклик `csops`, щоб відключити його**.\
Перевірте [**це для отримання додаткової інформації**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Ці права дозволяють **використовувати змінні середовища DYLD**, які можуть бути використані для впровадження бібліотек і коду. Перевірте [**це для отримання додаткової інформації**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` або `com.apple.rootless.storage`.`TCC`

[**Згідно з цим блогу**](https://objective-see.org/blog/blog\_0x4C.html) **і** [**цим блогу**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), ці права дозволяють **модифікувати** базу даних **TCC**.

### **`system.install.apple-software`** та **`system.install.apple-software.standar-user`**

Ці права дозволяють **встановлювати програмне забезпечення без запиту дозволів** у користувача, що може бути корисним для **підвищення привілеїв**.

### `com.apple.private.security.kext-management`

Права, необхідні для запиту **ядра на завантаження розширення ядра**.

### **`com.apple.private.icloud-account-access`**

Права **`com.apple.private.icloud-account-access`** дозволяють спілкуватися з **`com.apple.iCloudHelper`** XPC-сервісом, який **надасть токени iCloud**.

**iMovie** та **Garageband** мали ці права.

Для отримання більшої **інформації** про експлойт для **отримання токенів icloud** з цих прав перевірте доповідь: [**#OBTS v5.0: "Що відбувається на вашому Mac, залишається в iCloud Apple?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Я не знаю, що це дозволяє робити

### `com.apple.private.apfs.revert-to-snapshot`

TODO: У [**цьому звіті**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **зазначено, що це може бути використано для** оновлення вмісту, захищеного SSV, після перезавантаження. Якщо ви знаєте, як це зробити, надішліть PR, будь ласка!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: У [**цьому звіті**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **зазначено, що це може бути використано для** оновлення вмісту, захищеного SSV, після перезавантаження. Якщо ви знаєте, як це зробити, надішліть PR, будь ласка!

### `keychain-access-groups`

Ці права перераховують **групи ключів**, до яких має доступ додаток:
```xml
<key>keychain-access-groups</key>
<array>
<string>ichat</string>
<string>apple</string>
<string>appleaccount</string>
<string>InternetAccounts</string>
<string>IMCore</string>
</array>
```
### **`kTCCServiceSystemPolicyAllFiles`**

Надає **Повний доступ до диска** - один з найвищих дозволів TCC, які ви можете мати.

### **`kTCCServiceAppleEvents`**

Дозволяє додатку надсилати події іншим додаткам, які зазвичай використовуються для **автоматизації завдань**. Контролюючи інші додатки, він може зловживати дозволами, наданими цими іншими додатками.

Наприклад, змушуючи їх запитувати у користувача його пароль:

{% code overflow="wrap" %}
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

Або змушуючи їх виконувати **произвольні дії**.

### **`kTCCServiceEndpointSecurityClient`**

Дозволяє, серед інших дозволів, **записувати базу даних TCC користувачів**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Дозволяє **змінювати** атрибут **`NFSHomeDirectory`** користувача, що змінює шлях до його домашньої папки і, отже, дозволяє **обійти TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Дозволяє модифікувати файли всередині пакету додатків (всередині app.app), що **заборонено за замовчуванням**.

<figure><img src="../../../.gitbook/assets/image (31).png" alt=""><figcaption></figcaption></figure>

Можна перевірити, хто має цей доступ у _Системних налаштуваннях_ > _Конфіденційність та безпека_ > _Управління додатками._

### `kTCCServiceAccessibility`

Процес зможе **зловживати функціями доступності macOS**, що означає, що, наприклад, він зможе натискати клавіші. Тому він може запитати доступ для контролю додатка, такого як Finder, і підтвердити діалог з цим дозволом.

## Середній

### `com.apple.security.cs.allow-jit`

Цей дозвіл дозволяє **створювати пам'ять, яка є записуваною та виконуваною**, передаючи прапорець `MAP_JIT` функції системи `mmap()`. Перевірте [**це для отримання додаткової інформації**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Цей дозвіл дозволяє **перезаписувати або патчити C код**, використовувати давно застарілу **`NSCreateObjectFileImageFromMemory`** (яка є фундаментально небезпечною) або використовувати фреймворк **DVDPlayback**. Перевірте [**це для отримання додаткової інформації**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory).

{% hint style="danger" %}
Включення цього дозволу піддає ваш додаток загальним вразливостям у мовах програмування з небезпечним управлінням пам'яттю. Уважно розгляньте, чи потрібен вашому додатку цей виняток.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

Цей дозвіл дозволяє **модифікувати секції своїх власних виконуваних файлів** на диску, щоб примусово вийти. Перевірте [**це для отримання додаткової інформації**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection).

{% hint style="danger" %}
Дозвіл на відключення захисту виконуваної пам'яті є екстремальним дозволом, який усуває основний захист безпеки з вашого додатку, що робить можливим для зловмисника переписати виконуваний код вашого додатку без виявлення. Вибирайте більш вузькі дозволи, якщо це можливо.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Цей дозвіл дозволяє монтувати файлову систему nullfs (заборонено за замовчуванням). Інструмент: [**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master).

### `kTCCServiceAll`

Згідно з цим блогом, цей дозвіл TCC зазвичай зустрічається у формі:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Дозволити процесу **запитувати всі дозволи TCC**.

### **`kTCCServicePostEvent`**
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
</details>
