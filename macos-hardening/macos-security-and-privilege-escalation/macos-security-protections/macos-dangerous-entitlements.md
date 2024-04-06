# macOS Dangerous Entitlements & TCC perms

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити вашу **компанію в рекламі на HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв GitHub.

</details>

{% hint style="warning" %}
Зверніть увагу, що entitlements, які починаються з **`com.apple`**, недоступні для сторонніх розробників, лише Apple може надавати їх.
{% endhint %}

## Високий

### `com.apple.rootless.install.heritable`

Entitlement **`com.apple.rootless.install.heritable`** дозволяє **обійти SIP**. Перевірте [це для отримання додаткової інформації](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Entitlement **`com.apple.rootless.install`** дозволяє **обійти SIP**. Перевірте [це для отримання додаткової інформації](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (раніше відомий як `task_for_pid-allow`)**

Цей entitlement дозволяє отримати **порт завдання для будь-якого** процесу, крім ядра. Перевірте [**це для отримання додаткової інформації**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

Цей entitlement дозволяє іншим процесам з entitlement **`com.apple.security.cs.debugger`** отримати порт завдання процесу, який виконується бінарним файлом з цим entitlement та **впровадити код в нього**. Перевірте [**це для отримання додаткової інформації**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Додатки з entitlement Debugging Tool можуть викликати `task_for_pid()` для отримання дійсного порту завдання для непідписаних та сторонніх додатків з entitlement `Get Task Allow`, встановленим на `true`. Однак навіть з entitlement debugging tool, відладчик **не може отримати порти завдання** процесів, які **не мають entitlement `Get Task Allow`**, і які, отже, захищені Системою Інтегритету. Перевірте [**це для отримання додаткової інформації**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

Цей entitlement дозволяє **завантажувати фреймворки, плагіни або бібліотеки без підпису від Apple або підписані тим самим ідентифікатором команди**, тому злоумисник може використовувати деяке довільне завантаження бібліотеки для впровадження коду. Перевірте [**це для отримання додаткової інформації**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Цей entitlement дуже схожий на **`com.apple.security.cs.disable-library-validation`**, але **замість** прямого **вимкнення** перевірки бібліотек, він дозволяє процесу **викликати системний виклик `csops` для його вимкнення**.\
Перевірте [**це для отримання додаткової інформації**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Цей entitlement дозволяє **використовувати змінні середовища DYLD**, які можуть бути використані для впровадження бібліотек та коду. Перевірте [**це для отримання додаткової інформації**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` або `com.apple.rootless.storage`.`TCC`

[**Згідно з цим блогом**](https://objective-see.org/blog/blog\_0x4C.html) **та** [**цим блогом**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), ці entitlements дозволяють **змінювати** базу даних **TCC**.

### **`system.install.apple-software`** та **`system.install.apple-software.standar-user`**

Ці entitlements дозволяють **встановлювати програмне забезпечення без запиту дозволу від користувача**, що може бути корисним для **підвищення привілеїв**.

### `com.apple.private.security.kext-management`

Entitlement, необхідний для запиту ядру **завантажити розширення ядра**.

### **`com.apple.private.icloud-account-access`**

Entitlement **`com.apple.private.icloud-account-access`** дозволяє взаємодіяти з сервісом XPC **`com.apple.iCloudHelper`**, який **надасть токени iCloud**.

**iMovie** та **Garageband** мали цей entitlement.

Для отримання більш **детальної інформації** про експлойт для **отримання токенів iCloud** з цього entitlement, перегляньте виступ: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Я не знаю, що це дозволяє робити

### `com.apple.private.apfs.revert-to-snapshot`

TODO: У [**цьому звіті**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **зазначено, що це можна використовувати для** оновлення захищених вмістів SSV після перезавантаження. Якщо ви знаєте, як це зробити, надішліть PR, будь ласка!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: У [**цьому звіті**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **зазначено, що це можна використовувати для** оновлення захищених вмістів SSV після перезавантаження. Якщо ви знаєте, як це зробити, надішліть PR, будь ласка!

### `keychain-access-groups`

Цей entitlement перелічує **групи ключів**, до яких має доступ додаток:

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

Надає дозвіл на **повний доступ до диска**, один з найвищих дозволів TCC, які ви можете мати.

### **`kTCCServiceAppleEvents`**

Дозволяє додатку надсилати події до інших додатків, які часто використовуються для **автоматизації завдань**. Керуючи іншими додатками, він може зловживати дозволами, наданими цим іншим додаткам.

Наприклад, змушуючи їх запитувати у користувача його пароль:

{% code overflow="wrap" %}
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

Або змушувати їх виконувати **довільні дії**.

### **`kTCCServiceEndpointSecurityClient`**

Дозволяє, серед інших дозволів, **записувати базу даних користувачів TCC**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Дозволяє **змінювати** атрибут **`NFSHomeDirectory`** користувача, що змінює шлях його домашньої теки та, отже, дозволяє **обійти TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Дозволяє змінювати файли всередині пакунків програм (у програмі.app), що **заборонено за замовчуванням**.

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Можливо перевірити, хто має доступ до цього в _System Settings_ > _Privacy & Security_ > _App Management._

### `kTCCServiceAccessibility`

Процес зможе **зловживати функціями доступності macOS**, Що означає, наприклад, що він зможе натискати клавіші. Таким чином, він може запитати доступ до управління програмою, наприклад, Finder, та схвалити діалогове вікно з цим дозволом.

## Середній

### `com.apple.security.cs.allow-jit`

Цей дозвіл дозволяє **створювати пам'ять, яка є записувальною та виконувальною**, передаючи прапорець `MAP_JIT` до функції системи `mmap()`. Перевірте [**це для отримання додаткової інформації**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Цей дозвіл дозволяє **перевизначати або патчити C-код**, використовувати довгостроково застарілу функцію **`NSCreateObjectFileImageFromMemory`** (що фундаментально небезпечно), або використовувати фреймворк **DVDPlayback**. Перевірте [**це для отримання додаткової інформації**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory).

{% hint style="danger" %}
Включення цього дозволу викладає вашу програму на ризик загроз у пам'яті в мовах програмування з кодом, що не гарантує безпеку пам'яті. Ретельно розгляньте, чи вашій програмі потрібне це виключення.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

Цей дозвіл дозволяє **змінювати розділи власних виконуваних файлів** на диску для примусового виходу. Перевірте [**це для отримання додаткової інформації**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection).

{% hint style="danger" %}
Дозвіл на вимкнення захисту виконуваної пам'яті є екстремальним дозволом, який вилучає фундаментальний захист безпеки з вашої програми, зроблюючи можливим перезапис виконуваного коду вашої програми без виявлення. Віддавайте перевагу вузьким дозволам, якщо це можливо.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Цей дозвіл дозволяє монтувати файлову систему nullfs (заборонено за замовчуванням). Інструмент: [**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master).

### `kTCCServiceAll`

Згідно з цією статтею блогу, цей дозвіл зазвичай знаходиться у формі:

```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```

Дозвольте процесу **запитувати всі дозволи TCC**.

### **`kTCCServicePostEvent`**

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити вашу **компанію в рекламі на HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний мерч PEASS & HackTricks**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) **і** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **репозиторіїв на GitHub**.

</details>
