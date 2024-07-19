# macOS Kernel Extensions

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

Kernel extensions (Kexts) are **пакети** з розширенням **`.kext`**, які **завантажуються безпосередньо в простір ядра macOS**, надаючи додаткову функціональність основній операційній системі.

### Requirements

Очевидно, що це настільки потужно, що **завантажити розширення ядра** є **складним**. Це **вимоги**, які повинно виконувати розширення ядра, щоб бути завантаженим:

* Коли **входите в режим відновлення**, розширення ядра **повинні бути дозволені** для завантаження:

<figure><img src="../../../.gitbook/assets/image (327).png" alt=""><figcaption></figcaption></figure>

* Розширення ядра повинно бути **підписане сертифікатом підпису коду ядра**, який може бути **наданий тільки Apple**. Хто детально розгляне компанію та причини, чому це потрібно.
* Розширення ядра також повинно бути **нотаризоване**, Apple зможе перевірити його на наявність шкідливого ПЗ.
* Потім, **кореневий** користувач є тим, хто може **завантажити розширення ядра**, а файли всередині пакету повинні **належати кореню**.
* Під час процесу завантаження пакет повинен бути підготовлений у **захищеному місці, що не є кореневим**: `/Library/StagedExtensions` (вимагає надання `com.apple.rootless.storage.KernelExtensionManagement`).
* Нарешті, при спробі завантажити його, користувач [**отримає запит на підтвердження**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) і, якщо прийнято, комп'ютер повинен бути **перезавантажений** для його завантаження.

### Loading process

У Catalina це виглядало так: Цікаво відзначити, що процес **перевірки** відбувається в **користувацькому просторі**. Однак тільки програми з наданням **`com.apple.private.security.kext-management`** можуть **запитувати у ядра завантажити розширення**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **починає** процес **перевірки** для завантаження розширення
* Він спілкуватиметься з **`kextd`**, використовуючи **Mach service**.
2. **`kextd`** перевірить кілька речей, таких як **підпис**
* Він спілкуватиметься з **`syspolicyd`**, щоб **перевірити**, чи може розширення бути **завантаженим**.
3. **`syspolicyd`** **запитає** **користувача**, якщо розширення не було завантажено раніше.
* **`syspolicyd`** повідомить результат **`kextd`**
4. **`kextd`** нарешті зможе **сказати ядру завантажити** розширення

Якщо **`kextd`** недоступний, **`kextutil`** може виконати ті ж перевірки.

## Referencias

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

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
