# macOS XPC Connecting Process Check

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

## XPC Connecting Process Check

Коли встановлюється з'єднання з XPC-сервісом, сервер перевіряє, чи дозволено це з'єднання. Це перевірки, які зазвичай виконуються:

1. Перевірте, чи підписаний **процес, що підключається, сертифікатом, підписаним Apple** (видається лише Apple).
* Якщо це **не перевірено**, зловмисник може створити **підроблений сертифікат**, щоб відповідати будь-якій іншій перевірці.
2. Перевірте, чи підписаний процес, що підключається, **сертифікатом організації** (перевірка ID команди).
* Якщо це **не перевірено**, **будь-який сертифікат розробника** від Apple може бути використаний для підпису та підключення до сервісу.
3. Перевірте, чи **містить процес, що підключається, правильний ідентифікатор пакета**.
* Якщо це **не перевірено**, будь-який інструмент, **підписаний тією ж організацією**, може бути використаний для взаємодії з XPC-сервісом.
4. (4 або 5) Перевірте, чи має процес, що підключається, **правильний номер версії програмного забезпечення**.
* Якщо це **не перевірено**, старі, ненадійні клієнти, вразливі до ін'єкцій процесів, можуть бути використані для підключення до XPC-сервісу, навіть якщо інші перевірки виконані.
5. (4 або 5) Перевірте, чи має процес, що підключається, **захищений час виконання без небезпечних прав** (як ті, що дозволяють завантажувати довільні бібліотеки або використовувати змінні середовища DYLD).
1. Якщо це **не перевірено**, клієнт може бути **вразливим до ін'єкцій коду**.
6. Перевірте, чи має процес, що підключається, **право**, яке дозволяє йому підключатися до сервісу. Це стосується бінарних файлів Apple.
7. **Перевірка** повинна бути **базована** на **аудиторному токені клієнта**, **а не** на його ідентифікаторі процесу (**PID**), оскільки перше запобігає **атакам повторного використання PID**.
* Розробники **рідко використовують API виклик аудиторного токена**, оскільки він **приватний**, тому Apple може **змінити** його в будь-який момент. Крім того, використання приватних API не дозволено в додатках Mac App Store.
* Якщо використовується метод **`processIdentifier`**, він може бути вразливим.
* **`xpc_dictionary_get_audit_token`** слід використовувати замість **`xpc_connection_get_audit_token`**, оскільки останній також може бути [вразливим у певних ситуаціях](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).

### Communication Attacks

Для отримання додаткової інформації про атаку повторного використання PID перевірте:

{% content-ref url="macos-pid-reuse.md" %}
[macos-pid-reuse.md](macos-pid-reuse.md)
{% endcontent-ref %}

Для отримання додаткової інформації про атаку **`xpc_connection_get_audit_token`** перевірте:

{% content-ref url="macos-xpc_connection_get_audit_token-attack.md" %}
[macos-xpc\_connection\_get\_audit\_token-attack.md](macos-xpc\_connection\_get\_audit\_token-attack.md)
{% endcontent-ref %}

### Trustcache - Downgrade Attacks Prevention

Trustcache - це захисний метод, введений в машинах Apple Silicon, який зберігає базу даних CDHSAH бінарних файлів Apple, щоб лише дозволені, не модифіковані бінарні файли могли виконуватися. Це запобігає виконанню версій зниженого рівня.

### Code Examples

Сервер реалізує цю **перевірку** в функції, яка називається **`shouldAcceptNewConnection`**.

{% code overflow="wrap" %}
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
{% endcode %}

Об'єкт NSXPCConnection має **приватну** властивість **`auditToken`** (ту, що повинна використовуватися, але може змінитися) та **публічну** властивість **`processIdentifier`** (ту, що не повинна використовуватися).

Процес, що підключається, можна перевірити за допомогою чогось на зразок:

{% code overflow="wrap" %}
```objectivec
[...]
SecRequirementRef requirementRef = NULL;
NSString requirementString = @"anchor apple generic and identifier \"xyz.hacktricks.service\" and certificate leaf [subject.CN] = \"TEAMID\" and info [CFBundleShortVersionString] >= \"1.0\"";
/* Check:
- Signed by a cert signed by Apple
- Check the bundle ID
- Check the TEAMID of the signing cert
- Check the version used
*/

// Check the requirements with the PID (vulnerable)
SecRequirementCreateWithString(requirementString, kSecCSDefaultFlags, &requirementRef);
SecCodeCheckValidity(code, kSecCSDefaultFlags, requirementRef);

// Check the requirements wuing the auditToken (secure)
SecTaskRef taskRef = SecTaskCreateWithAuditToken(NULL, ((ExtendedNSXPCConnection*)newConnection).auditToken);
SecTaskValidateForRequirement(taskRef, (__bridge CFStringRef)(requirementString))
```
{% endcode %}

Якщо розробник не хоче перевіряти версію клієнта, він може принаймні перевірити, що клієнт не вразливий до ін'єкції процесів:

{% code overflow="wrap" %}
```objectivec
[...]
CFDictionaryRef csInfo = NULL;
SecCodeCopySigningInformation(code, kSecCSDynamicInformation, &csInfo);
uint32_t csFlags = [((__bridge NSDictionary *)csInfo)[(__bridge NSString *)kSecCodeInfoStatus] intValue];
const uint32_t cs_hard = 0x100;        // don't load invalid page.
const uint32_t cs_kill = 0x200;        // Kill process if page is invalid
const uint32_t cs_restrict = 0x800;    // Prevent debugging
const uint32_t cs_require_lv = 0x2000; // Library Validation
const uint32_t cs_runtime = 0x10000;   // hardened runtime
if ((csFlags & (cs_hard | cs_require_lv)) {
return Yes; // Accept connection
}
```
{% endcode %}

{% hint style="success" %}
Вивчайте та практикуйте AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на github.

</details>
{% endhint %}
