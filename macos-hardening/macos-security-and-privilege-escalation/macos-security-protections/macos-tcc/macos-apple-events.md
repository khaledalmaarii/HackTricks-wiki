# macOS Apple Events

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

**Apple Events**, Apple'ın macOS'undaki uygulamaların birbirleriyle iletişim kurmasını sağlayan bir özelliktir. Bunlar, macOS işletim sisteminin süreçler arası iletişimi yönetmekten sorumlu bir bileşeni olan **Apple Event Manager**'ın bir parçasıdır. Bu sistem, bir uygulamanın başka bir uygulamaya belirli bir işlemi gerçekleştirmesi için, dosya açma, veri alma veya komut yürütme gibi bir mesaj göndermesine olanak tanır.

Mina daemon'ı `/System/Library/CoreServices/appleeventsd` olup, `com.apple.coreservices.appleevents` hizmetini kaydeder.

Olay alabilen her uygulama, Apple Event Mach Port'unu sağlayarak bu daemon ile kontrol edecektir. Ve bir uygulama ona bir olay göndermek istediğinde, uygulama bu portu daemon'dan talep edecektir.

Sandboxed uygulamalar, olay gönderebilmek için `allow appleevent-send` ve `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` gibi ayrıcalıklara ihtiyaç duyar. `com.apple.security.temporary-exception.apple-events` gibi yetkilendirmelerin, olay gönderebilecek kişileri kısıtlayabileceğini unutmayın; bu da `com.apple.private.appleevents` gibi yetkilendirmelere ihtiyaç duyacaktır.

{% hint style="success" %}
It's possible to use the env variable **`AEDebugSends`** in order to log informtion about the message sent:
```bash
AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
```
{% endhint %}

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Ekip Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Ekip Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
