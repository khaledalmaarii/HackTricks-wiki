# macOS Kernel Extensions

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter**'da **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

## Temel Bilgiler

Kernel uzantıları (Kexts), **macOS çekirdek alanına doğrudan yüklenen** ve ana işletim sistemine ek işlevsellik sağlayan **`.kext`** uzantısına sahip **paketlerdir**.

### Gereksinimler

Açıkça, bu kadar güçlü olduğu için **bir kernel uzantısını yüklemek karmaşıktır**. Bir kernel uzantısının yüklenebilmesi için karşılaması gereken **gereksinimler** şunlardır:

* **kurtarma moduna** girerken, kernel **uzantılarının yüklenmesine izin verilmelidir**:

<figure><img src="../../../.gitbook/assets/image (327).png" alt=""><figcaption></figcaption></figure>

* Kernel uzantısı, yalnızca **Apple tarafından verilebilen** bir kernel kod imzalama sertifikası ile **imzalanmış olmalıdır**. Şirketi ve neden gerekli olduğunu detaylı bir şekilde inceleyecek olan kimdir.
* Kernel uzantısı ayrıca **notarize edilmelidir**, Apple bunu kötü amaçlı yazılım için kontrol edebilecektir.
* Ardından, **root** kullanıcısı **kernel uzantısını yükleyebilen** kişidir ve paket içindeki dosyalar **root'a ait olmalıdır**.
* Yükleme sürecinde, paket **korumalı bir kök olmayan konumda** hazırlanmalıdır: `/Library/StagedExtensions` (bu, `com.apple.rootless.storage.KernelExtensionManagement` iznini gerektirir).
* Son olarak, yüklemeye çalışırken, kullanıcı [**bir onay isteği alacaktır**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) ve kabul edilirse, bilgisayar **yeniden başlatılmalıdır**.

### Yükleme süreci

Catalina'da böyleydi: **doğrulama** sürecinin **kullanıcı alanında** gerçekleştiğini belirtmek ilginçtir. Ancak, yalnızca **`com.apple.private.security.kext-management`** iznine sahip uygulamalar **kernel'den bir uzantıyı yüklemesini isteyebilir**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **bir uzantıyı yüklemek için** **doğrulama** sürecini **başlatır**
* **`kextd`** ile **Mach servisi** kullanarak iletişim kuracaktır.
2. **`kextd`** birkaç şeyi kontrol edecektir, örneğin **imzayı**
* Uzantının **yüklenip yüklenemeyeceğini kontrol etmek için** **`syspolicyd`** ile iletişim kuracaktır.
3. **`syspolicyd`**, uzantı daha önce yüklenmemişse **kullanıcıya** **soracaktır**.
* **`syspolicyd`**, sonucu **`kextd`**'ye bildirecektir.
4. **`kextd`** nihayetinde **kernel'e uzantıyı yüklemesini söyleyebilecektir**.

Eğer **`kextd`** mevcut değilse, **`kextutil`** aynı kontrolleri gerçekleştirebilir.

## Referanslar

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter**'da **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
