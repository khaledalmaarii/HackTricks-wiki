# macOS Tehlikeli Yetkiler & TCC izinleri

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Ekip Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Ekip Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

{% hint style="warning" %}
**`com.apple`** ile başlayan yetkilerin üçüncü taraflara sunulmadığını, yalnızca Apple'ın bunları verebileceğini unutmayın.
{% endhint %}

## Yüksek

### `com.apple.rootless.install.heritable`

Yetki **`com.apple.rootless.install.heritable`**, **SIP'yi atlamaya** izin verir. Daha fazla bilgi için [bunu kontrol edin](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Yetki **`com.apple.rootless.install`**, **SIP'yi atlamaya** izin verir. Daha fazla bilgi için [bunu kontrol edin](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (önceden `task_for_pid-allow` olarak adlandırılıyordu)**

Bu yetki, **çekirdek hariç** herhangi bir süreç için **görev portunu** almayı sağlar. Daha fazla bilgi için [**bunu kontrol edin**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

Bu yetki, **`com.apple.security.cs.debugger`** yetkisine sahip diğer süreçlerin, bu yetkiye sahip ikili tarafından çalıştırılan sürecin görev portunu almasına ve **kod enjekte etmesine** izin verir. Daha fazla bilgi için [**bunu kontrol edin**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Debugging Tool Yetkisine sahip uygulamalar, `Get Task Allow` yetkisi `true` olarak ayarlanmış imzasız ve üçüncü taraf uygulamalar için geçerli bir görev portu almak üzere `task_for_pid()` çağrısı yapabilir. Ancak, debugging tool yetkisi ile bile, bir debugger **`Get Task Allow` yetkisine sahip olmayan** süreçlerin görev portlarını **alamaz** ve bu nedenle Sistem Bütünlüğü Koruması tarafından korunur. Daha fazla bilgi için [**bunu kontrol edin**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

Bu yetki, **Apple tarafından imzalanmamış veya ana yürütücü ile aynı Takım Kimliği ile imzalanmamış** çerçeveleri, eklentileri veya kütüphaneleri **yüklemeye** izin verir, bu nedenle bir saldırgan bazı keyfi kütüphane yüklemelerini kötüye kullanarak kod enjekte edebilir. Daha fazla bilgi için [**bunu kontrol edin**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Bu yetki, **`com.apple.security.cs.disable-library-validation`** ile çok benzer, ancak **doğrudan** kütüphane doğrulamasını **devre dışı bırakmak yerine**, sürecin **bunu devre dışı bırakmak için bir `csops` sistem çağrısı yapmasına** izin verir.\
Daha fazla bilgi için [**bunu kontrol edin**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Bu yetki, **kütüphaneleri ve kodu enjekte etmek için kullanılabilecek DYLD ortam değişkenlerini** kullanmaya izin verir. Daha fazla bilgi için [**bunu kontrol edin**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` veya `com.apple.rootless.storage`.`TCC`

[**Bu bloga göre**](https://objective-see.org/blog/blog\_0x4C.html) **ve** [**bu bloga göre**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), bu yetkiler **TCC** veritabanını **değiştirmeye** izin verir.

### **`system.install.apple-software`** ve **`system.install.apple-software.standar-user`**

Bu yetkiler, kullanıcıdan izin istemeden **yazılım yüklemeye** izin verir, bu da **yetki yükseltme** için faydalı olabilir.

### `com.apple.private.security.kext-management`

Bir **çekirdek uzantısını** yüklemek için çekirdekten talepte bulunmak için gereken yetki.

### **`com.apple.private.icloud-account-access`**

Yetki **`com.apple.private.icloud-account-access`**, **`com.apple.iCloudHelper`** XPC servisi ile iletişim kurmayı sağlar ve bu da **iCloud token'ları** sağlar.

**iMovie** ve **Garageband** bu yetkiye sahipti.

Bu yetkiden **icloud token'ları** almak için istismar hakkında daha fazla bilgi için konuşmayı kontrol edin: [**#OBTS v5.0: "Mac'inizde Olan, Apple'ın iCloud'unda Kalır?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Bunun neye izin verdiğini bilmiyorum

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**bu raporda**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **bu, bir yeniden başlatmadan sonra SSV korumalı içerikleri güncellemek için kullanılabileceği** belirtiliyor. Bunu nasıl yaptığını biliyorsanız bir PR gönderin lütfen!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**bu raporda**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **bu, bir yeniden başlatmadan sonra SSV korumalı içerikleri güncellemek için kullanılabileceği** belirtiliyor. Bunu nasıl yaptığını biliyorsanız bir PR gönderin lütfen!

### `keychain-access-groups`

Bu yetki, uygulamanın erişim sağladığı **anahtar zinciri** gruplarını listeler:
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

**Tam Disk Erişimi** izinleri verir, sahip olabileceğiniz TCC'nin en yüksek izinlerinden biridir.

### **`kTCCServiceAppleEvents`**

Uygulamanın, genellikle **görevleri otomatikleştirmek** için kullanılan diğer uygulamalara olaylar göndermesine izin verir. Diğer uygulamaları kontrol ederek, bu diğer uygulamalara verilen izinleri kötüye kullanabilir.

Kullanıcıdan şifresini istemelerini sağlamak gibi: 

{% code overflow="wrap" %}
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

Ya da **keyfi eylemler** gerçekleştirmelerine izin verir.

### **`kTCCServiceEndpointSecurityClient`**

Kullanıcıların TCC veritabanını **yazmalarına** izin verir.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Kullanıcının ana dizin yolunu değiştiren **`NFSHomeDirectory`** niteliğini **değiştirmeye** izin verir ve böylece **TCC'yi atlatmaya** olanak tanır.

### **`kTCCServiceSystemPolicyAppBundles`**

Uygulama paketinin içindeki dosyaları değiştirmeye izin verir (app.app içinde), bu varsayılan olarak **yasaktır**.

<figure><img src="../../../.gitbook/assets/image (31).png" alt=""><figcaption></figcaption></figure>

Bu erişime sahip olanları kontrol etmek mümkündür _Sistem Ayarları_ > _Gizlilik ve Güvenlik_ > _Uygulama Yönetimi_.

### `kTCCServiceAccessibility`

Süreç, **macOS erişilebilirlik özelliklerini** **istismar edebilecektir**, bu da örneğin tuş vuruşlarını basabilmesi anlamına gelir. Bu nedenle, Finder gibi bir uygulamayı kontrol etmek için erişim talep edebilir ve bu izinle onaylayabilir.

## Orta

### `com.apple.security.cs.allow-jit`

Bu yetki, `mmap()` sistem fonksiyonuna `MAP_JIT` bayrağını geçirerek **yazılabilir ve çalıştırılabilir bellek oluşturulmasına** izin verir. Daha fazla bilgi için [**bunu kontrol edin**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Bu yetki, **C kodunu geçersiz kılmaya veya yamanmaya** izin verir, uzun süredir kullanılmayan **`NSCreateObjectFileImageFromMemory`** (temelde güvensizdir) veya **DVDPlayback** çerçevesini kullanabilir. Daha fazla bilgi için [**bunu kontrol edin**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory).

{% hint style="danger" %}
Bu yetkiyi dahil etmek, uygulamanızı bellek-güvensiz kod dillerindeki yaygın güvenlik açıklarına maruz bırakır. Uygulamanızın bu istisnaya ihtiyacı olup olmadığını dikkatlice değerlendirin.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

Bu yetki, disk üzerindeki kendi çalıştırılabilir dosyalarının bölümlerini **değiştirmeye** izin verir. Daha fazla bilgi için [**bunu kontrol edin**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection).

{% hint style="danger" %}
Çalıştırılabilir Bellek Koruma Yetkisini Devre Dışı Bırakmak, uygulamanızdan temel bir güvenlik korumasını kaldıran aşırı bir yetkidir ve bir saldırganın uygulamanızın çalıştırılabilir kodunu tespit edilmeden yeniden yazmasını mümkün kılar. Mümkünse daha dar yetkileri tercih edin.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Bu yetki, bir nullfs dosya sistemini (varsayılan olarak yasak) bağlamaya izin verir. Araç: [**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master).

### `kTCCServiceAll`

Bu blog yazısına göre, bu TCC izni genellikle şu şekilde bulunur:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Allow the process to **tüm TCC izinlerini istemesine** izin verin.

### **`kTCCServicePostEvent`**
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
</details>
