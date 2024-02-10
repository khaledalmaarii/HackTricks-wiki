# macOS Tehlikeli Yetkiler ve TCC İzinleri

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

{% hint style="warning" %}
**`com.apple`** ile başlayan yetkilendirmelerin yalnızca Apple tarafından verilebildiğini unutmayın.
{% endhint %}

## Yüksek

### `com.apple.rootless.install.heritable`

**`com.apple.rootless.install.heritable`** yetkisi, **SIP'yi atlamaya** izin verir. Daha fazla bilgi için [buraya](macos-sip.md#com.apple.rootless.install.heritable) bakın.

### **`com.apple.rootless.install`**

**`com.apple.rootless.install`** yetkisi, **SIP'yi atlamaya** izin verir. Daha fazla bilgi için [buraya](macos-sip.md#com.apple.rootless.install) bakın.

### **`com.apple.system-task-ports` (önceden `task_for_pid-allow` olarak adlandırılıyordu)**

Bu yetki, çekirdek hariç olmak üzere **herhangi bir** işlem için **görev bağlantısını** almayı sağlar. Daha fazla bilgi için [**buraya**](../mac-os-architecture/macos-ipc-inter-process-communication/) bakın.

### `com.apple.security.get-task-allow`

Bu yetki, **`com.apple.security.cs.debugger`** yetkisine sahip diğer işlemlerin, bu yetkiye sahip olan ikili tarafından çalıştırılan işlemin görev bağlantısını almasına ve **üzerine kod enjekte etmesine** izin verir. Daha fazla bilgi için [**buraya**](../mac-os-architecture/macos-ipc-inter-process-communication/) bakın.

### `com.apple.security.cs.debugger`

Hata Ayıklama Aracı Yetkisi olan uygulamalar, `Get Task Allow` yetkisi `true` olarak ayarlanmış olan imzasız ve üçüncü taraf uygulamalar için geçerli bir görev bağlantısı almak için `task_for_pid()` çağrısı yapabilir. Bununla birlikte, hata ayıklama aracı yetkisi olsa bile, hata ayıklama aracı **`Get Task Allow` yetkisine** sahip olmayan işlemlerin görev bağlantılarını **alabilir**, bu nedenle Sistem Bütünlüğü Koruması tarafından korunan işlemler. Daha fazla bilgi için [**buraya**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger) bakın.

### `com.apple.security.cs.disable-library-validation`

Bu yetki, Apple tarafından imzalanmış veya ana yürütülebilir dosya ile aynı Takım Kimliği ile imzalanmış olmaksızın **çerçeveleri, eklentileri veya kitaplıkları yüklemeye** izin verir, bu nedenle bir saldırgan bazı keyfi kitaplık yüklemelerini kod enjekte etmek için kullanabilir. Daha fazla bilgi için [**buraya**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation) bakın.

### `com.apple.private.security.clear-library-validation`

Bu yetki, **`com.apple.security.cs.disable-library-validation`** ile çok benzerdir, ancak **kitaplık doğrulamasını doğrudan devre dışı bırakmak** yerine, işlemin bunu devre dışı bırakmak için bir `csops` sistem çağrısı yapmasına izin verir. Daha fazla bilgi için [**buraya**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/) bakın.

### `com.apple.security.cs.allow-dyld-environment-variables`

Bu yetki, kitaplıklar ve kod enjekte etmek için kullanılabilecek **DYLD çevre değişkenlerini** kullanmaya izin verir. Daha fazla bilgi için [**buraya**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables) bakın.

### `com.apple.private.tcc.manager` veya `com.apple.rootless.storage`.`TCC`

[**Bu bloga**](https://objective-see.org/blog/blog\_0x4C.html) **ve** [**bu bloga**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/) göre, bu yetkiler **TCC** veritabanını **değiştirmeye** izin verir.

### **`system.install.apple-software`** ve **`system.install.apple-software.standar-user`**

Bu yetkiler, kullanıcının iznini sormadan **yazılım yüklemeye** izin verir, bu da bir **ayrıcalık yükseltmesi** için faydalı olabilir.

### `com.apple.private.security.kext-management`

Çekirdeğin bir çekirdek uzantısını yüklemesini istemek için gereken yetki.

### **`com.apple.private.icloud-account-access`**

**`com.apple.private.icloud-account-access`** yetkisi, **`com.apple.iCloudHelper`** XPC hizmetiyle iletişim kurmayı sağlar ve bu hizmet **iCloud belirteçleri sağlar**.

**iMovie** ve **Garageband** bu yetkiye sahipti.

Bu yetkiye sahip olan uygulamadan **icloud belirteçleri almak** için yapılan saldırı hakkında daha fazla **bilgi** için konuşmaya bakın: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Bunu ne yapmaya izin verdiğini bilmiyorum

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**Bu raporda**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) bu, yeniden başlatmadan sonra SSV korumalı içeriği güncellemek için kullanılabileceği belirtiliyor. Nasıl olduğunu biliyorsanız lütfen bir PR gönderin!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**Bu raporda**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) bu, yeniden başlatmadan sonra SSV korumalı içeriği güncellemek için kullanılabileceği belirtiliyor. Nasıl olduğunu biliyorsanız lütfen bir PR gönderin!

### `keychain-access-groups`

Bu yetki, uygulamanın erişebileceği **anahtarlık** gruplarının listesidir:
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

Bu, sahip olabileceğiniz en yüksek TCC izinlerinden biri olan **Tam Disk Erişimi** izinlerini verir.

### **`kTCCServiceAppleEvents`**

Uygulamanın, genellikle **görevleri otomatikleştirmek** için yaygın olarak kullanılan diğer uygulamalara olaylar göndermesine izin verir. Diğer uygulamaları kontrol ederek, bu diğer uygulamalara verilen izinleri kötüye kullanabilir.

Kullanıcıdan şifresini istemelerini sağlamak gibi:

{% code overflow="wrap" %}
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

Veya onları **keyfi eylemler** gerçekleştirmeye zorlamak.

### **`kTCCServiceEndpointSecurityClient`**

Kullanıcıların TCC veritabanını **yazmasına** izin verir.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Kullanıcının ev klasörü yolunu değiştiren bir kullanıcının **`NFSHomeDirectory`** özniteliğini **değiştirmesine** izin verir ve böylece TCC'yi **atlamasına** olanak tanır.

### **`kTCCServiceSystemPolicyAppBundles`**

Varsayılan olarak **yasaklanmış olan** uygulama paketi içindeki dosyaları değiştirmeye izin verir.

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Bu erişime kimin sahip olduğunu kontrol etmek mümkündür: _Sistem Ayarları_ > _Gizlilik ve Güvenlik_ > _Uygulama Yönetimi_.

### `kTCCServiceAccessibility`

İşlem, macOS erişilebilirlik özelliklerini **kötüye kullanabilir**, bu da örneğin tuş vuruşları yapabilmesi anlamına gelir. Bu izinle Finder gibi bir uygulamayı kontrol etmek için erişim isteyebilir ve bu izinle iletişim kutusunu onaylayabilir.

## Orta

### `com.apple.security.cs.allow-jit`

Bu yetki, `mmap()` sistem işlevine `MAP_JIT` bayrağını geçerek **yazılabilir ve yürütülebilir bellek oluşturmayı** sağlar. Daha fazla bilgi için [**burayı kontrol edin**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Bu yetki, C kodunu **geçersiz kılmak veya yamalamak**, temel olarak güvensiz olan **`NSCreateObjectFileImageFromMemory`**'yi kullanmak (veya **DVDPlayback** çerçevesini kullanmak) için kullanılır. Daha fazla bilgi için [**burayı kontrol edin**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory).

{% hint style="danger" %}
Bu yetkiyi eklemek, uygulamanızı bellek güvenli olmayan kod dillerinde yaygın olarak görülen güvenlik açıklarına karşı savunmasız hale getirir. Uygulamanızın bu istisnayı ihtiyaç duyup duymadığını dikkatlice düşünün.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

Bu yetki, **kendi yürütülebilir dosyalarının** diskteki bölümlerini değiştirmeye izin verir. Daha fazla bilgi için [**burayı kontrol edin**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection).

{% hint style="danger" %}
Devre Dışı Bırakılabilir Sayfa Koruması Yetkisi, uygulamanızdan temel bir güvenlik korumasını kaldıran aşırı bir yetkidir ve bir saldırganın uygulamanızın yürütülebilir kodunu tespit edilmeden yeniden yazabilmesine olanak tanır. Mümkünse daha dar yetkileri tercih edin.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Bu yetki, varsayılan olarak yasaklanmış bir nullfs dosya sistemi bağlamayı sağlar. Araç: [**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master).

### `kTCCServiceAll`

Bu blog yazısına göre, bu TCC izni genellikle şu şekilde bulunur:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
**Tüm TCC izinlerini talep etmek için** işleme izin verin.

### **`kTCCServicePostEvent`**

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* Hacking hilelerinizi [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR göndererek paylaşın.

</details>
