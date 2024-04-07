# macOS Tehlikeli Yetkiler ve TCC izinleri

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na bakın(https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünleri**]'ni alın(https://peass.creator-spring.com)
* [**PEASS Ailesi**]'ni keşfedin(https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**]'in koleksiyonu
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

{% hint style="warning" %}
**`com.apple`** ile başlayan yetkiler üçüncü taraflar için mevcut değildir, yalnızca Apple tarafından verilebilir.
{% endhint %}

## Yüksek

### `com.apple.rootless.install.heritable`

**`com.apple.rootless.install.heritable`** yetkisi **SIP'yi atlamaya** izin verir. Daha fazla bilgi için [buraya bakın](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

**`com.apple.rootless.install`** yetkisi **SIP'yi atlamaya** izin verir. Daha fazla bilgi için [buraya bakın](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports`** (önceki adıyla `task_for_pid-allow`)

Bu yetki, çekirdek hariç **herhangi bir** işlem için **görev bağlantı noktasını almayı** sağlar. Daha fazla bilgi için [buraya bakın](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

Bu yetki, diğer işlemlerin **`com.apple.security.cs.debugger`** yetkisi ile bu yetkiye sahip olan ikili tarafından çalıştırılan işlemin görev bağlantı noktasını almasına ve üzerine kod enjekte etmesine izin verir. Daha fazla bilgi için [buraya bakın](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Hata Ayıklama Aracı Yetkisi olan uygulamalar, `Get Task Allow` yetkisi `true` olarak ayarlanmış olan imzasız ve üçüncü taraf uygulamalar için geçerli bir görev bağlantı noktasını almak için `task_for_pid()` çağrısı yapabilir. Ancak, hata ayıklama aracı yetkisi olsa bile, bir hata ayıklama aracı **`Get Task Allow` yetkisine sahip olmayan** ve dolayısıyla Sistem Bütünlüğü Koruması tarafından korunan işlemlerin görev bağlantı noktalarını alamaz. Daha fazla bilgi için [buraya bakın](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

Bu yetki, Apple tarafından imzalanmış veya ana yürütülebilir dosya ile aynı Takım Kimliği ile imzalanmamış çerçeveleri, eklentileri veya kütüphaneleri **yüklemeye izin verir**, bu nedenle bir saldırgan bazı keyfi kütüphane yüklemelerini kod enjekte etmek için kullanabilir. Daha fazla bilgi için [buraya bakın](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Bu yetki, **kütüphane doğrulamasını doğrudan devre dışı bırakmak yerine**, işlemi **devre dışı bırakmak için bir `csops` sistem çağrısı yapmasına** izin verir.\
Daha fazla bilgi için [buraya bakın](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Bu yetki, kütüphane ve kod enjekte etmek için kullanılabilecek **DYLD çevre değişkenlerini kullanmaya** izin verir. Daha fazla bilgi için [buraya bakın](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` veya `com.apple.rootless.storage`.`TCC`

[**Bu bloga göre**](https://objective-see.org/blog/blog\_0x4C.html) **ve** [**bu bloga göre**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), bu yetkiler **TCC** veritabanını **değiştirmeye izin verir**.

### **`system.install.apple-software`** ve **`system.install.apple-software.standar-user`**

Bu yetkiler, kullanıcıdan izin istemeden **yazılım yüklemeye** izin verir, bu da **bir ayrıcalık yükseltmesi** için faydalı olabilir.

### `com.apple.private.security.kext-management`

Çekirdeğe bir çekirdek uzantısını yüklemesi için gereken yetki.

### **`com.apple.private.icloud-account-access`**

**`com.apple.private.icloud-account-access`** yetkisi, **`com.apple.iCloudHelper`** XPC hizmeti ile iletişim kurmayı ve **iCloud belgelerini sağlamayı** mümkün kılar.

**iMovie** ve **Garageband** bu yetkiye sahipti.

Bu yetkiden **icloud belgelerini almak** için yapılan saldırı hakkında daha fazla **bilgi** için şu konuşmayı inceleyin: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Bu ne yapmaya izin verir bilmiyorum

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**Bu raporda**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **bahsedildiğine göre** bu, yeniden başlatmadan sonra SSV korumalı içerikleri güncellemek için kullanılabilir. Bunu nasıl yapacağınızı biliyorsanız lütfen bir PR gönderin!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**Bu raporda**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **bahsedildiğine göre** bu, yeniden başlatmadan sonra SSV korumalı içerikleri güncellemek için kullanılabilir. Bunu nasıl yapacağınızı biliyorsanız lütfen bir PR gönderin!

### `keychain-access-groups`

Bu yetki, uygulamanın erişim sağladığı **anahtarlık** gruplarını listeler:
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

Tam Disk Erişimi izinlerini verir, sahip olabileceğiniz TCC'nin en yüksek izinlerinden biri.

### **`kTCCServiceAppleEvents`**

Uygulamanın, genellikle **görevleri otomatikleştirmek** için kullanılan diğer uygulamalara olaylar göndermesine izin verir. Diğer uygulamaları kontrol ederek, bu diğer uygulamalara verilen izinleri kötüye kullanabilir.

Kullanıcıdan şifresini istemelerini sağlamak gibi:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

### **`kTCCServiceEndpointSecurityClient`**

Bu, diğer izinler arasında, **kullanıcıların TCC veritabanına yazma** izni verir.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Bu, bir kullanıcının ev klasörü yolunu değiştiren ve dolayısıyla **TCC'yi atlamasına izin veren** bir kullanıcının **`NFSHomeDirectory`** özniteliğini **değiştirmeye** izin verir.

### **`kTCCServiceSystemPolicyAppBundles`**

Varsayılan olarak **yasaklanmış olan** uygulama paketleri içindeki dosyaları değiştirmeye izin verir (uygulama.app içinde).

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

Bu erişime kimin sahip olduğunu kontrol etmek mümkündür: _Sistem Ayarları_ > _Gizlilik ve Güvenlik_ > _Uygulama Yönetimi._

### `kTCCServiceAccessibility`

İşlem, macOS erişilebilirlik özelliklerini **kötüye kullanabilir**, bu da örneğin tuş vuruşları yapabilmesi demektir. Bu nedenle Finder gibi bir uygulamayı kontrol etme erişimini isteyebilir ve bu izinle iletişim kutusunu onaylayabilir.

## Orta

### `com.apple.security.cs.allow-jit`

Bu ayrıcalık, `mmap()` sistem işlevine `MAP_JIT` bayrağını geçirerek **yazılabilir ve yürütülebilir bellek oluşturmayı** sağlar. Daha fazla bilgi için [**buraya bakın**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Bu ayrıcalık, C kodunu **geçersiz kılmaya veya yamamaya**, uzun süredir kullanılmayan **`NSCreateObjectFileImageFromMemory`**'yi (temelde güvensiz olan) kullanmaya veya **DVDPlayback** çerçevesini kullanmaya izin verir. Daha fazla bilgi için [**buraya bakın**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory).

{% hint style="danger" %}
Bu ayrıcalığı eklemek, uygulamanızı bellek güvensiz kod dillerinde yaygın güvenlik açıklarına maruz bırakır. Uygulamanızın bu istisnaya ihtiyaç duyup duymadığını dikkatlice düşünün.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

Bu ayrıcalık, **kendi yürütülebilir dosyalarının bölümlerini** diskte değiştirmeye izin verir. Daha fazla bilgi için [**buraya bakın**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection).

{% hint style="danger" %}
Devre Dışı Bırakılabilir Yürütülebilir Sayfa Koruma Ayrıcalığı, uygulamanızdan temel bir güvenlik korumasını kaldırarak, bir saldırganın uygulamanızın yürütülebilir kodunu algılanmadan yeniden yazmasını mümkün kılar. Mümkünse daha dar ayrıcalıkları tercih edin.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Bu ayrıcalık, bir nullfs dosya sistemi bağlamaya izin verir (varsayılan olarak yasaktır). Araç: [**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master).

### `kTCCServiceAll`

Bu blog yazısına göre, bu TCC izni genellikle şu formda bulunur:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
### **`kTCCServicePostEvent`**

<details>

<summary><strong>Tüm TCC izinlerini istemek için işleme izin verin</strong></summary>

Diğer HackTricks'i destekleme yolları:

* Şirketinizi HackTricks'te reklamını görmek veya HackTricks'i PDF olarak indirmek istiyorsanız [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünleri**](https://peass.creator-spring.com)'ni edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'u takip edin.
* Hacking püf noktalarınızı paylaşarak PR'lar göndererek [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
