# macOS Kernel Uzantıları

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

* **Bir ** **cybersecurity şirketinde mi çalışıyorsunuz? **Şirketinizi **HackTricks'te** görmek ister misiniz? **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek ister misiniz?** [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**The PEASS Ailesi**](https://opensea.io/collection/the-peass-family) 'ni keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonu
* [**PEASS ve HackTricks'in resmi ürünlerini**](https://peass.creator-spring.com) edinin
* **Discord** [**💬**](https://emojipedia.org/speech-balloon/) **grubuna katılın** veya [**telegram grubuna**](https://t.me/peass) veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live) 'u takip edin.
* **Hacking püf noktalarınızı göndererek PR göndererek** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **paylaşın**.

</details>

## Temel Bilgiler

Kernel uzantıları (Kexts), ana işletim sistemine ek işlevsellik sağlayan **`.kext`** uzantılı **paketler** olan ve **doğrudan macOS çekirdek alanına yüklenen** bileşenlerdir.

### Gereksinimler

Bu kadar güçlü olduğundan açıkça **bir çekirdek uzantısını yüklemek karmaşıktır**. Bir çekirdek uzantısının yüklenmesi gereken **gereksinimler** şunlardır:

* **Kurtarma moduna girildiğinde**, çekirdek **uzantıların yüklenmesine izin verilmelidir**:
  
<figure><img src="../../../.gitbook/assets/image (327).png" alt=""><figcaption></figcaption></figure>

* Çekirdek uzantısı, yalnızca **Apple** tarafından **verilebilen bir çekirdek kodu imzalama sertifikası ile imzalanmış olmalıdır**. Şirketi ve neden gerekli olduğunu detaylı olarak inceleyecek olan Apple.
* Çekirdek uzantısı ayrıca **notarized** olmalıdır, Apple tarafından kötü amaçlı yazılım açısından kontrol edilebilir.
* Ardından, **root** kullanıcısı, çekirdek uzantısını **yükleyebilen** ve paket içindeki dosyaların **root'a ait olması gereken** kişidir.
* Yükleme işlemi sırasında, paketin **korunan bir kök olmayan konumda hazırlanmış olması gerekir**: `/Library/StagedExtensions` (`com.apple.rootless.storage.KernelExtensionManagement` iznini gerektirir).
* Son olarak, yüklemeye çalışıldığında, kullanıcı [**bir onay isteği alacaktır**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html) ve kabul edilirse, bilgisayarın yüklenmesi için **yeniden başlatılması gerekir**.

### Yükleme işlemi

Catalina'da böyleydi: **Doğrulama** işlemi **userland** 'da gerçekleşir. Ancak, yalnızca **`com.apple.private.security.kext-management`** iznine sahip uygulamalar, çekirdeğe bir uzantı yüklemesini **istemek** için **çekirdeğe başvurabilir**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli, bir uzantının yüklenmesi için **doğrulama** işlemini **başlatır**
* Bir **Mach hizmeti** kullanarak **`kextd`** ile iletişim kuracaktır.
2. **`kextd`**, **imza** gibi birçok şeyi kontrol edecektir.
* **`syspolicyd`** ile iletişim kurarak uzantının **yüklenip yüklenemeyeceğini kontrol edecektir**.
3. **`syspolicyd`**, uzantının daha önce yüklenmediyse **kullanıcıya bir onay isteği gönderecektir**.
* **`syspolicyd`**, sonucu **`kextd`** 'ye bildirecektir**
4. **`kextd`**, sonunda çekirdeğe uzantıyı yüklemesini **söyleyebilecektir**

**`kextd`** mevcut değilse, **`kextutil`** aynı kontrolleri yapabilir.

## Referanslar

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

* **Bir ** **cybersecurity şirketinde mi çalışıyorsunuz? **Şirketinizi **HackTricks'te** görmek ister misiniz? **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek ister misiniz?** [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**The PEASS Ailesi**](https://opensea.io/collection/the-peass-family) 'ni keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonu
* [**PEASS ve HackTricks'in resmi ürünlerini**](https://peass.creator-spring.com) edinin
* **Discord** [**💬**](https://emojipedia.org/speech-balloon/) **grubuna katılın** veya [**telegram grubuna**](https://t.me/peass) veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live) 'u takip edin.
* **Hacking püf noktalarınızı göndererek PR göndererek** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **paylaşın**.

</details>
