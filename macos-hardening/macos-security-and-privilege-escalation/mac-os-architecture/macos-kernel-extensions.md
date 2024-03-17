# macOS Kernel Uzantıları

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

* **Bir siber güvenlik şirketinde mi çalışıyorsunuz**? **Şirketinizi HackTricks'te görmek ister misiniz**? Ya da **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek ister misiniz**? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonunu
* [**PEASS ve HackTricks'in resmi ürünlerini**](https://peass.creator-spring.com) edinin
* **Discord** [**💬**](https://emojipedia.org/speech-balloon/) **grubuna katılın** veya [**telegram grubuna**](https://t.me/peass) veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live) **takip edin**.
* **Hacking püf noktalarınızı göndererek PR göndererek** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **paylaşın**.

</details>

## Temel Bilgiler

Kernel uzantıları (Kexts), ana işletim sistemine ek işlevsellik sağlayan ve **`.kext`** uzantısına sahip **paketler** olan **doğrudan macOS çekirdek alanına yüklenen** bileşenlerdir.

### Gereksinimler

Bu kadar güçlü olduğundan, bir kernel uzantısını yüklemek **oldukça karmaşıktır**. Bir kernel uzantısının yüklenmesi için karşılanması gereken **gereksinimler** şunlardır:

* Kurtarma moduna **girildiğinde**, kernel **uzantılarının yüklenmesine izin verilmelidir**:

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* Kernel uzantısı, yalnızca **Apple tarafından verilebilen bir çekirdek kodu imzalama sertifikasıyla** imzalanmış olmalıdır. Şirketi ve neden gerekli olduğunu detaylı olarak inceleyecek olan Apple.
* Kernel uzantısı ayrıca **notarized** olmalıdır, Apple tarafından kötü amaçlı yazılım için kontrol edilebilir olacaktır.
* Ardından, **root** kullanıcısı, kernel uzantısını **yükleyebilen** ve paket içindeki dosyaların **root'a ait olması gereken** kişidir.
* Yükleme işlemi sırasında, paketin **korunan bir kök olmayan konumda** hazırlanması gerekir: `/Library/StagedExtensions` (`com.apple.rootless.storage.KernelExtensionManagement` iznini gerektirir).
* Son olarak, yüklemeye çalışıldığında, kullanıcı [**bir onay isteği alacak**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html) ve kabul edilirse, bilgisayarın yüklenmesi için **yeniden başlatılması gerekecektir**.

### Yükleme Süreci

Catalina'da böyleydi: **Doğrulama** sürecinin **userland**'da gerçekleştiğini belirtmek ilginçtir. Ancak, yalnızca **`com.apple.private.security.kext-management`** iznine sahip uygulamalar, uzantının yüklenmesini istemek için çekirdeğe başvurabilir: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli, bir uzantının yüklenmesi için **doğrulama** sürecini **başlatır**
* Bir **Mach servisi** kullanarak **`kextd`** ile iletişim kuracaktır.
2. **`kextd`**, imza gibi birkaç şeyi kontrol edecek
* Uzantının **yüklenip yüklenemeyeceğini kontrol etmek** için **`syspolicyd`** ile iletişim kuracaktır.
3. **`syspolicyd`**, uzantı daha önce yüklenmediyse **kullanıcıya bir onay isteği gönderecektir**.
* **`syspolicyd`**, sonucu **`kextd`'ye** bildirecektir
4. **`kextd`**, sonunda çekirdeğe uzantıyı yüklemesi için **talimat verebilecektir**

Eğer **`kextd`** mevcut değilse, **`kextutil`** aynı kontrolleri yapabilir.

## Referanslar

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

* **Bir siber güvenlik şirketinde mi çalışıyorsunuz**? **Şirketinizi HackTricks'te görmek ister misiniz**? Ya da **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek ister misiniz**? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonunu
* [**PEASS ve HackTricks'in resmi ürünlerini**](https://peass.creator-spring.com) edinin
* **Discord** [**💬**](https://emojipedia.org/speech-balloon/) **grubuna katılın** veya [**telegram grubuna**](https://t.me/peass) veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live) **takip edin**.
* **Hacking püf noktalarınızı göndererek PR göndererek** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **paylaşın**.

</details>
