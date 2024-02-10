# macOS Çekirdek Uzantıları

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hacklemeyi öğrenin<strong>!</strong></summary>

* **Bir siber güvenlik şirketinde çalışıyor musunuz**? **Şirketinizi HackTricks'te duyurmak** ister misiniz? **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzdaki [**NFT'leri**](https://opensea.io/collection/the-peass-family) keşfedin.
* [**PEASS ve HackTricks'in resmi ürünlerini**](https://peass.creator-spring.com) edinin.
* **Discord** [**💬**](https://emojipedia.org/speech-balloon/) **grubuna katılın** veya [**telegram grubuna**](https://t.me/peass) veya **Twitter'da** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live) **beni takip edin**.
* **Hacking hilelerinizi göndererek** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **ile paylaşın**.

</details>

## Temel Bilgiler

Çekirdek uzantıları (Kext'ler), ana işletim sistemine ek işlevsellik sağlayan **`.kext`** uzantılı **paketlerdir** ve doğrudan macOS çekirdek alanına yüklenir.

### Gereksinimler

Açıkçası, bu kadar güçlü olduğu için bir çekirdek uzantısını yüklemek **karmaşık bir işlemdir**. Bir çekirdek uzantısının yüklenmesi için karşılanması gereken **gereksinimler** şunlardır:

* **Kurtarma moduna girildiğinde**, çekirdek **uzantılarının yüklenmesine izin verilmelidir**:

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* Çekirdek uzantısı, yalnızca **Apple tarafından verilebilen bir çekirdek kodu imzalama sertifikasıyla imzalanmalıdır**. Apple, şirketi ve nedenlere ayrıntılı olarak inceleyecektir.
* Çekirdek uzantısı ayrıca **notarized** olmalıdır, Apple tarafından kötü amaçlı yazılım kontrol edilebilir.
* Ardından, **root** kullanıcısı, çekirdek uzantısını **yükleyebilen** ve paket içindeki dosyaların **root'a ait olması gereken** kullanıcıdır.
* Yükleme işlemi sırasında, paketin **korunan bir kök olmayan konuma** hazırlanması gerekmektedir: `/Library/StagedExtensions` (`com.apple.rootless.storage.KernelExtensionManagement` iznini gerektirir).
* Son olarak, yüklemeye çalışıldığında, kullanıcı [**bir onay isteği alacak**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html) ve kabul edilirse, bunu yüklemek için bilgisayarın **yeniden başlatılması gerekmektedir**.

### Yükleme işlemi

Catalina'da durum şöyleydi: **Doğrulama** işlemi **kullanıcı alanında** gerçekleşir. Ancak, yalnızca **`com.apple.private.security.kext-management`** iznine sahip uygulamalar, çekirdeğe bir uzantı yüklemesini **istemek için çekirdeğe başvurabilir**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** komut satırı arayüzü, bir uzantıyı yüklemek için **doğrulama** işlemini **başlatır**
* Bir **Mach hizmeti** kullanarak **`kextd`** ile iletişim kurar.
2. **`kextd`**, imza gibi birkaç şeyi kontrol eder
* **`syspolicyd`** ile iletişim kurarak uzantının **yüklenip yüklenemeyeceğini kontrol eder**.
3. **`syspolicyd`**, uzantı daha önce yüklenmediyse **kullanıcıya bir onay istemi** yapar.
* **`syspolicyd`**, sonucu **`kextd`'ye bildirir**.
4. **`kextd`**, sonunda çekirdeğe uzantıyı **yüklemek için** izin verebilir

**`kextd`** kullanılamıyorsa, **`kextutil`** aynı kontrolleri yapabilir.

## Referanslar

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hacklemeyi öğrenin<strong>!</strong></summary>

* **Bir siber güvenlik şirketinde çalışıyor musunuz**? **Şirketinizi HackTricks'te duyurmak** ister misiniz? **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzdaki [**NFT'leri**](https://opensea.io/collection/the-peass-family) keşfedin.
* [**PEASS ve HackTricks'in resmi ürünlerini**](https://peass.creator-spring.com) edinin.
* **Discord** [**💬**](https://emojipedia.org/speech-balloon/) **grubuna katılın** veya [**telegram grubuna**](https://t.me/peass) veya **Twitter'da** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live) **beni takip edin**.
* **Hacking hilelerinizi göndererek** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **ile paylaşın**.

</details>
