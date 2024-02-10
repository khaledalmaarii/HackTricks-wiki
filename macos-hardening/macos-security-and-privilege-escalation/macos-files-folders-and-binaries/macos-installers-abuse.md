# macOS Yükleyicilerin Kötüye Kullanımı

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## Pkg Temel Bilgileri

Bir macOS **yükleyici paketi** (aynı zamanda `.pkg` dosyası olarak da bilinir), macOS'in **yazılım dağıtmak** için kullandığı bir dosya formatıdır. Bu dosyalar, bir yazılımın kurulumunu ve doğru şekilde çalışmasını sağlamak için gereken her şeyi içeren bir **kutu gibidir**.

Paket dosyası kendisi, hedef bilgisayara kurulacak bir **dosya ve dizin hiyerarşisini içeren bir arşivdir**. Ayrıca, kurulumdan önce ve sonra yapılandırma dosyalarını ayarlama veya yazılımın eski sürümlerini temizleme gibi görevleri gerçekleştirmek için **komut dosyalarını** içerebilir.

### Hiyerarşi

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

* **Distribution (xml)**: Özelleştirmeler (başlık, hoş geldiniz metni...) ve komut/yükleme kontrolleri
* **PackageInfo (xml)**: Bilgi, yükleme gereksinimleri, yükleme konumu, çalıştırılacak komut dosyalarının yolları
* **Malzeme listesi (bom)**: Dosyaların kurulumu, güncellenmesi veya kaldırılması için dosya izinleriyle birlikte
* **Payload (CPIO arşivi gzip sıkıştırılmış)**: PackageInfo'daki `install-location`'a kurulacak dosyalar
* **Komut dosyaları (CPIO arşivi gzip sıkıştırılmış)**: Kurulumdan önce ve sonra çalıştırılan komut dosyaları ve daha fazla kaynak, geçici bir dizine çıkarılır.

### Sıkıştırmanın Çözülmesi
```bash
# Tool to directly get the files inside a package
pkgutil —expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files ina. more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
## DMG Temel Bilgileri

DMG dosyaları veya Apple Disk Görüntüleri, Apple'ın macOS işletim sistemi için disk görüntüleri için kullanılan bir dosya formatıdır. Bir DMG dosyası, genellikle sıkıştırılmış ve bazen şifrelenmiş olan ham blok verilerini içeren, kendi dosya sistemi olan bir **bağlanabilir disk görüntüsüdür**. Bir DMG dosyasını açtığınızda, macOS, içeriğine erişmenizi sağlayarak onu bir fiziksel disk gibi bağlar.

### Hiyerarşi

<figure><img src="../../../.gitbook/assets/image (12) (2).png" alt=""><figcaption></figcaption></figure>

Bir DMG dosyasının hiyerarşisi içeriğe bağlı olarak farklı olabilir. Ancak, uygulama DMG'leri için genellikle şu yapıyı takip eder:

* Üst Düzey: Bu, disk görüntüsünün köküdür. Genellikle uygulamayı ve muhtemelen Uygulamalar klasörüne bir bağlantıyı içerir.
* Uygulama (.app): Bu, gerçek uygulamadır. macOS'ta bir uygulama genellikle uygulamayı oluşturan birçok bireysel dosya ve klasör içeren bir pakettir.
* Uygulamalar Bağlantısı: Bu, macOS'taki Uygulamalar klasörüne bir kısayoldur. Amacı, uygulamayı kurmayı kolaylaştırmaktır. Uygulama dosyasını bu kısayola sürükleyerek uygulamayı kurabilirsiniz.

## pkg kötüye kullanımı ile ayrıcalık yükseltme

### Genel dizinlerden çalıştırma

Örneğin, bir kurulum öncesi veya sonrası betiği **`/var/tmp/Installerutil`** dizininden çalıştırılıyorsa, saldırgan bu betiği kontrol edebiliyorsa ayrıcalıkları yükseltebilir. Veya başka bir benzer örnek:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Bu, birçok kurulum ve güncelleme programının **kök olarak bir şeyi yürütmek** için çağırabileceği [genel bir işlev](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg)dir. Bu işlev, **yürütülecek** olan **dosyanın yolunu** parametre olarak kabul eder, ancak saldırgan bu dosyayı **değiştirebilirse**, ayrıcalıkları yükseltmek için kötüye kullanabilir.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
Daha fazla bilgi için bu konuşmayı kontrol edin: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Montaj ile Yürütme

Bir kurulum programı `/tmp/fixedname/bla/bla`'ya yazarsa, `/tmp/fixedname` üzerine sahibi olmayan bir **montaj oluşturmak** mümkündür, böylece kurulum sırasında herhangi bir dosyayı değiştirebilir ve kurulum sürecini kötüye kullanabilirsiniz.

Buna bir örnek, **CVE-2021-26089**'dur, bu zafiyet, bir periyodik betiği üzerine yazarak kök olarak yürütme elde etmeyi başarmıştır. Daha fazla bilgi için bu konuşmaya göz atın: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## Zararlı olarak pkg

### Boş Yük

Sadece **pre ve post-install betikleri** içeren bir **`.pkg`** dosyası oluşturmak mümkündür, herhangi bir yük olmadan.

### Distribution xml'de JS

Paketin **distribution xml** dosyasına **`<script>`** etiketleri eklemek mümkündür ve bu kod yürütülecek ve **`system.run`** kullanarak komutlar yürütülebilir:

<figure><img src="../../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

## Referanslar

* [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'da takip edin.**
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek** paylaşın.

</details>
