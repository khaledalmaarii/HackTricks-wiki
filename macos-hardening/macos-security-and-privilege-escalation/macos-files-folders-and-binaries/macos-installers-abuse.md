# macOS Yükleyicilerin Kötüye Kullanımı

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'da **takip edin**.
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## Pkg Temel Bilgileri

Bir macOS **yükleme paketi** (ayrıca `.pkg` dosyası olarak da bilinir), macOS tarafından **yazılım dağıtmak** için kullanılan bir dosya biçimidir. Bu dosyalar, bir yazılım parçasının **kurulması ve doğru şekilde çalıştırılması için gereken her şeyi içeren bir kutu gibidir**.

Paket dosyası kendisi, hedef bilgisayara kurulacak olan bir **dosya ve dizin hiyerarşisini** içeren bir arşivdir. Ayrıca, yazılımın eski sürümlerini temizleme veya yapılandırma dosyalarını ayarlama gibi görevleri gerçekleştirmek için **kurulumdan önce ve sonra görevleri gerçekleştiren betikleri** de içerebilir.

### Hiyerarşi

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

* **Dağıtım (xml)**: Özelleştirmeler (başlık, karşılama metni...) ve betik/kurulum kontrolleri
* **PackageInfo (xml)**: Bilgi, kurulum gereksinimleri, kurulum konumu, çalıştırılacak betik yolları
* **Malzeme listesi (bom)**: Dosyaların listesi, dosya izinleriyle birlikte kurulacak, güncellenecek veya kaldırılacak
* **Yük (CPIO arşivi gzip sıkıştırılmış)**: PackageInfo'dan `kurulum konumu`'na kurulacak dosyalar
* **Betikler (CPIO arşivi gzip sıkıştırılmış)**: Kurulumdan önce ve sonra betikler ve daha fazlası, yürütme için geçici bir dizine çıkarılan kaynaklar.

### Sıkıştırma
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

DMG dosyaları veya Apple Disk Görüntüleri, Apple'ın macOS işletim sistemi tarafından disk görüntüleri için kullanılan bir dosya biçimidir. Bir DMG dosyası temelde **yerel olarak bağlanabilir bir disk görüntüsüdür** (kendi dosya sistemini içerir) ve genellikle sıkıştırılmış ve bazen şifrelenmiş ham blok verilerini içerir. Bir DMG dosyasını açtığınızda, macOS bunu **fiziksel bir disk gibi bağlar** ve içeriğine erişmenizi sağlar.

{% hint style="danger" %}
**`.dmg`** uzantılı yükleyicilerin **çok sayıda biçimi desteklediğini** unutmayın; geçmişte bazı zayıflıklar içerenleri **çekirdek kodu yürütmek** amacıyla kötüye kullanılmıştır.
{% endhint %}

### Hiyerarşi

<figure><img src="../../../.gitbook/assets/image (222).png" alt=""><figcaption></figcaption></figure>

Bir DMG dosyasının hiyerarşisi içeriğe bağlı olarak farklılık gösterebilir. Ancak, uygulama DMG'leri için genellikle şu yapıyı takip eder:

* Üst Düzey: Bu, disk görüntüsünün köküdür. Genellikle uygulamayı ve muhtemelen Uygulamalar klasörüne bir bağlantı içerir.
* Uygulama (.app): Bu, asıl uygulamadır. macOS'ta bir uygulama genellikle uygulamayı oluşturan birçok bireysel dosya ve klasör içeren bir pakettir.
* Uygulamalar Bağlantısı: Bu, macOS'taki Uygulamalar klasörüne bir kısayoldur. Amacı, uygulamayı yüklemeyi size kolaylaştırmaktır. Uygulamayı yüklemek için .app dosyasını bu kısayola sürükleyebilirsiniz.

## pkg Kötüye Kullanımı Aracılığıyla İzin Yükseltme

### Genel Dizinlerden Yürütme

Örneğin bir ön veya son kurulum betiği **`/var/tmp/Installerutil`** dizininden yürütülüyorsa ve saldırgan bu betiği kontrol edebiliyorsa, ayrıcalıkları yükseltebilir. Ya da başka bir benzer örnek:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Bu, birçok yükleyici ve güncelleme aracının **kök olarak bir şey yürütmek** için çağıracağı [genel bir işlev](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg)dir. Bu işlev, **yürütülecek dosyanın yolunu** parametre olarak alır, ancak bir saldırgan bu dosyayı **değiştirebilirse**, kök olarak bu dosyanın yürütülmesini kötüye kullanarak ayrıcalıkları yükseltebilir.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
### Bağlantı ile Yürütme

Eğer bir kurulum programı `/tmp/fixedname/bla/bla`'ya yazıyorsa, `/tmp/fixedname` üzerine sahibi olmayan bir **mount oluşturmak** mümkün olabilir, böylece kurulum sırasında **herhangi bir dosyayı değiştirebilir** ve kurulum sürecini kötüye kullanabilirsiniz.

Buna bir örnek **CVE-2021-26089**'dur, bu örnek **bir periyodik betiği üzerine yazarak** kök olarak yürütme elde etmeyi başardı. Daha fazla bilgi için şu konuşmaya bakın: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg olarak kötü amaçlı yazılım

### Boş Yük

Sadece bir **`.pkg`** dosyası oluşturmak mümkündür ve içinde herhangi bir yük olmadan **öncesi ve sonrası yükleme betikleri** bulundurabilirsiniz.

### Distribution xml'de JS

Paketin **distribution xml** dosyasına **`<script>`** etiketleri eklemek mümkündür ve bu kod yürütülecek ve **`system.run`** kullanarak **komutlar yürütülebilir**:

<figure><img src="../../../.gitbook/assets/image (1040).png" alt=""><figcaption></figcaption></figure>

## Referanslar

* [**DEF CON 27 - Pkgs Açma MacOS Kurulum Paketlerinin İçine Bakış ve Yaygın Güvenlik Açıkları**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "MacOS Kurulum Programlarının Vahşi Dünyası" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
* [**DEF CON 27 - Pkgs Açma MacOS Kurulum Paketlerinin İçine Bakış**](https://www.youtube.com/watch?v=kCXhIYtODBg)
