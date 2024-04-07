# Linux Adli Bilişim

<figure><img src="../../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçlarıyla desteklenen **otomatik iş akışları** oluşturun ve otomatikleştirin.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Sıfırdan kahramana kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## Başlangıç Bilgi Toplama

### Temel Bilgiler

Öncelikle, **iyi bilinen ikili dosyalar ve kütüphanelere sahip bir USB**'ye sahip olmanız önerilir (sadece ubuntu alabilir ve _/bin_, _/sbin_, _/lib_ ve _/lib64_ klasörlerini kopyalayabilirsiniz), ardından USB'yi bağlayın ve çevresel değişkenleri değiştirerek bu ikili dosyaları kullanın:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Bir kez sistemi iyi ve bilinen ikili dosyaları kullanacak şekilde yapılandırdıktan sonra **bazı temel bilgileri çıkarmaya** başlayabilirsiniz:
```bash
date #Date and time (Clock may be skewed, Might be at a different timezone)
uname -a #OS info
ifconfig -a || ip a #Network interfaces (promiscuous mode?)
ps -ef #Running processes
netstat -anp #Proccess and ports
lsof -V #Open files
netstat -rn; route #Routing table
df; mount #Free space and mounted devices
free #Meam and swap space
w #Who is connected
last -Faiwx #Logins
lsmod #What is loaded
cat /etc/passwd #Unexpected data?
cat /etc/shadow #Unexpected data?
find /directory -type f -mtime -1 -print #Find modified files during the last minute in the directory
```
#### Şüpheli bilgiler

Temel bilgileri elde ederken şu gibi garip şeyleri kontrol etmelisiniz:

- **Root işlemleri** genellikle düşük PIDS ile çalışır, bu yüzden büyük bir PID'ye sahip bir root işlemi bulursanız şüphelenebilirsiniz
- `/etc/passwd` içinde kabuğu olmayan kullanıcıların **kayıtlı girişlerini** kontrol edin
- `/etc/shadow` içinde kabuğu olmayan kullanıcılar için **şifre hash'lerini** kontrol edin

### Bellek Dökümü

Çalışan sistemin belleğini elde etmek için [**LiME**](https://github.com/504ensicsLabs/LiME) kullanmanız önerilir.\
Bunu **derlemek** için, kurban makinenin kullandığı **aynı çekirdeği** kullanmanız gerekir.

{% hint style="info" %}
Kurban makineye **LiME veya başka bir şey kuramayacağınızı** unutmayın, çünkü bu makineye çeşitli değişiklikler yapacaktır
{% endhint %}

Bu yüzden, Ubuntu'nun aynı sürümüne sahipseniz `apt-get install lime-forensics-dkms` komutunu kullanabilirsiniz.\
Diğer durumlarda, [**LiME**](https://github.com/504ensicsLabs/LiME)'ı github'dan indirip doğru çekirdek başlıklarıyla derlemeniz gerekir. Kurban makinenin **kesin çekirdek başlıklarını** elde etmek için, sadece `/lib/modules/<çekirdek sürümü>` dizinini kopyalayıp makinenize yapıştırabilir ve ardından bunları kullanarak LiME'ı **derleyebilirsiniz**:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME, 3 **formatı** destekler:

* Ham (her segment bir araya getirilir)
* Dolgulu (ham ile aynı, ancak sağ bitlerde sıfırlarla)
* Lime (metadata ile birlikte önerilen format)

LiME ayrıca, dump'ı **sistemde depolamak yerine ağ üzerinden göndermek** için şöyle bir şey kullanılabilir: `path=tcp:4444`

### Disk Görüntüleme

#### Kapatma

Öncelikle, **sistemi kapatmanız gerekecek**. Bu her zaman bir seçenek olmayabilir çünkü bazen sistem, şirketin kapatmaya kıyamadığı bir üretim sunucusu olabilir.\
Sistemi kapatmanın **2 yolu** vardır, **normal kapatma** ve **"fişi çekme" kapatma**. İlk yöntem, **işlemlerin normal şekilde sonlandırılmasına** ve **dosya sisteminin senkronize edilmesine** izin verecektir, ancak aynı zamanda olası **zararlı yazılımın delilleri yok etmesine** de izin verecektir. "Fişi çekme" yaklaşımı, **bazı bilgi kaybı** taşıyabilir (belleğin bir görüntüsünü zaten aldığımız için çok fazla bilgi kaybolmayacak) ve **zararlı yazılımın buna karşı bir şey yapma şansı olmayacak**. Bu nedenle, eğer bir **zararlı yazılım olabileceğinden şüpheleniyorsanız**, sadece sistemde **`sync`** **komutunu** çalıştırın ve fişi çekin.

#### Diskten bir görüntü almak

Bilgisayarınızı **dava ile ilgili herhangi bir şeye bağlamadan önce**, bilginin değiştirilmesini önlemek için **salt okunur olarak bağlanacağınızdan emin olmanız önemlidir**.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Disk Görüntüsü Ön Analizi

Daha fazla veri olmadan bir disk görüntüsü oluşturma.
```bash
#Find out if it's a disk image using "file" command
file disk.img
disk.img: Linux rev 1.0 ext4 filesystem data, UUID=59e7a736-9c90-4fab-ae35-1d6a28e5de27 (extents) (64bit) (large files) (huge files)

#Check which type of disk image it's
img_stat -t evidence.img
raw
#You can list supported types with
img_stat -i list
Supported image format types:
raw (Single or split raw file (dd))
aff (Advanced Forensic Format)
afd (AFF Multiple File)
afm (AFF with external metadata)
afflib (All AFFLIB image formats (including beta ones))
ewf (Expert Witness Format (EnCase))

#Data of the image
fsstat -i raw -f ext4 disk.img
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: Ext4
Volume Name:
Volume ID: 162850f203fd75afab4f1e4736a7e776

Last Written at: 2020-02-06 06:22:48 (UTC)
Last Checked at: 2020-02-06 06:15:09 (UTC)

Last Mounted at: 2020-02-06 06:15:18 (UTC)
Unmounted properly
Last mounted on: /mnt/disk0

Source OS: Linux
[...]

#ls inside the image
fls -i raw -f ext4 disk.img
d/d 11: lost+found
d/d 12: Documents
d/d 8193:       folder1
d/d 8194:       folder2
V/V 65537:      $OrphanFiles

#ls inside folder
fls -i raw -f ext4 disk.img 12
r/r 16: secret.txt

#cat file inside image
icat -i raw -f ext4 disk.img 16
ThisisTheMasterSecret
```
<figure><img src="../../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçlarıyla desteklenen **otomatikleştirilmiş iş akışları** oluşturun.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Bilinen Kötü Amaçlı Yazılımları Arayın

### Değiştirilmiş Sistem Dosyaları

Linux, potansiyel sorunlu dosyaları tespit etmek için sistem bileşenlerinin bütünlüğünü sağlama konusunda araçlar sunar.

* **RedHat tabanlı sistemler**: Kapsamlı bir kontrol için `rpm -Va` kullanın.
* **Debian tabanlı sistemler**: İlk doğrulama için `dpkg --verify` kullanın, ardından `debsums | grep -v "OK$"` ( `apt-get install debsums` ile `debsums`'ı yükledikten sonra) kullanarak herhangi bir sorunu belirleyin.

### Kötü Amaçlı Yazılım/Rootkit Tespitçileri

Kötü amaçlı yazılımları bulmak için yararlı olabilecek araçlar hakkında bilgi edinmek için aşağıdaki sayfayı okuyun:

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## Yüklenen Programları Arayın

Debian ve RedHat sistemlerinde yüklenen programları etkili bir şekilde aramak için sistem günlüklerini ve veritabanlarını, yaygın dizinlerde manuel kontrolle birlikte kullanmayı düşünün.

* Debian için, paket yüklemeleri hakkında ayrıntıları almak için _**`/var/lib/dpkg/status`**_ ve _**`/var/log/dpkg.log`**_ dosyalarını inceleyin, belirli bilgileri filtrelemek için `grep` kullanın.
* RedHat kullanıcıları, yüklü paketleri listelemek için `rpm -qa --root=/mntpath/var/lib/rpm` ile RPM veritabanını sorgulayabilir.

Bu paket yöneticileri dışında veya manuel olarak yüklenen yazılımları bulmak için _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ ve _**`/sbin`**_ gibi dizinleri keşfedin. Dizin listelerini sistem özel komutlarla birleştirerek, bilinen paketlerle ilişkilendirilmeyen yürütülebilir dosyaları tanımlamak için arama işleminizi geliştirin.
```bash
# Debian package and log details
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
# RedHat RPM database query
rpm -qa --root=/mntpath/var/lib/rpm
# Listing directories for manual installations
ls /usr/sbin /usr/bin /bin /sbin
# Identifying non-package executables (Debian)
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
# Identifying non-package executables (RedHat)
find /sbin/ –exec rpm -qf {} \; | grep "is not"
# Find exacuable files
find / -type f -executable | grep <something>
```
<figure><img src="../../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçlarıyla desteklenen **otomatik iş akışlarını** kolayca oluşturun ve otomatikleştirin.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Silinmiş Çalışan İkili Dosyaları Kurtarın

/tmp/exec dizininden çalıştırılan ve daha sonra silinen bir işlemi hayal edin. Bu çıkarılabilir.
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Otomatik Başlatma Konumlarını İnceleyin

### Zamanlanmış Görevler
```bash
cat /var/spool/cron/crontabs/*  \
/var/spool/cron/atjobs \
/var/spool/anacron \
/etc/cron* \
/etc/at* \
/etc/anacrontab \
/etc/incron.d/* \
/var/spool/incron/* \

#MacOS
ls -l /usr/lib/cron/tabs/ /Library/LaunchAgents/ /Library/LaunchDaemons/ ~/Library/LaunchAgents/
```
### Hizmetler

Bir kötü amaçlı yazılımın hizmet olarak yüklenebileceği yollar:

- **/etc/inittab**: rc.sysinit gibi başlatma betiklerini çağırır, daha sonra başlangıç betiklerine yönlendirir.
- **/etc/rc.d/** ve **/etc/rc.boot/**: Hizmet başlatma betiklerini içerir, ikincisi eski Linux sürümlerinde bulunur.
- **/etc/init.d/**: Debian gibi belirli Linux sürümlerinde başlangıç betiklerini depolamak için kullanılır.
- Hizmetler ayrıca **/etc/inetd.conf** veya **/etc/xinetd/** üzerinden etkinleştirilebilir, Linux varyantına bağlı olarak değişir.
- **/etc/systemd/system**: Sistem ve hizmet yöneticisi betikleri için bir dizin.
- **/etc/systemd/system/multi-user.target.wants/**: Çoklu kullanıcı çalışma düzeyinde başlatılması gereken hizmetlere bağlantıları içerir.
- **/usr/local/etc/rc.d/**: Özel veya üçüncü taraf hizmetleri için.
- **\~/.config/autostart/**: Kullanıcıya özgü otomatik başlatma uygulamaları için, kullanıcı odaklı kötü amaçlı yazılımların gizlenmesi için bir saklanma noktası olabilir.
- **/lib/systemd/system/**: Kurulu paketler tarafından sağlanan sistem genelinde varsayılan birim dosyaları.

### Çekirdek Modülleri

Kötü amaçlı yazılımlar tarafından genellikle kök kiti bileşenleri olarak kullanılan Linux çekirdek modülleri, sistem başlangıcında yüklenir. Bu modüller için kritik olan dizinler ve dosyalar şunlardır:

- **/lib/modules/$(uname -r)**: Çalışan çekirdek sürümü için modülleri içerir.
- **/etc/modprobe.d**: Modül yüklemeyi kontrol etmek için yapılandırma dosyalarını içerir.
- **/etc/modprobe** ve **/etc/modprobe.conf**: Genel modül ayarları için dosyalar.

### Diğer Otomatik Başlatma Konumları

Linux, kullanıcı oturum açtığında otomatik olarak programları çalıştırmak için çeşitli dosyalar kullanır ve potansiyel olarak kötü amaçlı yazılımları barındırabilir:

- **/etc/profile.d/**\*, **/etc/profile** ve **/etc/bash.bashrc**: Herhangi bir kullanıcı oturumu için çalıştırılır.
- **\~/.bashrc**, **\~/.bash\_profile**, **\~/.profile** ve **\~/.config/autostart**: Kullanıcıya özgü dosyalar, kullanıcı oturum açtığında çalıştırılır.
- **/etc/rc.local**: Tüm sistem hizmetleri başladıktan sonra çalışır, çoklu kullanıcı ortamına geçişin sonunu işaretler.

## Günlükleri İnceleme

Linux sistemleri, çeşitli günlük dosyaları aracılığıyla kullanıcı etkinliklerini ve sistem olaylarını izler. Bu günlükler, yetkisiz erişimi, kötü amaçlı yazılım bulaşmalarını ve diğer güvenlik olaylarını tespit etmek için hayati öneme sahiptir. Önemli günlük dosyaları şunları içerir:

- **/var/log/syslog** (Debian) veya **/var/log/messages** (RedHat): Sistem genelindeki mesajları ve etkinlikleri yakalar.
- **/var/log/auth.log** (Debian) veya **/var/log/secure** (RedHat): Kimlik doğrulama denemelerini, başarılı ve başarısız oturum açmalarını kaydeder.
- İlgili kimlik doğrulama olaylarını filtrelemek için `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` komutunu kullanın.
- **/var/log/boot.log**: Sistem başlatma mesajlarını içerir.
- **/var/log/maillog** veya **/var/log/mail.log**: E-posta sunucusu etkinliklerini kaydeder, e-posta ile ilgili hizmetleri izlemek için faydalıdır.
- **/var/log/kern.log**: Hata ve uyarıları içeren çekirdek mesajlarını saklar.
- **/var/log/dmesg**: Aygıt sürücüsü mesajlarını tutar.
- **/var/log/faillog**: Güvenlik ihlali soruşturmalarına yardımcı olan başarısız oturum açma denemelerini kaydeder.
- **/var/log/cron**: Cron işi yürütmelerini kaydeder.
- **/var/log/daemon.log**: Arka planda çalışan hizmet etkinliklerini izler.
- **/var/log/btmp**: Başarısız oturum açma denemelerini belgeler.
- **/var/log/httpd/**: Apache HTTPD hata ve erişim günlüklerini içerir.
- **/var/log/mysqld.log** veya **/var/log/mysql.log**: MySQL veritabanı etkinliklerini kaydeder.
- **/var/log/xferlog**: FTP dosya transferlerini kaydeder.
- **/var/log/**: Burada beklenmeyen günlükleri her zaman kontrol edin.

{% hint style="info" %}
Linux sistem günlükleri ve denetim alt sistemleri, bir sızma veya kötü amaçlı yazılım olayında devre dışı bırakılabilir veya silinebilir. Linux sistemlerinde günlükler genellikle kötü amaçlı etkinlikler hakkında en kullanışlı bilgileri içerdiğinden, sızıntı yapanlar genellikle bunları siler. Bu nedenle, mevcut günlük dosyalarını inceleyerek, silinme veya oynama belirtisi olabilecek boşlukları veya sırasız girişleri aramak önemlidir.
{% endhint %}

**Linux, her kullanıcı için bir komut geçmişini saklar**, şurada depolanır:

- \~/.bash\_history
- \~/.zsh\_history
- \~/.zsh\_sessions/\*
- \~/.python\_history
- \~/.\*\_history

Ayrıca, `last -Faiwx` komutu bir kullanıcı oturum listesi sağlar. Bilinmeyen veya beklenmeyen oturum açmaları için kontrol edin.

Ek ayrıcalıklar sağlayabilecek dosyaları kontrol edin:

- Beklenmeyen kullanıcı ayrıcalıklarını belirlemek için `/etc/sudoers` dosyasını inceleyin.
- Beklenmeyen kullanıcı ayrıcalıklarını belirlemek için `/etc/sudoers.d/` dizinini inceleyin.
- Olağandışı grup üyeliklerini veya izinleri belirlemek için `/etc/groups` dosyasını inceleyin.
- Olağandışı grup üyeliklerini veya izinleri belirlemek için `/etc/passwd` dosyasını inceleyin.

Bazı uygulamalar kendi günlüklerini oluşturur:

- **SSH**: Yetkisiz uzak bağlantılar için _\~/.ssh/authorized\_keys_ ve _\~/.ssh/known\_hosts_ dosyalarını inceleyin.
- **Gnome Masaüstü**: Gnome uygulamaları aracılığıyla son erişilen dosyalar için _\~/.recently-used.xbel_ dosyasına bakın.
- **Firefox/Chrome**: Şüpheli etkinlikler için _\~/.mozilla/firefox_ veya _\~/.config/google-chrome_ dizinlerinde tarayıcı geçmişini ve indirmeleri kontrol edin.
- **VIM**: Erişilen dosya yolları ve arama geçmişi gibi kullanım detayları için _\~/.viminfo_ dosyasını inceleyin.
- **Open Office**: Kompromize uğramış dosyaları gösterebilecek son belge erişimlerini kontrol edin.
- **FTP/SFTP**: Yetkisiz dosya transferleri için _\~/.ftp\_history_ veya _\~/.sftp\_history_ günlüklerini inceleyin.
- **MySQL**: Yürütülen MySQL sorgularını içeren _\~/.mysql\_history_ dosyasını araştırın, yetkisiz veritabanı etkinliklerini ortaya çıkarabilir.
- **Less**: Görüntülenen dosyaları ve yürütülen komutları içeren _\~/.lesshst_ dosyasını analiz edin.
- **Git**: Depolardaki değişiklikler için _\~/.gitconfig_ ve proje _.git/logs_ dosyalarını inceleyin.

### USB Günlükleri

[**usbrip**](https://github.com/snovvcrash/usbrip), USB olay geçmişi tablolarını oluşturmak için Linux günlük dosyalarını (`/var/log/syslog*` veya dağıtıma bağlı olarak `/var/log/messages*`) ayrıştıran saf Python 3 dilinde yazılmış küçük bir yazılımdır.

**Kullanılan tüm USB'leri bilmek ilginç olacaktır** ve yetkili bir USB listesine sahipseniz "ihlal olaylarını" bulmak için daha da faydalı olacaktır (bu listede olmayan USB'lerin kullanımı).

### Kurulum
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### Örnekler
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
Daha fazla örnek ve bilgi için github içine bakın: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

<figure><img src="../../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçları tarafından desteklenen **otomatikleştirilmiş iş akışları** oluşturun ve yönetin.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Kullanıcı Hesaplarını ve Oturum Etkinliklerini İnceleme

Bilinen yetkisiz olaylara yakın zamanda oluşturulan veya kullanılan sıradışı isimleri veya hesapları kontrol etmek için _**/etc/passwd**_, _**/etc/shadow**_ ve **güvenlik günlüklerini** inceleyin. Ayrıca, olası sudo kaba kuvvet saldırılarını kontrol edin.\
Ayrıca, kullanıcılara verilen beklenmeyen ayrıcalıkları kontrol etmek için _**/etc/sudoers**_ ve _**/etc/groups**_ gibi dosyaları kontrol edin.\
Son olarak, **şifresiz hesapları** veya **kolayca tahmin edilebilen** şifreleri olan hesapları arayın.

## Dosya Sistemi İnceleme

### Kötü Amaçlı Yazılım İncelemesinde Dosya Sistemi Yapılarını Analiz Etme

Kötü amaçlı yazılım olaylarını araştırırken, dosya sistemi yapısı bilgi kaynağıdır ve olayların sıralamasını ve kötü amaçlı yazılımın içeriğini ortaya çıkarır. Ancak, kötü amaçlı yazılım yazarları, dosya zaman damgalarını değiştirme veya veri depolama için dosya sisteminden kaçınma gibi analizi engellemek için teknikler geliştirmektedir.

Bu anti-forensik yöntemlere karşı koymak için şunlar önemlidir:

* **Olay zaman çizelgesi analizi** yapmak için **Autopsy** gibi araçları kullanarak olay zaman çizelgelerini görselleştirmek veya ayrıntılı zaman çizelgesi verileri için **Sleuth Kit's** `mactime` kullanmak.
* Saldırganlar tarafından kullanılan kabuk veya PHP betiklerini içerebilecek **sistem $PATH'indeki beklenmedik betikleri incelemek**.
* **/dev içindeki tipik olmayan dosyaları incelemek**, genellikle özel dosyalar içerir ancak kötü amaçlı yazılım ile ilişkili dosyaları içerebilir.
* ".. " (nokta nokta boşluk) veya "..^G" (nokta nokta kontrol-G) gibi adlara sahip **gizli dosyaları veya dizinleri aramak**, kötü amaçlı içeriği gizleyebilir.
* `find / -user root -perm -04000 -print` komutunu kullanarak **setuid root dosyalarını tanımlamak**. Bu, saldırganlar tarafından kötüye kullanılabilecek yüksek izinlere sahip dosyaları bulur.
* İnode tablolarındaki **silme zaman damgalarını incelemek**, kök kiti veya truva atlarının varlığını gösterebilecek toplu dosya silmelerini belirlemek için.
* Bir tane tanımladıktan sonra **yan yana kötü amaçlı dosyaları bulmak için ardışık inode'ları incelemek**.
* **Son zamanlarda değiştirilmiş dosyaları kontrol etmek için yaygın ikili dizinleri** (_/bin_, _/sbin_) incelemek, çünkü bunlar kötü amaçlı yazılım tarafından değiştirilmiş olabilir.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
{% hint style="info" %}
**Saldırgan**, dosyaları **meşru görünmesi** için **zamanı değiştirebilir**, ancak **inode**'u değiştiremez. Eğer bir **dosyanın**, aynı klasördeki diğer dosyalarla aynı zamanda **oluşturulduğunu ve değiştirildiğini** gösterdiğini fark ederseniz, ancak **inode** beklenenden **daha büyükse**, o dosyanın **zaman damgaları değiştirilmiş** demektir.
{% endhint %}

## Farklı dosya sistem sürümlerini karşılaştırın

### Dosya Sistem Sürümü Karşılaştırma Özeti

Değişiklikleri belirlemek ve dosya sistem sürümlerini karşılaştırmak için basitleştirilmiş `git diff` komutlarını kullanırız:

* **Yeni dosyaları bulmak için**, iki dizini karşılaştırın:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
* **Değiştirilmiş içerik için**, belirli satırları yok sayarak değişiklikleri listeleyin:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
* **Silinmiş dosyaları tespit etmek için**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
* **Filtre seçenekleri** (`--diff-filter`), eklenen (`A`), silinen (`D`) veya değiştirilen (`M`) dosyalar gibi belirli değişikliklere odaklanmanıza yardımcı olur.
* `A`: Eklenen dosyalar
* `C`: Kopyalanan dosyalar
* `D`: Silinen dosyalar
* `M`: Değiştirilen dosyalar
* `R`: Yeniden adlandırılan dosyalar
* `T`: Tür değişiklikleri (ör. dosya simgeye)
* `U`: Birleştirilmemiş dosyalar
* `X`: Bilinmeyen dosyalar
* `B`: Bozuk dosyalar

## Referanslar

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
* [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
* **Kitap: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

<details>

<summary><strong>Sıfırdan kahraman olana kadar AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

**Bir ** **cybersecurity şirketinde mi çalışıyorsunuz? Şirketinizin **HackTricks'te** reklamını görmek ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!

* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* [**Resmi PEASS & HackTricks ürünlerine**](https://peass.creator-spring.com) sahip olun
* **Katılın** [**💬**](https://emojipedia.org/speech-balloon/) **Discord grubuna**](https://discord.gg/hRep4RUj7f) veya **telegram grubuna** veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**

**Hacking püf noktalarınızı göndererek HackTricks** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **aracılığıyla paylaşın.**

</details>

<figure><img src="../../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçlarıyla desteklenen **iş akışlarını kolayca oluşturun ve otomatikleştirin**.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
