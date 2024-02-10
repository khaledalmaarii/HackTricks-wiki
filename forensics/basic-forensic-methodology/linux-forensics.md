# Linux Dijital Delil İncelemesi

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçları tarafından desteklenen iş akışlarını kolayca oluşturabilir ve otomatikleştirebilirsiniz.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hacklemeyi öğrenin<strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'i **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek** paylaşın.

</details>

## İlk Bilgi Toplama

### Temel Bilgiler

İlk olarak, **iyi bilinen ikili ve kütüphanelere sahip bir USB**'ye sahip olmanız önerilir (sadece ubuntu alabilir ve _/bin_, _/sbin_, _/lib_ ve _/lib64_ klasörlerini kopyalayabilirsiniz), ardından USB'yi bağlayın ve çevre değişkenlerini bu ikilileri kullanacak şekilde değiştirin:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Sistem ayarlarını iyi ve bilinen ikili dosyaları kullanacak şekilde yapılandırdıktan sonra, **bazı temel bilgileri çıkarmaya** başlayabilirsiniz:
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

Temel bilgileri elde ederken şunları kontrol etmelisiniz:

* **Root işlemleri** genellikle düşük PIDS ile çalışır, bu yüzden büyük bir PID'ye sahip bir root işlemi bulursanız şüphelenebilirsiniz.
* `/etc/passwd` içinde kabuğu olmayan kullanıcıların **kayıtlı girişlerini** kontrol edin.
* Kabuğu olmayan kullanıcıların **şifre hash'lerini** `/etc/shadow` içinde kontrol edin.

### Bellek Dökümü

Çalışan sistemin belleğini elde etmek için [**LiME**](https://github.com/504ensicsLabs/LiME) kullanmanız önerilir.\
Onu **derlemek** için, kurban makinenin kullandığı **aynı çekirdeği** kullanmanız gerekmektedir.

{% hint style="info" %}
Unutmayın ki, kurban makineye LiME veya başka bir şey **kuramazsınız**, çünkü bunlar birçok değişiklik yapacaktır.
{% endhint %}

Bu yüzden, Ubuntu'nun aynı sürümüne sahipseniz `apt-get install lime-forensics-dkms` komutunu kullanabilirsiniz.\
Diğer durumlarda, [**LiME**'yi](https://github.com/504ensicsLabs/LiME) github'dan indirmeniz ve doğru çekirdek başlıklarıyla derlemeniz gerekmektedir. Kurban makinenin **kesin çekirdek başlıklarını** elde etmek için, sadece `/lib/modules/<çekirdek sürümü>` dizinini kopyalayın ve ardından onları kullanarak LiME'yi **derleyin**:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME 3 **formatı** destekler:

* Ham (her segment birleştirilmiş)
* Dolgulu (ham ile aynı, ancak sağ bitlerde sıfır ile doldurulmuş)
* Lime (metadata ile birlikte önerilen format)

LiME ayrıca, bunun yerine **dökümü ağ üzerinden göndermek** için kullanılabilir, örneğin: `path=tcp:4444`

### Disk Görüntüleme

#### Kapatma

Öncelikle, **sistemi kapatmanız** gerekecektir. Bu her zaman bir seçenek olmayabilir, çünkü sistem bazen şirketin kapatamayacağı bir üretim sunucusu olabilir.\
Sistemi kapatmanın **2 yolu** vardır, biri **normal kapatma** diğeri ise **"fişi çekme" kapatması**. İlk yöntem, **işlemlerin normal şekilde sonlandırılmasına** ve **dosya sisteminin senkronize edilmesine** izin verecektir, ancak aynı zamanda **mümkün olan kötü amaçlı yazılımın delilleri yok etmesine** de izin verecektir. "Fişi çekme" yaklaşımı, **bazı bilgi kaybı** taşıyabilir (belleğin bir görüntüsünü zaten aldığımız için çok fazla bilgi kaybolmayacak) ve **kötü amaçlı yazılımın buna karşı yapabileceği bir şey olmayacaktır**. Bu nedenle, bir **kötü amaçlı yazılım** olabileceğinden şüpheleniyorsanız, sistemin üzerinde **`sync`** **komutunu** çalıştırın ve fişi çekin.

#### Diskin bir görüntüsünü almak

Önemli bir nokta, **bilgisayarınızı dava ile ilgili herhangi bir şeye bağlamadan önce**, bilginin değiştirilmesini önlemek için **salt okunur olarak bağlanacağınızdan emin olmanız gerektiğidir**.
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
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçları tarafından desteklenen iş akışlarını kolayca oluşturabilir ve otomatikleştirebilirsiniz.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Bilinen Kötü Amaçlı Yazılımları Arama

### Değiştirilmiş Sistem Dosyaları

Linux, potansiyel sorunlu dosyaları tespit etmek için sistem bileşenlerinin bütünlüğünü sağlamak için araçlar sunar.

- **RedHat tabanlı sistemler**: Kapsamlı bir kontrol için `rpm -Va` kullanın.
- **Debian tabanlı sistemler**: İlk doğrulama için `dpkg --verify` kullanın, ardından herhangi bir sorunu belirlemek için `debsums | grep -v "OK$"` (apt-get install debsums ile `debsums`'ı yükledikten sonra) kullanın.

### Kötü Amaçlı Yazılım/Kökkit Tespit Araçları

Kötü amaçlı yazılım bulmak için kullanışlı olabilecek araçlar hakkında bilgi edinmek için aşağıdaki sayfayı okuyun:

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## Yüklenmiş Programları Arama

Debian ve RedHat sistemlerinde yüklenmiş programları etkili bir şekilde aramak için, sistem günlüklerini ve veritabanlarını yanı sıra ortak dizinlerde manuel kontrol yapmayı düşünebilirsiniz.

- Debian için, paket kurulumları hakkında ayrıntıları almak için **_`/var/lib/dpkg/status`_** ve **_`/var/log/dpkg.log`_** dosyalarını inceleyin ve belirli bilgileri filtrelemek için `grep` kullanın.

- RedHat kullanıcıları, yüklenmiş paketleri listelemek için `rpm -qa --root=/mntpath/var/lib/rpm` komutunu kullanarak RPM veritabanını sorgulayabilirler.

Bu paket yöneticileri dışında manuel olarak veya bunların dışında yüklenen yazılımları ortaya çıkarmak için **_`/usr/local`_**, **_`/opt`_**, **_`/usr/sbin`_**, **_`/usr/bin`_**, **_`/bin`_**, ve **_`/sbin`_** gibi dizinleri keşfedin. Dizin listelerini sistem özel komutlarıyla birleştirerek, bilinen paketlere bağlı olmayan yürütülebilir dosyaları belirlemek için arama sürecinizi geliştirin.
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
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçları tarafından desteklenen **otomatik iş akışları** oluşturabilir ve otomatikleştirebilirsiniz.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Silinen Çalışan İkili Dosyaları Kurtarma

/tmp/exec dizininden çalıştırılan ve silinen bir işlem hayal edin. Bunun çıkarılması mümkündür.
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
### Zamanlanmış Görevler

Zamanlanmış görevler, Linux sistemlerde otomatik olarak çalıştırılan görevlerdir. Bu görevler, belirli bir zaman veya olaya bağlı olarak çalıştırılabilir. Zamanlanmış görevlerin listesini görmek için aşağıdaki komutu kullanabilirsiniz:

```bash
crontab -l
```

Bu komut, mevcut kullanıcıya ait zamanlanmış görevleri listeler.
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

Kötü amaçlı yazılımın hizmet olarak kurulabileceği yollar:

- **/etc/inittab**: rc.sysinit gibi başlatma betiklerini çağırarak başlatma betiklerine yönlendirir.
- **/etc/rc.d/** ve **/etc/rc.boot/**: Hizmet başlatma için betikleri içerir, ikincisi eski Linux sürümlerinde bulunur.
- **/etc/init.d/**: Debian gibi belirli Linux sürümlerinde başlatma betiklerini depolamak için kullanılır.
- Hizmetler ayrıca **/etc/inetd.conf** veya **/etc/xinetd/** üzerinden etkinleştirilebilir, Linux varyantına bağlı olarak.
- **/etc/systemd/system**: Sistem ve hizmet yöneticisi betikleri için bir dizin.
- **/etc/systemd/system/multi-user.target.wants/**: Çok kullanıcılı bir çalışma düzeyinde başlatılması gereken hizmetlere bağlantılar içerir.
- **/usr/local/etc/rc.d/**: Özel veya üçüncü taraf hizmetleri için.
- **~/.config/autostart/**: Kullanıcıya özgü otomatik başlatma uygulamaları için, kullanıcı hedefli kötü amaçlı yazılım için bir saklanma noktası olabilir.
- **/lib/systemd/system/**: Kurulu paketler tarafından sağlanan sistem genelinde varsayılan birim dosyalarını içerir.


### Çekirdek Modülleri

Kötü amaçlı yazılım tarafından kök kiti bileşeni olarak sıklıkla kullanılan Linux çekirdek modülleri, sistem başlangıcında yüklenir. Bu modüller için kritik olan dizinler ve dosyalar şunlardır:

- **/lib/modules/$(uname -r)**: Çalışan çekirdek sürümü için modülleri içerir.
- **/etc/modprobe.d**: Modül yüklemeyi kontrol etmek için yapılandırma dosyalarını içerir.
- **/etc/modprobe** ve **/etc/modprobe.conf**: Genel modül ayarları için dosyalar.

### Diğer Otomatik Başlatma Konumları

Linux, kullanıcı oturumu açıldığında otomatik olarak programları çalıştırmak için çeşitli dosyalar kullanır ve bu dosyalar kötü amaçlı yazılım barındırabilir:

- **/etc/profile.d/***, **/etc/profile** ve **/etc/bash.bashrc**: Her kullanıcı oturumu açıldığında çalıştırılır.
- **~/.bashrc**, **~/.bash_profile**, **~/.profile** ve **~/.config/autostart**: Kullanıcıya özgü oturum açmalarında çalışan dosyalar.
- **/etc/rc.local**: Tüm sistem hizmetleri başladıktan sonra çalışır, çok kullanıcılı bir ortama geçişin sonunu işaretler.

## Günlükleri İncele

Linux sistemleri, çeşitli günlük dosyaları aracılığıyla kullanıcı etkinliklerini ve sistem olaylarını takip eder. Bu günlükler, yetkisiz erişimi, kötü amaçlı yazılım enfeksiyonlarını ve diğer güvenlik olaylarını tespit etmek için önemlidir. Önemli günlük dosyaları şunları içerir:

- **/var/log/syslog** (Debian) veya **/var/log/messages** (RedHat): Sistem genelindeki mesajları ve etkinlikleri kaydeder.
- **/var/log/auth.log** (Debian) veya **/var/log/secure** (RedHat): Kimlik doğrulama girişimlerini, başarılı ve başarısız oturum açmalarını kaydeder.
- İlgili kimlik doğrulama olaylarını filtrelemek için `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` komutunu kullanın.
- **/var/log/boot.log**: Sistem başlatma mesajlarını içerir.
- **/var/log/maillog** veya **/var/log/mail.log**: E-posta sunucusu etkinliklerini kaydeder, e-posta ile ilgili hizmetleri izlemek için kullanışlıdır.
- **/var/log/kern.log**: Hata ve uyarılar da dahil olmak üzere çekirdek mesajlarını saklar.
- **/var/log/dmesg**: Aygıt sürücüsü mesajlarını içerir.
- **/var/log/faillog**: Başarısız oturum açma girişimlerini kaydeder, güvenlik ihlali soruşturmalarına yardımcı olur.
- **/var/log/cron**: Cron işi yürütmelerini kaydeder.
- **/var/log/daemon.log**: Arka planda çalışan hizmet etkinliklerini takip eder.
- **/var/log/btmp**: Başarısız oturum açma girişimlerini belgeler.
- **/var/log/httpd/**: Apache HTTPD hata ve erişim günlüklerini içerir.
- **/var/log/mysqld.log** veya **/var/log/mysql.log**: MySQL veritabanı etkinliklerini kaydeder.
- **/var/log/xferlog**: FTP dosya transferlerini kaydeder.
- **/var/log/**: Burada beklenmedik günlükler için her zaman kontrol yapın.

{% hint style="info" %}
Linux sistem günlükleri ve denetim alt sistemi, bir saldırı veya kötü amaçlı yazılım olayında devre dışı bırakılabilir veya silinebilir. Linux sistemlerindeki günlükler genellikle kötü amaçlı etkinlikler hakkında en kullanışlı bilgileri içerdiğinden, saldırganlar bunları rutin olarak siler. Bu nedenle, mevcut günlük dosyalarını incelemek önemlidir ve silme veya oynama belirtileri olabilecek boşlukları veya sırasız girişleri aramak önemlidir.
{% endhint %}

**Linux, her kullanıcı için bir komut geçmişi tutar**, bu geçmiş aşağıdaki dosyalarda saklanır:

- ~/.bash_history
- ~/.zsh_history
- ~/.zsh_sessions/*
- ~/.python_history
- ~/.*_history

Ayrıca, `last -Faiwx` komutu kullanıcı oturum açmalarının bir listesini sağlar. Bilinmeyen veya beklenmeyen oturum açmaları için kontrol edin.

Ek ayrıcalıklar sağlayabilecek dosyaları kontrol edin:

- Verilen beklenmeyen kullanıcı ayrıcalıklarını belirlemek için `/etc/sudoers` dosyasını gözden geçirin.
- Verilen beklenmeyen kullanıcı ayrıcalıklarını belirlemek için `/etc/sudoers.d/` dizinini gözden geçirin.
- Olağandışı grup üyeliklerini veya izinleri belirlemek için `/etc/groups` dosyasını inceleyin.
- Olağandışı grup üyeliklerini veya izinleri belirlemek için `/etc/passwd` dosyasını inceleyin.

Bazı uygulamalar kendi günlüklerini oluşturur:

- **SSH**: Yetkisiz uzak bağlantıları belirlemek için _~/.ssh/authorized_keys_ ve _~/.ssh/known_hosts_ dosyalarını inceleyin.
- **Gnome Masaüstü**: Gnome uygulamaları aracılığıyla son zamanlarda erişilen dosyalar için _~/.recently-used.xbel_ dosyasına bakın.
- **Firefox/Chrome**: Şüpheli etkinlikleri belirlemek için tarayıcı geçmişi ve indirmeleri _~/.mozilla/firefox_ veya _~/.config/google-chrome_ dizininde kontrol edin.
- **VIM**: Erişilen dosya yolları ve arama geçmişi gibi kullanım ayrıntıları için _~/.viminfo_ dosyasını gözden geçirin.
- **Open Office**: Kompromize edilmiş dosyaları gösterebilecek son belge erişimlerini kontrol edin.
- **FTP/SFTP**: Yetkisiz dosya transferleri için _~/.ftp_history_ veya _~/.sftp_history_ günlüklerini inceleyin.
- **MySQL**: Yetkisiz veritabanı etkinliklerini ortaya çıkarabilecek _~/.mysql_history_ dosyasını araştırın.
- **Less**: Görüntülenen dosyaları ve yürütülen komutları içeren _~/.lesshst_ dosyasını analiz edin.
- **Git**: Değişiklikleri belirlemek için _~/.gitconfig_ ve proje _.git/logs_ dosyalarını inceleyin.

### USB Günlükleri

[**usbrip**](https://github.com/snovvcrash/usbrip), Linux günlük dosyalarını (`/var/log/syslog*` veya dağıtıma bağlı olarak `/var/log/messages*`) USB olay geçmişi tabloları oluşturmak için ayrıştıran, saf Python 3 ile yazılmış küçük bir yazılımdır.

**Kullanılan tüm USB'leri bilmek** ilginç olacaktır ve yetkilendirilmiş bir USB listesine sahipseniz, "ihlal olaylarını" (bu listede olmayan USB'lerin kullanımı) bulmak için daha da kullanışlı olacaktır.

### Kurulum
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### Örnekler

#### 1. Disk İmagesi Oluşturma

Bir Linux sistemde disk imajı oluşturmak için `dd` komutunu kullanabilirsiniz. Aşağıdaki komut, `/dev/sda` diskinden bir imaj oluşturur ve `image.dd` adında bir dosyaya kaydeder:

```bash
dd if=/dev/sda of=image.dd
```

#### 2. Disk İmagesini İnceleme

Oluşturulan disk imajını incelemek için `file` komutunu kullanabilirsiniz. Aşağıdaki komut, `image.dd` dosyasının türünü ve özelliklerini gösterir:

```bash
file image.dd
```

#### 3. İmzaları İnceleme

İmzaları incelemek için `binwalk` aracını kullanabilirsiniz. Aşağıdaki komut, `image.dd` dosyasındaki imzaları gösterir:

```bash
binwalk image.dd
```

#### 4. Dosya Sistemini İnceleme

Disk imajındaki dosya sistemini incelemek için `mmls` komutunu kullanabilirsiniz. Aşağıdaki komut, `image.dd` dosyasındaki dosya sistemini gösterir:

```bash
mmls image.dd
```

#### 5. Dosyaları İnceleme

Disk imajındaki dosyaları incelemek için `foremost` aracını kullanabilirsiniz. Aşağıdaki komut, `image.dd` dosyasındaki dosyaları kurtarır:

```bash
foremost -i image.dd -o output_directory
```

#### 6. Log Dosyalarını İnceleme

Log dosyalarını incelemek için `grep` komutunu kullanabilirsiniz. Aşağıdaki komut, `auth.log` dosyasında belirli bir kelimeyi arar:

```bash
grep "kelime" auth.log
```

#### 7. Bellek İmagesini İnceleme

Bellek imajını incelemek için `volatility` aracını kullanabilirsiniz. Aşağıdaki komut, `memdump.mem` dosyasındaki süreçleri ve bağlantıları gösterir:

```bash
volatility -f memdump.mem imageinfo
volatility -f memdump.mem pslist
volatility -f memdump.mem connections
```

#### 8. Ağ İncelemesi

Ağ trafiğini incelemek için `tcpdump` komutunu kullanabilirsiniz. Aşağıdaki komut, `eth0` arayüzündeki ağ trafiğini kaydeder:

```bash
tcpdump -i eth0 -w capture.pcap
```

#### 9. Sistem Günlüklerini İnceleme

Sistem günlüklerini incelemek için `/var/log` dizinindeki günlük dosyalarını kullanabilirsiniz. Aşağıdaki komut, `auth.log` dosyasını görüntüler:

```bash
cat /var/log/auth.log
```

#### 10. Kullanıcı İncelemesi

Kullanıcıları incelemek için `/etc/passwd` dosyasını kullanabilirsiniz. Aşağıdaki komut, sistemdeki kullanıcıları gösterir:

```bash
cat /etc/passwd
```
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
Daha fazla örnek ve bilgi için github'a bakın: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)



<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçları tarafından desteklenen iş akışlarını kolayca oluşturun ve otomatikleştirin.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}



## Kullanıcı Hesaplarını ve Oturum Açma Etkinliklerini İnceleyin

Bilinen yetkisiz olaylara yakın zamanda oluşturulan veya kullanılan sıradışı isimleri veya hesapları tespit etmek için _**/etc/passwd**_, _**/etc/shadow**_ ve **güvenlik günlüklerini** inceleyin. Ayrıca, olası sudo brute-force saldırılarını kontrol edin.\
Ayrıca, kullanıcılara verilen beklenmeyen ayrıcalıkları kontrol etmek için _**/etc/sudoers**_ ve _**/etc/groups**_ gibi dosyalara bakın.\
Son olarak, şifresi olmayan veya kolayca tahmin edilebilen şifrelere sahip hesapları arayın.

## Dosya Sistemi İncelemesi

### Zararlı Yazılım İncelemesinde Dosya Sistemi Yapılarını Analiz Etme

Zararlı yazılım olaylarını incelemek için dosya sistemi yapısı bilgileri önemli bir kaynaktır ve hem olayların sırasını hem de zararlı yazılımın içeriğini ortaya çıkarır. Bununla birlikte, zararlı yazılım yazarları, dosya zaman damgalarını değiştirme veya veri depolama için dosya sisteminden kaçınma gibi analizi engellemek için teknikler geliştirmektedir.

Bu anti-forensik yöntemlere karşı koymak için şunlar önemlidir:

- **Olay zaman çizelgesini görselleştirmek** için **Autopsy** gibi araçları kullanarak kapsamlı bir zaman çizelgesi analizi yapın veya ayrıntılı zaman çizelgesi verileri için **Sleuth Kit'in** `mactime`'ını kullanın.
- Saldırganlar tarafından kullanılan kabuk veya PHP betiklerini içerebilecek sistemdeki beklenmedik betikleri inceleyin.
- Geleneksel olarak özel dosyalar içerdiği için **/dev** içindeki tipik olmayan dosyalara bakın, çünkü zararlı yazılım ile ilişkili dosyalar içerebilir.
- ".. " (nokta nokta boşluk) veya "..^G" (nokta nokta kontrol-G) gibi isimlere sahip **gizli dosyaları veya dizinleri arayın**, bunlar zararlı içeriği gizleyebilir.
- Aşağıdaki komutu kullanarak **setuid root dosyalarını** belirleyin:
```find / -user root -perm -04000 -print```
Bu, saldırganlar tarafından kötüye kullanılabilecek yükseltilmiş izinlere sahip dosyaları bulur.
- Kök kiti veya truva atlarının varlığını gösterebilecek toplu dosya silmelerini tespit etmek için inode tablolarındaki silme zaman damgalarını **inceleyin**.
- Bir tane belirledikten sonra yakındaki zararlı dosyaları tespit etmek için ardışık inode'ları **inceleyin**, çünkü birlikte yerleştirilmiş olabilirler.
- Zararlı yazılım tarafından değiştirilmiş olabileceği için **/bin_, _/sbin_ gibi yaygın ikili dizinleri** son zamanlarda değiştirilen dosyalar için kontrol edin.
```bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
```
{% hint style="info" %}
Not: Bir **saldırgan**, **dosyaların görünümünü meşru** göstermek için **zamanı değiştirebilir**, ancak **inode**'u değiştiremez. Bir **dosyanın**, aynı klasördeki diğer dosyalarla aynı **zamanda oluşturulduğunu ve değiştirildiğini gösterdiği**, ancak **inode**'un **beklenmedik şekilde daha büyük olduğu** durumda, o dosyanın **zaman damgalarının değiştirildiği** anlaşılır.
{% endhint %}

## Farklı dosya sistem sürümlerini karşılaştırma

### Dosya Sistem Sürümü Karşılaştırma Özeti

Dosya sistem sürümlerini karşılaştırmak ve değişiklikleri belirlemek için basitleştirilmiş `git diff` komutlarını kullanırız:

- **Yeni dosyaları bulmak** için iki dizini karşılaştırın:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Değiştirilmiş içerik için**, belirli satırları görmezden gelerek değişiklikleri listeleyin:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Silinmiş dosyaları tespit etmek için**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Filtre seçenekleri** (`--diff-filter`), eklenen (`A`), silinen (`D`) veya değiştirilen (`M`) dosyalar gibi belirli değişikliklere odaklanmayı sağlar.
- `A`: Eklenen dosyalar
- `C`: Kopyalanan dosyalar
- `D`: Silinen dosyalar
- `M`: Değiştirilen dosyalar
- `R`: Yeniden adlandırılan dosyalar
- `T`: Tür değişiklikleri (örneğin, dosyadan sembole)
- `U`: Birleştirilmemiş dosyalar
- `X`: Bilinmeyen dosyalar
- `B`: Bozuk dosyalar

## Referanslar

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
* [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
* **Kitap: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

**Bir siber güvenlik şirketinde mi çalışıyorsunuz?** **Şirketinizi HackTricks'te reklamını görmek ister misiniz?** veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek ister misiniz?** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!

* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuz olan [**NFT'lerimizi**](https://opensea.io/collection/the-peass-family) keşfedin.
* [**Resmi PEASS & HackTricks ürünlerine**](https://peass.creator-spring.com) göz atın.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**'u takip edin**.

**Hacking hilelerinizi** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **ile göndererek paylaşın**.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Dünyanın en gelişmiş topluluk araçları tarafından desteklenen **iş akışlarını kolayca oluşturun ve otomatikleştirin** için [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)'i kullanın.
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
