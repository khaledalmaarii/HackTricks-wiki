# Linux Forensics

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Dünyanın **en gelişmiş** topluluk araçlarıyla desteklenen **iş akışlarını** kolayca oluşturmak ve **otomatikleştirmek** için [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=linux-forensics) kullanın.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=linux-forensics" %}

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

## İlk Bilgi Toplama

### Temel Bilgiler

Öncelikle, üzerinde **iyi bilinen ikili dosyalar ve kütüphaneler** bulunan bir **USB**'ye sahip olmanız önerilir (sadece ubuntu alıp _/bin_, _/sbin_, _/lib,_ ve _/lib64_ klasörlerini kopyalayabilirsiniz), ardından USB'yi bağlayın ve bu ikili dosyaları kullanmak için ortam değişkenlerini değiştirin:
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

Temel bilgileri elde ederken, garip şeyler için kontrol etmelisiniz:

* **Root süreçleri** genellikle düşük PID'lerle çalışır, bu yüzden büyük bir PID'ye sahip bir root süreci bulursanız şüphelenebilirsiniz.
* `/etc/passwd` içinde shell'i olmayan kullanıcıların **kayıtlı girişlerini** kontrol edin.
* Shell'i olmayan kullanıcılar için `/etc/shadow` içinde **şifre hash'lerini** kontrol edin.

### Bellek Dökümü

Çalışan sistemin belleğini elde etmek için [**LiME**](https://github.com/504ensicsLabs/LiME) kullanmanız önerilir.\
Bunu **derlemek** için, kurban makinesinin kullandığı **aynı çekirdek** ile çalışmalısınız.

{% hint style="info" %}
Kurban makinesine **LiME veya başka bir şey** yükleyemeyeceğinizi unutmayın, çünkü bu makinede birçok değişiklik yapacaktır.
{% endhint %}

Bu nedenle, eğer aynı Ubuntu sürümüne sahipseniz `apt-get install lime-forensics-dkms` kullanabilirsiniz.\
Diğer durumlarda, [**LiME**](https://github.com/504ensicsLabs/LiME) dosyasını github'dan indirmeniz ve doğru çekirdek başlıkları ile derlemeniz gerekir. Kurban makinesinin **tam çekirdek başlıklarını** elde etmek için, sadece `/lib/modules/<kernel version>` dizinini makinenize **kopyalayabilir** ve ardından bunları kullanarak LiME'yi **derleyebilirsiniz**:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME 3 **formatı** destekler:

* Ham (her segment bir araya getirilmiş)
* Doldurulmuş (ham ile aynı, ancak sağ bitlerde sıfırlar ile)
* Lime (meta verilerle önerilen format)

LiME ayrıca **dökümü ağ üzerinden göndermek için** de kullanılabilir, bunu yapmak için şöyle bir şey kullanabilirsiniz: `path=tcp:4444`

### Disk Görüntüleme

#### Kapatma

Öncelikle, **sistemi kapatmanız** gerekecek. Bu her zaman bir seçenek değildir çünkü bazen sistem, şirketin kapatmayı göze alamayacağı bir üretim sunucusu olabilir.\
Sistemi kapatmanın **2 yolu** vardır, bir **normal kapatma** ve bir **"fişi çekme" kapatma**. İlk yöntem, **işlemlerin normal şekilde sonlanmasına** ve **dosya sisteminin** **senkronize edilmesine** izin verir, ancak aynı zamanda olası **kötü amaçlı yazılımın** **delilleri yok etmesine** de olanak tanır. "Fişi çekme" yaklaşımı, **biraz bilgi kaybı** taşıyabilir (bilgilerin çoğu kaybolmayacak çünkü zaten belleğin bir görüntüsünü aldık) ve **kötü amaçlı yazılımın** bununla ilgili bir şey yapma fırsatı olmayacaktır. Bu nedenle, eğer **kötü amaçlı yazılım** olabileceğinden **şüpheleniyorsanız**, sistemde **`sync`** **komutunu** çalıştırın ve fişi çekin.

#### Diskin görüntüsünü alma

**Bilgisayarınızı davayla ilgili herhangi bir şeye bağlamadan önce**, bunun **sadece okunur olarak** bağlanacağından emin olmanız önemlidir, böylece herhangi bir bilgiyi değiştirmemiş olursunuz.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Disk Image ön analizi

Veri olmayan bir disk görüntüsünü görüntüleme.
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
<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Dünyanın **en gelişmiş** topluluk araçlarıyla desteklenen **iş akışlarını** kolayca oluşturmak ve **otomatikleştirmek** için [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=linux-forensics) kullanın.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=linux-forensics" %}

## Bilinen Kötü Amaçlı Yazılımları Ara

### Değiştirilmiş Sistem Dosyaları

Linux, potansiyel olarak sorunlu dosyaları tespit etmek için kritik olan sistem bileşenlerinin bütünlüğünü sağlamak için araçlar sunar.

* **RedHat tabanlı sistemler**: Kapsamlı bir kontrol için `rpm -Va` kullanın.
* **Debian tabanlı sistemler**: İlk doğrulama için `dpkg --verify` kullanın, ardından `debsums | grep -v "OK$"` (önce `debsums`'ı `apt-get install debsums` ile yükledikten sonra) ile herhangi bir sorunu tespit edin.

### Kötü Amaçlı Yazılım/Rootkit Tespit Cihazları

Kötü amaçlı yazılımları bulmak için faydalı olabilecek araçlar hakkında bilgi edinmek için aşağıdaki sayfayı okuyun:

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## Yüklenmiş Programları Ara

Debian ve RedHat sistemlerinde yüklenmiş programları etkili bir şekilde aramak için sistem günlüklerini ve veritabanlarını, yaygın dizinlerde manuel kontrollerle birleştirmeyi düşünün.

* Debian için, paket yüklemeleri hakkında bilgi almak için _**`/var/lib/dpkg/status`**_ ve _**`/var/log/dpkg.log`**_ dosyalarını kontrol edin, belirli bilgileri filtrelemek için `grep` kullanın.
* RedHat kullanıcıları, yüklenmiş paketleri listelemek için `rpm -qa --root=/mntpath/var/lib/rpm` ile RPM veritabanını sorgulayabilir.

Bu paket yöneticileri dışında veya manuel olarak yüklenmiş yazılımları ortaya çıkarmak için _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ ve _**`/sbin`**_ gibi dizinleri keşfedin. Bilinen paketlerle ilişkilendirilmemiş çalıştırılabilir dosyaları tanımlamak için dizin listelemelerini sistem özel komutlarıyla birleştirerek tüm yüklenmiş programlar için aramanızı geliştirin.
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
<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Dünyanın **en gelişmiş** topluluk araçlarıyla desteklenen **iş akışlarını** kolayca oluşturmak ve **otomatikleştirmek** için [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=linux-forensics) kullanın.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=linux-forensics" %}

## Silinmiş Çalışan İkili Dosyaları Kurtarma

/tmp/exec'ten çalıştırılan ve ardından silinen bir süreci hayal edin. Onu çıkarmak mümkündür.
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Autostart konumlarını incele

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

Kötü amaçlı yazılımın bir hizmet olarak kurulabileceği yollar:

* **/etc/inittab**: rc.sysinit gibi başlatma betiklerini çağırır, daha sonra başlatma betiklerine yönlendirir.
* **/etc/rc.d/** ve **/etc/rc.boot/**: Hizmet başlatma betiklerini içerir, ikincisi daha eski Linux sürümlerinde bulunur.
* **/etc/init.d/**: Başlatma betiklerini depolamak için Debian gibi belirli Linux sürümlerinde kullanılır.
* Hizmetler, Linux varyantına bağlı olarak **/etc/inetd.conf** veya **/etc/xinetd/** aracılığıyla da etkinleştirilebilir.
* **/etc/systemd/system**: Sistem ve hizmet yöneticisi betikleri için bir dizin.
* **/etc/systemd/system/multi-user.target.wants/**: Çok kullanıcılı çalışma seviyesinde başlatılması gereken hizmetlere bağlantılar içerir.
* **/usr/local/etc/rc.d/**: Özel veya üçüncü taraf hizmetler için.
* **\~/.config/autostart/**: Kullanıcıya özgü otomatik başlatma uygulamaları için, kullanıcı hedefli kötü amaçlı yazılımlar için bir saklanma yeri olabilir.
* **/lib/systemd/system/**: Yüklenmiş paketler tarafından sağlanan sistem genelindeki varsayılan birim dosyaları.

### Çekirdek Modülleri

Kötü amaçlı yazılım tarafından genellikle rootkit bileşenleri olarak kullanılan Linux çekirdek modülleri, sistem önyüklemesi sırasında yüklenir. Bu modüller için kritik dizinler ve dosyalar şunlardır:

* **/lib/modules/$(uname -r)**: Çalışan çekirdek sürümü için modülleri tutar.
* **/etc/modprobe.d**: Modül yüklemeyi kontrol etmek için yapılandırma dosyalarını içerir.
* **/etc/modprobe** ve **/etc/modprobe.conf**: Küresel modül ayarları için dosyalar.

### Diğer Otomatik Başlatma Yerleri

Linux, kullanıcı girişi sırasında programları otomatik olarak çalıştırmak için çeşitli dosyalar kullanır, bu da kötü amaçlı yazılımları barındırma potansiyeline sahiptir:

* **/etc/profile.d/**\*, **/etc/profile**, ve **/etc/bash.bashrc**: Herhangi bir kullanıcı girişi için çalıştırılır.
* **\~/.bashrc**, **\~/.bash\_profile**, **\~/.profile**, ve **\~/.config/autostart**: Kullanıcıya özgü dosyalar, kullanıcı giriş yaptığında çalışır.
* **/etc/rc.local**: Tüm sistem hizmetleri başlatıldıktan sonra çalışır, çok kullanıcılı bir ortama geçişin sonunu işaret eder.

## Günlükleri İnceleyin

Linux sistemleri, kullanıcı etkinliklerini ve sistem olaylarını çeşitli günlük dosyaları aracılığıyla takip eder. Bu günlükler, yetkisiz erişim, kötü amaçlı yazılım enfeksiyonları ve diğer güvenlik olaylarını tanımlamak için kritik öneme sahiptir. Anahtar günlük dosyaları şunlardır:

* **/var/log/syslog** (Debian) veya **/var/log/messages** (RedHat): Sistem genelindeki mesajları ve etkinlikleri yakalar.
* **/var/log/auth.log** (Debian) veya **/var/log/secure** (RedHat): Kimlik doğrulama girişimlerini, başarılı ve başarısız girişleri kaydeder.
* İlgili kimlik doğrulama olaylarını filtrelemek için `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` komutunu kullanın.
* **/var/log/boot.log**: Sistem başlatma mesajlarını içerir.
* **/var/log/maillog** veya **/var/log/mail.log**: E-posta sunucusu etkinliklerini kaydeder, e-posta ile ilgili hizmetleri takip etmek için yararlıdır.
* **/var/log/kern.log**: Hata ve uyarılar da dahil olmak üzere çekirdek mesajlarını saklar.
* **/var/log/dmesg**: Aygıt sürücü mesajlarını tutar.
* **/var/log/faillog**: Başarısız giriş girişimlerini kaydeder, güvenlik ihlali soruşturmalarına yardımcı olur.
* **/var/log/cron**: Cron işlerinin yürütülmelerini kaydeder.
* **/var/log/daemon.log**: Arka plan hizmeti etkinliklerini takip eder.
* **/var/log/btmp**: Başarısız giriş girişimlerini belgeler.
* **/var/log/httpd/**: Apache HTTPD hata ve erişim günlüklerini içerir.
* **/var/log/mysqld.log** veya **/var/log/mysql.log**: MySQL veritabanı etkinliklerini kaydeder.
* **/var/log/xferlog**: FTP dosya transferlerini kaydeder.
* **/var/log/**: Burada beklenmedik günlükleri her zaman kontrol edin.

{% hint style="info" %}
Linux sistem günlükleri ve denetim alt sistemleri, bir ihlal veya kötü amaçlı yazılım olayında devre dışı bırakılabilir veya silinebilir. Çünkü Linux sistemlerindeki günlükler genellikle kötü niyetli etkinlikler hakkında en yararlı bilgileri içerir, bu nedenle saldırganlar bunları düzenli olarak siler. Bu nedenle, mevcut günlük dosyalarını incelerken, silinme veya müdahale belirtisi olabilecek boşluklar veya düzensiz girişler aramak önemlidir.
{% endhint %}

**Linux, her kullanıcı için bir komut geçmişi tutar**, şu dosyalarda saklanır:

* \~/.bash\_history
* \~/.zsh\_history
* \~/.zsh\_sessions/\*
* \~/.python\_history
* \~/.\*\_history

Ayrıca, `last -Faiwx` komutu kullanıcı girişlerinin bir listesini sağlar. Bilinmeyen veya beklenmedik girişler için kontrol edin.

Ek ayrıcalıklar verebilecek dosyaları kontrol edin:

* Beklenmedik kullanıcı ayrıcalıkları verilmiş olabileceğinden `/etc/sudoers` dosyasını gözden geçirin.
* Beklenmedik kullanıcı ayrıcalıkları verilmiş olabileceğinden `/etc/sudoers.d/` dosyasını gözden geçirin.
* Herhangi bir olağandışı grup üyeliği veya izinleri tanımlamak için `/etc/groups` dosyasını inceleyin.
* Herhangi bir olağandışı grup üyeliği veya izinleri tanımlamak için `/etc/passwd` dosyasını inceleyin.

Bazı uygulamalar ayrıca kendi günlüklerini oluşturur:

* **SSH**: Yetkisiz uzaktan bağlantılar için _\~/.ssh/authorized\_keys_ ve _\~/.ssh/known\_hosts_ dosyalarını inceleyin.
* **Gnome Masaüstü**: Gnome uygulamaları aracılığıyla yakın zamanda erişilen dosyalar için _\~/.recently-used.xbel_ dosyasını kontrol edin.
* **Firefox/Chrome**: Şüpheli etkinlikler için _\~/.mozilla/firefox_ veya _\~/.config/google-chrome_ dizinlerinde tarayıcı geçmişi ve indirmeleri kontrol edin.
* **VIM**: Erişim sağlanan dosya yolları ve arama geçmişi gibi kullanım detayları için _\~/.viminfo_ dosyasını gözden geçirin.
* **Open Office**: Kompromize olmuş dosyaları gösterebilecek yakın tarihli belge erişimlerini kontrol edin.
* **FTP/SFTP**: Yetkisiz olabilecek dosya transferleri için _\~/.ftp\_history_ veya _\~/.sftp\_history_ dosyalarını gözden geçirin.
* **MySQL**: Yetkisiz veritabanı etkinliklerini ortaya çıkarabilecek yürütülen MySQL sorguları için _\~/.mysql\_history_ dosyasını araştırın.
* **Less**: Görüntülenen dosyalar ve yürütülen komutlar dahil olmak üzere kullanım geçmişi için _\~/.lesshst_ dosyasını analiz edin.
* **Git**: Depolardaki değişiklikler için _\~/.gitconfig_ ve proje _.git/logs_ dosyalarını inceleyin.

### USB Günlükleri

[**usbrip**](https://github.com/snovvcrash/usbrip), USB olay geçmişi tabloları oluşturmak için Linux günlük dosyalarını (`/var/log/syslog*` veya `/var/log/messages*` dağıtıma bağlı olarak) ayrıştıran saf Python 3 ile yazılmış küçük bir yazılımdır.

Kullanılan tüm USB'leri **bilmek** ilginçtir ve "ihlal olaylarını" bulmak için yetkilendirilmiş bir USB listesine sahip olursanız daha faydalı olacaktır (o listedeki USB'lerin dışındaki USB'lerin kullanımı). 

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
Daha fazla örnek ve bilgi için github'ı ziyaret edin: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Dünyanın **en gelişmiş** topluluk araçlarıyla desteklenen **iş akışlarını** kolayca oluşturmak ve **otomatikleştirmek** için [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=linux-forensics) kullanın.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=linux-forensics" %}

## Kullanıcı Hesaplarını ve Giriş Aktivitelerini Gözden Geçirin

_**/etc/passwd**_, _**/etc/shadow**_ ve **güvenlik günlüklerini** inceleyin; olağandışı isimler veya bilinen yetkisiz olaylarla yakın zamanda oluşturulmuş veya kullanılmış hesaplar arayın. Ayrıca, olası sudo brute-force saldırılarını kontrol edin.\
Ayrıca, kullanıcılara verilen beklenmedik ayrıcalıkları kontrol etmek için _**/etc/sudoers**_ ve _**/etc/groups**_ gibi dosyaları kontrol edin.\
Son olarak, **şifresiz** veya **kolay tahmin edilebilen** şifreleri olan hesapları arayın.

## Dosya Sistemini İnceleyin

### Kötü Amaçlı Yazılım Soruşturmasında Dosya Sistemi Yapılarını Analiz Etme

Kötü amaçlı yazılım olaylarını araştırırken, dosya sisteminin yapısı bilgi kaynağı olarak kritik öneme sahiptir; olayların sırasını ve kötü amaçlı yazılımın içeriğini ortaya çıkarır. Ancak, kötü amaçlı yazılım yazarları bu analizi engellemek için dosya zaman damgalarını değiştirmek veya veri depolamak için dosya sisteminden kaçınmak gibi teknikler geliştirmektedir.

Bu anti-forensic yöntemlere karşı koymak için:

* **Olay zaman çizelgelerini görselleştirmek için** **Autopsy** gibi araçlar kullanarak **kapsamlı bir zaman çizelgesi analizi** yapın veya **Sleuth Kit'in** `mactime` aracını detaylı zaman çizelgesi verileri için kullanın.
* **Sistem $PATH'inde beklenmedik betikleri** araştırın; bu, saldırganlar tarafından kullanılan shell veya PHP betiklerini içerebilir.
* **Atypik dosyalar için `/dev`'i inceleyin**; bu genellikle özel dosyalar içerir, ancak kötü amaçlı yazılımla ilgili dosyalar barındırabilir.
* **Gizli dosyalar veya dizinler** arayın; ".. " (nokta nokta boşluk) veya "..^G" (nokta nokta kontrol-G) gibi isimlere sahip olabilirler ve kötü amaçlı içerikleri gizleyebilirler.
* **setuid root dosyalarını tanımlayın**; komut: `find / -user root -perm -04000 -print` Bu, saldırganlar tarafından kötüye kullanılabilecek yükseltilmiş izinlere sahip dosyaları bulur.
* **Kütük tablolarındaki silme zaman damgalarını gözden geçirin**; bu, kök kitleri veya trojanların varlığını gösterebilecek kitlesel dosya silme işlemlerini tespit etmek için kullanılabilir.
* **Bir kötü amaçlı dosya tespit edildikten sonra** yanındaki ardışık inode'ları inceleyin; bunlar birlikte yerleştirilmiş olabilir.
* **Son zamanlarda değiştirilmiş dosyalar için yaygın ikili dizinleri** (_/bin_, _/sbin_) kontrol edin; bunlar kötü amaçlı yazılım tarafından değiştirilmiş olabilir.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
{% hint style="info" %}
Bir **saldırganın** **dosyaları meşru** göstermek için **zamanı değiştirebileceğini**, ancak **inode'u** değiştiremeyeceğini unutmayın. Eğer bir **dosyanın**, aynı klasördeki diğer dosyalarla **aynı zamanda** oluşturulup değiştirildiğini gösteriyorsa, ancak **inode** **beklenmedik şekilde büyükse**, o zaman **o dosyanın zaman damgaları değiştirilmiştir**.
{% endhint %}

## Farklı dosya sistemi sürümlerini karşılaştırma

### Dosya Sistemi Sürüm Karşılaştırma Özeti

Dosya sistemi sürümlerini karşılaştırmak ve değişiklikleri belirlemek için basitleştirilmiş `git diff` komutlarını kullanıyoruz:

* **Yeni dosyaları bulmak için**, iki dizini karşılaştırın:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
* **Değiştirilmiş içerik için**, belirli satırları göz ardı ederek değişiklikleri listeleyin:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
* **Silinmiş dosyaları tespit etmek için**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
* **Filtre seçenekleri** (`--diff-filter`), eklenen (`A`), silinen (`D`) veya değiştirilen (`M`) dosyalar gibi belirli değişikliklere daraltmaya yardımcı olur.
* `A`: Eklenen dosyalar
* `C`: Kopyalanan dosyalar
* `D`: Silinen dosyalar
* `M`: Değiştirilen dosyalar
* `R`: Yeniden adlandırılan dosyalar
* `T`: Tür değişiklikleri (örn., dosya ile symlink)
* `U`: Birleştirilmemiş dosyalar
* `X`: Bilinmeyen dosyalar
* `B`: Bozuk dosyalar

## Referanslar

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
* [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
* **Kitap: Linux Sistemleri için Kötü Amaçlı Yazılım Adli Bilişim Alan Rehberi**

<details>

<summary><strong> sıfırdan kahramana AWS hacking öğrenin </strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Ekip Uzmanı)</strong></a><strong>!</strong></summary>

Bir **siber güvenlik şirketinde** mi çalışıyorsunuz? **şirketinizin HackTricks'te reklamını görmek** mi istiyorsunuz? veya **PEASS'ın en son sürümüne erişim** mi istiyorsunuz ya da **HackTricks'i PDF olarak indirin**? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!

* [**PEASS Ailesini**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'ler**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* [**resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* **Katılın** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya **bana** **Twitter'da** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**

**Hacking ipuçlarınızı paylaşmak için** [**hacktricks repo'suna**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo'suna**](https://github.com/carlospolop/hacktricks-cloud) **PR gönderin.**

</details>

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=linux-forensics) kullanarak dünyanın **en gelişmiş** topluluk araçlarıyla desteklenen **iş akışlarını** kolayca oluşturun ve **otomatikleştirin**.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=linux-forensics" %}
