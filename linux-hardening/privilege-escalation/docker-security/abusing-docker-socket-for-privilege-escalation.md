# Docker Soketini İstismar Ederek Yetki Yükseltme

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek** paylaşın.

</details>

Bazı durumlarda sadece **docker soketine erişiminiz** vardır ve bunu kullanarak **yetkileri yükseltmek** istersiniz. Bazı eylemler çok şüpheli olabilir ve bunlardan kaçınmak isteyebilirsiniz, bu yüzden yetkileri yükseltmek için kullanışlı olabilecek farklı bayrakları burada bulabilirsiniz:

### Mount ile

Kök olarak çalışan bir konteynerde **dosya sisteminin** farklı bölümlerini **mount** edebilir ve **erişebilirsiniz**.\
Ayrıca bir mount'u kullanarak konteyner içinde yetkileri yükseltebilirsiniz.

* **`-v /:/host`** -> Ana bilgisayar dosya sistemi konteynere mount edilir, böylece **ana bilgisayar dosya sistemini okuyabilirsiniz**.
* Ana bilgisayarda olduğunuz hissini vermek istiyorsanız, diğer savunma mekanizmalarını devre dışı bırakarak bayraklar kullanabilirsiniz:
* `--privileged`
* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `-security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* \*\*`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` \*\* -> Bu, önceki yönteme benzer, ancak burada **cihaz diski mount ediliyoruz**. Ardından, konteyner içinde `mount /dev/sda1 /mnt` komutunu çalıştırarak **ana bilgisayar dosya sistemine** `/mnt` üzerinden **erişebilirsiniz**.
* Ana bilgisayarda `fdisk -l` komutunu çalıştırarak `</dev/sda1>` cihazını mount etmek için bulun
* **`-v /tmp:/host`** -> Herhangi bir nedenle sadece ana bilgisayardan bazı dizinleri mount edebilir ve ana bilgisayarda erişiminiz varsa. Mount edin ve mount edilen dizinde **suid** ile **`/bin/bash`** oluşturun, böylece ana bilgisayardan çalıştırabilir ve root'a yükseltebilirsiniz.

{% hint style="info" %}
Belki `/tmp` klasörünü mount edemeyebilirsiniz, ancak **farklı yazılabilir bir klasörü** mount edebilirsiniz. Yazılabilir dizinleri şu komutu kullanarak bulabilirsiniz: `find / -writable -type d 2>/dev/null`

**Linux makinesindeki tüm dizinlerin suid bitini desteklemeyeceğini unutmayın!** Suid bitini destekleyen dizinleri kontrol etmek için `mount | grep -v "nosuid"` komutunu çalıştırın. Örneğin, genellikle `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` ve `/var/lib/lxcfs` suid bitini desteklemez.

Ayrıca, **`/etc`** veya **yapılandırma dosyalarını içeren başka bir klasörü** mount edebiliyorsanız, kök olarak docker konteynerinde bunları değiştirerek ana bilgisayarda **istismar etmek** ve yetkileri yükseltmek için kullanabilirsiniz (belki `/etc/shadow`'u değiştirerek).
{% endhint %}

### Konteynerden Kaçma

* **`--privileged`** -> Bu bayrakla konteynerden [tüm izolasyonu kaldırırsınız](docker-privileged.md#what-affects). Kök olarak ayrıcalıklı konteynerlerden kaçmak için teknikleri kontrol edin (docker-breakout-privilege-escalation/#automatic-enumeration-and-escape).
* **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> [Yetenekleri istismar etmek](../linux-capabilities.md) için, **o yeteneği konteynere verin** ve çalışmasını engelleyebilecek diğer koruma yöntemlerini devre dışı bırakın.

### Curl

Bu sayfada docker bayraklarını kullanarak yetkileri yükseltme yöntemlerini tartıştık, bu yöntemleri **curl** komutunu kullanarak nasıl istismar edeceğinizi sayfada bulabilirsiniz:

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek** paylaşın.

</details>
