# Docker Soketini İstismar Ederek Yetki Yükseltme

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'ı takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

Bazen sadece **docker soketine erişiminiz** olur ve bunu **yetki yükseltmek** için kullanmak istersiniz. Bazı eylemler çok şüpheli olabilir ve bunlardan kaçınmak isteyebilirsiniz, bu yüzden burada yetki yükseltmek için faydalı olabilecek farklı bayraklar bulabilirsiniz:

### Mount Üzerinden

Farklı **dosya sistemi** parçalarını kök olarak çalışan bir konteynerde **mount** edebilir ve bunlara **erişebilirsiniz**.\
Ayrıca konteyner içinde **yetki yükseltmek için bir mount'u istismar edebilirsiniz**.

* **`-v /:/host`** -> Ana bilgisayar dosya sistemini konteynerde mount edin, böylece **ana bilgisayar dosya sistemini okuyabilirsiniz.**
* Ana bilgisayarda **bulunduğunuz hissini** yaşamak istiyorsanız ama konteynerde iseniz, şunları kullanarak diğer savunma mekanizmalarını devre dışı bırakabilirsiniz:
* `--privileged`
* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `-security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* \*\*`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` \*\* -> Bu, önceki yönteme benzer, ancak burada **cihaz diskini mount ediyoruz**. Ardından, konteyner içinde `mount /dev/sda1 /mnt` komutunu çalıştırın ve **/mnt**'de **ana bilgisayar dosya sistemine** erişebilirsiniz.
* Mount etmek için `</dev/sda1>` cihazını bulmak için ana bilgisayarda `fdisk -l` komutunu çalıştırın.
* **`-v /tmp:/host`** -> Herhangi bir nedenle sadece ana bilgisayardan bazı dizinleri **mount edebiliyorsanız** ve ana bilgisayarda erişiminiz varsa. Mount edin ve mount edilen dizinde **suid** ile bir **`/bin/bash`** oluşturun, böylece **ana bilgisayardan çalıştırabilir ve root'a yükselebilirsiniz**.

{% hint style="info" %}
Belirli bir nedenle `/tmp` dizinini mount edemeyebilirsiniz, ancak **farklı bir yazılabilir dizini** mount edebilirsiniz. Yazılabilir dizinleri bulmak için: `find / -writable -type d 2>/dev/null` komutunu kullanabilirsiniz.

**Unutmayın ki, bir linux makinesindeki tüm dizinler suid bitini desteklemeyecektir!** Hangi dizinlerin suid bitini desteklediğini kontrol etmek için `mount | grep -v "nosuid"` komutunu çalıştırın. Örneğin genellikle `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` ve `/var/lib/lxcfs` suid bitini desteklemez.

Ayrıca, eğer **`/etc`** veya **konfigürasyon dosyalarını içeren** başka bir dizini **mount edebiliyorsanız**, bunları docker konteynerinden root olarak değiştirip **ana bilgisayarda istismar edebilir** ve yetki yükseltebilirsiniz (belki `/etc/shadow`'ı değiştirerek).
{% endhint %}

### Konteynerden Kaçış

* **`--privileged`** -> Bu bayrak ile [konteynerden tüm izolasyonu kaldırırsınız](docker-privileged.md#what-affects). [Köktan yetkili konteynerlerden kaçış tekniklerini](docker-breakout-privilege-escalation/#automatic-enumeration-and-escape) kontrol edin.
* **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> [yetki yükseltmek için yetenekleri istismar etmek](../linux-capabilities.md), **bu yeteneği konteynere verin** ve istismarın çalışmasını engelleyebilecek diğer koruma yöntemlerini devre dışı bırakın.

### Curl

Bu sayfada docker bayraklarını kullanarak yetki yükseltme yollarını tartıştık, **curl** komutunu kullanarak bu yöntemleri istismar etmenin yollarını bulabilirsiniz:

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'ı takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
