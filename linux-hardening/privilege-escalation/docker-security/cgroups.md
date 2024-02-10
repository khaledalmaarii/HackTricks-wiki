# CGroups

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan ileri seviyeye öğrenmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek** paylaşın.

</details>

## Temel Bilgiler

**Linux Kontrol Grupları** veya **cgroups**, Linux çekirdeğinin bir özelliğidir ve CPU, bellek ve disk G/Ç gibi sistem kaynaklarının tahsisini, sınırlamasını ve önceliklendirmesini sağlar. **İşlem gruplarının kaynak kullanımını yönetme ve izolasyon** amacıyla faydalı olan bir mekanizma sunar.

**Cgroups'ın iki versiyonu** bulunmaktadır: versiyon 1 ve versiyon 2. Her ikisi de aynı anda bir sistemde kullanılabilir. Temel fark, **cgroups versiyon 2'nin**, işlem grupları arasında daha ayrıntılı ve ayrıntılı kaynak dağılımı sağlayan **hiyerarşik, ağaç benzeri bir yapı** getirmesidir. Ayrıca, versiyon 2, yeni kaynak denetleyicileri desteği, eski uygulamalar için daha iyi destek ve geliştirilmiş performans dahil olmak üzere çeşitli iyileştirmeler getirir.

Yeni hiyerarşik düzenin yanı sıra, cgroups versiyon 2, yeni kaynak denetleyicileri desteği, eski uygulamalar için daha iyi destek ve geliştirilmiş performans gibi **birçok diğer değişiklik ve iyileştirmeyi** de tanıttı.

Genel olarak, cgroups **versiyon 2, versiyon 1'den daha fazla özellik ve daha iyi performans** sunar, ancak eski sistemlerle uyumluluk endişesi olduğu durumlarda hala versiyon 1 kullanılabilir.

Herhangi bir işlem için v1 ve v2 cgroups'ları /proc/\<pid> dizinindeki cgroup dosyasına bakarak listeleyebilirsiniz. Bu komutla kabuğunuzun cgroups'larını kontrol etmeye başlayabilirsiniz:
```shell-session
$ cat /proc/self/cgroup
12:rdma:/
11:net_cls,net_prio:/
10:perf_event:/
9:cpuset:/
8:cpu,cpuacct:/user.slice
7:blkio:/user.slice
6:memory:/user.slice 5:pids:/user.slice/user-1000.slice/session-2.scope 4:devices:/user.slice
3:freezer:/
2:hugetlb:/testcgroup
1:name=systemd:/user.slice/user-1000.slice/session-2.scope
0::/user.slice/user-1000.slice/session-2.scope
```
Çıktı yapısı aşağıdaki gibidir:

- **2-12 Numaraları**: Her bir satır farklı bir cgroup'ı temsil eden cgroups v1'i belirtir. Bu cgroup'lar için denetleyiciler yanında belirtilir.
- **1 Numarası**: Ayrıca cgroups v1'i temsil eder, ancak yalnızca yönetim amaçlıdır (örneğin, systemd tarafından ayarlanır) ve bir denetleyiciye sahip değildir.
- **0 Numarası**: cgroups v2'yi temsil eder. Denetleyiciler listelenmez ve bu satır yalnızca cgroups v2 çalıştıran sistemlerde bulunur.
- **İsimler hiyerarşiktir**, dosya yollarını andırır ve farklı cgroup'lar arasındaki yapı ve ilişkiyi gösterir.
- **/user.slice veya /system.slice gibi isimler**, cgroup'ların kategorizasyonunu belirtir, user.slice genellikle systemd tarafından yönetilen oturumlar için ve system.slice sistem hizmetleri için kullanılır.

### Cgroup'ları Görüntüleme

Dosya sistemi genellikle çeşitli **cgroup'lara** erişmek için kullanılır ve geleneksel olarak çekirdek etkileşimleri için kullanılan Unix sistem çağrı arayüzünden ayrılır. Bir kabuğun cgroup yapılandırmasını incelemek için, kabuğun cgroup'ını ortaya koyan **/proc/self/cgroup** dosyasına bakılmalıdır. Ardından, **/sys/fs/cgroup** (veya **`/sys/fs/cgroup/unified`**) dizinine giderek, cgroup'ın adını paylaşan bir dizin bulunabilir ve cgroup ile ilgili çeşitli ayarları ve kaynak kullanımı bilgilerini gözlemleyebilirsiniz.

![Cgroup Dosya Sistemi](../../../.gitbook/assets/image%20(10)%20(2)%20(2).png)

Cgroup'lar için ana arayüz dosyaları **cgroup** ile başlar. **cgroup.procs** dosyası, cat gibi standart komutlarla görüntülenebilen, cgroup içindeki işlemleri listeler. Başka bir dosya olan **cgroup.threads**, thread bilgilerini içerir.

![Cgroup Procs](../../../.gitbook/assets/image%20(1)%20(1)%20(5).png)

Kabukları yöneten cgroup'lar genellikle bellek kullanımını ve işlem sayısını düzenleyen iki denetleyici içerir. Bir denetleyiciyle etkileşimde bulunmak için, denetleyicinin ön ekini taşıyan dosyalara bakılmalıdır. Örneğin, cgroup içindeki thread sayısını belirlemek için **pids.current** başvurulur.

![Cgroup Bellek](../../../.gitbook/assets/image%20(3)%20(5).png)

Bir değerde **max** belirtimi, cgroup için belirli bir sınırlamanın olmadığını gösterir. Bununla birlikte, cgroup'ların hiyerarşik yapısı nedeniyle sınırlamalar, dizin hiyerarşisinde daha düşük bir seviyede bulunan bir cgroup tarafından uygulanabilir.

### Cgroup'ları Manipüle Etme ve Oluşturma

İşlemler, **Process ID (PID)**'lerini `cgroup.procs` dosyasına yazarak cgroup'lara atanır. Bunun için kök yetkilerine ihtiyaç vardır. Örneğin, bir işlem eklemek için:
```bash
echo [pid] > cgroup.procs
```
Benzer şekilde, **PID sınırlaması gibi cgroup özelliklerini değiştirmek**, ilgili dosyaya istenen değeri yazarak yapılır. Bir cgroup için maksimum 3.000 PID ayarlamak için:
```bash
echo 3000 > pids.max
```
**Yeni cgroups oluşturma**, cgroup hiyerarşisi içinde yeni bir alt dizin oluşturmayı içerir, bu da çekirdeğin gerekli arayüz dosyalarını otomatik olarak oluşturmasını sağlar. İşlemi olmayan cgroups `rmdir` ile kaldırılabilir, ancak bazı kısıtlamalara dikkat edilmelidir:

- **İşlemler yalnızca yaprak cgroups içine yerleştirilebilir** (yani, hiyerarşinin en içteki olanları).
- **Bir cgroup, ebeveyninde bulunmayan bir denetleyiciye sahip olamaz**.
- **Çocuk cgroups için denetleyiciler** `cgroup.subtree_control` dosyasında açıkça belirtilmelidir. Örneğin, bir çocuk cgroup'ta CPU ve PID denetleyicilerini etkinleştirmek için:
```bash
echo "+cpu +pids" > cgroup.subtree_control
```
**Kök cgroup**, bu kurallardan muaf olan ve doğrudan işlem yerleştirme izni veren bir istisnadır. Bu, süreçleri systemd yönetiminden kaldırmak için kullanılabilir.

Bir cgroup içindeki **CPU kullanımını izlemek**, `cpu.stat` dosyası aracılığıyla mümkündür. Bu dosya, bir hizmetin alt süreçleri arasındaki kullanımı takip etmek için yararlı olan toplam CPU süresini gösterir:

<figure><img src="../../../.gitbook/assets/image (2) (6) (3).png" alt=""><figcaption>cpu.stat dosyasında gösterilen CPU kullanım istatistikleri</figcaption></figure>

## Referanslar
* **Kitap: How Linux Works, 3. Baskı: Her Süper Kullanıcının Bilmesi Gerekenler, Brian Ward**

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi Twitter'da takip edin 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live).
* Hacking hilelerinizi **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>
