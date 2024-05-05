# CGroups

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahraman olmaya kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na(https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünleri**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## Temel Bilgiler

**Linux Kontrol Grupları**, veya **cgroups**, Linux çekirdeğinin bir özelliğidir ve CPU, bellek ve disk G/Ç gibi sistem kaynaklarının süreç grupları arasında tahsisini, sınırlamasını ve önceliklendirmesini sağlar. **Süreç koleksiyonlarının kaynak kullanımını yönetme ve izole etme** mekanizması sunar, kaynak sınırlaması, iş yükü izolasyonu ve farklı süreç grupları arasında kaynak önceliklendirmesi gibi amaçlar için faydalıdır.

**Cgroups'ın iki sürümü** bulunmaktadır: sürüm 1 ve sürüm 2. Her ikisi de aynı anda bir sistemde kullanılabilir. Temel fark, **cgroups sürüm 2**'nin daha ayrıntılı ve detaylı kaynak dağıtımını sağlayan **hiyerarşik, ağaç benzeri bir yapı** getirmesidir. Ayrıca, sürüm 2, şunları içeren çeşitli iyileştirmeler getirir:

Yeni hiyerarşik organizasyonun yanı sıra, cgroups sürüm 2 ayrıca **birkaç diğer değişiklik ve iyileştirmeyi** de tanıttı, yeni kaynak denetleyicileri desteği, eski uygulamalar için daha iyi destek ve geliştirilmiş performans.

Genel olarak, cgroups **sürüm 2, sürüm 1'den daha fazla özellik ve daha iyi performans** sunar, ancak eski sistemlerle uyumluluk endişesi varsa sürüm 1 hala belirli senaryolarda kullanılabilir.

Herhangi bir sürecin v1 ve v2 cgroups'larını görmek için /proc/\<pid> dizinindeki cgroup dosyasına bakarak listeleyebilirsiniz. Kendi kabuğunuzun cgroups'larını bu komutla görebilirsiniz:
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
* **Sayılar 2-12**: cgroups v1'i temsil eder, her bir satır farklı bir cgroup'u belirtir. Bu denetleyiciler yan yana belirtilir.
* **Sayı 1**: Ayrıca cgroups v1'i temsil eder, ancak yalnızca yönetim amaçları için (örneğin, systemd tarafından belirlenir) ve bir denetleyiciye sahip değildir.
* **Sayı 0**: cgroups v2'yi temsil eder. Denetleyiciler listelenmez ve bu satır yalnızca cgroups v2 çalıştıran sistemlerde bulunur.
* **İsimler hiyerarşiktir**, dosya yollarını andırır ve farklı cgroup'lar arasındaki yapı ve ilişkiyi gösterir.
* **/user.slice veya /system.slice** gibi isimler, cgroup'ların kategorizasyonunu belirtir; user.slice genellikle systemd tarafından yönetilen oturumlar için ve system.slice sistem hizmetleri için kullanılır.

### cgroup'ları Görüntüleme

Dosya sistemi genellikle **cgroup'lere** erişmek için kullanılır ve geleneksel olarak çekirdek etkileşimleri için kullanılan Unix sistem çağrı arayüzünden ayrılır. Bir kabuğun cgroup yapılandırmasını incelemek için, bir kişinin **/proc/self/cgroup** dosyasına bakması gerekir, bu dosya kabuğun cgroup'unu ortaya çıkarır. Ardından, **/sys/fs/cgroup** (veya **`/sys/fs/cgroup/unified`**) dizinine giderek cgroup'un adını paylaşan bir dizini bulabilir ve cgroup'a ilişkin çeşitli ayarları ve kaynak kullanımı bilgilerini gözlemleyebilirsiniz.

![Cgroup Dosya Sistemi](<../../../.gitbook/assets/image (1128).png>)

cgroup'lar için ana arayüz dosyaları **cgroup** ile başlar. Standart komutlar gibi görüntülenebilen **cgroup.procs** dosyası, cgroup içindeki işlemleri listeler. Başka bir dosya olan **cgroup.threads**, iş parçacığı bilgilerini içerir.

![Cgroup Procs](<../../../.gitbook/assets/image (281).png>)

Kabukları yöneten cgroup'lar genellikle bellek kullanımını ve işlem sayısını düzenleyen iki denetleyiciyi kapsar. Bir denetleyiciyle etkileşim kurmak için, denetleyicinin ön ekini taşıyan dosyalar incelenmelidir. Örneğin, **pids.current** ifadesi, cgroup içindeki iş parçacığı sayısını belirlemek için başvurulabilir.

![Cgroup Bellek](<../../../.gitbook/assets/image (677).png>)

Bir değerde **max** ifadesi, cgroup için belirli bir sınırın olmadığını gösterir. Ancak, cgroup'ların hiyerarşik yapısı nedeniyle sınırlar dizin hiyerarşisinde daha düşük bir seviyede bir cgroup tarafından uygulanmış olabilir.

### cgroup'ları Manipüle Etme ve Oluşturma

İşlemler, **Process ID'lerini (PID) `cgroup.procs` dosyasına yazarak** cgroup'lara atanır. Bunun için kök ayrıcalıkları gereklidir. Örneğin, bir işlem eklemek için:
```bash
echo [pid] > cgroup.procs
```
Benzer şekilde, **bir PID sınırı belirlemek gibi cgroup özelliklerini değiştirmek**, ilgili dosyaya istenilen değeri yazarak yapılır. Bir cgroup için maksimum 3,000 PID belirlemek için:
```bash
echo 3000 > pids.max
```
**Yeni cgroups oluşturma**, cgroup hiyerarşisi içinde yeni bir alt dizin oluşturmayı içerir, bu da çekirdeği gerekli arayüz dosyalarını otomatik olarak oluşturmaya zorlar. Etkin olmayan işlemi olmayan cgroups `rmdir` ile kaldırılabilir, ancak belirli kısıtlamalara dikkat edilmelidir:

* **İşlemler yalnızca yaprak cgroups içine yerleştirilebilir** (yani, hiyerarşide en içte olanlar).
* **Bir cgroup, ebeveyninde bulunmayan bir denetleyiciye sahip olamaz**.
* **Çocuk cgroups için denetleyiciler**, `cgroup.subtree_control` dosyasında açıkça belirtilmelidir. Örneğin, bir çocuk cgroup'ta CPU ve PID denetleyicilerini etkinleştirmek için:
```bash
echo "+cpu +pids" > cgroup.subtree_control
```
**Kök cgroup**, doğrudan işlem yerleşimi sağlayan bu kurallardan bir istisnadır. Bu, işlemleri systemd yönetiminden kaldırmak için kullanılabilir.

Bir cgroup içinde **CPU kullanımını izlemek**, toplam CPU süresinin tüketildiği `cpu.stat` dosyası aracılığıyla mümkündür, hizmetin alt işlemleri arasındaki kullanımı takip etmek için faydalıdır:

<figure><img src="../../../.gitbook/assets/image (908).png" alt=""><figcaption><p>CPU kullanım istatistikleri, cpu.stat dosyasında gösterildiği gibi</p></figcaption></figure>

## Referanslar

* **Kitap: How Linux Works, 3. Baskı: Her Süper Kullanıcının Bilmesi Gerekenler, Yazar: Brian Ward**
