# CGroups

{% hint style="success" %}
AWS Hacking'ı öğrenin ve uygulayın: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitimi AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitimi GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'ı Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak PR'ler göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}

## Temel Bilgiler

**Linux Kontrol Grupları**, veya **cgroups**, Linux çekirdeğinin bir özelliğidir ve CPU, bellek ve disk G/Ç gibi sistem kaynaklarının süreç grupları arasında tahsisini, sınırlamasını ve önceliklendirmesini sağlar. **Süreç koleksiyonlarının kaynak kullanımını yönetme ve izole etme** mekanizması sunar, kaynak sınırlaması, iş yükü izolasyonu ve farklı süreç grupları arasında kaynak önceliklendirmesi gibi amaçlar için faydalıdır.

**Cgroups'ın iki versiyonu** bulunmaktadır: versiyon 1 ve versiyon 2. Her ikisi de aynı anda bir sistemde kullanılabilir. Temel fark, **cgroups versiyon 2**'nin **hiyerarşik, ağaç benzeri bir yapı** getirmesidir, süreç grupları arasında daha nüanslı ve detaylı kaynak dağıtımını sağlar. Ayrıca, versiyon 2, şunları içeren çeşitli iyileştirmeler getirir:

Yeni hiyerarşik organizasyonun yanı sıra, cgroups versiyon 2 ayrıca **birkaç diğer değişiklik ve iyileştirmeyi** de tanıttı, yeni kaynak denetleyicilerini destekleme, eski uygulamalar için daha iyi destek ve geliştirilmiş performans dahil.

Genel olarak, cgroups **versiyon 2, versiyon 1'den daha fazla özellik ve daha iyi performans** sunar, ancak eski sistemlerle uyumluluk endişesi varsa hala versiyon 1 kullanılabilir.

Herhangi bir sürecin v1 ve v2 cgroups'larını görmek için /proc/\<pid> dizinindeki cgroup dosyasına bakarak listeyebilirsiniz. Kabuğunuzun cgroups'larını görmek için bu komutu kullanarak başlayabilirsiniz:
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
* **Sayılar 2-12**: cgroups v1'i temsil eder, her satır farklı bir cgroup'u belirtir. Bu denetleyiciler sayıların yanında belirtilir.
* **Sayı 1**: Ayrıca cgroups v1'i temsil eder, ancak yalnızca yönetim amaçlıdır (örneğin, systemd tarafından belirlenir) ve bir denetleyici içermez.
* **Sayı 0**: cgroups v2'yi temsil eder. Denetleyiciler listelenmez ve bu satır yalnızca cgroups v2 çalıştıran sistemlerde bulunur.
* **İsimler hiyerarşiktir**, dosya yollarını andırır ve farklı cgroup'lar arasındaki yapıyı ve ilişkiyi gösterir.
* **/user.slice veya /system.slice** gibi isimler, cgroup'ların kategorizasyonunu belirtir; user.slice genellikle systemd tarafından yönetilen oturumlar için ve system.slice sistem hizmetleri için kullanılır.

### Cgroup'ları Görüntüleme

Dosya sistemi genellikle **cgroup'lara** erişmek için kullanılır ve geleneksel olarak çekirdek etkileşimleri için kullanılan Unix sistem çağrı arayüzünden farklıdır. Bir kabuğun cgroup yapılandırmasını incelemek için, bir kişinin kabuğunun cgroup'unu ortaya koyan **/proc/self/cgroup** dosyasına bakılmalıdır. Ardından, **/sys/fs/cgroup** (veya **`/sys/fs/cgroup/unified`**) dizinine gidilerek, cgroup'un adını paylaşan bir dizin bulunarak, cgroup'a ilişkin çeşitli ayarları ve kaynak kullanımı bilgilerini gözlemlemek mümkündür.

![Cgroup Dosya Sistemi](<../../../.gitbook/assets/image (1128).png>)

Cgroup'lar için ana arayüz dosyaları **cgroup** ile başlar. Standart komutlar gibi görüntülenebilen **cgroup.procs** dosyası, cgroup içindeki işlemleri listeler. Başka bir dosya olan **cgroup.threads**, iş parçacığı bilgilerini içerir.

![Cgroup Procs](<../../../.gitbook/assets/image (281).png>)

Kabukları yöneten cgroup'lar genellikle bellek kullanımını ve işlem sayısını düzenleyen iki denetleyiciyi kapsar. Bir denetleyici ile etkileşime geçmek için, denetleyicinin ön ekini taşıyan dosyalar incelenmelidir. Örneğin, **pids.current** ifadesi, cgroup içindeki iş parçacığı sayısını belirlemek için başvurulabilir.

![Cgroup Bellek](<../../../.gitbook/assets/image (677).png>)

Bir değerde **max** belirtildiğinde, cgroup için belirli bir sınır olmadığını gösterir. Ancak, cgroup'ların hiyerarşik yapısı nedeniyle, sınırlar dizin hiyerarşisinde daha düşük bir seviyede bir cgroup tarafından uygulanmış olabilir.

### Cgroup'ları Manipüle Etme ve Oluşturma

İşlemler, **Process ID'lerini (PID) `cgroup.procs` dosyasına yazarak** cgroup'lara atanır. Bunun için kök ayrıcalıkları gereklidir. Örneğin, bir işlem eklemek için:
```bash
echo [pid] > cgroup.procs
```
Benzer şekilde, **bir PID sınırı belirlemek gibi cgroup özelliklerini değiştirmek**, ilgili dosyaya istenilen değeri yazarak yapılır. Bir cgroup için maksimum 3,000 PID belirlemek için:
```bash
echo 3000 > pids.max
```
**Yeni cgroups oluşturma**, cgroup hiyerarşisi içinde yeni bir alt dizin oluşturmayı içerir, bu da çekirdeği gerekli arayüz dosyalarını otomatik olarak oluşturmaya zorlar. Etkin olmayan işlem olmayan cgroups `rmdir` ile kaldırılabilir, ancak belirli kısıtlamalara dikkat edilmelidir:

- **İşlemler yalnızca yaprak cgroups içine yerleştirilebilir** (yani, hiyerarşide en içte olanlar).
- **Bir cgroup, ebeveyninde bulunmayan bir denetleyiciye sahip olamaz**.
- **Çocuk cgroups için denetleyiciler**, `cgroup.subtree_control` dosyasında açıkça belirtilmelidir. Örneğin, bir çocuk cgroup'ta CPU ve PID denetleyicilerini etkinleştirmek için:
```bash
echo "+cpu +pids" > cgroup.subtree_control
```
**Kök cgroup**, bu kurallardan bir istisnadır ve doğrudan işlem yerleştirme izni verir. Bu, işlemleri systemd yönetiminden kaldırmak için kullanılabilir.

Bir cgroup içinde **CPU kullanımını izlemek** mümkündür, toplam CPU süresini gösteren `cpu.stat` dosyası, bir hizmetin alt işlemleri arasındaki kullanımı takip etmek için faydalıdır:

<figure><img src="../../../.gitbook/assets/image (908).png" alt=""><figcaption><p>cpu.stat dosyasında gösterilen CPU kullanım istatistikleri</p></figcaption></figure>

## Referanslar

* **Kitap: How Linux Works, 3. Baskı: Her Süper Kullanıcının Bilmesi Gerekenler - Brian Ward**
