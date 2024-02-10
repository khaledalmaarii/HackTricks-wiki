# CGroup Adı Alanı

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramanla öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklam vermek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek** katkıda bulunun.

</details>

## Temel Bilgiler

CGroup adı alanı, **bir ad alanı içinde çalışan süreçlerin cgroup hiyerarşilerini izole etme** sağlayan bir Linux çekirdek özelliğidir. Cgroups, **kontrol grupları** anlamına gelen bir çekirdek özelliğidir ve CPU, bellek ve I/O gibi **sistem kaynakları üzerinde sınırlamaları yönetmek ve uygulamak** için süreçleri hiyerarşik gruplara organize etmeyi sağlar.

Cgroup adı alanları, diğer ad alanı türleri (PID, mount, ağ vb.) gibi ayrı bir ad alanı türü değildir, ancak ad alanı izolasyonu kavramıyla ilişkilidir. **Cgroup adı alanları, cgroup hiyerarşisinin görünümünü sanallaştırır**, böylece cgroup adı alanında çalışan süreçler, ana bilgisayarda veya diğer ad alanlarında çalışan süreçlerle karşılaştırıldığında hiyerarşinin farklı bir görünümünü elde eder.

### Nasıl Çalışır:

1. Yeni bir cgroup adı alanı oluşturulduğunda, **oluşturan sürecin cgroup'una dayalı bir cgroup hiyerarşisi görünümüyle başlar**. Bu, yeni cgroup adı alanında çalışan süreçlerin, oluşturan sürecin cgroup'ının kökünde yer alan cgroup alt ağacıyla sınırlı olan tüm cgroup hiyerarşisinin bir alt kümesini göreceği anlamına gelir.
2. Bir cgroup adı alanı içindeki süreçler, **kendi cgroup'larını hiyerarşinin kökü olarak görürler**. Bu, ad alanı içindeki süreçlerin bakış açısından, kendi cgroup'ları kök olarak görünür ve kendi alt ağaçlarının dışındaki cgroup'ları göremez veya erişemezler.
3. Cgroup adı alanları, kaynakların doğrudan izolasyonunu sağlamaz; **yalnızca cgroup hiyerarşisi görünümünün izolasyonunu sağlar**. **Kaynak kontrolü ve izolasyonu, cgroup** alt sistemleri (örneğin, cpu, bellek vb.) tarafından hala uygulanır.

Daha fazla CGroups bilgisi için:

{% content-ref url="../cgroups.md" %}
[cgroups.md](../cgroups.md)
{% endcontent-ref %}

## Lab:

### Farklı Ad Alanları Oluşturma

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
`--mount-proc` parametresini kullanarak `/proc` dosya sisteminin yeni bir örneğini bağladığınızda, yeni bağlama alanının **o ad alanına özgü işlem bilgilerinin doğru ve izole bir görünümünü** sağlarsınız.

<details>

<summary>Hata: bash: fork: Bellek tahsis edilemedi</summary>

`unshare` komutu `-f` seçeneği olmadan çalıştırıldığında, Linux'un yeni PID (Process ID) ad alanlarını nasıl işlediği nedeniyle bir hata oluşur. Ana ayrıntılar ve çözüm aşağıda belirtilmiştir:

1. **Sorun Açıklaması**:
- Linux çekirdeği, bir işlemin `unshare` sistem çağrısını kullanarak yeni ad alanları oluşturmasına izin verir. Ancak, yeni bir PID ad alanının oluşturulmasını başlatan işlem (unshare işlemi olarak adlandırılır) yeni ad alanına girmez; sadece çocuk işlemleri girer.
- `%unshare -p /bin/bash%` komutunu çalıştırmak, `/bin/bash`'i `unshare` ile aynı işlemde başlatır. Sonuç olarak, `/bin/bash` ve çocuk işlemleri orijinal PID ad alanında bulunur.
- Yeni ad alanındaki `/bin/bash`'in ilk çocuk işlemi PID 1 olur. Bu işlem çıkış yaptığında, eğer başka işlem yoksa ad alanının temizlenmesini tetikler, çünkü PID 1 yetim işlemleri benimseme özel rolüne sahiptir. Linux çekirdeği daha sonra o ad alanında PID tahsisini devre dışı bırakır.

2. **Sonuç**:
- Yeni bir ad alanındaki PID 1'in çıkışı, `PIDNS_HASH_ADDING` bayrağının temizlenmesine neden olur. Bu, yeni bir işlem oluştururken `alloc_pid` işlevinin yeni bir PID tahsis edememesine ve "Bellek tahsis edilemedi" hatasının oluşmasına yol açar.

3. **Çözüm**:
- Sorun, `unshare` ile `-f` seçeneğini kullanarak çözülebilir. Bu seçenek, `unshare`'in yeni bir PID ad alanı oluşturduktan sonra yeni bir işlem çatallamasını sağlar.
- `%unshare -fp /bin/bash%` komutunu çalıştırmak, `unshare` komutunun kendisinin yeni ad alanında PID 1 haline gelmesini sağlar. `/bin/bash` ve çocuk işlemleri bu yeni ad alanında güvenli bir şekilde sınırlanır, PID 1'in erken çıkışını önler ve normal PID tahsisine izin verir.

`unshare` komutunun `-f` bayrağıyla çalıştığından emin olarak, yeni PID ad alanı doğru bir şekilde korunur ve `/bin/bash` ve alt işlemleri bellek tahsis hatasıyla karşılaşmadan çalışabilir.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Hangi ad alanında olduğunuzu kontrol edin

Bir sürecin hangi ad alanında olduğunu kontrol etmek için aşağıdaki komutu kullanabilirsiniz:

```bash
cat /proc/$$/cgroup
```

Bu komut, mevcut sürecin ad alanını gösteren bir çıktı verecektir. Ad alanı, `/sys/fs/cgroup` dizinindeki bir dosyada listelenir.
```bash
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### Tüm CGroup isim alanlarını bulun

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Bir CGroup ad alanına giriş yapın
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
Ayrıca, başka bir işlem ad alanına **yalnızca root olarak girebilirsiniz**. Ve başka bir ad alanına **bir tanımlayıcı olmadan** (örneğin `/proc/self/ns/cgroup`) **giremezsiniz**.

## Referanslar
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'da takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
