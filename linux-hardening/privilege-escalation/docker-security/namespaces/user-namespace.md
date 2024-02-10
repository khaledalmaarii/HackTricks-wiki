# Kullanıcı Ad Alanı

<details>

<summary><strong>AWS hackleme becerilerinizi sıfırdan ileri seviyeye taşıyın</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile</strong>!</summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek** katkıda bulunun.

</details>

## Temel Bilgiler

Kullanıcı ad alanı, Linux çekirdeğinin bir özelliğidir ve her bir kullanıcı ad alanının **kendi kullanıcı ve grup kimlik eşlemelerine izolasyon sağlar**, böylece her bir kullanıcı ad alanı **kendi kullanıcı ve grup kimliklerine sahip olabilir**. Bu izolasyon, aynı kullanıcı ve grup kimliklerini sayısal olarak paylaşsalar bile farklı kullanıcı ad alanlarında çalışan işlemlerin **farklı yetkilere ve sahipliklere sahip olmasını** sağlar.

Kullanıcı ad alanları, özellikle her bir konteynerin kendi bağımsız kullanıcı ve grup kimliklerine sahip olması gereken konteynerleştirme işlemlerinde kullanışlıdır. Bu, konteynerler ve ana sistem arasında daha iyi bir güvenlik ve izolasyon sağlar.

### Nasıl Çalışır:

1. Yeni bir kullanıcı ad alanı oluşturulduğunda, **boş bir kullanıcı ve grup kimlik eşlemesi kümesiyle başlar**. Bu, yeni kullanıcı ad alanında çalışan herhangi bir işlemin **başlangıçta ad alanı dışında hiçbir yetkiye sahip olmadığı** anlamına gelir.
2. Kimlik eşlemeleri, yeni ad alanındaki kullanıcı ve grup kimlikleri ile ebeveyn (veya ana) ad alanındaki kimlikler arasında kurulabilir. Bu, yeni ad alanındaki işlemlerin, ebeveyn ad alanındaki kullanıcı ve grup kimliklerine karşılık gelen yetkilere ve sahipliklere sahip olmasını sağlar. Bununla birlikte, kimlik eşlemeleri belirli aralıklara ve kimliklerin alt kümelerine kısıtlanabilir, böylece yeni ad alanındaki işlemlere verilen yetkiler üzerinde ince kontrol sağlanabilir.
3. Bir kullanıcı ad alanı içinde, işlemler ad alanı içindeki işlemler için tam kök yetkilerine (UID 0) sahip olabilirken, ad alanı dışında sınırlı yetkilere sahip olabilir. Bu, konteynerlerin kendi ad alanlarında tam kök yetkilerine sahip olmadan ana sistem üzerinde kök benzeri yeteneklerle çalışmasını sağlar.
4. İşlemler, `setns()` sistem çağrısı kullanılarak ad alanları arasında hareket edebilir veya `unshare()` veya `clone()` sistem çağrıları kullanılarak `CLONE_NEWUSER` bayrağıyla yeni ad alanları oluşturabilir. Bir işlem yeni bir ad alanına geçtiğinde veya bir ad alanı oluşturduğunda, o ad alanıyla ilişkilendirilen kullanıcı ve grup kimlik eşlemelerini kullanmaya başlar.

## Lab:

### Farklı Ad Alanları Oluşturma

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
`--mount-proc` parametresini kullanarak `/proc` dosya sisteminin yeni bir örneğini bağladığınızda, yeni bağlama alanının **o ad alanına özgü işlem bilgilerinin doğru ve izole bir görünümünü** sağlarsınız.

<details>

<summary>Hata: bash: fork: Bellek tahsis edilemedi</summary>

`unshare` komutu `-f` seçeneği olmadan çalıştırıldığında, Linux'un yeni PID (Process ID) ad alanlarını nasıl işlediği nedeniyle bir hata oluşur. Ana ayrıntılar ve çözüm aşağıda belirtilmiştir:

1. **Sorun Açıklaması**:
- Linux çekirdeği, bir işlemin `unshare` sistem çağrısını kullanarak yeni ad alanları oluşturmasına izin verir. Ancak, yeni bir PID ad alanının oluşturulmasını başlatan işlem (unshare işlemi olarak adlandırılır) yeni ad alanına girmemektedir; sadece çocuk işlemleri girer.
- `%unshare -p /bin/bash%` komutu `/bin/bash`'i `unshare` ile aynı işlemde başlatır. Sonuç olarak, `/bin/bash` ve çocuk işlemleri orijinal PID ad alanında bulunur.
- Yeni ad alanındaki `/bin/bash`'in ilk çocuk işlemi PID 1 olur. Bu işlem çıkış yaptığında, öksüz işlemleri devralma özel rolüne sahip olduğu için, başka işlem olmadığında ad alanının temizlenmesini tetikler. Linux çekirdeği o ad alanında PID tahsisini devre dışı bırakır.

2. **Sonuç**:
- Yeni bir ad alanındaki PID 1'in çıkışı, `PIDNS_HASH_ADDING` bayrağının temizlenmesine neden olur. Bu, yeni bir işlem oluştururken `alloc_pid` işlevinin yeni bir PID tahsis edememesine ve "Bellek tahsis edilemedi" hatasının oluşmasına yol açar.

3. **Çözüm**:
- Sorun, `unshare` ile `-f` seçeneğini kullanarak çözülebilir. Bu seçenek, yeni PID ad alanı oluşturduktan sonra `unshare`'in yeni bir işlem çatallamasını sağlar.
- `%unshare -fp /bin/bash%` komutunu çalıştırmak, `unshare` komutunun kendisinin yeni ad alanında PID 1 haline gelmesini sağlar. `/bin/bash` ve çocuk işlemleri bu yeni ad alanında güvenli bir şekilde yer alır, PID 1'in erken çıkışını önler ve normal PID tahsisine izin verir.

`unshare` komutunun `-f` bayrağıyla çalıştığından emin olarak, yeni PID ad alanı doğru bir şekilde korunur ve `/bin/bash` ve alt işlemleri bellek tahsis hatasıyla karşılaşmadan çalışabilir.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
Kullanıcı ad alanını kullanmak için Docker daemon'ı **`--userns-remap=default`** ile başlatılmalıdır (Ubuntu 14.04'te, bunu `/etc/default/docker` dosyasını düzenleyerek ve ardından `sudo service docker restart` komutunu çalıştırarak yapabilirsiniz).

### &#x20;Hangi ad alanında olduğunuzu kontrol edin
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
Docker konteynerinden kullanıcı haritasını kontrol etmek mümkündür:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
Veya aşağıdaki komutu kullanarak ana makineden:
```bash
cat /proc/<pid>/uid_map
```
### Tüm Kullanıcı ad alanlarını bulun

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Bir Kullanıcı ad alanına giriş yapın

{% endcode %}
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
Ayrıca, yalnızca kök kullanıcıysanız başka bir işlem ad alanına **girebilirsiniz**. Ve başka bir ad alanına **bir tanımlayıcı** (örneğin `/proc/self/ns/user`) olmadan **giremezsiniz**.

### Yeni Kullanıcı ad alanı oluşturma (eşlemelerle)

{% code overflow="wrap" %}
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```
{% endcode %}
```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### Yetenekleri Kurtarma

Kullanıcı ad alanları durumunda, **yeni bir kullanıcı ad alanı oluşturulduğunda, ad alanına giren işlem, bu ad alanı içinde tam bir yetenek kümesine sahip olur**. Bu yetenekler, işlemin ayrıcalıklı işlemler yapmasına olanak tanır, örneğin **dosya sistemlerini bağlama**, cihazlar oluşturma veya dosyaların sahipliğini değiştirme, ancak **yalnızca kullanıcı ad alanının bağlamı içinde**.

Örneğin, bir kullanıcı ad alanı içinde `CAP_SYS_ADMIN` yeteneğine sahip olduğunuzda, bu yeteneği gerektiren işlemleri gerçekleştirebilirsiniz, örneğin dosya sistemlerini bağlama, ancak yalnızca kullanıcı ad alanınızın bağlamı içinde. Bu yetenekle gerçekleştirdiğiniz işlemler ana sistem veya diğer ad alanlarını etkilemez.

{% hint style="warning" %}
Bu nedenle, yeni bir işlemi yeni bir Kullanıcı ad alanına yerleştirmek **tüm yetenekleri geri getirse de** (CapEff: 000001ffffffffff), aslında **yalnızca ad alanıyla ilgili olanları kullanabilirsiniz** (örneğin bağlama). Bu tek başına bir Docker konteynerinden kaçmak için yeterli değildir.
{% endhint %}
```bash
# There are the syscalls that are filtered after changing User namespace with:
unshare -UmCpf  bash

Probando: 0x067 . . . Error
Probando: 0x070 . . . Error
Probando: 0x074 . . . Error
Probando: 0x09b . . . Error
Probando: 0x0a3 . . . Error
Probando: 0x0a4 . . . Error
Probando: 0x0a7 . . . Error
Probando: 0x0a8 . . . Error
Probando: 0x0aa . . . Error
Probando: 0x0ab . . . Error
Probando: 0x0af . . . Error
Probando: 0x0b0 . . . Error
Probando: 0x0f6 . . . Error
Probando: 0x12c . . . Error
Probando: 0x130 . . . Error
Probando: 0x139 . . . Error
Probando: 0x140 . . . Error
Probando: 0x141 . . . Error
Probando: 0x143 . . . Error
```
## Referanslar
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
