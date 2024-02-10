# Ağ Ad Alanı

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünleri**](https://peass.creator-spring.com)'ni edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek** paylaşın.

</details>

## Temel Bilgiler

Ağ ad alanı, Linux çekirdeğinin bir özelliğidir ve ağ yığınının izolasyonunu sağlar, böylece **her ağ ad alanının kendi bağımsız ağ yapılandırmasına**, arayüzlerine, IP adreslerine, yönlendirme tablolarına ve güvenlik duvarı kurallarına sahip olmasını sağlar. Bu izolasyon, her bir konteynerin diğer konteynerlerden ve ana sistemden bağımsız olarak kendi ağ yapılandırmasına sahip olması gereken konteynerleştirme gibi çeşitli senaryolarda faydalıdır.

### Nasıl Çalışır:

1. Yeni bir ağ ad alanı oluşturulduğunda, **tamamen izole edilmiş bir ağ yığını** ile başlar ve döngü arayüzü (lo) hariç **hiçbir ağ arayüzü** bulunmaz. Bu, yeni ağ ad alanında çalışan işlemlerin varsayılan olarak diğer ad alanlarındaki veya ana sistemdeki işlemlerle iletişim kuramayacağı anlamına gelir.
2. veth çiftleri gibi **sanal ağ arayüzleri**, ağ ad alanları arasında veya bir ad alanı ile ana sistem arasında ağ bağlantısı kurmak için oluşturulabilir ve taşınabilir. Örneğin, bir veth çiftinin bir ucu bir konteynerin ağ ad alanına yerleştirilebilir ve diğer ucu köprüye veya ana ad alanındaki başka bir ağ arayüzüne bağlanarak konteynere ağ bağlantısı sağlanabilir.
3. Bir ad alanı içindeki ağ arayüzleri, diğer ad alanlarından bağımsız olarak **kendi IP adreslerine, yönlendirme tablolarına ve güvenlik duvarı kurallarına** sahip olabilir. Bu, farklı ağ ad alanlarındaki işlemlerin farklı ağ yapılandırmalarına sahip olmasını ve ayrı ağ sistemlerinde çalışıyormuş gibi çalışmasını sağlar.
4. İşlemler, `setns()` sistem çağrısı kullanılarak ad alanları arasında taşınabilir veya `unshare()` veya `clone()` sistem çağrıları kullanılarak `CLONE_NEWNET` bayrağı ile yeni ad alanları oluşturabilir. Bir işlem yeni bir ad alanına taşındığında veya oluşturulduğunda, o ad alanıyla ilişkili ağ yapılandırmasını ve arayüzleri kullanmaya başlar.

## Lab:

### Farklı Ad Alanları Oluşturma

#### CLI
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
```
`--mount-proc` parametresini kullanarak `/proc` dosya sisteminin yeni bir örneğini bağladığınızda, yeni bağlama alanının **o ad alanına özgü işlem bilgilerinin doğru ve izole bir görünümünü** sağlarsınız.

<details>

<summary>Hata: bash: fork: Bellek tahsis edilemedi</summary>

`unshare` komutu `-f` seçeneği olmadan çalıştırıldığında, Linux'un yeni PID (Process ID) ad alanlarını nasıl işlediği nedeniyle bir hata oluşur. Ana ayrıntılar ve çözüm aşağıda belirtilmiştir:

1. **Sorun Açıklaması**:
- Linux çekirdeği, bir işlemin `unshare` sistem çağrısını kullanarak yeni ad alanları oluşturmasına izin verir. Ancak, yeni bir PID ad alanının oluşturulmasını başlatan işlem (unshare işlemi olarak adlandırılır) yeni ad alanına girmemektedir; sadece çocuk işlemleri girer.
- `%unshare -p /bin/bash%` komutu, `/bin/bash`'i `unshare` ile aynı işlemde başlatır. Sonuç olarak, `/bin/bash` ve çocuk işlemleri orijinal PID ad alanında bulunur.
- Yeni ad alanındaki `/bin/bash`'in ilk çocuk işlemi PID 1 olur. Bu işlem çıkış yaptığında, eğer başka işlem yoksa ad alanının temizlenmesini tetikler, çünkü PID 1 yetim işlemleri sahiplenme özel rolüne sahiptir. Linux çekirdeği daha sonra o ad alanında PID tahsisini devre dışı bırakır.

2. **Sonuç**:
- Yeni bir ad alanındaki PID 1'in çıkışı, `PIDNS_HASH_ADDING` bayrağının temizlenmesine yol açar. Bu, yeni bir işlem oluştururken `alloc_pid` işlevinin yeni bir PID tahsis edememesine ve "Bellek tahsis edilemedi" hatasının oluşmasına neden olur.

3. **Çözüm**:
- Sorun, `unshare` ile `-f` seçeneğini kullanarak çözülebilir. Bu seçenek, `unshare`'in yeni bir PID ad alanı oluşturduktan sonra yeni bir işlem çatallamasını sağlar.
- `%unshare -fp /bin/bash%` komutunu çalıştırmak, `unshare` komutunun kendisinin yeni ad alanında PID 1 haline gelmesini sağlar. `/bin/bash` ve çocuk işlemleri bu yeni ad alanında güvenli bir şekilde sınırlanır, PID 1'in erken çıkışını önler ve normal PID tahsisine izin verir.

`unshare` komutunun `-f` bayrağıyla çalıştığından emin olarak, yeni PID ad alanı doğru bir şekilde korunur ve `/bin/bash` ve alt işlemleri bellek tahsis hatasıyla karşılaşmadan çalışabilir.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
# Run ifconfig or ip -a
```
### &#x20;Hangi ad alanında olduğunuzu kontrol edin

Bir sürecin hangi ad alanında olduğunu kontrol etmek için aşağıdaki komutu kullanabilirsiniz:

```bash
ls -l /proc/<PID>/ns/
```

Burada `<PID>`, kontrol etmek istediğiniz sürecin kimlik numarasını temsil eder. Bu komut, sürecin bulunduğu ad alanlarının sembolik bağlantılarını listeler.
```bash
ls -l /proc/self/ns/net
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/net -> 'net:[4026531840]'
```
### Tüm Ağ isim alanlarını bulun

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name net -exec readlink {} \; 2>/dev/null | sort -u | grep "net:"
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name net -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Bir Ağ ad alanına giriş yapın

{% endcode %}
```bash
nsenter -n TARGET_PID --pid /bin/bash
```
Ayrıca, başka bir işlem ad alanına **yalnızca root olarak girebilirsiniz**. Ve başka bir ad alanına **bir tanımlayıcı olmadan** (örneğin `/proc/self/ns/net`) **giremezsiniz**.

## Referanslar
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmaya kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
