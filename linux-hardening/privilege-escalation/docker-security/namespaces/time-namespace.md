# Zaman Ad Alanı

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramanla öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'u** takip edin.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek** paylaşın.

</details>

## Temel Bilgiler

Linux'taki zaman ad alanı, ad alanı başına sistem monotonic ve boot-time saatlerine göre ofsetler sağlar. Linux konteynerlarında yaygın olarak kullanılır, böylece bir konteyner içinde tarih/saat değiştirilebilir ve bir kontrol noktasından veya anlık görüntüden geri yüklendikten sonra saatler ayarlanabilir.

## Lab:

### Farklı Ad Alanları Oluşturma

#### CLI
```bash
sudo unshare -T [--mount-proc] /bin/bash
```
`--mount-proc` parametresini kullanarak `/proc` dosya sisteminin yeni bir örneğini bağladığınızda, yeni bağlama alanının **o ad alanına özgü işlem bilgilerinin doğru ve izole bir görünümünü** sağlarsınız.

<details>

<summary>Hata: bash: fork: Bellek tahsis edilemedi</summary>

`unshare` komutu `-f` seçeneği olmadan çalıştırıldığında, Linux'un yeni PID (Process ID) ad alanlarını nasıl işlediği nedeniyle bir hata oluşur. Ana ayrıntılar ve çözüm aşağıda belirtilmiştir:

1. **Sorun Açıklaması**:
- Linux çekirdeği, bir işlemin `unshare` sistem çağrısını kullanarak yeni ad alanları oluşturmasına izin verir. Ancak, yeni bir PID ad alanının oluşturulmasını başlatan işlem (unshare işlemi olarak adlandırılır) yeni ad alanına girmemektedir; sadece çocuk işlemleri girer.
- `%unshare -p /bin/bash%` komutu, `/bin/bash`'i `unshare` ile aynı işlemde başlatır. Sonuç olarak, `/bin/bash` ve çocuk işlemleri orijinal PID ad alanında bulunur.
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
cat /proc/$$/ns/* | awk '{print $NF}' | xargs -I{} readlink -f {}
```

Bu komut, mevcut sürecin bulunduğu ad alanlarını listeler.
```bash
ls -l /proc/self/ns/time
lrwxrwxrwx 1 root root 0 Apr  4 21:16 /proc/self/ns/time -> 'time:[4026531834]'
```
### Tüm Zaman ad alanlarını bulun

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name time -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name time -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Bir Zaman ad alanına giriş yapın
```bash
nsenter -T TARGET_PID --pid /bin/bash
```
Ayrıca, başka bir süreç ad alanına **yalnızca root olarak girebilirsiniz**. Ve başka bir ad alanına **bir tanımlayıcı olmadan** (örneğin `/proc/self/ns/net`) **giremezsiniz**.

## Referanslar
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
* [https://www.phoronix.com/news/Linux-Time-Namespace-Coming](https://www.phoronix.com/news/Linux-Time-Namespace-Coming)

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
