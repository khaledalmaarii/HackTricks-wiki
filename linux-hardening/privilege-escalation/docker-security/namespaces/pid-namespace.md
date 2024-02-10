# PID Ad Alanı

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramanla öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## Temel Bilgiler

PID (Process IDentifier) ad alanı, Linux çekirdeğinde bir özelliktir ve diğer ad alanlarındaki PID'lerden bağımsız olarak bir grup işlemin kendi benzersiz PID kümesine sahip olmasını sağlayarak işlem izolasyonu sağlar. Bu, özellikle güvenlik ve kaynak yönetimi için işlem izolasyonunun önemli olduğu konteynerleştirme durumlarında kullanışlıdır.

Yeni bir PID ad alanı oluşturulduğunda, bu ad alanındaki ilk işleme PID 1 atanır. Bu işlem, yeni ad alanının "init" işlemi olur ve ad alanı içindeki diğer işlemleri yönetmekten sorumludur. Ad alanı içinde oluşturulan her bir sonraki işlem, bu ad alanı içinde benzersiz bir PID'ye sahip olacak ve bu PID'ler diğer ad alanlarındaki PID'lerden bağımsız olacaktır.

Bir PID ad alanı içindeki bir işlem açısından, yalnızca aynı ad alanındaki diğer işlemleri görebilir. Diğer ad alanlarındaki işlemlerden haberdar değildir ve geleneksel işlem yönetimi araçlarını (örneğin, `kill`, `wait`, vb.) kullanarak bunlarla etkileşime geçemez. Bu, işlemlerin birbirleriyle etkileşimini engelleyen bir izolasyon seviyesi sağlar.

### Nasıl Çalışır:

1. Yeni bir işlem oluşturulduğunda (örneğin, `clone()` sistem çağrısı kullanılarak), işlem yeni veya mevcut bir PID ad alanına atanabilir. **Yeni bir ad alanı oluşturulursa, işlem bu ad alanının "init" işlemi olur**.
2. **Çekirdek**, yeni ad alanındaki PID'ler ile ebeveyn ad alanındaki karşılık gelen PID'ler arasında bir **eşleme tutar** (yani, yeni ad alanının oluşturulduğu ad alan). Bu eşleme, PID'leri gerektiğinde çevirmek için çekirdeğe olanak sağlar, örneğin farklı ad alanlarındaki işlemler arasında sinyal gönderirken.
3. **PID ad alanı içindeki işlemler yalnızca aynı ad alanındaki diğer işlemleri görebilir ve bunlarla etkileşime geçebilir**. Diğer ad alanlarındaki işlemlerden haberdar değillerdir ve PID'leri kendi ad alanları içinde benzersizdir.
4. Bir **PID ad alanı yok edildiğinde** (örneğin, ad alanının "init" işlemi çıkış yaptığında), **o ad alanı içindeki tüm işlemler sonlandırılır**. Bu, ad alanıyla ilişkili tüm kaynakların düzgün bir şekilde temizlendiğini sağlar.

## Lab:

### Farklı Ad Alanları Oluşturma

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Hata: bash: fork: Bellek tahsis edilemiyor</summary>

`unshare` komutu `-f` seçeneği olmadan çalıştırıldığında, Linux'un yeni PID (Process ID) namespace'leri nasıl işlediği nedeniyle bir hata oluşur. Ana detaylar ve çözüm aşağıda belirtilmiştir:

1. **Sorun Açıklaması**:
- Linux çekirdeği, bir işlemin `unshare` sistem çağrısını kullanarak yeni namespace'ler oluşturmasına izin verir. Ancak, yeni bir PID namespace'inin oluşturulmasını başlatan işlem (unshare işlemi olarak adlandırılır) yeni namespace'e girmemektedir; sadece çocuk işlemleri girmektedir.
- `%unshare -p /bin/bash%` komutu, `/bin/bash`'i `unshare` ile aynı işlemde başlatır. Sonuç olarak, `/bin/bash` ve çocuk işlemleri orijinal PID namespace'inde bulunur.
- Yeni namespace'deki `/bin/bash`'in ilk çocuk işlemi PID 1 olur. Bu işlem çıkış yaptığında, eğer başka işlem yoksa, namespace'in temizlenmesini tetikler. Çünkü PID 1 yetim işlemleri sahiplenme özel rolüne sahiptir. Linux çekirdeği, o namespace'de PID tahsisini devre dışı bırakır.

2. **Sonuç**:
- Yeni bir namespace'deki PID 1'in çıkışı, `PIDNS_HASH_ADDING` bayrağının temizlenmesine neden olur. Bu, yeni bir işlem oluştururken `alloc_pid` fonksiyonunun yeni bir PID tahsis edememesine ve "Bellek tahsis edilemiyor" hatasının oluşmasına yol açar.

3. **Çözüm**:
- Sorun, `unshare` komutunu `-f` seçeneğiyle kullanarak çözülebilir. Bu seçenek, `unshare`'in yeni bir PID namespace oluşturduktan sonra yeni bir işlem çatallamasını sağlar.
- `%unshare -fp /bin/bash%` komutunu çalıştırmak, `unshare` komutunun kendisinin yeni namespace'de PID 1 olmasını sağlar. `/bin/bash` ve çocuk işlemleri bu yeni namespace içinde güvenli bir şekilde yer alır, PID 1'in erken çıkışını engeller ve normal PID tahsisine izin verir.

`unshare` komutunun `-f` bayrağıyla çalıştığından emin olarak, yeni PID namespace'inin doğru bir şekilde korunduğundan ve `/bin/bash` ve alt işlemlerinin bellek tahsis hatasıyla karşılaşmadan çalışmasına izin verilir.

</details>

`--mount-proc` parametresini kullanarak `/proc` dosya sisteminin yeni bir örneğini bağladığınızda, yeni mount namespace'inin **o namespace'e özgü işlem bilgilerinin doğru ve izole bir görünümünü** sağlamış olursunuz.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Hangi ad alanında olduğunuzu kontrol edin

Bir sürecin hangi ad alanında olduğunu kontrol etmek için aşağıdaki komutu kullanabilirsiniz:

```bash
ls -l /proc/<PID>/ns
```

Burada `<PID>`, ad alanını kontrol etmek istediğiniz sürecin kimlik numarasını temsil eder. Bu komutu çalıştırdığınızda, sürecin PID ad alanı hakkında bilgi içeren bir dizi sembolik bağlantı göreceksiniz.

Örneğin, PID'si 123 olan bir sürecin ad alanlarını kontrol etmek için aşağıdaki komutu kullanabilirsiniz:

```bash
ls -l /proc/123/ns
```

Bu komutu çalıştırdığınızda, sürecin PID ad alanı hakkında bilgi içeren sembolik bağlantıları göreceksiniz.
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Tüm PID ad alanlarını bulun

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
{% endcode %}

Not: İlk (varsayılan) PID ad alanından kök kullanıcısı, yeni PID ad alanlarındaki süreçleri bile görebilir, bu yüzden tüm PID ad alanlarını görebiliriz.

### Bir PID ad alanına giriş yapma
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
PID ad alanına varsayılan ad alanından girdiğinizde, hala tüm işlemleri görebilirsiniz. Ve PID ad alanındaki işlem, PID ad alanındaki yeni bash'i görebilir.

Ayrıca, **yalnızca kök kullanıcıysanız başka bir işlem PID ad alanına girebilirsiniz**. Ve **/proc/self/ns/pid** gibi ona işaret eden bir tanımlayıcı olmadan **başka bir ad alana giremezsiniz**.

## Referanslar
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
