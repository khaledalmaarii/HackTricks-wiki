# UTS Ad Alanı

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramanla öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimizden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'u** takip edin.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek** paylaşın.

</details>

## Temel Bilgiler

UTS (UNIX Time-Sharing System) ad alanı, Linux çekirdeğinin bir özelliğidir ve iki sistem tanımlayıcısının (hostname ve NIS (Network Information Service) etki alanı adı) **izolasyonunu sağlar**. Bu izolasyon, her UTS ad alanının **kendi bağımsız hostname ve NIS etki alanı adına** sahip olmasını sağlar. Bu özellik, her bir konteynerin kendi hostname'una sahip ayrı bir sistem gibi görünmesi gereken konteynerleştirme senaryolarında özellikle kullanışlıdır.

### Nasıl Çalışır:

1. Yeni bir UTS ad alanı oluşturulduğunda, **ebeveyn ad alanından hostname ve NIS etki alanı adının bir kopyasıyla başlar**. Bu, yeni ad alanının oluşturulduğunda, yeni ad alanının **ebeveyniyle aynı tanımlayıcılara sahip olduğu** anlamına gelir. Ancak, ad alanı içindeki hostname veya NIS etki alanı adında yapılan herhangi bir sonraki değişiklik, diğer ad alanlarını etkilemez.
2. UTS ad alanı içindeki işlemler, sırasıyla `sethostname()` ve `setdomainname()` sistem çağrılarını kullanarak **hostname ve NIS etki alanı adını değiştirebilir**. Bu değişiklikler, ad alanına özgüdür ve diğer ad alanlarını veya ana sistemini etkilemez.
3. İşlemler, `setns()` sistem çağrısını kullanarak ad alanları arasında hareket edebilir veya `unshare()` veya `clone()` sistem çağrılarını `CLONE_NEWUTS` bayrağıyla kullanarak yeni ad alanları oluşturabilir. Bir işlem yeni bir ad alanına geçtiğinde veya bir ad alanı oluşturduğunda, o ad alanıyla ilişkilendirilen hostname ve NIS etki alanı adını kullanmaya başlar.

## Lab:

### Farklı Ad Alanları Oluşturma

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
`--mount-proc` parametresini kullanarak `/proc` dosya sisteminin yeni bir örneğini bağladığınızda, yeni bağlama alanının **o ad alanına özgü işlem bilgilerinin doğru ve izole bir görünümünü** sağlarsınız.

<details>

<summary>Hata: bash: fork: Bellek tahsis edilemiyor</summary>

`unshare` komutu `-f` seçeneği olmadan çalıştırıldığında, Linux'un yeni PID (İşlem Kimliği) ad alanlarını nasıl işlediği nedeniyle bir hata oluşur. Ana ayrıntılar ve çözüm aşağıda belirtilmiştir:

1. **Sorun Açıklaması**:
- Linux çekirdeği, bir işlemin `unshare` sistem çağrısını kullanarak yeni ad alanları oluşturmasına izin verir. Ancak, yeni bir PID ad alanının oluşturulmasını başlatan işlem (unshare işlemi olarak adlandırılır) yeni ad alanına girmemektedir; sadece çocuk işlemleri girer.
- `%unshare -p /bin/bash%` komutu, `/bin/bash`'i `unshare` ile aynı işlemde başlatır. Sonuç olarak, `/bin/bash` ve çocuk işlemleri orijinal PID ad alanında bulunur.
- Yeni ad alanındaki `/bin/bash`'in ilk çocuk işlemi PID 1 olur. Bu işlem çıkış yaptığında, eğer başka işlem yoksa ad alanının temizlenmesini tetikler, çünkü PID 1 yetim işlemleri sahiplenme özel rolüne sahiptir. Linux çekirdeği daha sonra o ad alanında PID tahsisini devre dışı bırakır.

2. **Sonuç**:
- Yeni bir ad alanındaki PID 1'in çıkışı, `PIDNS_HASH_ADDING` bayrağının temizlenmesine neden olur. Bu, yeni bir işlem oluştururken `alloc_pid` işlevinin yeni bir PID tahsis edememesine ve "Bellek tahsis edilemiyor" hatasının oluşmasına yol açar.

3. **Çözüm**:
- Sorun, `unshare` ile `-f` seçeneğini kullanarak çözülebilir. Bu seçenek, `unshare`'in yeni PID ad alanı oluşturduktan sonra yeni bir işlem çatallamasını sağlar.
- `%unshare -fp /bin/bash%` komutunu çalıştırmak, `unshare` komutunun kendisinin yeni ad alanında PID 1 haline gelmesini sağlar. `/bin/bash` ve çocuk işlemleri bu yeni ad alanında güvenli bir şekilde sınırlanır, PID 1'in erken çıkışını önler ve normal PID tahsisine izin verir.

`unshare` komutunun `-f` bayrağıyla çalıştığından emin olarak, yeni PID ad alanı doğru bir şekilde korunur ve `/bin/bash` ve alt işlemleri bellek tahsis hatasıyla karşılaşmadan çalışabilir.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Hangi ad alanında olduğunuzu kontrol edin

Bir işlemin hangi ad alanında olduğunu kontrol etmek için aşağıdaki komutu kullanabilirsiniz:

```bash
$ cat /proc/$$/ns/uts
```

Bu komut, işlem kimliği (`$$`) kullanılarak `/proc` dosya sistemi altındaki `ns/uts` dosyasını okur. Çıktı, işlemin hangi ad alanında olduğunu gösterir.
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Tüm UTS isim alanlarını bulun

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Bir UTS ad alanına giriş yapma

{% endcode %}
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
Ayrıca, yalnızca root kullanıcısıysanız **başka bir işlem ad alanına girebilirsiniz**. Ve **/proc/self/ns/uts** gibi bir tanımlayıcıya sahip olmadan **başka bir ad alanına giremezsiniz**.

### Host adını değiştirme
```bash
unshare -u /bin/bash
hostname newhostname # Hostname won't be changed inside the host UTS ns
```
## Referanslar
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** isterseniz [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
