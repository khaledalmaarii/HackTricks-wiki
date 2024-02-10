# Mount Namespace

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramanla öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'u** takip edin.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek** paylaşın.

</details>

## Temel Bilgiler

Bir mount namespace, bir grup işlem tarafından görülen dosya sistemi bağlama noktalarının izolasyonunu sağlayan bir Linux çekirdek özelliğidir. Her mount namespace'in kendi dosya sistemi bağlama noktaları kümesi vardır ve **bir namespace içindeki bağlama noktalarına yapılan değişiklikler diğer namespace'leri etkilemez**. Bu, farklı mount namespace'lerde çalışan işlemlerin dosya sistemi hiyerarşisinin farklı görüntülerine sahip olabileceği anlamına gelir.

Mount namespace'ler, her bir konteynerin diğer konteynerlerden ve ana sistemden izole edilmiş kendi dosya sistemi ve yapılandırmasına sahip olması gereken konteynerleştirme gibi durumlarda özellikle kullanışlıdır.

### Nasıl Çalışır:

1. Yeni bir mount namespace oluşturulduğunda, **ebeveyn namespace'inin bağlama noktalarının bir kopyası ile başlatılır**. Bu, oluşturulduğunda yeni namespace'in ebeveyniyle aynı dosya sistemi görüntüsünü paylaştığı anlamına gelir. Bununla birlikte, namespace içindeki bağlama noktalarına yapılan herhangi bir sonraki değişiklik, ebeveyni veya diğer namespace'leri etkilemeyecektir.
2. Bir işlem, kendi namespace'i içinde bir bağlama noktasını değiştirdiğinde, örneğin bir dosya sistemi bağlama veya çıkarma yaptığında, **değişiklik yalnızca o namespace'e özgüdür** ve diğer namespace'leri etkilemez. Bu, her bir namespace'in kendi bağımsız dosya sistemi hiyerarşisine sahip olmasını sağlar.
3. İşlemler, `setns()` sistem çağrısını kullanarak namespace'ler arasında hareket edebilir veya `unshare()` veya `clone()` sistem çağrılarını `CLONE_NEWNS` bayrağıyla kullanarak yeni namespace'ler oluşturabilir. Bir işlem yeni bir namespace'e geçer veya bir tane oluşturursa, o namespace ile ilişkilendirilen bağlama noktalarını kullanmaya başlar.
4. **Dosya tanımlayıcıları ve inode'lar namespace'ler arasında paylaşılır**, bu da bir namespace'deki bir işlemin bir dosyaya işaret eden açık bir dosya tanımlayıcısına sahip olduğu durumda, bu dosya tanımlayıcısını başka bir namespace'deki bir işleme **geçirebileceği** ve **her iki işlemin aynı dosyaya erişeceği** anlamına gelir. Bununla birlikte, dosyanın yolu bağlama noktalarındaki farklılıklar nedeniyle her iki namespace'de aynı olmayabilir. 

## Lab:

### Farklı Namespace'ler Oluşturma

#### CLI
```bash
sudo unshare -m [--mount-proc] /bin/bash
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
- Sorun, `unshare` ile `-f` seçeneğini kullanarak çözülebilir. Bu seçenek, yeni PID ad alanı oluşturduktan sonra `unshare`'in yeni bir işlem çatallamasını sağlar.
- `%unshare -fp /bin/bash%` komutunu çalıştırmak, `unshare` komutunun kendisinin yeni ad alanında PID 1 haline gelmesini sağlar. `/bin/bash` ve çocuk işlemleri bu yeni ad alanında güvenli bir şekilde yer alır, PID 1'in erken çıkışını önler ve normal PID tahsisine izin verir.

`unshare` komutunun `-f` bayrağıyla çalıştığından emin olarak, yeni PID ad alanı doğru bir şekilde korunur ve `/bin/bash` ve alt işlemleri bellek tahsis hatasıyla karşılaşmadan çalışabilir.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Hangi ad alanında olduğunuzu kontrol edin

Bir işlemin hangi ad alanında olduğunu kontrol etmek için aşağıdaki komutu kullanabilirsiniz:

```bash
ls -l /proc/$$/ns
```

Bu komut, işlem kimliği (`$$`) ile `/proc` dizinindeki `ns` alt dizinindeki sembolik bağlantıları listeler. Her sembolik bağlantı, işlemin hangi ad alanında olduğunu gösterir.
```bash
ls -l /proc/self/ns/mnt
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/mnt -> 'mnt:[4026531841]'
```
### Tüm Mount ad alanlarını bulun

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Bir Mount ad alanına giriş yapın

{% endcode %}
```bash
nsenter -m TARGET_PID --pid /bin/bash
```
Ayrıca, yalnızca root kullanıcısıysanız **başka bir işlem ad alanına girebilirsiniz**. Ve **bir tanımlayıcıya** (örneğin `/proc/self/ns/mnt`) işaret eden olmadan **başka bir ad alanına giremezsiniz**.

Yeni bağlantılar yalnızca ad alanı içinde erişilebilir olduğundan, bir ad alanının hassas bilgiler içermesi mümkündür ve bu bilgilere yalnızca ad alanından erişilebilir.

### Bir şeyi bağla
```bash
# Generate new mount ns
unshare -m /bin/bash
mkdir /tmp/mount_ns_example
mount -t tmpfs tmpfs /tmp/mount_ns_example
mount | grep tmpfs # "tmpfs on /tmp/mount_ns_example"
echo test > /tmp/mount_ns_example/test
ls /tmp/mount_ns_example/test # Exists

# From the host
mount | grep tmpfs # Cannot see "tmpfs on /tmp/mount_ns_example"
ls /tmp/mount_ns_example/test # Doesn't exist
```
## Referanslar
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)


<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** isterseniz [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek paylaşın**.

</details>
