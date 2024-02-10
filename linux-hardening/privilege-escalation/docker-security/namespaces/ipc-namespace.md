# IPC Adı Alanı

<details>

<summary><strong>AWS hackleme becerilerinizi sıfırdan ileri seviyeye taşıyın</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile</strong>!</summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## Temel Bilgiler

IPC (Inter-Process Communication - Süreçler Arası İletişim) adı alanı, Linux çekirdeğinin bir özelliğidir ve mesaj kuyrukları, paylaşılan bellek segmentleri ve semaforlar gibi System V IPC nesnelerinin **izolasyonunu** sağlar. Bu izolasyon, **farklı IPC adı alanlarındaki süreçlerin birbirlerinin IPC nesnelerine doğrudan erişememesini veya değiştirememesini** sağlayarak süreç grupları arasında ek bir güvenlik ve gizlilik katmanı sağlar.

### Nasıl Çalışır:

1. Yeni bir IPC adı alanı oluşturulduğunda, **tamamen izole edilmiş bir System V IPC nesnesi kümesiyle başlar**. Bu, yeni IPC adı alanında çalışan süreçlerin, varsayılan olarak diğer ad alanlarındaki veya ana sistemdeki IPC nesnelerine erişememesi veya müdahale edememesi anlamına gelir.
2. Bir ad alanı içinde oluşturulan IPC nesneleri, yalnızca o ad alanındaki süreçler tarafından **görülebilir ve erişilebilir**. Her IPC nesnesi, kendi ad alanı içinde benzersiz bir anahtarla tanımlanır. Anahtar farklı ad alanlarında aynı olabilir, ancak nesneler kendileri izole edilmiştir ve ad alanları arasında erişilemezler.
3. Süreçler, `setns()` sistem çağrısını kullanarak ad alanları arasında hareket edebilir veya `unshare()` veya `clone()` sistem çağrılarını `CLONE_NEWIPC` bayrağıyla kullanarak yeni ad alanları oluşturabilir. Bir süreç yeni bir ad alanına geçtiğinde veya bir ad alanı oluşturduğunda, o ad alanıyla ilişkili IPC nesnelerini kullanmaya başlar.

## Lab:

### Farklı Ad Alanları Oluşturma

#### CLI
```bash
sudo unshare -i [--mount-proc] /bin/bash
```
`--mount-proc` parametresini kullanarak `/proc` dosya sisteminin yeni bir örneğini bağladığınızda, yeni bağlama alanının **o ad alanına özgü işlem bilgilerinin doğru ve izole bir görünümünü** sağlarsınız.

<details>

<summary>Hata: bash: fork: Bellek tahsis edilemedi</summary>

`unshare` komutu `-f` seçeneği olmadan çalıştırıldığında, Linux'un yeni PID (Process ID) ad alanlarını nasıl işlediği nedeniyle bir hata oluşur. Ana ayrıntılar ve çözüm aşağıda belirtilmiştir:

1. **Sorun Açıklaması**:
- Linux çekirdeği, bir işlemin `unshare` sistem çağrısını kullanarak yeni ad alanları oluşturmasına izin verir. Ancak, yeni bir PID ad alanının oluşturulmasını başlatan işlem (unshare işlemi olarak adlandırılır) yeni ad alana girmez; sadece çocuk işlemleri girer.
- `%unshare -p /bin/bash%` komutunu çalıştırmak, `/bin/bash`'i `unshare` ile aynı işlemde başlatır. Sonuç olarak, `/bin/bash` ve çocuk işlemleri orijinal PID ad alanında bulunur.
- Yeni ad alanındaki `/bin/bash`'in ilk çocuk işlemi PID 1 olur. Bu işlem çıkış yaptığında, eğer başka işlem yoksa ad alanının temizlenmesini tetikler, çünkü PID 1 yetim işlemleri sahiplenme özel rolüne sahiptir. Linux çekirdeği daha sonra o ad alanda PID tahsisini devre dışı bırakır.

2. **Sonuç**:
- Yeni bir ad alanındaki PID 1'in çıkışı, `PIDNS_HASH_ADDING` bayrağının temizlenmesine yol açar. Bu, yeni bir işlem oluştururken `alloc_pid` işlevinin yeni bir PID tahsis edememesine ve "Bellek tahsis edilemedi" hatasının oluşmasına neden olur.

3. **Çözüm**:
- Sorun, `unshare` ile `-f` seçeneğini kullanarak çözülebilir. Bu seçenek, `unshare`'in yeni bir PID ad alanı oluşturduktan sonra yeni bir işlem çatallamasını sağlar.
- `%unshare -fp /bin/bash%` komutunu çalıştırmak, `unshare` komutunun kendisinin yeni ad alanında PID 1 olmasını sağlar. `/bin/bash` ve çocuk işlemleri bu yeni ad alanında güvenli bir şekilde sınırlanır, PID 1'in erken çıkışını önler ve normal PID tahsisine izin verir.

`unshare` komutunun `-f` bayrağıyla çalıştığından emin olarak, yeni PID ad alanı doğru bir şekilde korunur ve `/bin/bash` ve alt işlemleri bellek tahsis hatasıyla karşılaşmadan çalışabilir.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Hangi ad alanında olduğunuzu kontrol edin

Bir sürecin hangi ad alanında olduğunu kontrol etmek için aşağıdaki komutu kullanabilirsiniz:

```bash
ls -l /proc/<PID>/ns/ipc
```

Burada `<PID>`, kontrol etmek istediğiniz sürecin kimlik numarasını temsil eder. Bu komutu çalıştırdığınızda, sürecin IPC ad alanında bulunup bulunmadığını görebilirsiniz.
```bash
ls -l /proc/self/ns/ipc
lrwxrwxrwx 1 root root 0 Apr  4 20:37 /proc/self/ns/ipc -> 'ipc:[4026531839]'
```
### Tüm IPC isim alanlarını bulun

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name ipc -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name ipc -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### IPC ad alanına girin

{% endcode %}
```bash
nsenter -i TARGET_PID --pid /bin/bash
```
Ayrıca, yalnızca kök kullanıcıysanız başka bir işlem ad alanına **geçebilirsiniz**. Ve başka bir ad alanına **bir tanımlayıcı** (örneğin `/proc/self/ns/net`) işaret etmeden **geçemezsiniz**.

### IPC nesnesi oluşturma
```bash
# Container
sudo unshare -i /bin/bash
ipcmk -M 100
Shared memory id: 0
ipcs -m

------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status
0x2fba9021 0          root       644        100        0

# From the host
ipcs -m # Nothing is seen
```
## Referanslar
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)



<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
