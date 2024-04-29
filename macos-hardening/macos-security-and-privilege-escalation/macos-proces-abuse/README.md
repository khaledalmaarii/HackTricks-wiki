# macOS İşlem Kötüye Kullanımı

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramana öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na (https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünleri**](https://peass.creator-spring.com)'ni edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'da **takip edin**.
* **Hacking püf noktalarınızı paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## İşlemler Temel Bilgileri

Bir işlem çalışan bir yürütülebilir dosyanın bir örneğidir, ancak işlemler kod çalıştırmaz, bunlar thread'lerdir. Bu nedenle **işlemler yalnızca çalışan thread'ler için konteynerlerdir**, belleği, tanımlayıcıları, bağlantı noktalarını, izinleri sağlarlar...

Geleneksel olarak, işlemler diğer işlemler içinde (PID 1 hariç) **`fork`** çağrısı yaparak başlatılırdı, bu işlem mevcut işlemi tam olarak kopyalayacak ve ardından **çocuk işlem** genellikle yeni yürütülebilir dosyayı yüklemek ve çalıştırmak için **`execve`** çağrısını yapacaktı. Daha sonra, bu işlemi hafızayı kopyalamadan daha hızlı hale getirmek için **`vfork`** tanıtıldı.\
Daha sonra **`posix_spawn`** tanıtıldı, **`vfork`** ve **`execve`**'yi bir araya getirerek ve bayrakları kabul ederek:

* `POSIX_SPAWN_RESETIDS`: Etkili kimlikleri gerçek kimliklere sıfırlar
* `POSIX_SPAWN_SETPGROUP`: İşlem grubu üyeliğini ayarlar
* `POSUX_SPAWN_SETSIGDEF`: Sinyal varsayılan davranışını ayarlar
* `POSIX_SPAWN_SETSIGMASK`: Sinyal maskesini ayarlar
* `POSIX_SPAWN_SETEXEC`: Aynı işlemde yürütme (daha fazla seçenekle `execve` gibi)
* `POSIX_SPAWN_START_SUSPENDED`: Askıya alınmış olarak başlat
* `_POSIX_SPAWN_DISABLE_ASLR`: ASLR olmadan başlat
* `_POSIX_SPAWN_NANO_ALLOCATOR:` libmalloc'ın Nano tahsisatçısını kullan
* `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Veri segmentlerinde `rwx`'e izin ver
* `POSIX_SPAWN_CLOEXEC_DEFAULT`: Varsayılan olarak exec(2) ile tüm dosya tanımlamalarını kapat
* `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLR kaydırmasının yüksek bitlerini rastgele hale getir

Ayrıca, `posix_spawn` başlatılan işlemin bazı yönlerini kontrol eden bir dizi **`posix_spawnattr`** belirtmeye ve tanımlayıcıların durumunu değiştirmek için **`posix_spawn_file_actions`** kullanmaya olanak tanır.

Bir işlem öldüğünde, **dönüş kodunu ebeveyn işleme** (ebeveyn öldüyse, yeni ebeveyn PID 1'dir) `SIGCHLD` sinyali ile gönderir. Ebeveyn bu değeri `wait4()` veya `waitid()` çağırarak almalı ve bu gerçekleşene kadar çocuk kaynak tüketmeyen ancak hala listelenen bir zombi durumunda kalır.

### PID'ler

PID'ler, işlem tanımlayıcıları, benzersiz bir işlemi tanımlar. XNU'da **PID'ler** **64 bit** olup monotonik olarak artar ve **asla sarılmaz** (istismarları önlemek için).

### İşlem Grupları, Oturumlar ve Koalisyonlar

**İşlemler**, onları daha kolay işlemek için gruplara yerleştirilebilir. Örneğin, bir kabuk betiğindeki komutlar aynı işlem grubunda olacak, bu nedenle örneğin kill kullanarak **onlara birlikte sinyal göndermek mümkün olacaktır**.\
Ayrıca, işlemleri **oturumlarda gruplandırmak mümkündür**. Bir işlem bir oturum başlattığında (`setsid(2)`), çocuk işlemler oturumun içine yerleştirilir, kendi oturumlarını başlatmadıkça.

Koalisyon, Darwin'de işlemleri gruplamanın başka bir yoludur. Bir koalisyona katılan bir işlem, havuz kaynaklarına erişim sağlamasına, bir defteri paylaşmasına veya Jetsam ile yüzleşmesine olanak tanır. Koalisyonların farklı rolleri vardır: Lider, XPC hizmeti, Uzantı.

### Kimlik Bilgileri ve Personalar

Her işlem, sistemdeki ayrıcalıklarını tanımlayan **kimlik bilgilerini** tutar. Her işlemin birincil `uid` ve birincil `gid`'si olacaktır (ancak birkaç gruba ait olabilir).\
Eğer ikili dosyada `setuid/setgid` biti varsa kullanıcı ve grup kimliğini değiştirmek mümkündür.\
Yeni uid/gid'ler belirlemek için birkaç işlev vardır.

Syscall **`persona`**, bir **alternatif** kimlik bilgisi kümesi sağlar. Bir persona benimsemek, uid'sini, gid'sini ve grup üyeliklerini **aynı anda** varsaymayı içerir. [**Kaynak kodunda**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) yapıyı bulmak mümkündür.
```c
struct kpersona_info { uint32_t persona_info_version;
uid_t    persona_id; /* overlaps with UID */
int      persona_type;
gid_t    persona_gid;
uint32_t persona_ngroups;
gid_t    persona_groups[NGROUPS];
uid_t    persona_gmuid;
char     persona_name[MAXLOGNAME + 1];

/* TODO: MAC policies?! */
}
```
## İplikler Temel Bilgileri

1. **POSIX İplikler (pthreads):** macOS, C/C++ için standart bir iplik API'si olan POSIX iplikleri (`pthreads`) destekler. macOS'taki pthreads uygulaması, `/usr/lib/system/libsystem_pthread.dylib` içinde bulunur ve genelde bulunan `libpthread` projesinden gelir. Bu kütüphane iplik oluşturmak ve yönetmek için gerekli işlevleri sağlar.
2. **İplik Oluşturma:** Yeni iplikler oluşturmak için `pthread_create()` işlevi kullanılır. Bu işlev, içsel olarak `bsdthread_create()` işlevini çağırır, bu işlev XNU çekirdeğine (macOS'un temel aldığı çekirdek) özgü düşük seviyeli bir sistem çağrısıdır. Bu sistem çağrısı, iplik davranışını belirleyen `pthread_attr` (öznitelikler) türetilmiş çeşitli bayrakları alır, bu davranışlar arasında zamanlama politikaları ve yığın boyutu bulunur.
* **Varsayılan Yığın Boyutu:** Yeni iplikler için varsayılan yığın boyutu 512 KB'dir, tipik işlemler için yeterli olsa da daha fazla veya daha az alan gerekiyorsa iplik öznitelikleri aracılığıyla ayarlanabilir.
3. **İplik Başlatma:** `__pthread_init()` işlevi, iplik kurulumu sırasında önemlidir ve `env[]` argümanını kullanarak yığının konumu ve boyutu gibi ayrıntıları içerebilen çevre değişkenlerini ayrıştırmak için kullanılır.

#### macOS'ta İplik Sonlandırma

1. **İpliklerin Sonlandırılması:** İplikler genellikle `pthread_exit()` çağrılarak sonlandırılır. Bu işlev, bir ipliğin temiz bir şekilde çıkmasına izin verir, gerekli temizliği yapar ve ipliği bekleyenlere bir dönüş değeri göndermesine olanak tanır.
2. **İplik Temizliği:** `pthread_exit()` çağrıldığında, `pthread_terminate()` işlevi çağrılır ve tüm ilişkili iplik yapılarının kaldırılmasını ele alır. Bu işlev, Mach iplik bağlantı noktalarını (Mach, XNU çekirdeğindeki iletişim alt sistemi) serbest bırakır ve iplikle ilişkili çekirdek düzeyindeki yapıları kaldıran `bsdthread_terminate` sistem çağrısını yapar.

#### Senkronizasyon Mekanizmaları

Paylaşılan kaynaklara erişimi yönetmek ve yarış koşullarını önlemek için macOS, birkaç senkronizasyon ilkelini sağlar. Bu, veri bütünlüğünü ve sistem kararlılığını sağlamak için çoklu iplik ortamlarında kritiktir:

1. **Müteksinler:**
* **Normal Müteksin (İmza: 0x4D555458):** 56 bayt için müteksin ve 4 bayt için imza olmak üzere 60 bayt boyutunda standart müteksin.
* **Hızlı Müteksin (İmza: 0x4d55545A):** Normal müteksine benzer ancak daha hızlı işlemler için optimize edilmiş, aynı zamanda 60 bayt boyutundadır.
2. **Durum Değişkenleri:**
* Belirli koşulların gerçekleşmesini beklemek için kullanılır, 40 bayt artı 4 bayt imza ile 44 bayt boyutundadır.
* **Durum Değişkeni Öznitelikleri (İmza: 0x434e4441):** Durum değişkenleri için yapılandırma öznitelikleri, 12 bayt boyutundadır.
3. **Bir Kez Değişkeni (İmza: 0x4f4e4345):**
* Başlatma kodunun yalnızca bir kez yürütülmesini sağlar. Boyutu 12 bayttır.
4. **Okuma-Yazma Kilidi:**
* Aynı anda birden fazla okuyucuya veya bir yazıcıya izin verir, paylaşılan verilere verimli erişimi kolaylaştırır.
* **Okuma Yazma Kilidi (İmza: 0x52574c4b):** 196 bayt boyutundadır.
* **Okuma Yazma Kilidi Öznitelikleri (İmza: 0x52574c41):** Okuma-yazma kilitleri için öznitelikler, 20 bayt boyutundadır.

{% hint style="success" %}
Bu nesnelerin son 4 baytı taşmaları algılamak için kullanılır.
{% endhint %}

### İplik Yerel Değişkenler (TLV)

**İplik Yerel Değişkenler (TLV)**, macOS'ta yürütülebilir dosyalar için biçim olan Mach-O dosyaları bağlamında, çoklu iplikli bir uygulamadaki **her iplik** için özgü değişkenleri bildirmek için kullanılır. Bu, her ipliğin kendi ayrı değişken örneğine sahip olduğundan çakışmaları önlemek ve müteksinler gibi açık senkronizasyon mekanizmalarına gerek duymadan veri bütünlüğünü korumak için bir yol sağlar.

C ve ilgili dillerde, bir iplik yerel değişkeni **`__thread`** anahtar kelimesini kullanarak bildirebilirsiniz. İşte örneğinizde nasıl çalıştığı:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Bu parça, `tlv_var`'ı bir iş parçacığı yerel değişkeni olarak tanımlar. Bu kodu çalıştıran her iş parçacığı kendi `tlv_var`'ına sahip olacak ve bir iş parçacığının `tlv_var`'ına yaptığı değişiklikler diğer bir iş parçacığındaki `tlv_var`'ı etkilemeyecektir.

Mach-O ikilisinde, iş parçacığı yerel değişkenlerle ilgili veriler belirli bölümlere düzenlenmiştir:

* **`__DATA.__thread_vars`**: Bu bölüm, iş parçacığı yerel değişkenleri hakkında metadata içerir, türleri ve başlatma durumları gibi.
* **`__DATA.__thread_bss`**: Bu bölüm, açıkça başlatılmamış iş parçacığı yerel değişkenleri için kullanılır. Sıfırlanmış veriler için ayrılan belleğin bir parçasıdır.

Mach-O ayrıca bir iş parçacığı çıkış yaptığında iş parçacığı yerel değişkenlerini yönetmek için **`tlv_atexit`** adında özel bir API sağlar. Bu API, bir iş parçacığı sonlandığında iş parçacığı yerel verilerini temizleyen özel fonksiyonları **kaydetmenize** olanak tanır.

### İş Parçacığı Öncelikleri

İş parçacığı önceliklerini anlamak, işletim sisteminin hangi iş parçacıklarını çalıştıracağına ve ne zaman çalıştıracağına karar verirken bakılması gereken konuları içerir. Bu karar, her iş parçacığına atanan öncelik seviyesinden etkilenir. macOS ve Unix benzeri sistemlerde, bu kavramlar `nice`, `renice` ve Kalite Hizmeti (QoS) sınıfları gibi kavramlar kullanılarak ele alınır.

#### Nice ve Renice

1. **Nice:**
* Bir işlemin `nice` değeri, önceliğini etkileyen bir numaradır. Her işlem, genellikle 0 olan -20 (en yüksek öncelik) ile 19 (en düşük öncelik) arasında değişen bir güzel değere sahiptir. Bir işlem oluşturulduğunda varsayılan güzel değer genellikle 0'dır.
* Daha düşük bir güzel değer (-20'ye daha yakın) bir işlemi daha "bencil" yapar, yani diğer işlemlere göre daha fazla CPU zamanı verir.
2. **Renice:**
* `renice`, zaten çalışan bir işlemin güzel değerini değiştirmek için kullanılan bir komuttur. Bu, işlemlerin önceliğini dinamik olarak ayarlamak için kullanılabilir, yeni güzel değerlere göre CPU zamanı tahsisini artırarak veya azaltarak işlemlerin önceliğini ayarlamak için kullanılabilir.
* Örneğin, bir işlemin geçici olarak daha fazla CPU kaynağına ihtiyacı varsa, `renice` kullanarak güzel değerini düşürebilirsiniz.

#### Kalite Hizmeti (QoS) Sınıfları

QoS sınıfları, özellikle **Grand Central Dispatch (GCD)** gibi sistemleri destekleyen macOS gibi sistemlerde iş parçacığı önceliklerini ele almanın daha modern bir yaklaşımıdır. QoS sınıfları, işin önemine veya aciliyetine göre farklı seviyelere kategorize etmeye olanak tanır. macOS, bu QoS sınıflarına dayanarak iş parçacığı önceliğini otomatik olarak yönetir:

1. **Kullanıcı Etkileşimli:**
* Bu sınıf, şu anda kullanıcıyla etkileşimde olan veya iyi bir kullanıcı deneyimi sağlamak için hemen sonuçlar gerektiren görevler içindir. Bu görevler, arayüzün yanıt vermesini sağlamak için en yüksek önceliği alır (örneğin, animasyonlar veya etkinlik işleme).
2. **Kullanıcı Başlatılan:**
* Kullanıcının başlattığı ve hemen sonuçlar beklediği görevler, belge açma veya hesaplama gerektiren bir düğmeye tıklama gibi. Bunlar yüksek öncelikli ancak kullanıcı etkileşimli görevlerin altındadır.
3. **Yardımcı:**
* Bu görevler uzun süre çalışır ve genellikle bir ilerleme göstergesi gösterir (örneğin, dosyaları indirme, veri içe aktarma). Kullanıcı başlatılan görevlerden daha düşük önceliğe sahiptir ve hemen bitmesi gerekmez.
4. **Arka Plan:**
* Bu sınıf, arka planda çalışan ve kullanıcı tarafından görülmeyen görevler içindir. Bunlar dizinleme, senkronizasyon veya yedekleme gibi görevler olabilir. En düşük önceliğe sahiptirler ve sistem performansı üzerinde minimal etkiye sahiptirler.

QoS sınıflarını kullanarak, geliştiricilerin kesin öncelik numaralarını yönetmeleri gerekmez, ancak görevin doğasına odaklanabilirler ve sistem CPU kaynaklarını buna göre optimize eder.

Ayrıca, **iş parçacığı zamanlama politikaları** adında farklı zamanlama politikaları vardır, bu politikaların dikkate alınacak bir dizi zamanlama parametresini belirtmek için akışlar sağlar. Bu, `thread_policy_[set/get]` kullanılarak yapılabilir. Bu, yarış koşulu saldırılarında faydalı olabilir.
### Python Enjeksiyonu

Eğer **`PYTHONINSPECT`** ortam değişkeni ayarlanmışsa, python işlemi tamamlandığında bir python komut satırına düşer. Ayrıca, etkileşimli bir oturumun başında yürütülecek bir python betiğini belirtmek için **`PYTHONSTARTUP`** kullanmak da mümkündür.\
Ancak, **`PYTHONINSPECT`** etkileşimli oturum oluşturduğunda **`PYTHONSTARTUP`** betiği yürütülmeyecektir.

**`PYTHONPATH`** ve **`PYTHONHOME`** gibi diğer ortam değişkenleri de bir python komutunun keyfi kodu yürütmesini sağlamak için kullanışlı olabilir.

**`pyinstaller`** ile derlenen yürütülebilir dosyalar, gömülü bir python kullanıyor olsalar bile bu ortam değişkenlerini kullanmayacaktır.

{% hint style="danger" %}
Genel olarak, ortam değişkenlerini kötüye kullanarak python'un keyfi kod yürütmesini sağlayacak bir yol bulamadım.\
Ancak, insanların çoğu **Hombrew** kullanarak python'u yükler, bu da python'u varsayılan yönetici kullanıcısı için bir **yazılabilir konuma** yükler. Bunu şu şekilde ele geçirebilirsiniz:
```bash
mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
cat > /opt/homebrew/bin/python3 <<EOF
#!/bin/bash
# Extra hijack code
/opt/homebrew/bin/python3.old "$@"
EOF
chmod +x /opt/homebrew/bin/python3
```
## Tespit

### Kalkan

[**Shield**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)), **enjeksiyon işlemlerini tespit edebilen ve engelleyebilen** açık kaynaklı bir uygulamadır:

- **Çevresel Değişkenler Kullanarak**: Aşağıdaki çevresel değişkenlerin varlığını izleyecektir: **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** ve **`ELECTRON_RUN_AS_NODE`**
- **`task_for_pid`** çağrıları Kullanarak: Bir işlemin başka bir işlemin **görev bağlantı noktasını almak istediğinde** (bu, işleme kod enjekte etmeyi sağlar) bulunur.
- **Electron uygulama parametreleri**: Birisi bir Electron uygulamasını hata ayıklama modunda başlatmak ve böylece kod enjekte etmek için **`--inspect`**, **`--inspect-brk`** ve **`--remote-debugging-port`** komut satırı argümanlarını kullanabilir.
- **Sembolik bağlantılar** veya **sabit bağlantılar** Kullanarak: Genellikle en yaygın kötüye kullanım, **kullanıcı ayrıcalıklarımızla bir bağlantı oluşturmak** ve **daha yüksek ayrıcalıklı bir konuma işaret etmek**tir. Hem sabit bağlantılar hem de sembolik bağlantılar için tespit çok basittir. Bağlantıyı oluşturan işlem hedef dosyadan **farklı bir ayrıcalık seviyesine** sahipse, bir **uyarı** oluştururuz. Ne yazık ki sembolik bağlantıların engellenmesi mümkün değildir, çünkü bağlantının oluşturulmasından önce bağlantının hedefi hakkında bilgiye sahip değiliz. Bu, Apple'ın EndpointSecuriy çerçevesinin bir kısıtlamasıdır.

### Diğer işlemler tarafından yapılan çağrılar

Bu [**blog yazısında**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) işlemi çalıştıran başka bir işlem tarafından kod enjekte eden işlemler hakkında bilgi almak için **`task_name_for_pid`** işlevini nasıl kullanabileceğinizi bulabilirsiniz ve ardından o diğer işlem hakkında bilgi alabilirsiniz.

Bu işlevi çağırmak için işlemi çalıştıran kişiyle **aynı uid** olmanız veya **root** olmanız gerekir (ve bu işlem, kod enjekte etmenin bir yolu değil, işlem hakkında bilgi döndürür).

## Referanslar

- [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
- [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
