# macOS Thread Injection via Task port

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Code

* [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
* [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)


## 1. Thread Hijacking

Başlangıçta, **`task_threads()`** fonksiyonu, uzaktaki görevden bir iş parçacığı listesi almak için görev portunda çağrılır. Bir iş parçacığı ele geçirilmek üzere seçilir. Bu yaklaşım, yeni önlemlerin `thread_create_running()`'i engellemesi nedeniyle yeni bir uzaktan iş parçacığı oluşturmanın yasak olduğu geleneksel kod enjeksiyon yöntemlerinden sapmaktadır.

İş parçacığını kontrol etmek için, **`thread_suspend()`** çağrılır ve yürütmesi durdurulur.

Uzaktaki iş parçacığında yalnızca **durdurma** ve **başlatma**, **kayıt** değerlerini **alma** ve **değiştirme** işlemlerine izin verilir. Uzaktan fonksiyon çağrıları, `x0` ile `x7` kayıtlarını **argümanlar** ile ayarlayarak, **`pc`**'yi hedeflenen fonksiyona ayarlayarak ve iş parçacığını etkinleştirerek başlatılır. İş parçacığının dönüşten sonra çökmediğinden emin olmak, dönüşün tespit edilmesini gerektirir.

Bir strateji, uzaktaki iş parçacığı için `thread_set_exception_ports()` kullanarak bir istisna işleyicisi **kaydetmektir**, fonksiyon çağrısından önce `lr` kaydını geçersiz bir adrese ayarlamaktır. Bu, fonksiyon yürütüldükten sonra bir istisna tetikler, istisna portuna bir mesaj gönderir ve dönüş değerini kurtarmak için iş parçacığının durumunu incelemeyi sağlar. Alternatif olarak, Ian Beer’in triple_fetch istismarından alınan bir yöntemle, `lr` sonsuz döngüye ayarlanır. İş parçacığının kayıtları, **`pc` o talimata işaret edene kadar** sürekli izlenir.

## 2. Mach portları ile iletişim

Sonraki aşama, uzaktaki iş parçacığı ile iletişimi kolaylaştırmak için Mach portları kurmaktır. Bu portlar, görevler arasında keyfi gönderme ve alma haklarının aktarımında önemli bir rol oynar.

İki yönlü iletişim için, bir yerel ve diğeri uzaktaki görevde olmak üzere iki Mach alma hakkı oluşturulur. Ardından, her port için bir gönderme hakkı karşıt göreve aktarılır ve mesaj alışverişi sağlanır.

Yerel port üzerinde odaklanıldığında, alma hakkı yerel görev tarafından tutulur. Port, `mach_port_allocate()` ile oluşturulur. Bu port için bir gönderme hakkını uzaktaki göreve aktarmak zorluk teşkil eder.

Bir strateji, `thread_set_special_port()` kullanarak yerel port için bir gönderme hakkını uzaktaki iş parçacığının `THREAD_KERNEL_PORT`'una yerleştirmeyi içerir. Ardından, uzaktaki iş parçacığına `mach_thread_self()` çağrısı yapması talimatı verilir, böylece gönderme hakkı alınır.

Uzaktaki port için süreç esasen tersine çevrilir. Uzaktaki iş parçacığı, `mach_reply_port()` aracılığıyla bir Mach portu oluşturması için yönlendirilir (çünkü `mach_port_allocate()` dönüş mekanizması nedeniyle uygun değildir). Port oluşturulduktan sonra, uzaktaki iş parçacığında bir gönderme hakkı oluşturmak için `mach_port_insert_right()` çağrılır. Bu hak daha sonra `thread_set_special_port()` kullanılarak çekirdekte saklanır. Yerel görevde, uzaktaki iş parçacığı üzerinde `thread_get_special_port()` kullanılarak uzaktaki görevde yeni tahsis edilen Mach portuna bir gönderme hakkı alınır.

Bu adımların tamamlanması, Mach portlarının kurulmasını sağlar ve iki yönlü iletişim için zemin hazırlar.

## 3. Temel Bellek Okuma/Yazma Primitifleri

Bu bölümde, temel bellek okuma ve yazma primitiflerini oluşturmak için yürütme primitifinin kullanılmasına odaklanılmaktadır. Bu ilk adımlar, uzaktaki süreç üzerinde daha fazla kontrol elde etmek için kritik öneme sahiptir, ancak bu aşamadaki primitifler pek fazla işlev görmeyecektir. Yakında, daha gelişmiş versiyonlara yükseltileceklerdir.

### Yürütme Primitifi Kullanarak Bellek Okuma ve Yazma

Amaç, belirli fonksiyonlar kullanarak bellek okuma ve yazma gerçekleştirmektir. Bellek okumak için, aşağıdaki yapıya benzeyen fonksiyonlar kullanılır:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Ve belleğe yazmak için bu yapıya benzer fonksiyonlar kullanılır:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Bu fonksiyonlar verilen montaj talimatlarına karşılık gelir:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Uygun Fonksiyonların Belirlenmesi

Yaygın kütüphanelerin taranması, bu işlemler için uygun adayları ortaya çıkardı:

1. **Belleği Okuma:**
`property_getName()` fonksiyonu, [Objective-C çalışma zamanı kütüphanesi](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html) için bellek okuma işlemi için uygun bir fonksiyon olarak belirlenmiştir. Fonksiyon aşağıda özetlenmiştir:
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
Bu fonksiyon, `objc_property_t`'nin ilk alanını döndürerek `read_func` gibi etkili bir şekilde çalışır.

2. **Bellek Yazma:**
Bellek yazmak için önceden oluşturulmuş bir fonksiyon bulmak daha zordur. Ancak, libxpc'den `_xpc_int64_set_value()` fonksiyonu, aşağıdaki ayrıştırma ile uygun bir adaydır:
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Bir belirli adrese 64-bit yazma işlemi gerçekleştirmek için, uzak çağrı şu şekilde yapılandırılır:
```c
_xpc_int64_set_value(address - 0x18, value)
```
Bu ilkelere dayanarak, paylaşılan bellek oluşturmak için sahne hazırlanmış olup, uzaktan süreci kontrol etmede önemli bir ilerleme kaydedilmiştir.

## 4. Paylaşılan Bellek Kurulumu

Amaç, yerel ve uzaktan görevler arasında paylaşılan bellek oluşturarak veri transferini basitleştirmek ve birden fazla argümanla fonksiyon çağrısını kolaylaştırmaktır. Yaklaşım, Mach bellek girişleri üzerine inşa edilmiş `libxpc` ve onun `OS_xpc_shmem` nesne türünü kullanmayı içerir.

### Süreç Genel Görünümü:

1. **Bellek Tahsisi**:
- `mach_vm_allocate()` kullanarak paylaşım için bellek tahsis edin.
- Tahsis edilen bellek bölgesi için bir `OS_xpc_shmem` nesnesi oluşturmak üzere `xpc_shmem_create()` kullanın. Bu fonksiyon, Mach bellek girişinin oluşturulmasını yönetecek ve `OS_xpc_shmem` nesnesinin `0x18` ofsetinde Mach gönderim hakkını saklayacaktır.

2. **Uzaktan Süreçte Paylaşılan Bellek Oluşturma**:
- Uzaktan `malloc()` çağrısıyla uzaktan süreçte `OS_xpc_shmem` nesnesi için bellek tahsis edin.
- Yerel `OS_xpc_shmem` nesnesinin içeriğini uzaktan sürece kopyalayın. Ancak, bu ilk kopya `0x18` ofsetinde yanlış Mach bellek giriş isimlerine sahip olacaktır.

3. **Mach Bellek Girişini Düzeltme**:
- Uzaktan görevde Mach bellek girişi için bir gönderim hakkı eklemek üzere `thread_set_special_port()` yöntemini kullanın.
- Uzaktan bellek girişinin ismi ile `0x18` ofsetindeki Mach bellek girişi alanını üzerine yazarak düzeltin.

4. **Paylaşılan Bellek Kurulumunu Tamamlama**:
- Uzaktan `OS_xpc_shmem` nesnesini doğrulayın.
- `xpc_shmem_remote()` ile uzaktan çağrı yaparak paylaşılan bellek haritasını oluşturun.

Bu adımları izleyerek, yerel ve uzaktan görevler arasında paylaşılan bellek verimli bir şekilde kurulacak ve veri transferleri ile birden fazla argüman gerektiren fonksiyonların yürütülmesi kolaylaşacaktır.

## Ek Kod Parçacıkları

Bellek tahsisi ve paylaşılan bellek nesnesi oluşturma için:
```c
mach_vm_allocate();
xpc_shmem_create();
```
Uzak süreçte paylaşılan bellek nesnesini oluşturmak ve düzeltmek için:
```c
malloc(); // for allocating memory remotely
thread_set_special_port(); // for inserting send right
```
Hatırlayın ki, paylaşılan bellek ayarının düzgün çalışmasını sağlamak için Mach portları ve bellek giriş adlarının detaylarını doğru bir şekilde ele almak önemlidir.

## 5. Tam Kontrol Sağlama

Paylaşılan belleği başarıyla kurduktan ve keyfi yürütme yetenekleri kazandıktan sonra, esasen hedef süreç üzerinde tam kontrol elde etmiş oluyoruz. Bu kontrolü sağlayan ana işlevler şunlardır:

1. **Keyfi Bellek İşlemleri**:
- Paylaşılan bölgeden veri kopyalamak için `memcpy()` çağrısını kullanarak keyfi bellek okumaları gerçekleştirin.
- Paylaşılan bölgeye veri aktarmak için `memcpy()` kullanarak keyfi bellek yazımları gerçekleştirin.

2. **Birden Fazla Argümanla Fonksiyon Çağrılarını Ele Alma**:
- 8'den fazla argüman gerektiren fonksiyonlar için, ek argümanları çağrı konvansiyonuna uygun olarak yığında düzenleyin.

3. **Mach Port Transferi**:
- Daha önce kurulmuş portlar aracılığıyla görevler arasında Mach portlarını Mach mesajları ile aktarın.

4. **Dosya Tanımlayıcı Transferi**:
- Ian Beer'in `triple_fetch` adlı tekniğinde vurgulanan dosya portlarını kullanarak süreçler arasında dosya tanımlayıcılarını aktarın.

Bu kapsamlı kontrol, [threadexec](https://github.com/bazad/threadexec) kütüphanesi içinde kapsüllenmiştir ve kurban süreci ile etkileşim için ayrıntılı bir uygulama ve kullanıcı dostu bir API sağlar.

## Önemli Hususlar:

- Sistem kararlılığını ve veri bütünlüğünü korumak için bellek okuma/yazma işlemleri için `memcpy()`'nin doğru kullanımını sağlayın.
- Mach portları veya dosya tanımlayıcılarını aktarırken, uygun protokolleri izleyin ve kaynakları sorumlu bir şekilde yönetin, sızıntıları veya istenmeyen erişimleri önleyin.

Bu yönergelere uyarak ve `threadexec` kütüphanesini kullanarak, süreçleri ayrıntılı bir düzeyde etkili bir şekilde yönetebilir ve etkileşimde bulunarak hedef süreç üzerinde tam kontrol elde edebilirsiniz.

## Referanslar
* [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.**

</details>
{% endhint %}
