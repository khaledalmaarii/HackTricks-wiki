# macOS Görev Portu Aracılığıyla İş Parçacığı Enjeksiyonu

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* Hacking hilelerinizi [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR göndererek paylaşın.

</details>

## Kod

* [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
* [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)


## 1. İş Parçacığı Kaçırma

İlk olarak, uzak görevden bir iş parçacığı listesi elde etmek için **`task_threads()`** işlevi çağrılır. Bir iş parçacığı kaçırma için bir iş parçacığı seçilir. Bu yaklaşım, `thread_create_running()`'i engelleyen yeni önlem nedeniyle yeni bir uzak iş parçacığı oluşturmanın yasak olduğu geleneksel kod enjeksiyon yöntemlerinden farklılık gösterir.

İş parçacığı kontrol etmek için **`thread_suspend()`** çağrılır ve iş parçacığının yürütmesi durdurulur.

Uzak iş parçacığı üzerinde izin verilen tek işlemler, iş parçacığını **durdurmak** ve **başlatmak**, kayıt değerlerini **alıp değiştirmek** içindir. Uzak işlev çağrıları, kayıtları `x0` ile `x7` arasındaki **argümanlar** olarak ayarlayarak, **`pc`**'yi hedeflenen işlevi hedeflemek üzere yapılandırarak ve iş parçacığını etkinleştirerek başlatılır. İş parçacığının dönüşten sonra çökmemesini sağlamak için dönüşün tespit edilmesi gerekmektedir.

Bir strateji, iş parçacığı için **bir istisna işleyici kaydetmek** için `thread_set_exception_ports()` kullanarak uzak iş parçacığı için bir istisna işleyici kaydetmektir. Bu, işlev çağrısından önce `lr` kaydını geçersiz bir adres olarak ayarlar. Bu, işlev yürütmesinden sonra bir istisna tetikler ve bir mesajı istisna bağlantı noktasına gönderir, iş parçacığının durumu incelenerek dönüş değeri kurtarılır. Alternatif olarak, Ian Beer'ın triple\_fetch saldırısından benimsenen bir yöntemde, `lr` sonsuz bir döngüye ayarlanır. Ardından iş parçacığının kayıtları sürekli olarak izlenir ve **`pc`'nin o talimatı işaret ettiği** kontrol edilir.

## 2. İletişim için Mach bağlantı noktaları

Sonraki aşama, uzak iş parçacığıyla iletişimi kolaylaştırmak için Mach bağlantı noktaları oluşturmaktır. Bu bağlantı noktaları, görevler arasında keyfi gönderme ve alma haklarının aktarılmasında önemli rol oynar.

İki yönlü iletişim için, biri yerel ve diğeri uzak görevde olmak üzere iki Mach alma hakkı oluşturulur. Ardından, her bağlantı noktası için bir gönderme hakkı karşıt göreve aktarılır, mesaj alışverişi yapılmasını sağlar.

Yerel bağlantı noktasına odaklanılarak, alma hakkı yerel görev tarafından tutulur. Bağlantı noktası `mach_port_allocate()` ile oluşturulur. Zorluk, bu bağlantı noktasına bir gönderme hakkını uzak göreve aktarmaktadır.

Bir strateji, `thread_set_special_port()`'u kullanarak yerel bağlantı noktasına bir gönderme hakkını uzak iş parçacığının `THREAD_KERNEL_PORT`'una yerleştirmektir. Ardından, uzak iş parçacığına `mach_thread_self()` çağrısı yapması talimatı verilir ve gönderme hakkını alması sağlanır.

Uzak bağlantı noktası için işlem temelde tersine çevrilir. Uzak iş parçacığına, `mach_port_allocate()`'in dönüş mekanizması nedeniyle uygun olmadığı için `mach_reply_port()` kullanarak bir Mach bağlantı noktası oluşturması talimatı verilir. Bağlantı noktası oluşturulduktan sonra, uzak iş parçacığında `mach_port_insert_right()` çağrılır ve bir gönderme hakkı oluşturulur. Bu hak daha sonra `thread_set_special_port()` kullanılarak çekirdeğe saklanır. Yerel görevde, uzak iş parçacığı üzerinde `thread_get_special_port()` kullanılarak, uzak görevde yeni oluşturulan Mach bağlantı noktasına bir gönderme hakkı elde edilir.

Bu adımların tamamlanması, Mach bağlantı noktalarının kurulmasını sağlar ve iki yönlü iletişim için temel oluşturur.

## 3. Temel Bellek Okuma/Yazma İşlemleri

Bu bölümde, temel bellek okuma ve yazma işlemlerini sağlamak için yürütme ilkelinin kullanılmasına odaklanılır. Bu ilk adımlar, uzak işlem üzerinde daha fazla kontrol sağlamak için önemlidir, ancak bu aşamadaki ilkel işlemler pek çok amaç için hizmet etmeyecektir. Yakında, bunlar daha gelişmiş sürümlere yükseltilecektir.

### Yürütme İlkelini Kullanarak Bellek Okuma ve Yazma

Bellek okuma işlemi için, aşağıdaki yapıya benzeyen işlevler kullanılır:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Ve belleğe yazmak için, bu yapıya benzer işlevler kullanılır:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Bu işlevler, verilen derleme talimatlarına karşılık gelir:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Uygun Fonksiyonları Belirleme

Ortak kütüphanelerin taranması, bu işlemler için uygun adayları ortaya çıkardı:

1. **Bellek Okuma:**
[Objective-C çalışma zamanı kütüphanesinden](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html) `property_getName()` fonksiyonu, bellek okuma için uygun bir fonksiyon olarak belirlenmiştir. Aşağıda fonksiyonun taslağı bulunmaktadır:
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
Bu işlev, `read_func` gibi davranarak `objc_property_t`'nin ilk alanını döndürerek etkili bir şekilde çalışır.

2. **Belleğe Yazma:**
Belleğe yazma için önceden oluşturulmuş bir işlev bulmak daha zorlu olabilir. Bununla birlikte, libxpc'deki `_xpc_int64_set_value()` işlevi aşağıdaki derlemesiyle uygun bir adaydır:
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Belirli bir adreste 64 bitlik bir yazma işlemi gerçekleştirmek için, uzaktan çağrı aşağıdaki gibi yapılandırılır:
```c
_xpc_int64_set_value(address - 0x18, value)
```
Bu temel yapılar oluşturulduktan sonra, uzak işlemi kontrol etmek için önemli bir adım olan paylaşılan belleğin oluşturulması için sahne hazırlanır.

## 4. Paylaşılan Bellek Kurulumu

Amaç, yerel ve uzak görevler arasında paylaşılan bellek oluşturmaktır. Bu, veri transferini basitleştirir ve çoklu argümanlara sahip işlevlerin çağrılmasını kolaylaştırır. Yaklaşım, `libxpc` ve onun `OS_xpc_shmem` nesne türünü kullanmayı içerir. Bu nesne türü, Mach bellek girişlerine dayanır.

### İşlem Genel Bakışı:

1. **Bellek Tahsisi**:
- Paylaşım için belleği `mach_vm_allocate()` kullanarak tahsis edin.
- Ayrılan bellek bölgesi için bir `OS_xpc_shmem` nesnesi oluşturmak için `xpc_shmem_create()` kullanın. Bu işlev, Mach bellek girişinin oluşturulmasını yönetecek ve Mach gönderme hakkını `OS_xpc_shmem` nesnesinin `0x18` ofsetinde depolayacaktır.

2. **Uzak İşlemde Paylaşılan Bellek Oluşturma**:
- Uzak işlemde `OS_xpc_shmem` nesnesi için bellek tahsis edin ve bunu uzaktan `malloc()` çağrısıyla yapın.
- Yerel `OS_xpc_shmem` nesnesinin içeriğini uzak işleme kopyalayın. Ancak, bu ilk kopyada `0x18` ofsetinde yanlış Mach bellek girişi adları olacaktır.

3. **Mach Bellek Girişini Düzeltme**:
- Uzak göreve Mach bellek girişi için bir gönderme hakkı eklemek için `thread_set_special_port()` yöntemini kullanın.
- Uzak bellek girişinin adıyla `0x18` ofsetindeki Mach bellek girişi alanını düzeltmek için üzerine yazın.

4. **Paylaşılan Bellek Kurulumunu Tamamlama**:
- Uzaktaki `OS_xpc_shmem` nesnesini doğrulayın.
- Uzaktan `xpc_shmem_remote()` çağrısıyla paylaşılan bellek eşlemesini oluşturun.

Bu adımları takip ederek, yerel ve uzak görevler arasında paylaşılan bellek verimli bir şekilde kurulacak ve basit veri transferleri ve çoklu argüman gerektiren işlevlerin yürütülmesi mümkün olacaktır.

## Ek Kod Parçacıkları

Bellek tahsisi ve paylaşılan bellek nesnesi oluşturmak için:
```c
mach_vm_allocate();
xpc_shmem_create();
```
Uzak işlemde paylaşılan bellek nesnesi oluşturmak ve düzeltmek için:
```c
malloc(); // for allocating memory remotely
thread_set_special_port(); // for inserting send right
```
Mach bağlantı noktalarının ve bellek giriş adlarının ayrıntılarını doğru bir şekilde ele alarak paylaşılan belleğin düzgün çalışmasını sağlamak önemlidir.


## 5. Tam Kontrol Elde Etme

Paylaşılan belleği başarıyla kurduktan ve keyfi yürütme yeteneklerini elde ettikten sonra, hedef süreç üzerinde tam kontrol elde etmiş oluruz. Bu kontrolü sağlayan temel işlevler şunlardır:

1. **Keyfi Bellek İşlemleri**:
- Paylaşılan bölgeden veri kopyalamak için `memcpy()` işlevini çağırarak keyfi bellek okumaları gerçekleştirin.
- Paylaşılan bölgeye veri aktarmak için `memcpy()` kullanarak keyfi bellek yazmaları gerçekleştirin.

2. **Birden Fazla Argümanı Olan Fonksiyon Çağrılarını Yönetme**:
- 8'den fazla argüman gerektiren fonksiyonlar için, ek argümanları çağırma kuralına uygun olarak yığına yerleştirin.

3. **Mach Bağlantı Noktası Aktarımı**:
- Daha önceden kurulan bağlantı noktaları aracılığıyla Mach mesajları ile Mach bağlantı noktalarını görevler arasında aktarın.

4. **Dosya Tanımlayıcı Aktarımı**:
- Ian Beer tarafından `triple_fetch`te vurgulanan bir teknik olan dosya tanımlayıcılarını işlemler arasında aktarın.

Bu kapsamlı kontrol, hedef süreçle etkileşim için ayrıntılı bir uygulama ve kullanıcı dostu bir API sağlayan [threadexec](https://github.com/bazad/threadexec) kütüphanesinde yer almaktadır.

## Önemli Düşünceler:

- Sistem kararlılığını ve veri bütünlüğünü korumak için bellek okuma/yazma işlemleri için `memcpy()` işlevini doğru bir şekilde kullanın.
- Mach bağlantı noktalarını veya dosya tanımlayıcılarını aktarırken, sızıntıları veya istenmeyen erişimleri önlemek için uygun protokollere uyun ve kaynakları sorumlu bir şekilde yönetin.

Bu yönergeleri takip ederek ve `threadexec` kütüphanesini kullanarak, hedef süreç üzerinde tam kontrol sağlayarak süreçleri ayrıntılı bir şekilde yönetebilir ve etkileşimde bulunabilirsiniz.

## Referanslar
* [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklam vermek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi Twitter'da takip edin 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live).
* Hacking hilelerinizi **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>
