# macOS MIG - Mach Arayüz Oluşturucusu

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek hackleme püf noktalarını paylaşın.

</details>
{% endhint %}

## Temel Bilgiler

MIG, **Mach IPC** kod oluşturma sürecini **basitleştirmek** için oluşturulmuştur. Temelde, sunucu ve istemcinin iletişim kurması için gerekli kodu **oluşturur**. Oluşturulan kodun kötü görünmesine rağmen, bir geliştiricinin bunu içe aktarması yeterli olacak ve kodu öncekinden çok daha basit olacaktır.

Tanım, `.defs` uzantısını kullanarak Arayüz Tanım Dili (IDL) ile belirtilir.

Bu tanımlar 5 bölüme sahiptir:

* **Alt sistem bildirimi**: `Alt sistem` anahtar kelimesi, **adı** ve **kimliği** belirtmek için kullanılır. Sunucunun çekirdekte çalışması gerekiyorsa **`KernelServer`** olarak işaretlenebilir.
* **Dahil ve içe aktarmalar**: MIG, C ön işleyiciyi kullanır, bu nedenle içe aktarmaları kullanabilir. Ayrıca, kullanıcı veya sunucu oluşturulan kodlar için `uimport` ve `simport` kullanmak mümkündür.
* **Tür bildirimleri**: Veri tiplerini tanımlamak mümkündür, ancak genellikle `mach_types.defs` ve `std_types.defs` içe aktarılır. Özel olanlar için bazı sözdizimi kullanılabilir:
* \[i`n/out]tran`: Gelen veya giden bir iletiyi çevirmesi gereken işlev
* `c[user/server]type`: Başka bir C türüne eşleme.
* `destructor`: Tür serbest bırakıldığında bu işlevi çağırın.
* **İşlemler**: Bunlar RPC yöntemlerinin tanımlarıdır. 5 farklı tür vardır:
* `routine`: Yanıt bekler
* `simpleroutine`: Yanıt beklemiyor
* `procedure`: Yanıt bekler
* `simpleprocedure`: Yanıt beklemiyor
* `function`: Yanıt bekler

### Örnek

Çok basit bir işlevle bir tanım dosyası oluşturun:

{% code title="myipc.defs" %}
```cpp
subsystem myipc 500; // Arbitrary name and id

userprefix USERPREF;        // Prefix for created functions in the client
serverprefix SERVERPREF;    // Prefix for created functions in the server

#include <mach/mach_types.defs>
#include <mach/std_types.defs>

simpleroutine Subtract(
server_port :  mach_port_t;
n1          :  uint32_t;
n2          :  uint32_t);
```
{% endcode %}

İlk **argümanın bağlanacak bağlantı noktası olduğunu** ve MIG'in **yanıt bağlantı noktasını otomatik olarak ele alacağını** unutmayın (`mig_get_reply_port()` çağrılmadığı sürece istemci kodunda). Ayrıca, **işlemlerin kimliğinin** belirtilen alt sistem kimliği ile başlayarak **ardışık** olacağını unutmayın (bu nedenle bir işlem kullanımdan kaldırıldığında silinir ve hala kimliğini kullanmak için `skip` kullanılır).

Şimdi, birbirleriyle iletişim kurabilecek sunucu ve istemci kodunu oluşturmak için MIG'i kullanın ve Çıkarma işlevini çağırmak için:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
Çeşitli yeni dosyalar mevcut dizinde oluşturulacaktır.

{% hint style="success" %}
Daha karmaşık bir örneği sisteminizde şu komutla bulabilirsiniz: `mdfind mach_port.defs`\
Ve aynı klasörden derleyebilirsiniz: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`
{% endhint %}

**`myipcServer.c`** ve **`myipcServer.h`** dosyalarında **`SERVERPREFmyipc_subsystem`** yapısının bildirimi ve tanımını bulabilirsiniz, bu yapı temelde alınan mesaj kimliğine göre çağrılacak işlevi tanımlar (başlangıç numarasını 500 olarak belirttik):

{% tabs %}
{% tab title="myipcServer.c" %}
```c
/* Description of this subsystem, for use in direct RPC */
const struct SERVERPREFmyipc_subsystem SERVERPREFmyipc_subsystem = {
myipc_server_routine,
500, // start ID
501, // end ID
(mach_msg_size_t)sizeof(union __ReplyUnion__SERVERPREFmyipc_subsystem),
(vm_address_t)0,
{
{ (mig_impl_routine_t) 0,
// Function to call
(mig_stub_routine_t) _XSubtract, 3, 0, (routine_arg_descriptor_t)0, (mach_msg_size_t)sizeof(__Reply__Subtract_t)},
}
};
```
{% endtab %}

{% tab title="myipcServer.h" %} 

### macOS IPC (Inter-Process Communication)

#### macOS MIG (Mach Interface Generator)

Mach Interface Generator (MIG) is a tool used to define inter-process communication interfaces in macOS. It generates server-side and client-side code for message-based communication between processes. By defining MIG interfaces, developers can create structured communication protocols for secure and efficient data exchange between processes in macOS.

#### macOS MIG (Mach Arayüz Oluşturucu)

Mach Arayüz Oluşturucu (MIG), macOS'ta ara işlem iletişimi arayüzlerini tanımlamak için kullanılan bir araçtır. MIG, işlemler arasında mesaj tabanlı iletişim için sunucu ve istemci tarafı kodu oluşturur. MIG arayüzlerini tanımlayarak, geliştiriciler macOS'ta işlemler arasında güvenli ve verimli veri alışverişi için yapılandırılmış iletişim protokolleri oluşturabilirler.
```c
/* Description of this subsystem, for use in direct RPC */
extern const struct SERVERPREFmyipc_subsystem {
mig_server_routine_t	server;	/* Server routine */
mach_msg_id_t	start;	/* Min routine number */
mach_msg_id_t	end;	/* Max routine number + 1 */
unsigned int	maxsize;	/* Max msg size */
vm_address_t	reserved;	/* Reserved */
struct routine_descriptor	/* Array of routine descriptors */
routine[1];
} SERVERPREFmyipc_subsystem;
```
{% endtab %}
{% endtabs %}

Önceki yapıya dayanarak **`myipc_server_routine`** işlevi **mesaj kimliğini** alacak ve çağrılacak uygun işlevi döndürecektir:
```c
mig_external mig_routine_t myipc_server_routine
(mach_msg_header_t *InHeadP)
{
int msgh_id;

msgh_id = InHeadP->msgh_id - 500;

if ((msgh_id > 0) || (msgh_id < 0))
return 0;

return SERVERPREFmyipc_subsystem.routine[msgh_id].stub_routine;
}
```
Bu örnekte tanımladığımız sadece 1 fonksiyon var, ancak daha fazla fonksiyon tanımlasaydık, bunlar **`SERVERPREFmyipc_subsystem`** dizisinin içinde olacaktı ve ilk fonksiyon **500** ID'ye, ikinci fonksiyon ise **501** ID'ye atanacaktı...

Eğer fonksiyondan bir **yanıt** bekleniyorsa, `mig_internal kern_return_t __MIG_check__Reply__<name>` fonksiyonu da mevcut olacaktı.

Aslında bu ilişkiyi **`myipcServer.h`** dosyasındaki **`subsystem_to_name_map_myipc`** yapısında (**diğer dosyalardaki **`subsystem_to_name_map_***`** yapısında) tanımlamak mümkündür:
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Son olarak, sunucunun çalışmasını sağlamak için önemli bir işlev olan **`myipc_server`** olacaktır, bu işlev aslında alınan kimliğe ilişkin işlevi **çağıracaktır**:

<pre class="language-c"><code class="lang-c">mig_external boolean_t myipc_server
(mach_msg_header_t *InHeadP, mach_msg_header_t *OutHeadP)
{
/*
* typedef struct {
* 	mach_msg_header_t Head;
* 	NDR_record_t NDR;
* 	kern_return_t RetCode;
* } mig_reply_error_t;
*/

mig_routine_t routine;

OutHeadP->msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REPLY(InHeadP->msgh_bits), 0);
OutHeadP->msgh_remote_port = InHeadP->msgh_reply_port;
/* Minimal size: routine() will update it if different */
OutHeadP->msgh_size = (mach_msg_size_t)sizeof(mig_reply_error_t);
OutHeadP->msgh_local_port = MACH_PORT_NULL;
OutHeadP->msgh_id = InHeadP->msgh_id + 100;
OutHeadP->msgh_reserved = 0;

if ((InHeadP->msgh_id > 500) || (InHeadP->msgh_id &#x3C; 500) ||
<strong>	    ((routine = SERVERPREFmyipc_subsystem.routine[InHeadP->msgh_id - 500].stub_routine) == 0)) {
</strong>		((mig_reply_error_t *)OutHeadP)->NDR = NDR_record;
((mig_reply_error_t *)OutHeadP)->RetCode = MIG_BAD_ID;
return FALSE;
}
<strong>	(*routine) (InHeadP, OutHeadP);
</strong>	return TRUE;
}
</code></pre>

Önceki vurgulanan satırları kontrol ederek, kimliğe göre çağrılacak işlevlere erişimi kontrol edin.

Aşağıdaki kod, istemcinin sunucudan çıkarmak için işlevleri çağırabileceği basit bir **sunucu** ve **istemci** oluşturmak için kullanılan koddur:

{% tabs %}
{% tab title="myipc_server.c" %}
```c
// gcc myipc_server.c myipcServer.c -o myipc_server

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "myipcServer.h"

kern_return_t SERVERPREFSubtract(mach_port_t server_port, uint32_t n1, uint32_t n2)
{
printf("Received: %d - %d = %d\n", n1, n2, n1 - n2);
return KERN_SUCCESS;
}

int main() {

mach_port_t port;
kern_return_t kr;

// Register the mach service
kr = bootstrap_check_in(bootstrap_port, "xyz.hacktricks.mig", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_check_in() failed with code 0x%x\n", kr);
return 1;
}

// myipc_server is the function that handles incoming messages (check previous exlpanation)
mach_msg_server(myipc_server, sizeof(union __RequestUnion__SERVERPREFmyipc_subsystem), port, MACH_MSG_TIMEOUT_NONE);
}
```
{% endtab %}

{% tab title="myipc_client.c" %} 

## myipc_client.c

```c
#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <mach/mach_traps.h>
#include <mach/mach_init.h>
#include <mach/mach_error.h>
#include <mach/mach_host.h>
#include <mach/mach_port.h>
#includejson <mach/mach_interface.h>
#include <mach/mach_types.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control.h>
#include <mach/mach_voucher_deallocate.h>
#include <mach/mach_voucher_extract_attr_recipe.h>
#include <mach/mach_voucher_extract_attr_recipe_reply.h>
#include json<mach/mach_voucher_notify.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_value_handle.h>
#include <mach/mach_voucher_attr_recipe.h>
#include <mach/mach_voucher_attr_recipe_command.h>
#include <mach/mach_voucher_attr_command.h>
#include <mach/mach_voucher_attr_control_command.h>
#include <mach/mach_voucher_attr_value_handle_command.h>
#include <mach/mach_voucher_debug.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes.h>
#include <mach/mach_voucher_attr_control_flags.h>
#include <mach/mach_voucher_attr_value_handle_flags.h>
#include <mach/mach_voucher_attr_value_handle_user.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher_attr_control_user.h>
#include <mach/mach_voucher_user_attributes
```c
// gcc myipc_client.c myipcUser.c -o myipc_client

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "myipcUser.h"

int main() {

// Lookup the receiver port using the bootstrap server.
mach_port_t port;
kern_return_t kr = bootstrap_look_up(bootstrap_port, "xyz.hacktricks.mig", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_look_up() failed with code 0x%x\n", kr);
return 1;
}
printf("Port right name %d\n", port);
USERPREFSubtract(port, 40, 2);
}
```
{% endtab %}
{% endtabs %}

### NDR\_record

NDR\_record, `libsystem_kernel.dylib` tarafından ihraç edilir ve MIG'in **verileri dönüştürmesine izin veren bir yapıdır, böylece kullanıldığı sistemden bağımsız olur** çünkü MIG farklı sistemler arasında kullanılması düşünülmüştür (ve sadece aynı makinede değil).

Bu ilginç çünkü bir ikili dosyada `_NDR_record` bağımlılık olarak bulunursa (`jtool2 -S <binary> | grep NDR` veya `nm`), bu, ikili dosyanın bir MIG istemcisi veya Sunucusu olduğu anlamına gelir.

Ayrıca **MIG sunucularının** dağıtım tablosu `__DATA.__const` içinde bulunur (veya macOS çekirdeğinde `__CONST.__constdata` ve diğer \*OS çekirdeklerinde `__DATA_CONST.__const`). Bu **`jtool2`** ile dökülebilir.

Ve **MIG istemcileri**, `__mach_msg` ile sunuculara göndermek için `__NDR_record`'ı kullanacaktır.

## İkili Analiz

### jtool

Birçok ikili dosya artık mach portlarını açığa çıkarmak için MIG'i kullandığından, MIG'nin kullanıldığını **tanımlamanın** ve her mesaj kimliği ile **MIG'in yürüttüğü işlevleri** belirlemenin nasıl olduğunu bilmek ilginçtir.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/#jtool2), bir Mach-O ikili dosyasından MIG bilgilerini ayrıştırabilir ve her mesaj kimliğini göstererek yürütülecek işlevi tanımlayabilir:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
Ayrıca, MIG işlevleri, çağrılan gerçek işlevin sadece kılıfıdır, bu da dissasembly alarak BL için grep yaparak çağrılan gerçek işlevi bulabilirsiniz demektir:
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### Montaj

Daha önce **alınan mesaj kimliğine bağlı olarak doğru işlevi çağıracak olan fonksiyonun `myipc_server`** olduğu belirtilmişti. Ancak genellikle binary dosyanın sembolleri olmayacaktır (işlev isimleri yok), bu yüzden **derlenmiş halinin nasıl göründüğünü kontrol etmek ilginç olacaktır** çünkü her zaman çok benzer olacaktır (bu işlevin kodu, sunulan işlevlerden bağımsızdır):

{% tabs %}
{% tab title="myipc_server derlenmiş 1" %}
<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
var_10 = arg0;
var_18 = arg1;
// Doğru işlev işaretçilerini bulmak için ilk talimatlar
*(int32_t *)var_18 = *(int32_t *)var_10 &#x26; 0x1f;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
if (*(int32_t *)(var_10 + 0x14) &#x3C;= 0x1f4 &#x26;&#x26; *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
rax = *(int32_t *)(var_10 + 0x14);
// Çağrılması gereken işlevin işaretçisini belirlemeye yardımcı olabilecek sign_extend_64 çağrısı
// Bu, rax'e çağrılması gereken çağrının işaretçisini depolar
// Kullanılan adresi kontrol et 0x100004040 (işlev adresleri dizisi)
// 0x1f4 = 500 (başlangıç ​​ID'si)
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
// If - else, if döndürmezken else doğru işlevi çağırır ve true döndürür
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
else {
// 2 argümanla doğru işlevi çağıran hesaplanmış adres
<strong>                    (var_20)(var_10, var_18);
</strong>                    var_4 = 0x1;
}
}
else {
*(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
rax = var_4;
return rax;
}
</code></pre>
{% endtab %}

{% tab title="myipc_server derlenmiş 2" %}
Bu, farklı bir Hopper free sürümünde derlenmiş aynı işlevdir:

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
r31 = r31 - 0x40;
saved_fp = r29;
stack[-8] = r30;
var_10 = arg0;
var_18 = arg1;
// Doğru işlev işaretçilerini bulmak için ilk talimatlar
*(int32_t *)var_18 = *(int32_t *)var_10 &#x26; 0x1f | 0x0;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
r8 = *(int32_t *)(var_10 + 0x14);
r8 = r8 - 0x1f4;
if (r8 > 0x0) {
if (CPU_FLAGS &#x26; G) {
r8 = 0x1;
}
}
if ((r8 &#x26; 0x1) == 0x0) {
r8 = *(int32_t *)(var_10 + 0x14);
r8 = r8 - 0x1f4;
if (r8 &#x3C; 0x0) {
if (CPU_FLAGS &#x26; L) {
r8 = 0x1;
}
}
if ((r8 &#x26; 0x1) == 0x0) {
r8 = *(int32_t *)(var_10 + 0x14);
// 0x1f4 = 500 (başlangıç ​​ID'si)
<strong>                    r8 = r8 - 0x1f4;
</strong>                    asm { smaddl     x8, w8, w9, x10 };
r8 = *(r8 + 0x8);
var_20 = r8;
r8 = r8 - 0x0;
if (r8 != 0x0) {
if (CPU_FLAGS &#x26; NE) {
r8 = 0x1;
}
}
// Önceki sürümdeki gibi aynı if else
// Kullanılan adresi kontrol et 0x100004040 (işlev adresleri dizisi)
<strong>                    if ((r8 &#x26; 0x1) == 0x0) {
</strong><strong>                            *(var_18 + 0x18) = **0x100004000;
</strong>                            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
else {
// İşlevin çağrılması gereken hesaplanmış adresine çağrı
<strong>                            (var_20)(var_10, var_18);
</strong>                            var_4 = 0x1;
}
}
else {
*(var_18 + 0x18) = **0x100004000;
*(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
}
else {
*(var_18 + 0x18) = **0x100004000;
*(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
r0 = var_4;
return r0;
}

</code></pre>
{% endtab %}
{% endtabs %}

Aslında **`0x100004000`** işlevine giderseniz, **`routine_descriptor`** yapılarının bir dizisini bulacaksınız. Yapının ilk öğesi, **işlevin uygulandığı adres** ve **yapı 0x28 bayt alır**, bu nedenle her 0x28 baytta (bayt 0'dan başlayarak) 8 bayt alabilir ve bu, **çağrılacak işlevin adresi** olacaktır:

<figure><img src="../../../../.gitbook/assets/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (36).png" alt=""><figcaption></figcaption></figure>

Bu veriler, [**bu Hopper betiği kullanılarak**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py) çıkarılabilir.
### Hata Ayıklama

MIG tarafından oluşturulan kod ayrıca `kernel_debug`'ı çağırarak giriş ve çıkış işlemleri hakkında günlükler oluşturur. Bunları **`trace`** veya **`kdv`** kullanarak kontrol etmek mümkündür: `kdv all | grep MIG`

## Referanslar

* [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{% hint style="success" %}
AWS Hacking öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitimi AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitimi GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Destek HackTricks</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}
