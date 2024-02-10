# macOS MIG - Mach Arayüzü Oluşturucusu

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

MIG, Mach IPC kodu oluşturma sürecini **basitleştirmek için oluşturulmuştur**. Temel olarak, sunucu ve istemcinin iletişim kurması için gereken kodu **otomatik olarak oluşturur**. Oluşturulan kod ne kadar kötü görünse de, bir geliştirici sadece bunu içe aktarması gerekecek ve kodu öncekinden çok daha basit olacaktır.

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

Şimdi, birbirleriyle iletişim kurabilen sunucu ve istemci kodunu oluşturmak için mig'i kullanın. Bu kodlar, Subtract fonksiyonunu çağırmak için birbirleriyle iletişim kurabilecekler.
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
Geçerli dizinde birkaç yeni dosya oluşturulacak.

**`myipcServer.c`** ve **`myipcServer.h`** dosyalarında **`SERVERPREFmyipc_subsystem`** yapısının bildirimi ve tanımını bulabilirsiniz. Bu yapı, alınan mesaj kimliğine dayalı olarak çağrılacak işlevi tanımlar (başlangıç numarası olarak 500 belirttik):

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
{% tab title="myipcServer.h" %}

```c
#ifndef myipcServer_h
#define myipcServer_h

#include <stdio.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <mach/mach_error.h>
#include <mach/mach_traps.h>
#include <mach/mach_types.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_server.h>
#include <mach/mach_host_user.h>
#include <mach/mach_host_reboot.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_host_info.h>
#include <mach/mach_host_notify.h>
#include <mach/mach_host_security.h>
#include <mach/mach_host_policy.h>
#include <mach/mach_host_qos.h>
#include <mach/mach_host_ledger.h>
#include <mach/mach_host_statistics.h>
#include <mach/mach_host_vm_info.h>
#include <mach/mach_host_vm_priv.h>
#include <mach/mach_host_vm_ext.h>
#include <mach/mach_host_vm_prot.h>
#include <mach/mach_host_vm_behavior.h>
#include <mach/mach_host_vm_region.h>
#include <mach/mach_host_vm_purgable.h>
#include <mach/mach_host_vm_wire.h>
#include <mach/mach_host_vm_pressure.h>
#include <mach/mach_host_vm_page_info.h>
#include <mach/mach_host_vm_page_query.h>
#include <mach/mach_host_vm_page_range.h>
#include <mach/mach_host_vm_page_behavior.h>
#include <mach/mach_host_vm_page_info_internal.h>
#include <mach/mach_host_vm_page_info_external.h>
#include <mach/mach_host_vm_page_info_basic.h>
#include <mach/mach_host_vm_page_info_extended.h>
#include <mach/mach_host_vm_page_info_compressed.h>
#include <mach/mach_host_vm_page_info_purgable.h>
#include <mach/mach_host_vm_page_info_wire.h>
#include <mach/mach_host_vm_page_info_shared.h>
#include <mach/mach_host_vm_page_info_iokit_mapped.h>
#include <mach/mach_host_vm_page_info_iokit_reusable.h>
#include <mach/mach_host_vm_page_info_iokit_shared.h>
#include <mach/mach_host_vm_page_info_iokit_private.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_reusable.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_private.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_reusable.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_reusable_private.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_reusable_private.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_basic.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_extended.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_compressed.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_purgable.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_wire.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_shared.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_mapped.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_reusable.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_shared.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_private.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_reusable.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_private.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_reusable.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_shared.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_mapped.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_reusable.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_shared.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_private.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_reusable.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_private.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_reusable.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_mapped.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_reusable.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_shared.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_private.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_reusable.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_private.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_mapped.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_reusable.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_shared.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_private.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_reusable.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_private.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_mapped.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_reusable.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_shared.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_private.h>
#include <mach/mach_host_vm_page_info_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_external_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire_iokit_iomapped_shared_private_reusable_compressed_purgable_wire
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

Önceki yapıya dayanarak, **`myipc_server_routine`** işlevi **mesaj kimliğini** alacak ve çağrılacak uygun işlevi döndürecektir:
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
Bu örnekte, tanımlamalarda sadece 1 fonksiyon tanımladık, ancak daha fazla fonksiyon tanımlasaydık, bunlar **`SERVERPREFmyipc_subsystem`** dizisinin içinde olacaktı ve ilk fonksiyon ID **500**'e, ikinci fonksiyon ID **501**'e atanacaktı...

Aslında bu ilişkiyi **`myipcServer.h`** dosyasındaki **`subsystem_to_name_map_myipc`** yapısında tanımlayabiliriz:
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Son olarak, sunucunun çalışmasını sağlamak için önemli bir işlev olan **`myipc_server`** olacak, bu işlev aslında alınan id'ye bağlı olan işlevi **çağıracaktır**:

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

ID'ye göre çağrılacak işlevi erişmek için önceden vurgulanan satırları kontrol edin.

Aşağıda, istemcinin sunucudan Subtract işlevlerini çağırabileceği basit bir **sunucu** ve **istemci** kodu bulunmaktadır:

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
{% tab title="myipc_client.c" %}

```c
#include <stdio.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <servers/bootstrap.h>

#define SERVER_NAME "com.example.myipc_server"

int main() {
    mach_port_t server_port;
    kern_return_t kr;
    char message[256];
    
    // Look up the server port
    kr = bootstrap_look_up(bootstrap_port, SERVER_NAME, &server_port);
    if (kr != KERN_SUCCESS) {
        printf("Failed to look up server port: %s\n", mach_error_string(kr));
        exit(1);
    }
    
    // Prepare the message
    snprintf(message, sizeof(message), "Hello from client");
    
    // Send the message
    kr = mach_msg((mach_msg_header_t *)&message, MACH_SEND_MSG, sizeof(message), 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        printf("Failed to send message: %s\n", mach_error_string(kr));
        exit(1);
    }
    
    printf("Message sent successfully\n");
    
    return 0;
}
```

{% endtab %}
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

### Binary Analizi

Birçok ikili dosya artık MIG'yi kullanarak mach bağlantı noktalarını açığa çıkardığından, MIG'nin kullanıldığını **belirlemek** ve her mesaj kimliğiyle **MIG'nin yürüteceği işlevleri** tanımak ilginç olabilir.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/#jtool2), bir Mach-O ikili dosyasından MIG bilgilerini ayrıştırabilir ve mesaj kimliğini göstererek yürütülecek işlevi tanımlayabilir:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
Daha önce, **alınan mesaj kimliğine bağlı olarak doğru işlevi çağıracak olan fonksiyonun** `myipc_server` olduğu belirtilmişti. Ancak genellikle ikili dosyanın sembolleri (işlev adları yok) olmayacaktır, bu yüzden dekompilasyonun nasıl göründüğünü kontrol etmek ilginç olacaktır çünkü her zaman çok benzer olacaktır (bu işlevin kodu, sunulan işlevlerden bağımsızdır):

{% tabs %}
{% tab title="myipc_server decompiled 1" %}
<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
var_10 = arg0;
var_18 = arg1;
// Uygun işlev işaretçilerini bulmak için ilk talimatlar
*(int32_t *)var_18 = *(int32_t *)var_10 &#x26; 0x1f;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
if (*(int32_t *)(var_10 + 0x14) &#x3C;= 0x1f4 &#x26;&#x26; *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
rax = *(int32_t *)(var_10 + 0x14);
// Bu işlevi tanımlamaya yardımcı olabilecek sign_extend_64 çağrısı
// Bu, çağrılması gereken işlevin işaretçisini rax'e depolar
// 0x1f4 = 500 (başlangıç ​​ID'si)
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
// If - else, if yanlış dönerken else doğru işlevi çağırır ve true döner
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

{% tab title="myipc_server decompiled 2" %}
Bu, farklı bir Hopper free sürümünde dekompile edilmiş aynı işlevdir:

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
r31 = r31 - 0x40;
saved_fp = r29;
stack[-8] = r30;
var_10 = arg0;
var_18 = arg1;
// Uygun işlev işaretçilerini bulmak için ilk talimatlar
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
// Önceki sürümdeki gibi if else
// 0x100004040 adresinin kullanımını kontrol edin (işlevlerin adresleri dizisi)
<strong>                    if ((r8 &#x26; 0x1) == 0x0) {
</strong><strong>                            *(var_18 + 0x18) = **0x100004000;
</strong>                            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
else {
// Hesaplanan adrese yapılan çağrıda işlevin çağrılması
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

Aslında **`0x100004000`** işlevine giderseniz, **`routine_descriptor`** yapılarının bir dizisini bulacaksınız. Yapının ilk öğesi, işlevin uygulandığı **adres**'dir ve **yapı 0x28 bayt** alır, bu yüzden her 0x28 baytta (bayt 0'dan başlayarak) 8 bayt alabilir ve bu, çağrılacak olan **işlevin adresi** olacaktır:

<figure><img src="../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Bu veriler, [**bu Hopper betiği kullanılarak**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py) çıkarılabilir.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hack
* **💬 [Discord grubuna](https://discord.gg/hRep4RUj7f) veya [telegram grubuna](https://t.me/peass) katılın** veya **Twitter'da** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)** bizi takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) **ve** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github reposuna PR göndererek paylaşın**.

</details>
