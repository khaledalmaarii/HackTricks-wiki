# macOS MIG - Mach Interface Generator

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

MIG was created to **simplify the process of Mach IPC** code creation. It basically **generates the needed code** for server and client to communicate with a given definition. Even if the generated code is ugly, a developer will just need to import it and his code will be much simpler than before.

### Example

Create a definition file, in this case with a very simple function:

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

DaH jImej mig lo'laHbe' ghaH client code je server code jatlhbe' Subtract vItlhutlh.
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
ghItlh 'ej **`myipcServer.h`** **`myipc_subsystem`** **`SERVERPREF`** **`struct`** **`definition`** **`declaration`** **`function`** **`received`** **`message ID`** **`based`** **`call`** **`defines`** **`starting number`** **`indicated`** **`we`** **`500`**:

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
#include <servers/bootstrap.h>
#include <mach/mach_traps.h>
#include <mach/mach_types.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/mach_interface.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_server.h>
#include <mach/mach_host_user.h>
#include <mach/mach_host_info.h>
#include <mach/mach_host_reboot.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_host_security.h>
#include <mach/mach_host_priv_server.h>
#include <mach/mach_host_user_server.h>
#include <mach/mach_host_info_server.h>
#include <mach/mach_host_reboot_server.h>
#include <mach/mach_host_special_ports_server.h>
#include <mach/mach_host_security_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach/mach_types_server.h>
#include <mach/mach_traps_server.h>
#include <mach/mach_error_server.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_voucher_types_server.h>
#include <mach/mach_voucher_server.h>
#include <mach/mach_time_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_interface_server.h>
#include <mach/mach_init_server.h>
#include <mach
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

**`myipc_server_routine`** jupwI'pu' **ghItlh ID** 'ej **ghItlh** jImej qar'a'chaj:
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
**Dujatlh:** 
vaj jatlhpu' **`SERVERPREFmyipc_subsystem`** lo'laHbe'chugh **1** pagh, 'ach vaj jatlhpu' pagh **1** pagh, **500** ID **1** pagh, **501** ID **2** pagh... **500** ID **1** pagh, **501** ID **2** pagh... **`myipcServer.h`** **`subsystem_to_name_map_myipc`** **struct** vItlhutlh **relation** 'e' vItlhutlh.
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Qatlh, **`myipc_server`** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **gh
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
    kern_return_t kr;
    mach_port_t server_port;
    char message[256] = "Hello from client!";
    mach_msg_header_t *msg = (mach_msg_header_t *)message;
    
    // Look up the server port
    kr = bootstrap_look_up(bootstrap_port, SERVER_NAME, &server_port);
    if (kr != KERN_SUCCESS) {
        printf("Failed to look up server port: %s\n", mach_error_string(kr));
        exit(1);
    }
    
    // Set up the message header
    msg->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    msg->msgh_size = sizeof(message);
    msg->msgh_remote_port = server_port;
    msg->msgh_local_port = MACH_PORT_NULL;
    msg->msgh_reserved = 0;
    msg->msgh_id = 0;
    
    // Send the message
    kr = mach_msg(msg, MACH_SEND_MSG, msg->msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        printf("Failed to send message: %s\n", mach_error_string(kr));
        exit(1);
    }
    
    printf("Message sent!\n");
    
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

### Binary Analysis

**QaStaHvIS** binaries vItlhutlh MIG vItlhutlh mach ports, **MIG vItlhutlh** **cheghDI' MIG** **ghItlhID** je **ghItlhID** **MIG executes** **ghItlhID**.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/#jtool2) Mach-O binary vItlhutlh MIG information parse vItlhutlh, message ID je function vItlhutlh execute vItlhutlh:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
It was previously mentioned that the function that will take care of **calling the correct function depending on the received message ID** was `myipc_server`. However, you usually won't have the symbols of the binary (no functions names), so it's interesting to **check how it looks like decompiled** as it will always be very similar (the code of this function is independent from the functions exposed):

{% tabs %}
{% tab title="myipc_server decompiled 1" %}
<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
var_10 = arg0;
var_18 = arg1;
// Initial instructions to find the proper function ponters
*(int32_t *)var_18 = *(int32_t *)var_10 &#x26; 0x1f;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
if (*(int32_t *)(var_10 + 0x14) &#x3C;= 0x1f4 &#x26;&#x26; *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
rax = *(int32_t *)(var_10 + 0x14);
// Call to sign_extend_64 that can help to identifyf this function
// This stores in rax the pointer to the call that needs to be called
// Check the used of the address 0x100004040 (functions addresses array)
// 0x1f4 = 500 (the strating ID)
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
// If - else, the if returns false, while the else call the correct function and returns true
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
else {
// Calculated address that calls the proper function with 2 arguments
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
This is the same function decompiled in a difefrent Hopper free version:

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
r31 = r31 - 0x40;
saved_fp = r29;
stack[-8] = r30;
var_10 = arg0;
var_18 = arg1;
// Initial instructions to find the proper function ponters
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
// 0x1f4 = 500 (the strating ID)
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
// Same if else as in the previous version
// Check the used of the address 0x100004040 (functions addresses array)
<strong>                    if ((r8 &#x26; 0x1) == 0x0) {
</strong><strong>                            *(var_18 + 0x18) = **0x100004000;
</strong>                            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
else {
// Call to the calculated address where the function should be
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

Actually if you go to the function **`0x100004000`** you will find the array of **`routine_descriptor`** structs. The first element of the struct is the **address** where the **function** is implemented, and the **struct takes 0x28 bytes**, so each 0x28 bytes (starting from byte 0) you can get 8 bytes and that will be the **address of the function** that will be called:

<figure><img src="../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

This data can be extracted [**using this Hopper script**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py).

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
