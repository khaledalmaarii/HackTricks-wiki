# macOS MIG - Generatore di Interfacce Mach

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

MIG è stato creato per **semplificare il processo di creazione del codice Mach IPC**. Fondamentalmente, **genera il codice necessario** per far comunicare il server e il client con una definizione data. Anche se il codice generato è brutto, uno sviluppatore dovrà solo importarlo e il suo codice sarà molto più semplice rispetto a prima.

### Esempio

Crea un file di definizione, in questo caso con una funzione molto semplice:

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

Ora utilizza mig per generare il codice del server e del client che saranno in grado di comunicare tra loro per chiamare la funzione Sottrai:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
Verranno creati diversi nuovi file nella directory corrente.

Nei file **`myipcServer.c`** e **`myipcServer.h`** puoi trovare la dichiarazione e la definizione della struttura **`SERVERPREFmyipc_subsystem`**, che essenzialmente definisce la funzione da chiamare in base all'ID del messaggio ricevuto (abbiamo indicato un numero di partenza di 500):

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
#include <mach/mach_port_types.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach_port_server.h>
#include <mach/mach_port_types_server.h>
#include <mach/mach
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

Basandosi sulla struttura precedente, la funzione **`myipc_server_routine`** riceverà l'**ID del messaggio** e restituirà la funzione corretta da chiamare:
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
In questo esempio abbiamo definito solo 1 funzione nelle definizioni, ma se avessimo definito più funzioni, sarebbero state all'interno dell'array di **`SERVERPREFmyipc_subsystem`** e la prima sarebbe stata assegnata all'ID **500**, la seconda all'ID **501**...

In realtà è possibile identificare questa relazione nella struttura **`subsystem_to_name_map_myipc`** da **`myipcServer.h`**:
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Infine, un'altra funzione importante per far funzionare il server sarà **`myipc_server`**, che è quella che effettivamente **chiama la funzione** relativa all'id ricevuto:

```c
mig_external boolean_t myipc_server
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
/* Dimensione minima: routine() la aggiornerà se diversa */
OutHeadP->msgh_size = (mach_msg_size_t)sizeof(mig_reply_error_t);
OutHeadP->msgh_local_port = MACH_PORT_NULL;
OutHeadP->msgh_id = InHeadP->msgh_id + 100;
OutHeadP->msgh_reserved = 0;

if ((InHeadP->msgh_id > 500) || (InHeadP->msgh_id < 500) ||
	    ((routine = SERVERPREFmyipc_subsystem.routine[InHeadP->msgh_id - 500].stub_routine) == 0)) {
		((mig_reply_error_t *)OutHeadP)->NDR = NDR_record;
((mig_reply_error_t *)OutHeadP)->RetCode = MIG_BAD_ID;
return FALSE;
}
	(*routine) (InHeadP, OutHeadP);
	return TRUE;
}
```

Controlla le linee precedentemente evidenziate per accedere alla funzione da chiamare tramite ID.

Di seguito è riportato il codice per creare un semplice **server** e **client** in cui il client può chiamare la funzione Sottrai dal server:

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
```c
#include <stdio.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <servers/bootstrap.h>
#include "myipc.h"

int main(int argc, char *argv[]) {
    mach_port_t server_port;
    kern_return_t kr;
    myipc_msg_t msg;

    // Get the server port
    kr = bootstrap_look_up(bootstrap_port, "com.example.myipc_server", &server_port);
    if (kr != KERN_SUCCESS) {
        printf("Failed to get server port: %s\n", mach_error_string(kr));
        exit(1);
    }

    // Prepare the message
    msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    msg.header.msgh_size = sizeof(msg);
    msg.header.msgh_remote_port = server_port;
    msg.header.msgh_local_port = MACH_PORT_NULL;
    msg.header.msgh_id = 0;
    msg.data = 42;

    // Send the message
    kr = mach_msg(&msg.header, MACH_SEND_MSG, sizeof(msg), 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        printf("Failed to send message: %s\n", mach_error_string(kr));
        exit(1);
    }

    printf("Message sent successfully\n");

    return 0;
}
```
{% endtab %}

{% tab title="myipc_server.c" %}
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
### Analisi binaria

Poiché molti binari utilizzano ora MIG per esporre le porte mach, è interessante sapere come **identificare che MIG è stato utilizzato** e le **funzioni che MIG esegue** con ciascun ID del messaggio.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/#jtool2) può analizzare le informazioni MIG da un binario Mach-O indicando l'ID del messaggio e identificando la funzione da eseguire:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
È stato precedentemente menzionato che la funzione che si occuperà di **chiamare la funzione corretta in base all'ID del messaggio ricevuto** è `myipc_server`. Tuttavia, di solito non si avranno i simboli del binario (nessun nome di funzione), quindi è interessante **vedere come appare decompilato**, poiché sarà sempre molto simile (il codice di questa funzione è indipendente dalle funzioni esposte):

{% tabs %}
{% tab title="myipc_server decompilato 1" %}
<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
var_10 = arg0;
var_18 = arg1;
// Istruzioni iniziali per trovare i puntatori alle funzioni corrette
*(int32_t *)var_18 = *(int32_t *)var_10 &#x26; 0x1f;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
if (*(int32_t *)(var_10 + 0x14) &#x3C;= 0x1f4 &#x26;&#x26; *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
rax = *(int32_t *)(var_10 + 0x14);
// Chiamata a sign_extend_64 che può aiutare a identificare questa funzione
// Questo memorizza in rax il puntatore alla chiamata che deve essere effettuata
// Controlla l'uso dell'indirizzo 0x100004040 (array degli indirizzi delle funzioni)
// 0x1f4 = 500 (l'ID di partenza)
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
// If - else, l'if restituisce false, mentre l'else chiama la funzione corretta e restituisce true
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
else {
// Indirizzo calcolato che chiama la funzione corretta con 2 argomenti
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

{% tab title="myipc_server decompilato 2" %}
Questa è la stessa funzione decompilata in una versione diversa di Hopper free:

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
r31 = r31 - 0x40;
saved_fp = r29;
stack[-8] = r30;
var_10 = arg0;
var_18 = arg1;
// Istruzioni iniziali per trovare i puntatori alle funzioni corrette
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
// 0x1f4 = 500 (l'ID di partenza)
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
// Stesso if else della versione precedente
// Controlla l'uso dell'indirizzo 0x100004040 (array degli indirizzi delle funzioni)
<strong>                    if ((r8 &#x26; 0x1) == 0x0) {
</strong><strong>                            *(var_18 + 0x18) = **0x100004000;
</strong>                            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
else {
// Chiamata all'indirizzo calcolato dove dovrebbe essere la funzione
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

In realtà, se si va alla funzione **`0x100004000`**, si troverà l'array di strutture **`routine_descriptor`**. Il primo elemento della struttura è l'**indirizzo** in cui è implementata la **funzione**, e la **struttura occupa 0x28 byte**, quindi ogni 0x28 byte (a partire dal byte 0) è possibile ottenere 8 byte e quello sarà l'**indirizzo della funzione** che verrà chiamata:

<figure><img src="../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Questi dati possono essere estratti [**utilizzando questo script di Hopper**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py).

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su GitHub.

</details>
