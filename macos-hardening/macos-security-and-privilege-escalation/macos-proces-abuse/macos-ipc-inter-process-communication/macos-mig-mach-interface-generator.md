# macOS MIG - Mach-Schnittstellengenerator

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

MIG wurde entwickelt, um den Prozess der Erstellung von Mach IPC-Code zu **vereinfachen**. Es generiert im Wesentlichen den benötigten Code, damit Server und Client gemäß einer gegebenen Definition kommunizieren können. Auch wenn der generierte Code hässlich ist, muss ein Entwickler ihn nur importieren und sein Code wird viel einfacher sein als zuvor.

### Beispiel

Erstellen Sie eine Definition-Datei, in diesem Fall mit einer sehr einfachen Funktion:

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

Verwenden Sie jetzt mig, um den Server- und Client-Code zu generieren, der in der Lage sein wird, miteinander zu kommunizieren, um die Subtract-Funktion aufzurufen:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
Es werden mehrere neue Dateien im aktuellen Verzeichnis erstellt.

In den Dateien **`myipcServer.c`** und **`myipcServer.h`** finden Sie die Deklaration und Definition der Struktur **`SERVERPREFmyipc_subsystem`**, die im Wesentlichen die Funktion definiert, die basierend auf der empfangenen Nachrichten-ID aufgerufen werden soll (wir haben eine Startnummer von 500 angegeben):

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
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher
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

Basierend auf der vorherigen Struktur wird die Funktion **`myipc_server_routine`** die **Nachrichten-ID** erhalten und die entsprechende Funktion zurückgeben, die aufgerufen werden soll:
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
In diesem Beispiel haben wir nur eine Funktion in den Definitionen definiert, aber wenn wir mehr Funktionen definiert hätten, wären sie im Array von **`SERVERPREFmyipc_subsystem`** enthalten gewesen und die erste Funktion hätte die ID **500** zugewiesen bekommen, die zweite Funktion die ID **501**...

Tatsächlich ist es möglich, diese Beziehung in der Struktur **`subsystem_to_name_map_myipc`** aus **`myipcServer.h`** zu identifizieren:
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Schließlich wird eine weitere wichtige Funktion benötigt, um den Server zum Laufen zu bringen: **`myipc_server`**. Diese Funktion ruft tatsächlich die mit der empfangenen ID verknüpfte Funktion auf:

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
/* Minimale Größe: routine() aktualisiert sie, wenn sie unterschiedlich ist */
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

Überprüfen Sie die zuvor hervorgehobenen Zeilen, um auf die Funktion zuzugreifen, die anhand der ID aufgerufen werden soll.

Im Folgenden finden Sie den Code zum Erstellen eines einfachen **Servers** und **Clients**, bei dem der Client die Funktionen des Servers aufrufen kann, um Subtraktionen durchzuführen:

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

### Binäre Analyse

Da viele Binärdateien jetzt MIG verwenden, um Mach-Ports freizugeben, ist es interessant zu wissen, wie man **feststellt, dass MIG verwendet wurde** und die **Funktionen, die MIG mit jeder Nachrichten-ID ausführt**, identifiziert.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/#jtool2) kann MIG-Informationen aus einer Mach-O-Binärdatei analysieren und die Nachrichten-ID angeben sowie die auszuführende Funktion identifizieren:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
Es wurde zuvor erwähnt, dass die Funktion, die sich um den Aufruf der richtigen Funktion je nach empfangener Nachrichten-ID kümmert, `myipc_server` ist. Es ist jedoch interessant zu überprüfen, wie sie dekompiliert aussieht, da sie immer sehr ähnlich sein wird (der Code dieser Funktion ist unabhängig von den freigegebenen Funktionen):

{% tabs %}
{% tab title="myipc_server dekompiliert 1" %}
<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
var_10 = arg0;
var_18 = arg1;
// Anfangsanweisungen zum Finden der richtigen Funktionszeiger
*(int32_t *)var_18 = *(int32_t *)var_10 &#x26; 0x1f;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
if (*(int32_t *)(var_10 + 0x14) &#x3C;= 0x1f4 &#x26;&#x26; *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
rax = *(int32_t *)(var_10 + 0x14);
// Aufruf von sign_extend_64, der helfen kann, diese Funktion zu identifizieren
// Dadurch wird rax auf den Zeiger gesetzt, der aufgerufen werden muss
// Überprüfen Sie die Verwendung der Adresse 0x100004040 (Array der Funktionsadressen)
// 0x1f4 = 500 (die Start-ID)
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
// If-Else, das If gibt false zurück, während Else die richtige Funktion aufruft und true zurückgibt
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
else {
// Berechnete Adresse, die die richtige Funktion mit 2 Argumenten aufruft
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

{% tab title="myipc_server dekompiliert 2" %}
Dies ist dieselbe Funktion, dekompiliert in einer anderen Hopper Free-Version:

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
r31 = r31 - 0x40;
saved_fp = r29;
stack[-8] = r30;
var_10 = arg0;
var_18 = arg1;
// Anfangsanweisungen zum Finden der richtigen Funktionszeiger
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
// 0x1f4 = 500 (die Start-ID)
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
// Dasselbe If-Else wie in der vorherigen Version
// Überprüfen Sie die Verwendung der Adresse 0x100004040 (Array der Funktionsadressen)
<strong>                    if ((r8 &#x26; 0x1) == 0x0) {
</strong><strong>                            *(var_18 + 0x18) = **0x100004000;
</strong>                            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
else {
// Aufruf der berechneten Adresse, an der die Funktion sein sollte
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

Tatsächlich finden Sie im Funktion **`0x100004000`** das Array der **`routine_descriptor`**-Strukturen. Das erste Element der Struktur ist die **Adresse**, an der die **Funktion** implementiert ist, und die **Struktur nimmt 0x28 Bytes** ein. Daher können Sie alle 0x28 Bytes (beginnend ab Byte 0) 8 Bytes erhalten, und das wird die **Adresse der Funktion** sein, die aufgerufen wird:

<figure><img src="../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Diese Daten können [**mit diesem Hopper-Skript**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py) extrahiert werden.
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) **bei** oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) **und** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories einreichen.**

</details>
