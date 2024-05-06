# macOS MIG - Ο Παραγωγός Διεπαφής Mach

<details>

<summary><strong>Μάθετε την χρήση του AWS hacking από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα κόλπα σας στο χάκινγκ υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Βασικές Πληροφορίες

Το MIG δημιουργήθηκε για να **απλοποιήσει τη διαδικασία δημιουργίας κώδικα Mach IPC**. Βασικά **δημιουργεί τον απαιτούμενο κώδικα** για τον εξυπηρετητή και τον πελάτη ώστε να επικοινωνούν με μια δεδομένη ορισμένη λειτουργία. Ακόμα κι αν ο δημιουργημένος κώδικας είναι άσχημος, ένας προγραμματιστής θα χρειαστεί απλώς να τον εισάγει και ο κώδικάς του θα είναι πολύ απλούστερος από πριν.

Η ορισμένη λειτουργία καθορίζεται στη Γλώσσα Ορισμού Διεπαφής (IDL) χρησιμοποιώντας την επέκταση `.defs`.

Αυτές οι ορισμοί έχουν 5 ενότητες:

* **Δήλωση υποσυστήματος**: Η λέξη-κλειδί υποσύστημα χρησιμοποιείται για να υποδείξει το **όνομα** και το **ID**. Είναι επίσης δυνατό να το σημειώσετε ως **`KernelServer`** αν ο εξυπηρετητής πρέπει να τρέχει στον πυρήνα.
* **Συμπερίληψη και εισαγωγές**: Το MIG χρησιμοποιεί τον προεπεξεργαστή C, έτσι μπορεί να χρησιμοποιήσει εισαγωγές. Επιπλέον, είναι δυνατό να χρησιμοποιήσετε `uimport` και `simport` για κώδικα που δημιουργείται από χρήστη ή εξυπηρετητή.
* **Δηλώσεις τύπων**: Είναι δυνατό να ορίσετε τύπους δεδομένων αν και συνήθως θα εισάγει τα `mach_types.defs` και `std_types.defs`. Για προσαρμοσμένους τύπους μπορεί να χρησιμοποιηθεί κάποια σύνταξη:
* \[i`n/out]tran`: Συνάρτηση που πρέπει να μεταφραστεί από ένα εισερχόμενο ή προς ένα εξερχόμενο μήνυμα
* `c[user/server]type`: Αντιστοίχιση σε άλλον τύπο C.
* `destructor`: Καλέστε αυτήν τη συνάρτηση όταν ο τύπος απελευθερώνεται.
* **Λειτουργίες**: Αυτές είναι οι ορισμοί των μεθόδων RPC. Υπάρχουν 5 διαφορετικοί τύποι:
* `routine`: Αναμένει απάντηση
* `simpleroutine`: Δεν αναμένει απάντηση
* `procedure`: Αναμένει απάντηση
* `simpleprocedure`: Δεν αναμένει απάντηση
* `function`: Αναμένει απάντηση

### Παράδειγμα

Δημιουργήστε ένα αρχείο ορισμού, σε αυτήν την περίπτωση με μια πολύ απλή λειτουργία:

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

Σημειώστε ότι το πρώτο **όρισμα είναι τη θύρα προς σύνδεση** και το MIG θα **χειριστεί αυτόματα τη θύρα απάντησης** (εκτός αν καλείτε την `mig_get_reply_port()` στον κώδικα του πελάτη). Επιπλέον, το **ID των λειτουργιών** θα είναι **συνεχόμενο** ξεκινώντας από το ID του υποσυστήματος που υποδεικνύεται (έτσι αν μια λειτουργία είναι αποσυρμένη, διαγράφεται και χρησιμοποιείται το `skip` για να εξακολουθεί να χρησιμοποιεί το ID της).

Τώρα χρησιμοποιήστε το MIG για να δημιουργήσετε τον κώδικα εξυπηρετητή και πελάτη που θα μπορούν να επικοινωνούν μεταξύ τους για να καλέσουν τη λειτουργία Αφαίρεση:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
Θα δημιουργηθούν αρκετά νέα αρχεία στον τρέχοντα κατάλογο.

{% hint style="success" %}
Μπορείτε να βρείτε ένα πιο πολύπλοκο παράδειγμα στο σύστημά σας με: `mdfind mach_port.defs`\
Και μπορείτε να το μεταγλωτίσετε από τον ίδιο φάκελο με: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`
{% endhint %}

Στα αρχεία **`myipcServer.c`** και **`myipcServer.h`** μπορείτε να βρείτε τη δήλωση και τον ορισμό της δομής **`SERVERPREFmyipc_subsystem`**, η οποία ουσιαστικά ορίζει τη λειτουργία που θα κληθεί με βάση το αναγνωριστικό μηνύματος που λαμβάνεται (καθορίσαμε έναν αριθμό εκκίνησης των 500):

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

{% tab title="myipcServer.h" %}Ορισμός των συναρτήσεων που υλοποιούνται από τον server. Κάθε συνάρτηση αντιστοιχεί σε ένα MIG request. Ορίζει τις συναρτήσεις που καλούνται κατά την εκτέλεση των αιτημάτων από τον client. Περιέχει τις υπογραφές των συναρτήσεων που πρέπει να υλοποιηθούν από τον server. %}
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

Βασισμένο στην προηγούμενη δομή, η συνάρτηση **`myipc_server_routine`** θα λάβει το **ID μηνύματος** και θα επιστρέψει την κατάλληλη συνάρτηση προς κλήση:
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
Σε αυτό το παράδειγμα έχουμε ορίσει μόνο 1 λειτουργία στις ορισμούς, αλλά αν είχαμε ορίσει περισσότερες λειτουργίες, θα βρίσκονταν μέσα στον πίνακα του **`SERVERPREFmyipc_subsystem`** και η πρώτη θα είχε ανατεθεί στο ID **500**, η δεύτερη στο ID **501**...

Αν η λειτουργία αναμενόταν να στείλει μια **απάντηση**, θα υπήρχε επίσης η λειτουργία `mig_internal kern_return_t __MIG_check__Reply__<όνομα>`.

Πράγματι, είναι δυνατό να αναγνωριστεί αυτή η σχέση στη δομή **`subsystem_to_name_map_myipc`** από το **`myipcServer.h`** (**`subsystem_to_name_map_***`** σε άλλα αρχεία):
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Τέλος, μια άλλη σημαντική λειτουργία για τη λειτουργία του διακομιστή θα είναι η **`myipc_server`**, η οποία είναι αυτή που θα καλέσει πραγματικά τη σχετική **συνάρτηση** που σχετίζεται με το ληφθέν αναγνωριστικό:

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
/* Ελάχιστο μέγεθος: η συνάρτηση routine() θα το ενημερώσει αν είναι διαφορετικό */
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

Ελέγξτε τις προηγουμένως επισημασμένες γραμμές προσπελαίνοντας τη συνάρτηση που θα κληθεί με βάση το αναγνωριστικό.

Το παρακάτω είναι ο κώδικας για τη δημιουργία ενός απλού **διακομιστή** και **πελάτη** όπου ο πελάτης μπορεί να καλέσει τις λειτουργίες Subtract από το διακομιστή:

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

{% tab title="myipc_client.c" %}Ο πελάτης IPC είναι υπεύθυνος για την επικοινωνία με τον εξυπηρετητή IPC και την ανταλλαγή δεδομένων μαζί του. Ο πελάτης χρησιμοποιεί τις συναρτήσεις που δημιουργήθηκαν από το MIG για να αποστείλει αιτήματα στον εξυπηρετητή και να λάβει απαντήσεις. Ο πελάτης πρέπει να είναι προσεκτικός με τα δεδομένα που αποστέλλονται και να ελέγχει την εγκυρότητά τους προκειμένου να αποφευχθεί η κατάχρηση διεργασιϋών. %}
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

### Το NDR\_record

Το NDR\_record εξάγεται από το `libsystem_kernel.dylib`, και είναι ένας δομικός τύπος που επιτρέπει στο MIG να **μετασχηματίζει τα δεδομένα ώστε να είναι ανεξάρτητα από το σύστημα** στο οποίο χρησιμοποιείται, καθώς το MIG σχεδιάστηκε να χρησιμοποιείται μεταξύ διαφορετικών συστημάτων (και όχι μόνο στον ίδιο υπολογιστή).

Αυτό είναι ενδιαφέρον επειδή αν το `_NDR_record` βρεθεί σε ένα δυαδικό ως εξάρτηση (`jtool2 -S <binary> | grep NDR` ή `nm`), σημαίνει ότι το δυαδικό είναι ένας πελάτης ή Διακομιστής MIG.

Επιπλέον, **οι Διακομιστές MIG** έχουν τον πίνακα αποστολής στο `__DATA.__const` (ή στο `__CONST.__constdata` στον πυρήνα macOS και `__DATA_CONST.__const` σε άλλους πυρήνες \*OS). Αυτό μπορεί να ανακτηθεί με το **`jtool2`**.

Και **οι πελάτες MIG** θα χρησιμοποιήσουν το `__NDR_record` για να στείλουν με το `__mach_msg` στους διακομιστές.

## Ανάλυση Δυαδικού

### jtool

Καθώς πολλά δυαδικά χρησιμοποιούν πλέον το MIG για να εκθέτουν mach ports, είναι ενδιαφέρον να γνωρίζουμε πώς να **αναγνωρίσουμε ότι χρησιμοποιήθηκε το MIG** και τις **λειτουργίες που εκτελεί το MIG** με κάθε αναγνωριστικό μηνύματος.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/#jtool2) μπορεί να αναλύσει πληροφορίες MIG από ένα δυαδικό Mach-O, ενδεικτικά το αναγνωριστικό μηνύματος και την αναγνώριση της λειτουργίας προς εκτέλεση:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
Επιπλέον, οι λειτουργίες MIG είναι απλά περιτύλιγμα της πραγματικής λειτουργίας που καλείται, πράγμα που σημαίνει ότι με την ανάλυση του κώδικα και την αναζήτηση για BL ενδέχεται να εντοπίσετε την πραγματική λειτουργία που καλείται:
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### Συναρτήσεις

Προηγουμένως αναφέρθηκε ότι η συνάρτηση που θα αναλάβει το **να καλέσει τη σωστή συνάρτηση ανάλογα με το αναγνωριστικό μηνύματος που λαμβάνεται** ήταν η `myipc_server`. Ωστόσο, συνήθως δεν θα έχετε τα σύμβολα του δυαδικού (καμία ονομασία συναρτήσεων), επομένως είναι ενδιαφέρον να **ελέγξετε πώς μοιάζει αποσυναρμολογημένο** καθώς θα είναι πάντα πολύ παρόμοιο (ο κώδικας αυτής της συνάρτησης είναι ανεξάρτητος από τις εκτεθειμένες συναρτήσεις):

{% tabs %}
{% tab title="Αποσυναρμολογημένο myipc_server 1" %}
<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
var_10 = arg0;
var_18 = arg1;
// Αρχικές οδηγίες για την εύρεση των κατάλληλων δεικτών συναρτήσεων
*(int32_t *)var_18 = *(int32_t *)var_10 & 0x1f;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
if (*(int32_t *)(var_10 + 0x14) <= 0x1f4 && *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
rax = *(int32_t *)(var_10 + 0x14);
// Κλήση της sign_extend_64 που μπορεί να βοηθήσει στον εντοπισμό αυτής της συνάρτησης
// Αυτό αποθηκεύει στο rax τον δείκτη προς την κλήση που πρέπει να γίνει
// Ελέγξτε τη χρήση της διεύθυνσης 0x100004040 (πίνακας διευθύνσεων συναρτήσεων)
// 0x1f4 = 500 (η αρχική ID)
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
// Αν - αλλιώς, το if επιστρέφει false, ενώ το else καλεί τη σωστή συνάρτηση και επιστρέφει true
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
else {
// Υπολογισμένη διεύθυνση που καλεί τη σωστή συνάρτηση με 2 ορίσματα
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

{% tab title="Αποσυναρμολογημένο myipc_server 2" %}
Αυτή είναι η ίδια συνάρτηση αποσυναρμολογημένη σε μια διαφορετική έκδοση του Hopper free:

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
r31 = r31 - 0x40;
saved_fp = r29;
stack[-8] = r30;
var_10 = arg0;
var_18 = arg1;
// Αρχικές οδηγίες για την εύρεση των κατάλληλων δεικτών συναρτήσεων
*(int32_t *)var_18 = *(int32_t *)var_10 & 0x1f | 0x0;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
r8 = *(int32_t *)(var_10 + 0x14);
r8 = r8 - 0x1f4;
if (r8 > 0x0) {
if (CPU_FLAGS & G) {
r8 = 0x1;
}
}
if ((r8 & 0x1) == 0x0) {
r8 = *(int32_t *)(var_10 + 0x14);
r8 = r8 - 0x1f4;
if (r8 < 0x0) {
if (CPU_FLAGS & L) {
r8 = 0x1;
}
}
if ((r8 & 0x1) == 0x0) {
r8 = *(int32_t *)(var_10 + 0x14);
// 0x1f4 = 500 (η αρχική ID)
<strong>                    r8 = r8 - 0x1f4;
</strong>                    asm { smaddl     x8, w8, w9, x10 };
r8 = *(r8 + 0x8);
var_20 = r8;
r8 = r8 - 0x0;
if (r8 != 0x0) {
if (CPU_FLAGS & NE) {
r8 = 0x1;
}
}
// Ίδιο if else με την προηγούμενη έκδοση
// Ελέγξτε τη χρήση της διεύθυνσης 0x100004040 (πίνακας διευθύνσεων συναρτήσεων)
<strong>                    if ((r8 & 0x1) == 0x0) {
</strong><strong>                            *(var_18 + 0x18) = **0x100004000;
</strong>                            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
else {
// Κλήση στην υπολογισμένη διεύθυνση όπου πρέπει να γίνει η κλήση της συνάρτησης
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

Πράγματι, αν πάτε στη συνάρτηση **`0x100004000`** θα βρείτε τον πίνακα των δομών **`routine_descriptor`**. Το πρώτο στοιχείο της δομής είναι η **διεύθυνση** όπου η **συνάρτηση** υλοποιείται, και η **δομή παίρνει 0x28 bytes**, οπότε κάθε 0x28 bytes (ξεκινώντας από το byte 0) μπορείτε να πάρετε 8 bytes και αυτό θα είναι η **διεύθυνση της συνάρτησης** που θα κληθεί:

<figure><img src="../../../../.gitbook/assets/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (36).png" alt=""><figcaption></figcaption></figure>

Αυτά τα δεδομένα μπορούν να εξαχθούν [**χρησιμοποιώντας αυτό το σενάριο Hopper**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py).
### Αποσφαλμάτωση

Ο κώδικας που δημιουργείται από το MIG καλεί επίσης το `kernel_debug` για τη δημιουργία καταγραφών σχετικά με τις λειτουργίες κατά την είσοδο και έξοδο. Είναι δυνατόν να τις ελέγξετε χρησιμοποιώντας **`trace`** ή **`kdv`**: `kdv all | grep MIG`

## Αναφορές

* [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
