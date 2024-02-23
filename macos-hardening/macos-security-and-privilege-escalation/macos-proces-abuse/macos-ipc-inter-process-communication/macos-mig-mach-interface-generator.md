# macOS MIG - Ο Παραγωγός Διεπαφής Mach

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Red Team του HackTricks στο AWS)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

Ο MIG δημιουργήθηκε για να **απλοποιήσει τη διαδικασία δημιουργίας κώδικα Mach IPC**. Βασικά **παράγει τον απαιτούμενο κώδικα** για τον εξυπηρετητή και τον πελάτη να επικοινωνούν με μια δεδομένη ορισμένη. Ακόμη κι αν ο παραγόμενος κώδικας είναι άσχημος, ένας προγραμματιστής θα χρειαστεί απλώς να τον εισάγει και ο κώδικάς του θα είναι πολύ απλούστερος από πριν.

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

Τώρα χρησιμοποιήστε το mig για να δημιουργήσετε τον κώδικα εξυπηρετητή και πελάτη που θα μπορούν να επικοινωνούν μεταξύ τους για να καλέσουν τη λειτουργία Subtract:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
Θα δημιουργηθούν αρκετά νέα αρχεία στον τρέχοντα κατάλογο.

Στα αρχεία **`myipcServer.c`** και **`myipcServer.h`** μπορείτε να βρείτε τη δήλωση και τον ορισμό της δομής **`SERVERPREFmyipc_subsystem`**, η οποία ουσιαστικά ορίζει τη λειτουργία που θα κληθεί με βάση το αναγνωριστικό μηνύματος που λαμβάνεται (καθορίσαμε έναν αρχικό αριθμό 500):

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

{% tab title="myipcServer.h" %}Το MIG (Mach Interface Generator) είναι ένα εργαλείο που χρησιμοποιείται για τη δημιουργία διεπαφών επικοινωνίας μεταξύ διεργασιών στο macOS. Με τη χρήση του MIG, μπορούμε να ορίσουμε μηνύματα και δομές δεδομένων που χρησιμοποιούνται για την επικοινωνία μεταξύ διεργασιών. Αυτό μπορεί να χρησιμοποιηθεί για την εκτέλεση επιθέσεων εκμετάλλευσης προνομίων στο macOS μέσω της κατάχρησης των μηνυμάτων IPC. {% endtab %}
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
Σε αυτό το παράδειγμα έχουμε ορίσει μόνο 1 συνάρτηση στις ορισμούς, αλλά αν είχαμε ορίσει περισσότερες συναρτήσεις, θα βρίσκονταν μέσα στον πίνακα του **`SERVERPREFmyipc_subsystem`** και η πρώτη θα είχε ανατεθεί στο ID **500**, η δεύτερη στο ID **501**...

Πράγματι, είναι δυνατό να αναγνωριστεί αυτή η σχέση στη δομή **`subsystem_to_name_map_myipc`** από το **`myipcServer.h`**:
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Τέλος, μια άλλη σημαντική λειτουργία για τη λειτουργία του διακομιστή θα είναι η **`myipc_server`**, η οποία είναι αυτή που θα καλέσει πραγματικά τη συνάρτηση που σχετίζεται με το ληφθέν αναγνωριστικό:

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

Ελέγξτε τις προηγουμένως επισημασμένες γραμμές πρόσβασης στη συνάρτηση που θα κληθεί με βάση το αναγνωριστικό.

Παρακάτω είναι ο κώδικας για τη δημιουργία ενός απλού **διακομιστή** και **πελάτη** όπου ο πελάτης μπορεί να καλέσει τις λειτουργίες αφαίρεσης από το διακομιστή:

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

{% tab title="myipc_client.c" %} {% endtab %}
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
### Ανάλυση Δυαδικών Αρχείων

Καθώς πολλά δυαδικά αρχεία χρησιμοποιούν πλέον το MIG για να αποκαλύπτουν θύρες mach, είναι ενδιαφέρον να γνωρίζουμε πώς να **αναγνωρίσουμε ότι χρησιμοποιήθηκε το MIG** και τις **λειτουργίες που εκτελεί το MIG** με κάθε αναγνωριστικό μηνύματος.

Το [**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/#jtool2) μπορεί να αναλύσει πληροφορίες MIG από ένα δυαδικό αρχείο Mach-O, ενδεικτικά του αναγνωριστικού μηνύματος και της αναγνώρισης της λειτουργίας προς εκτέλεση:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
Ήταν προηγουμένως αναφερόμενο ότι η λειτουργία που θα αναλάβει το **να καλέσει τη σωστή λειτουργία ανάλογα με το αναγνωριστικό μηνύματος που λαμβάνεται** ήταν η `myipc_server`. Ωστόσο, συνήθως δεν θα έχετε τα σύμβολα του δυαδικού (καμία ονομασία λειτουργιών), επομένως είναι ενδιαφέρον να **ελέγξετε πώς φαίνεται αποσυναρμολογημένο** καθώς θα είναι πάντα πολύ παρόμοιο (ο κώδικας αυτής της λειτουργίας είναι ανεξάρτητος από τις εκτεθειμένες λειτουργίες):

{% tabs %}
{% tab title="myipc_server αποσυναρμολογημένο 1" %}
<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
var_10 = arg0;
var_18 = arg1;
// Αρχικές οδηγίες για την εύρεση των κατάλληλων δεικτών λειτουργιών
*(int32_t *)var_18 = *(int32_t *)var_10 &#x26; 0x1f;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
if (*(int32_t *)(var_10 + 0x14) &#x3C;= 0x1f4 &#x26;&#x26; *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
rax = *(int32_t *)(var_10 + 0x14);
// Κλήση της sign_extend_64 που μπορεί να βοηθήσει στην ταυτοποίηση αυτής της λειτουργίας
// Αποθηκεύει στο rax τον δείκτη προς την κλήση που πρέπει να γίνει
// Ελέγξτε τη χρήση της διεύθυνσης 0x100004040 (πίνακας διευθύνσεων λειτουργιών)
// 0x1f4 = 500 (το αρχικό ID)
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
// Αν - αλλιώς, το if επιστρέφει false, ενώ το else καλεί τη σωστή λειτουργία και επιστρέφει true
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
else {
// Υπολογισμένη διεύθυνση που καλεί την κατάλληλη λειτουργία με 2 ορίσματα
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

{% tab title="myipc_server αποσυναρμολογημένο 2" %}
Αυτή είναι η ίδια λειτουργία αποσυναρμολογημένη σε μια διαφορετική έκδοση του Hopper free:

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
r31 = r31 - 0x40;
saved_fp = r29;
stack[-8] = r30;
var_10 = arg0;
var_18 = arg1;
// Αρχικές οδηγίες για την εύρεση των κατάλληλων δεικτών λειτουργιών
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
// 0x1f4 = 500 (το αρχικό ID)
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
// Ίδιο if else με την προηγούμενη έκδοση
// Ελέγξτε τη χρήση της διεύθυνσης 0x100004040 (πίνακας διευθύνσεων λειτουργιών)
<strong>                    if ((r8 &#x26; 0x1) == 0x0) {
</strong><strong>                            *(var_18 + 0x18) = **0x100004000;
</strong>                            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
else {
// Κλήση στην υπολογισμένη διεύθυνση όπου πρέπει να γίνει η λειτουργία
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

Πράγματι, αν πάτε στη λειτουργία **`0x100004000`** θα βρείτε τον πίνακα των δομών **`routine_descriptor`**. Το πρώτο στοιχείο της δομής είναι η **διεύθυνση** όπου η **λειτουργία** υλοποιείται, και η **δομή παίρνει 0x28 bytes**, οπότε κάθε 0x28 bytes (ξεκινώντας από το byte 0) μπορείτε να πάρετε 8 bytes και αυτό θα είναι η **διεύθυνση της λειτουργίας** που θα κληθεί:

<figure><img src="../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Αυτά τα δεδομένα μπορούν να εξαχθούν [**χρησιμοποιώντας αυτό το σενάριο Hopper**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py).
* **Συμμετέχετε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγράφου**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.
