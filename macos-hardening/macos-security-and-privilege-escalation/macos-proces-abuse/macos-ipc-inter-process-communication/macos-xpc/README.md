# macOS XPC

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

## Basic Information

XPC, που σημαίνει XNU (ο πυρήνας που χρησιμοποιείται από το macOS) δια-Διεργασιών Επικοινωνία, είναι ένα πλαίσιο για **επικοινωνία μεταξύ διεργασιών** στο macOS και το iOS. Το XPC παρέχει έναν μηχανισμό για την πραγματοποίηση **ασφαλών, ασύγχρονων κλήσεων μεθόδων μεταξύ διαφορετικών διεργασιών** στο σύστημα. Είναι μέρος της ασφάλειας της Apple, επιτρέποντας τη **δημιουργία εφαρμογών με διαχωρισμένα δικαιώματα** όπου κάθε **συστατικό** εκτελείται με **μόνο τα δικαιώματα που χρειάζεται** για να κάνει τη δουλειά του, περιορίζοντας έτσι τη δυνητική ζημιά από μια παραβιασμένη διεργασία.

Το XPC χρησιμοποιεί μια μορφή Δια-Διεργασιών Επικοινωνίας (IPC), η οποία είναι ένα σύνολο μεθόδων για διαφορετικά προγράμματα που εκτελούνται στο ίδιο σύστημα να στέλνουν δεδομένα πίσω και μπροστά.

Τα κύρια οφέλη του XPC περιλαμβάνουν:

1. **Ασφάλεια**: Με τον διαχωρισμό της εργασίας σε διαφορετικές διεργασίες, κάθε διεργασία μπορεί να έχει μόνο τα δικαιώματα που χρειάζεται. Αυτό σημαίνει ότι ακόμη και αν μια διεργασία παραβιαστεί, έχει περιορισμένη ικανότητα να προκαλέσει ζημιά.
2. **Σταθερότητα**: Το XPC βοηθά στην απομόνωση των κραστών στο συστατικό όπου συμβαίνουν. Αν μια διεργασία κρασάρει, μπορεί να επανεκκινηθεί χωρίς να επηρεάσει το υπόλοιπο σύστημα.
3. **Απόδοση**: Το XPC επιτρέπει εύκολη ταυτόχρονη εκτέλεση, καθώς διαφορετικές εργασίες μπορούν να εκτελούνται ταυτόχρονα σε διαφορετικές διεργασίες.

Η μόνη **ανεπιθύμητη συνέπεια** είναι ότι **ο διαχωρισμός μιας εφαρμογής σε πολλές διεργασίες** που επικοινωνούν μέσω XPC είναι **λιγότερο αποδοτικός**. Αλλά στα σημερινά συστήματα αυτό δεν είναι σχεδόν αισθητό και τα οφέλη είναι καλύτερα.

## Application Specific XPC services

Τα XPC συστατικά μιας εφαρμογής είναι **μέσα στην ίδια την εφαρμογή.** Για παράδειγμα, στο Safari μπορείτε να τα βρείτε σε **`/Applications/Safari.app/Contents/XPCServices`**. Έχουν επέκταση **`.xpc`** (όπως **`com.apple.Safari.SandboxBroker.xpc`**) και είναι **επίσης πακέτα** με το κύριο δυαδικό αρχείο μέσα σε αυτό: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` και ένα `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

Όπως μπορεί να σκέφτεστε, ένα **συστατικό XPC θα έχει διαφορετικά δικαιώματα και προνόμια** από τα άλλα συστατικά XPC ή το κύριο δυαδικό αρχείο της εφαρμογής. ΕΚΤΟΣ αν μια υπηρεσία XPC είναι ρυθμισμένη με [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession) ρυθμισμένη σε “True” στο αρχείο **Info.plist** της. Σε αυτή την περίπτωση, η υπηρεσία XPC θα εκτελείται στην **ίδια ασφαλή συνεδρία με την εφαρμογή** που την κάλεσε.

Οι υπηρεσίες XPC **ξεκινούνται** από **launchd** όταν απαιτείται και **κλείνουν** μόλις ολοκληρωθούν όλες οι εργασίες για να απελευθερωθούν οι πόροι του συστήματος. **Τα XPC συστατικά που είναι συγκεκριμένα για την εφαρμογή μπορούν να χρησιμοποιηθούν μόνο από την εφαρμογή**, μειώνοντας έτσι τον κίνδυνο που σχετίζεται με πιθανές ευπάθειες.

## System Wide XPC services

Οι υπηρεσίες XPC σε επίπεδο συστήματος είναι προσβάσιμες σε όλους τους χρήστες. Αυτές οι υπηρεσίες, είτε launchd είτε τύπου Mach, πρέπει να είναι **καθορισμένες σε αρχεία plist** που βρίσκονται σε καθορισμένους καταλόγους όπως **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`**, ή **`/Library/LaunchAgents`**.

Αυτά τα αρχεία plists θα έχουν ένα κλειδί που ονομάζεται **`MachServices`** με το όνομα της υπηρεσίας, και ένα κλειδί που ονομάζεται **`Program`** με τη διαδρομή προς το δυαδικό αρχείο:
```xml
cat /Library/LaunchDaemons/com.jamf.management.daemon.plist

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Program</key>
<string>/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfDaemon.app/Contents/MacOS/JamfDaemon</string>
<key>AbandonProcessGroup</key>
<true/>
<key>KeepAlive</key>
<true/>
<key>Label</key>
<string>com.jamf.management.daemon</string>
<key>MachServices</key>
<dict>
<key>com.jamf.management.daemon.aad</key>
<true/>
<key>com.jamf.management.daemon.agent</key>
<true/>
<key>com.jamf.management.daemon.binary</key>
<true/>
<key>com.jamf.management.daemon.selfservice</key>
<true/>
<key>com.jamf.management.daemon.service</key>
<true/>
</dict>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
The ones in **`LaunchDameons`** είναι εκτελούμενες από τον root. Έτσι, αν μια διαδικασία χωρίς δικαιώματα μπορεί να επικοινωνήσει με μία από αυτές, θα μπορούσε να είναι σε θέση να κλιμακώσει τα δικαιώματα.

## XPC Objects

* **`xpc_object_t`**

Κάθε μήνυμα XPC είναι ένα αντικείμενο λεξικού που απλοποιεί τη σειριοποίηση και την αποσειριοποίηση. Επιπλέον, το `libxpc.dylib` δηλώνει τους περισσότερους από τους τύπους δεδομένων, οπότε είναι δυνατό να διασφαλιστεί ότι τα ληφθέντα δεδομένα είναι του αναμενόμενου τύπου. Στο C API, κάθε αντικείμενο είναι ένα `xpc_object_t` (και ο τύπος του μπορεί να ελεγχθεί χρησιμοποιώντας το `xpc_get_type(object)`).\
Επιπλέον, η συνάρτηση `xpc_copy_description(object)` μπορεί να χρησιμοποιηθεί για να αποκτήσει μια συμβολοσειρά αναπαράστασης του αντικειμένου που μπορεί να είναι χρήσιμη για σκοπούς αποσφαλμάτωσης.\
Αυτά τα αντικείμενα έχουν επίσης μερικές μεθόδους για κλήση όπως `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

Τα `xpc_object_t` δημιουργούνται καλώντας τη συνάρτηση `xpc_<objetType>_create`, η οποία εσωτερικά καλεί το `_xpc_base_create(Class, Size)` όπου υποδεικνύεται ο τύπος της κλάσης του αντικειμένου (ένας από τους `XPC_TYPE_*`) και το μέγεθός του (κάποια επιπλέον 40B θα προστεθούν στο μέγεθος για μεταδεδομένα). Αυτό σημαίνει ότι τα δεδομένα του αντικειμένου θα ξεκινούν από την απόσταση 40B.\
Επομένως, το `xpc_<objectType>_t` είναι κάπως υποκλάση του `xpc_object_t`, το οποίο θα ήταν υποκλάση του `os_object_t*`.

{% hint style="warning" %}
Σημειώστε ότι θα πρέπει να είναι ο προγραμματιστής που χρησιμοποιεί το `xpc_dictionary_[get/set]_<objectType>` για να αποκτήσει ή να ορίσει τον τύπο και την πραγματική τιμή ενός κλειδιού.
{% endhint %}

* **`xpc_pipe`**

Ένα **`xpc_pipe`** είναι ένας σωλήνας FIFO που οι διαδικασίες μπορούν να χρησιμοποιήσουν για να επικοινωνήσουν (η επικοινωνία χρησιμοποιεί μηνύματα Mach).\
Είναι δυνατό να δημιουργηθεί ένας XPC server καλώντας το `xpc_pipe_create()` ή το `xpc_pipe_create_from_port()` για να τον δημιουργήσει χρησιμοποιώντας μια συγκεκριμένη θύρα Mach. Στη συνέχεια, για να λάβει μηνύματα, είναι δυνατό να καλέσει το `xpc_pipe_receive` και το `xpc_pipe_try_receive`.

Σημειώστε ότι το αντικείμενο **`xpc_pipe`** είναι ένα **`xpc_object_t`** με πληροφορίες στη δομή του σχετικά με τις δύο θύρες Mach που χρησιμοποιούνται και το όνομα (αν υπάρχει). Το όνομα, για παράδειγμα, ο daemon `secinitd` στο plist του `/System/Library/LaunchDaemons/com.apple.secinitd.plist` ρυθμίζει τον σωλήνα που ονομάζεται `com.apple.secinitd`.

Ένα παράδειγμα ενός **`xpc_pipe`** είναι ο **bootstrap pipe** που δημιουργείται από τον **`launchd`** καθιστώντας δυνατή την κοινή χρήση θύρων Mach.

* **`NSXPC*`**

Αυτά είναι αντικείμενα υψηλού επιπέδου Objective-C που επιτρέπουν την αφαίρεση των συνδέσεων XPC.\
Επιπλέον, είναι πιο εύκολο να αποσφαλματωθούν αυτά τα αντικείμενα με το DTrace από τα προηγούμενα.

* **`GCD Queues`**

Το XPC χρησιμοποιεί GCD για να περάσει μηνύματα, επιπλέον δημιουργεί ορισμένες ουρές εκτέλεσης όπως `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## XPC Services

Αυτά είναι **πακέτα με επέκταση `.xpc`** που βρίσκονται μέσα στον φάκελο **`XPCServices`** άλλων έργων και στο `Info.plist` έχουν τον `CFBundlePackageType` ρυθμισμένο σε **`XPC!`**.\
Αυτό το αρχείο έχει άλλες ρυθμιστικές κλειδιά όπως `ServiceType` που μπορεί να είναι Application, User, System ή `_SandboxProfile` που μπορεί να ορίσει μια sandbox ή `_AllowedClients` που μπορεί να υποδεικνύει δικαιώματα ή ID που απαιτούνται για να επικοινωνήσουν με τον σερβερ. Αυτές και άλλες ρυθμιστικές επιλογές θα είναι χρήσιμες για να ρυθμίσουν την υπηρεσία κατά την εκκίνηση.

### Starting a Service

Η εφαρμογή προσπαθεί να **συνδεθεί** με μια υπηρεσία XPC χρησιμοποιώντας το `xpc_connection_create_mach_service`, στη συνέχεια ο launchd εντοπίζει τον daemon και ξεκινά το **`xpcproxy`**. Το **`xpcproxy`** επιβάλλει τις ρυθμισμένες περιορισμούς και δημιουργεί την υπηρεσία με τα παρεχόμενα FDs και τις θύρες Mach.

Για να βελτιωθεί η ταχύτητα αναζήτησης της υπηρεσίας XPC, χρησιμοποιείται μια κρυφή μνήμη.

Είναι δυνατό να παρακολουθήσετε τις ενέργειες του `xpcproxy` χρησιμοποιώντας:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
The XPC βιβλιοθήκη χρησιμοποιεί `kdebug` για να καταγράψει ενέργειες καλώντας `xpc_ktrace_pid0` και `xpc_ktrace_pid1`. Οι κωδικοί που χρησιμοποιεί είναι αδημοσίευτοι, οπότε είναι απαραίτητο να τους προσθέσετε στο `/usr/share/misc/trace.codes`. Έχουν το πρόθεμα `0x29` και για παράδειγμα ένας είναι `0x29000004`: `XPC_serializer_pack`.\
Το εργαλείο `xpcproxy` χρησιμοποιεί το πρόθεμα `0x22`, για παράδειγμα: `0x2200001c: xpcproxy:will_do_preexec`.

## XPC Μηνύματα Εκδηλώσεων

Οι εφαρμογές μπορούν να **εγγραφούν** σε διάφορα μηνύματα **εκδηλώσεων**, επιτρέποντάς τους να **ξεκινούν κατόπιν αιτήματος** όταν συμβαίνουν τέτοιες εκδηλώσεις. Η **ρύθμιση** για αυτές τις υπηρεσίες γίνεται σε αρχεία **plist του launchd**, που βρίσκονται στους **ίδιους καταλόγους με τους προηγούμενους** και περιέχουν ένα επιπλέον **κλειδί `LaunchEvent`**.

### Έλεγχος Διαδικασίας Σύνδεσης XPC

Όταν μια διαδικασία προσπαθεί να καλέσει μια μέθοδο μέσω μιας σύνδεσης XPC, η **υπηρεσία XPC θα πρέπει να ελέγξει αν αυτή η διαδικασία επιτρέπεται να συνδεθεί**. Ακολουθούν οι κοινές μέθοδοι για να το ελέγξετε και οι κοινές παγίδες:

{% content-ref url="macos-xpc-connecting-process-check/" %}
[macos-xpc-connecting-process-check](macos-xpc-connecting-process-check/)
{% endcontent-ref %}

## Εξουσιοδότηση XPC

Η Apple επιτρέπει επίσης στις εφαρμογές να **ρυθμίζουν ορισμένα δικαιώματα και πώς να τα αποκτούν**, ώστε αν η καλούσα διαδικασία τα έχει, να είναι **επιτρεπτό να καλέσει μια μέθοδο** από την υπηρεσία XPC:

{% content-ref url="macos-xpc-authorization.md" %}
[macos-xpc-authorization.md](macos-xpc-authorization.md)
{% endcontent-ref %}

## Sniffer XPC

Για να καταγράψετε τα μηνύματα XPC μπορείτε να χρησιμοποιήσετε [**xpcspy**](https://github.com/hot3eed/xpcspy) που χρησιμοποιεί **Frida**.
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
Ένα άλλο πιθανό εργαλείο που μπορεί να χρησιμοποιηθεί είναι το [**XPoCe2**](https://newosxbook.com/tools/XPoCe2.html).

## Παράδειγμα Κώδικα C για Επικοινωνία XPC

{% tabs %}
{% tab title="xpc_server.c" %}
```c
// gcc xpc_server.c -o xpc_server

#include <xpc/xpc.h>

static void handle_event(xpc_object_t event) {
if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
// Print received message
const char* received_message = xpc_dictionary_get_string(event, "message");
printf("Received message: %s\n", received_message);

// Create a response dictionary
xpc_object_t response = xpc_dictionary_create(NULL, NULL, 0);
xpc_dictionary_set_string(response, "received", "received");

// Send response
xpc_connection_t remote = xpc_dictionary_get_remote_connection(event);
xpc_connection_send_message(remote, response);

// Clean up
xpc_release(response);
}
}

static void handle_connection(xpc_connection_t connection) {
xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
handle_event(event);
});
xpc_connection_resume(connection);
}

int main(int argc, const char *argv[]) {
xpc_connection_t service = xpc_connection_create_mach_service("xyz.hacktricks.service",
dispatch_get_main_queue(),
XPC_CONNECTION_MACH_SERVICE_LISTENER);
if (!service) {
fprintf(stderr, "Failed to create service.\n");
exit(EXIT_FAILURE);
}

xpc_connection_set_event_handler(service, ^(xpc_object_t event) {
xpc_type_t type = xpc_get_type(event);
if (type == XPC_TYPE_CONNECTION) {
handle_connection(event);
}
});

xpc_connection_resume(service);
dispatch_main();

return 0;
}
```
{% endtab %}

{% tab title="xpc_client.c" %}
```c
// gcc xpc_client.c -o xpc_client

#include <xpc/xpc.h>

int main(int argc, const char *argv[]) {
xpc_connection_t connection = xpc_connection_create_mach_service("xyz.hacktricks.service", NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);

xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
// Print received message
const char* received_message = xpc_dictionary_get_string(event, "received");
printf("Received message: %s\n", received_message);
}
});

xpc_connection_resume(connection);

xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
xpc_dictionary_set_string(message, "message", "Hello, Server!");

xpc_connection_send_message(connection, message);

dispatch_main();

return 0;
}
```
{% endtab %}

{% tab title="xyz.hacktricks.service.plist" %}
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>Label</key>
<string>xyz.hacktricks.service</string>
<key>MachServices</key>
<dict>
<key>xyz.hacktricks.service</key>
<true/>
</dict>
<key>Program</key>
<string>/tmp/xpc_server</string>
<key>ProgramArguments</key>
<array>
<string>/tmp/xpc_server</string>
</array>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}
```bash
# Compile the server & client
gcc xpc_server.c -o xpc_server
gcc xpc_client.c -o xpc_client

# Save server on it's location
cp xpc_server /tmp

# Load daemon
sudo cp xyz.hacktricks.service.plist /Library/LaunchDaemons
sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.service.plist

# Call client
./xpc_client

# Clean
sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.service.plist
sudo rm /Library/LaunchDaemons/xyz.hacktricks.service.plist /tmp/xpc_server
```
## XPC Communication Objective-C Code Example

{% tabs %}
{% tab title="oc_xpc_server.m" %}
```objectivec
// gcc -framework Foundation oc_xpc_server.m -o oc_xpc_server
#include <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

@interface MyXPCObject : NSObject <MyXPCProtocol>
@end


@implementation MyXPCObject
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply {
NSLog(@"Received message: %@", some_string);
NSString *response = @"Received";
reply(response);
}
@end

@interface MyDelegate : NSObject <NSXPCListenerDelegate>
@end


@implementation MyDelegate

- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
newConnection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)];

MyXPCObject *my_object = [MyXPCObject new];

newConnection.exportedObject = my_object;

[newConnection resume];
return YES;
}
@end

int main(void) {

NSXPCListener *listener = [[NSXPCListener alloc] initWithMachServiceName:@"xyz.hacktricks.svcoc"];

id <NSXPCListenerDelegate> delegate = [MyDelegate new];
listener.delegate = delegate;
[listener resume];

sleep(10); // Fake something is done and then it ends
}
```
{% endtab %}

{% tab title="oc_xpc_client.m" %}
```objectivec
// gcc -framework Foundation oc_xpc_client.m -o oc_xpc_client
#include <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

int main(void) {
NSXPCConnection *connection = [[NSXPCConnection alloc] initWithMachServiceName:@"xyz.hacktricks.svcoc" options:NSXPCConnectionPrivileged];
connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)];
[connection resume];

[[connection remoteObjectProxy] sayHello:@"Hello, Server!" withReply:^(NSString *response) {
NSLog(@"Received response: %@", response);
}];

[[NSRunLoop currentRunLoop] run];

return 0;
}
```
{% endtab %}

{% tab title="xyz.hacktricks.svcoc.plist" %}
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>Label</key>
<string>xyz.hacktricks.svcoc</string>
<key>MachServices</key>
<dict>
<key>xyz.hacktricks.svcoc</key>
<true/>
</dict>
<key>Program</key>
<string>/tmp/oc_xpc_server</string>
<key>ProgramArguments</key>
<array>
<string>/tmp/oc_xpc_server</string>
</array>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}
```bash
# Compile the server & client
gcc -framework Foundation oc_xpc_server.m -o oc_xpc_server
gcc -framework Foundation oc_xpc_client.m -o oc_xpc_client

# Save server on it's location
cp oc_xpc_server /tmp

# Load daemon
sudo cp xyz.hacktricks.svcoc.plist /Library/LaunchDaemons
sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist

# Call client
./oc_xpc_client

# Clean
sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist
sudo rm /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist /tmp/oc_xpc_server
```
## Client inside a Dylb code
```objectivec
// gcc -dynamiclib -framework Foundation oc_xpc_client.m -o oc_xpc_client.dylib
// gcc injection example:
// DYLD_INSERT_LIBRARIES=oc_xpc_client.dylib /path/to/vuln/bin

#import <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

__attribute__((constructor))
static void customConstructor(int argc, const char **argv)
{
NSString*  _serviceName = @"xyz.hacktricks.svcoc";

NSXPCConnection* _agentConnection = [[NSXPCConnection alloc] initWithMachServiceName:_serviceName options:4096];

[_agentConnection setRemoteObjectInterface:[NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)]];

[_agentConnection resume];

[[_agentConnection remoteObjectProxyWithErrorHandler:^(NSError* error) {
(void)error;
NSLog(@"Connection Failure");
}] sayHello:@"Hello, Server!" withReply:^(NSString *response) {
NSLog(@"Received response: %@", response);
}    ];
NSLog(@"Done!");

return;
}
```
## Remote XPC

Αυτή η λειτουργία που παρέχεται από το `RemoteXPC.framework` (από το `libxpc`) επιτρέπει την επικοινωνία μέσω XPC μέσω διαφορετικών hosts.\
Οι υπηρεσίες που υποστηρίζουν το remote XPC θα έχουν στο plist τους το κλειδί UsesRemoteXPC όπως είναι η περίπτωση του `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Ωστόσο, αν και η υπηρεσία θα είναι καταχωρημένη με το `launchd`, είναι το `UserEventAgent` με τα plugins `com.apple.remoted.plugin` και `com.apple.remoteservicediscovery.events.plugin` που παρέχει τη λειτουργικότητα.

Επιπλέον, το `RemoteServiceDiscovery.framework` επιτρέπει την απόκτηση πληροφοριών από το `com.apple.remoted.plugin` εκθέτοντας συναρτήσεις όπως `get_device`, `get_unique_device`, `connect`...

Μόλις χρησιμοποιηθεί το connect και συγκεντρωθεί το socket `fd` της υπηρεσίας, είναι δυνατή η χρήση της κλάσης `remote_xpc_connection_*`.

Είναι δυνατή η απόκτηση πληροφοριών σχετικά με τις απομακρυσμένες υπηρεσίες χρησιμοποιώντας το εργαλείο cli `/usr/libexec/remotectl` χρησιμοποιώντας παραμέτρους όπως:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump withuot indicateing a servie
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
Η επικοινωνία μεταξύ του BridgeOS και του host πραγματοποιείται μέσω μιας ειδικής διεπαφής IPv6. Το `MultiverseSupport.framework` επιτρέπει τη δημιουργία sockets των οποίων το `fd` θα χρησιμοποιηθεί για την επικοινωνία.\
Είναι δυνατή η εύρεση αυτών των επικοινωνιών χρησιμοποιώντας `netstat`, `nettop` ή την ανοιχτού κώδικα επιλογή, `netbottom`.

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
