# macOS XPC

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) στο github.

</details>

## Βασικές Πληροφορίες

Το XPC, που σημαίνει XNU (το πυρήνας που χρησιμοποιείται από το macOS) Inter-Process Communication, είναι ένα πλαίσιο για **επικοινωνία μεταξύ διεργασιών** στο macOS και το iOS. Το XPC παρέχει ένα μηχανισμό για την πραγματοποίηση **ασφαλών, ασύγχρονων κλήσεων μεθόδων μεταξύ διαφορετικών διεργασιών** στο σύστημα. Αποτελεί μέρος του ασφαλούς παραδείγματος της Apple, επιτρέποντας την **δημιουργία εφαρμογών με διαχωρισμένα προνόμια**, όπου κάθε **συνιστώσα** λειτουργεί με **μόνο τα δικαιώματα που χρειάζεται** για να εκτελέσει την εργασία της, περιορίζοντας έτσι την πιθανή ζημιά από μια παραβιασμένη διεργασία.

Το XPC χρησιμοποιεί μια μορφή Διαδικασίας Επικοινωνίας (IPC), που είναι ένα σύνολο μεθόδων για διάφορα προγράμματα που εκτελούνται στο ίδιο σύστημα να ανταλλάσσουν δεδομένα.

Οι κύρια οφέλη του XPC περιλαμβάνουν:

1. **Ασφάλεια**: Με τον διαχωρισμό της εργασίας σε διάφορες διεργασίες, κάθε διεργασία μπορεί να έχει μόνο τα δικαιώματα που χρειάζεται. Αυτό σημαίνει ότι ακόμα και αν μια διεργασία παραβιαστεί, έχει περιορισμένη ικανότητα να προκαλέσει ζημιά.
2. **Σταθερότητα**: Το XPC βοηθά στην απομόνωση των καταρρίψεων στη συνιστώσα όπου συμβαίνουν. Εάν μια διεργασία καταρρεύσει, μπορεί να επανεκκινηθεί χωρίς να επηρεάζει το υπόλοιπο σύστημα.
3. **Απόδοση**: Το XPC επιτρέπει εύκολη ταυτόχρονη εκτέλεση, καθώς διάφορες εργασίες μπορούν να εκτελούνται ταυτόχρονα σε διάφορες διεργασίες.

Το μόνο **μειονέκτημα** είναι ότι η **διαχωρισμένη εφαρμογή σε πολλές διεργασίες** που επικοινωνούν μέσω XPC είναι **λιγότερο αποδοτική**. Ωστόσο, στα σημερινά συστήματα αυτό δεν είναι σχεδόν αντιληπτό και τα οφέλη είναι μεγαλύτερα.

## Εφαρμογές Ειδικές XPC

Οι συνιστώσες XPC μιας εφαρμογής βρίσκονται **μέσα στην ίδια την εφαρμογή**. Για παράδειγμα, στο Safari μπορείτε να τις βρείτε στο **`/Applications/Safari.app/Contents/XPCServices`**. Έχουν την κατάληξη **`.xpc`** (όπως **`com.apple.Safari.SandboxBroker.xpc`**) και είναι **επίσης δέσμες** με τον κύριο δυαδικό αρχείο μέσα σε αυτό: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` και ένα `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

Όπως μπορείτε να σκεφτείτε, μια **συνιστώσα XPC θα έχει διαφορετικά δικαιώματα και προνόμια** από τις άλλες συνιστώσες XPC ή το κύριο δυαδικό αρχείο της εφαρμογής. ΕΚΤΟΣ αν ένα XPC service έχει ρυθμιστεί με την [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/xpcservice/joinexistingsession) να έχει την τιμή "True" στο αρχείο **Info.plist** του. Σε αυτήν την περίπτωση, το XPC service θα εκτελείται στην **ίδια ασφαλή συνεδρία με την εφαρμογή** που το κάλεσε.

Τα XPC services **ξεκινούν** από τον **launchd** όταν απαιτούνται και **τερματίζονται** όταν ολοκληρώνονται όλες οι εργασίες για να απελευθερωθούν οι πόροι του συστήματος. **Οι εφαρμογές μπορούν να χρησιμοποι
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
Αυτά που βρίσκονται στο **`LaunchDameons`** τρέχουν από τον ριζικό χρήστη. Έτσι, αν ένα μη προνομιούχο διεργασία μπορεί να επικοινωνήσει με ένα από αυτά, μπορεί να αναβαθμίσει τα δικαιώματά του.

## Μηνύματα XPC Event

Οι εφαρμογές μπορούν να **εγγραφούν** σε διάφορα **μηνύματα γεγονότων**, επιτρέποντάς τους να εκτελούνται κατά παραγγελία όταν συμβούν τέτοια γεγονότα. Η ρύθμιση για αυτές τις υπηρεσίες γίνεται σε αρχεία **plist του launchd**, που βρίσκονται στους **ίδιους καταλόγους με τα προηγούμενα** και περιέχουν ένα επιπλέον κλειδί **`LaunchEvent`**.

### Έλεγχος Σύνδεσης Διεργασίας XPC

Όταν μια διεργασία προσπαθεί να καλέσει μια μέθοδο μέσω μιας σύνδεσης XPC, η **XPC υπηρεσία πρέπει να ελέγξει αν η διεργασία αυτή έχει άδεια να συνδεθεί**. Εδώ παρουσιάζονται οι συνηθισμένοι τρόποι ελέγχου και οι συνηθισμένες παγίδες:

{% content-ref url="macos-xpc-connecting-process-check/" %}
[macos-xpc-connecting-process-check](macos-xpc-connecting-process-check/)
{% endcontent-ref %}

## Εξουσιοδότηση XPC

Η Apple επιτρέπει επίσης στις εφαρμογές να **διαμορφώσουν ορισμένα δικαιώματα και τον τρόπο απόκτησής τους**, έτσι ώστε αν η καλούσα διεργασία τα έχει, θα **επιτρέπεται να καλέσει μια μέθοδο** από την XPC υπηρεσία:

{% content-ref url="macos-xpc-authorization.md" %}
[macos-xpc-authorization.md](macos-xpc-authorization.md)
{% endcontent-ref %}

## XPC Sniffer

Για να καταγράψετε τα μηνύματα XPC, μπορείτε να χρησιμοποιήσετε το [**xpcspy**](https://github.com/hot3eed/xpcspy), το οποίο χρησιμοποιεί το **Frida**.
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
## Παράδειγμα κώδικα C για επικοινωνία XPC

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
{% tab title="xpc_client.c" %}

```c
#include <stdio.h>
#include <xpc/xpc.h>

int main(int argc, const char * argv[]) {
    xpc_connection_t connection = xpc_connection_create_mach_service("com.apple.securityd", NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
    
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        xpc_type_t type = xpc_get_type(event);
        
        if (type == XPC_TYPE_DICTIONARY) {
            const char *description = xpc_dictionary_get_string(event, "description");
            printf("Received event: %s\n", description);
        }
    });
    
    xpc_connection_resume(connection);
    
    sleep(10);
    
    xpc_release(connection);
    
    return 0;
}
```

This is a simple example of an XPC client in C. It creates a connection to the `com.apple.securityd` Mach service, which is a privileged service responsible for security-related tasks on macOS. The `xpc_connection_create_mach_service` function is used to create the connection.

The `xpc_connection_set_event_handler` function sets a block of code to be executed when an event is received from the server. In this example, it checks if the received event is a dictionary and prints the value of the "description" key.

The `xpc_connection_resume` function starts the connection and allows events to be received.

The `sleep` function is used to keep the program running for 10 seconds before releasing the connection with `xpc_release`.

This is just a basic example to demonstrate the usage of XPC in macOS. In a real-world scenario, you would typically perform more complex operations and handle different types of events.
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
{% tab title="xyz.hacktricks.service.plist" %}

Το αρχείο `xyz.hacktricks.service.plist` περιέχει τις ρυθμίσεις για ένα XPC service στο macOS. Το XPC (Inter-Process Communication) είναι ένα μηχανισμός που επιτρέπει την επικοινωνία μεταξύ διαφορετικών διεργασιών στο macOS. Αυτό το αρχείο περιέχει πληροφορίες για το πώς θα εκτελεστεί το XPC service και ποιες δικαιώματα θα έχει.

Για να εκμεταλλευτείτε το XPC service, μπορείτε να τροποποιήσετε αυτό το αρχείο για να αλλάξετε τις ρυθμίσεις του. Μπορείτε να προσθέσετε δικαιώματα προνομίων ή να αλλάξετε τον τρόπο εκτέλεσης του XPC service. Αυτό μπορεί να οδηγήσει σε εκμετάλλευση προνομίων και ανέβασμα δικαιωμάτων στο σύστημα.

Είναι σημαντικό να είστε προσεκτικοί κατά την τροποποίηση αυτού του αρχείου, καθώς μπορεί να προκαλέσετε προβλήματα στο σύστημα σας ή να προκαλέσετε ανεπιθύμητες συνέπειες. Πριν προχωρήσετε, συνιστάται να έχετε κατανόηση του τρόπου λειτουργίας του XPC service και των επιπτώσεών του.

Για περισσότερες πληροφορίες σχετικά με το πώς να εκμεταλλευτείτε το XPC service στο macOS, ανατρέξτε στο αντίστοιχο κεφάλαιο του βιβλίου.

{% endtab %}
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
## Παράδειγμα κώδικα XPC επικοινωνίας Objective-C

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
{% tab title="xyz.hacktricks.svcoc.plist" %}

Το αρχείο `xyz.hacktricks.svcoc.plist` περιέχει τις ρυθμίσεις για την εκτέλεση του `xyz.hacktricks.svcoc` στο macOS. Αυτό το αρχείο παρέχει πληροφορίες για το πώς ο επιθετικός μπορεί να εκμεταλλευτεί το XPC για να αποκτήσει προνόμια στο σύστημα.

Για να εκμεταλλευτεί ένα XPC, ο επιθετικός πρέπει να ανακαλύψει τον κατάλληλο κώδικα XPC και να τον εκμεταλλευτεί για να εκτελέσει κακόβουλο κώδικα. Αυτό μπορεί να γίνει με τη χρήση εργαλείων όπως το `xpcproxy` ή το `xpcd`. Ο επιθετικός μπορεί να εκμεταλλευτεί το XPC για να αποκτήσει προνόμια χρησιμοποιώντας μια από τις παρακάτω μεθόδους:

- Εκμετάλλευση ευπάθειας στον κώδικα XPC για να εκτελέσει κακόβουλο κώδικα.
- Εκμετάλλευση ευπάθειας στην ανάγνωση/εγγραφή μνήμης για να αποκτήσει πρόσβαση σε ευαίσθητες πληροφορίες.
- Εκμετάλλευση ευπάθειας στην ανάγνωση/εγγραφή αρχείων για να αποκτήσει πρόσβαση σε ευαίσθητα δεδομένα.

Ο επιθετικός μπορεί επίσης να εκμεταλλευτεί το XPC για να εκτελέσει κακόβουλο κώδικα σε ένα εξωτερικό σύστημα, χρησιμοποιώντας την απομακρυσμένη εκτέλεση κώδικα XPC.

Για να προστατευθείτε από τις επιθέσεις XPC, μπορείτε να εφαρμόσετε τις παρακάτω μεθόδους ασφάλειας:

- Ελέγξτε την αυθεντικότητα των XPC που εκτελούνται στο σύστημά σας.
- Περιορίστε τα δικαιώματα πρόσβασης των XPC.
- Εφαρμόστε μέτρα ασφαλείας για την ανάγνωση/εγγραφή μνήμης και αρχείων από τα XPC.
- Ενημερώστε το σύστημά σας με τις τελευταίες ενημερώσεις ασφαλείας.

Αυτές οι προφυλάξεις μπορούν να βοηθήσουν στην αποτροπή των επιθέσεων XPC και στην προστασία του συστήματός σας από προνόμια εκτελέσιμου κώδικα.

{% endtab %}
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
## Πελάτης μέσα σε κώδικα Dylb

Ο παρακάτω κώδικας παρουσιάζει έναν πελάτη που εκτελείται μέσα σε έναν κώδικα Dylb.

```objective-c
#include <stdio.h>
#include <dlfcn.h>

int main(int argc, char *argv[]) {
    void *handle;
    int (*add)(int, int);
    char *error;

    handle = dlopen("./libadd.dylib", RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "%s\n", dlerror());
        return 1;
    }

    add = dlsym(handle, "add");
    if ((error = dlerror()) != NULL) {
        fprintf(stderr, "%s\n", error);
        return 1;
    }

    printf("The sum is: %d\n", add(5, 3));

    dlclose(handle);
    return 0;
}
```

Ο παραπάνω κώδικας φορτώνει δυναμικά τη βιβλιοθήκη `libadd.dylib` και καλεί τη συνάρτηση `add` που βρίσκεται μέσα σε αυτήν. Η συνάρτηση `add` πραγματοποιεί την πρόσθεση δύο αριθμών και επιστρέφει το αποτέλεσμα. Το αποτέλεσμα εκτυπώνεται στην οθόνη.

Για να εκτελέσετε τον παραπάνω κώδικα, πρέπει να δημιουργήσετε τη βιβλιοθήκη `libadd.dylib` που περιέχει τη συνάρτηση `add`. Μπορείτε να το κάνετε αυτό με τη χρήση του Xcode ή του gcc.

Για παράδειγμα, μπορείτε να δημιουργήσετε ένα αρχείο με τον κώδικα της συνάρτησης `add` και να το μεταγλωττίσετε σε μια βιβλιοθήκη χρησιμοποιώντας την ακόλουθη εντολή:

```bash
gcc -shared -o libadd.dylib add.c
```

Αφού δημιουργήσετε τη βιβλιοθήκη, μπορείτε να μεταγλωττίσετε και να εκτελέσετε τον παραπάνω κώδικα.
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
<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
