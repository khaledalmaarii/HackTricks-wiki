# Αποσφαλμάτωση Προεπιλεγμένου Αμμοβολίου του macOS

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

Σε αυτήν τη σελίδα μπορείτε να βρείτε πώς να δημιουργήσετε μια εφαρμογή για να εκτελέσετε αυθαίρετες εντολές από μέσα στο προεπιλεγμένο αμμοβόλιο του macOS:

1. Μεταγλωττίστε την εφαρμογή:

{% code title="main.m" %}
```objectivec
#include <Foundation/Foundation.h>

int main(int argc, const char * argv[]) {
@autoreleasepool {
while (true) {
char input[512];

printf("Enter command to run (or 'exit' to quit): ");
if (fgets(input, sizeof(input), stdin) == NULL) {
break;
}

// Remove newline character
size_t len = strlen(input);
if (len > 0 && input[len - 1] == '\n') {
input[len - 1] = '\0';
}

if (strcmp(input, "exit") == 0) {
break;
}

system(input);
}
}
return 0;
}
```
{% endcode %}

Μεταγλωτίστε το εκτελώντας: `clang -framework Foundation -o SandboxedShellApp main.m`

2. Κατασκευάστε το πακέτο `.app`
```bash
mkdir -p SandboxedShellApp.app/Contents/MacOS
mv SandboxedShellApp SandboxedShellApp.app/Contents/MacOS/

cat << EOF > SandboxedShellApp.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CFBundleIdentifier</key>
<string>com.example.SandboxedShellApp</string>
<key>CFBundleName</key>
<string>SandboxedShellApp</string>
<key>CFBundleVersion</key>
<string>1.0</string>
<key>CFBundleExecutable</key>
<string>SandboxedShellApp</string>
</dict>
</plist>
EOF
```
3. Ορισμός των δικαιωμάτων

{% tabs %}
{% tab title="sandbox" %}
```bash
cat << EOF > entitlements.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.app-sandbox</key>
<true/>
</dict>
</plist>
EOF
```
{% tab title="sandbox + downloads" %}

Η ασφάλεια του macOS ενισχύεται με τη χρήση του μηχανισμού αμμοβολίας (sandboxing). Ο μηχανισμός αμμοβολίας περιορίζει τις δυνατότητες μιας εφαρμογής, περιορίζοντας την πρόσβασή της σε ευαίσθητους πόρους του συστήματος. Αυτό μειώνει τον κίνδυνο εκμετάλλευσης ευπαθειών του συστήματος από κακόβουλο λογισμικό.

Ο μηχανισμός αμμοβολίας του macOS περιλαμβάνει προκαθορισμένους κανόνες για την πρόσβαση σε διάφορους πόρους, όπως αρχεία, δίκτυο και συσκευές. Αυτοί οι κανόνες ορίζονται από τον προγραμματιστή της εφαρμογής και επιβάλλονται από το λειτουργικό σύστημα.

Όταν μια εφαρμογή προσπαθεί να αποκτήσει πρόσβαση σε έναν πόρο που είναι περιορισμένος από τον μηχανισμό αμμοβολίας, ο χρήστης λαμβάνει μια ειδοποίηση και μπορεί να αποφασίσει εάν επιτρέπει ή όχι την πρόσβαση. Αυτό παρέχει ένα επιπλέον επίπεδο προστασίας για το σύστημα.

Ωστόσο, ο μηχανισμός αμμοβολίας δεν είναι απόλυτα αδιάβροχος και μπορεί να υπάρχουν ευπάθειες που επιτρέπουν την παράκαμψη των περιορισμών του. Οι επιθέσεις που εκμεταλλεύονται αυτές τις ευπαθείς σημεία μπορούν να οδηγήσουν σε απόκτηση αυξημένων δικαιωμάτων (privilege escalation) και παράκαμψη των μέτρων ασφαλείας του συστήματος.

Για να αποφύγετε τις επιθέσεις που εκμεταλλεύονται τον μηχανισμό αμμοβολίας, είναι σημαντικό να ενημερώνετε το macOS σας σε κανονική βάση και να αποφεύγετε την εγκατάσταση ανεπιθύμητου λογισμικού. Επίσης, μπορείτε να ελέγξετε τις ρυθμίσεις ασφαλείας του συστήματος σας και να προσαρμόσετε τους κανόνες αμμοβολίας για κάθε εφαρμογή, ανάλογα με τις ανάγκες σας.

Τέλος, είναι σημαντικό να είστε επιφυλακτικοί κατά την περιήγηση στο διαδίκτυο και να αποφεύγετε τη λήψη αρχείων από αναξιόπιστες πηγές. Αυτό μπορεί να μειώσει τον κίνδυνο εκτέλεσης κακόβουλου κώδικα στο σύστημά σας.

{% endtab %}
```bash
cat << EOF > entitlements.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.app-sandbox</key>
<true/>
<key>com.apple.security.files.downloads.read-write</key>
<true/>
</dict>
</plist>
EOF
```
{% endtab %}
{% endtabs %}

4. Υπογράψτε την εφαρμογή (θα χρειαστεί να δημιουργήσετε ένα πιστοποιητικό στο keychain)
```bash
codesign --entitlements entitlements.plist -s "YourIdentity" SandboxedShellApp.app
./SandboxedShellApp.app/Contents/MacOS/SandboxedShellApp

# An d in case you need this in the future
codesign --remove-signature SandboxedShellApp.app
```
<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΠΛΑΝΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
