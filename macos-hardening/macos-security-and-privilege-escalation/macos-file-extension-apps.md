# macOS Χειριστές Εφαρμογών Αρχείων & Σχήματος URL

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο Hacking του AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο Hacking του GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
{% endhint %}

## Βάση Δεδομένων LaunchServices

Αυτή είναι μια βάση δεδομένων όλων των εγκατεστημένων εφαρμογών στο macOS που μπορεί να ερευνηθεί για να ληφθούν πληροφορίες για κάθε εγκατεστημένη εφαρμογή, όπως τα σχήματα URL που υποστηρίζει και οι τύποι MIME.

Είναι δυνατόν να αδειάσετε αυτήν τη βάση δεδομένων με:

{% code overflow="wrap" %}
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
{% endcode %}

Ή χρησιμοποιώντας το εργαλείο [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Το **`/usr/libexec/lsd`** είναι το μυαλό της βάσης δεδομένων. Παρέχει **πολλές υπηρεσίες XPC** όπως `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, και άλλες. Αλλά απαιτεί επίσης **κάποιες αδειοδοτήσεις** στις εφαρμογές για να μπορούν να χρησιμοποιήσουν τις εκτεθειμένες λειτουργίες XPC, όπως `.launchservices.changedefaulthandler` ή `.launchservices.changeurlschemehandler` για να αλλάξουν τις προεπιλεγμένες εφαρμογές για τύπους αρχείων ή σχήματα URL και άλλα.

Το **`/System/Library/CoreServices/launchservicesd`** δηλώνει την υπηρεσία `com.apple.coreservices.launchservicesd` και μπορεί να αναζητηθεί για να λάβετε πληροφορίες σχετικά με εκτελούμενες εφαρμογές. Μπορεί να αναζητηθεί με το εργαλείο συστήματος /**`usr/bin/lsappinfo`** ή με το [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

## Χειριστές εφαρμογών για επέκταση αρχείου & σχήμα URL

Η παρακάτω γραμμή μπορεί να είναι χρήσιμη για να βρείτε τις εφαρμογές που μπορούν να ανοίξουν αρχεία ανάλογα με την επέκταση:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
{% endcode %}

Ή χρησιμοποιήστε κάτι όπως το [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps):
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
Μπορείτε επίσης να ελέγξετε τις επεκτάσεις που υποστηρίζονται από μια εφαρμογή κάνοντας:
```
cd /Applications/Safari.app/Contents
grep -A3 CFBundleTypeExtensions Info.plist  | grep string
<string>css</string>
<string>pdf</string>
<string>webarchive</string>
<string>webbookmark</string>
<string>webhistory</string>
<string>webloc</string>
<string>download</string>
<string>safariextz</string>
<string>gif</string>
<string>html</string>
<string>htm</string>
<string>js</string>
<string>jpg</string>
<string>jpeg</string>
<string>jp2</string>
<string>txt</string>
<string>text</string>
<string>png</string>
<string>tiff</string>
<string>tif</string>
<string>url</string>
<string>ico</string>
<string>xhtml</string>
<string>xht</string>
<string>xml</string>
<string>xbl</string>
<string>svg</string>
```
{% hint style="success" %}
Μάθετε & εξασκηθείτε στο Hacking του AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο Hacking του GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Κοινοποιήστε τεχνικές χάκινγκ υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) στο GitHub.

</details>
{% endhint %}
