# macOS Office Sandbox Bypasses

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

### Word Sandbox bypass via Launch Agents

Η εφαρμογή χρησιμοποιεί ένα **custom Sandbox** χρησιμοποιώντας την εξουσία **`com.apple.security.temporary-exception.sbpl`** και αυτό το custom sandbox επιτρέπει την εγγραφή αρχείων οπουδήποτε, αρκεί το όνομα του αρχείου να ξεκινά με `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Επομένως, η εκμετάλλευση ήταν τόσο εύκολη όσο το **να γράψεις ένα `plist`** LaunchAgent στο `~/Library/LaunchAgents/~$escape.plist`.

Δες την [**αρχική αναφορά εδώ**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).

### Word Sandbox bypass via Login Items and zip

Θυμήσου ότι από την πρώτη εκμετάλλευση, το Word μπορεί να γράψει αυθαίρετα αρχεία των οποίων το όνομα ξεκινά με `~$`, αν και μετά την επιδιόρθωση της προηγούμενης ευπάθειας δεν ήταν δυνατή η εγγραφή στο `/Library/Application Scripts` ή στο `/Library/LaunchAgents`.

Ανακαλύφθηκε ότι από μέσα στο sandbox είναι δυνατό να δημιουργηθεί ένα **Login Item** (εφαρμογές που θα εκτελούνται όταν ο χρήστης συνδέεται). Ωστόσο, αυτές οι εφαρμογές **δεν θα εκτελούνται εκτός αν** είναι **notarized** και **δεν είναι δυνατή η προσθήκη args** (έτσι δεν μπορείς απλά να τρέξεις ένα reverse shell χρησιμοποιώντας **`bash`**).

Από την προηγούμενη εκμετάλλευση Sandbox, η Microsoft απενεργοποίησε την επιλογή να γράφει αρχεία στο `~/Library/LaunchAgents`. Ωστόσο, ανακαλύφθηκε ότι αν βάλεις ένα **zip αρχείο ως Login Item**, το `Archive Utility` θα **αποσυμπιέσει** απλά το αρχείο στην τρέχουσα τοποθεσία του. Έτσι, επειδή από προεπιλογή ο φάκελος `LaunchAgents` από το `~/Library` δεν δημιουργείται, ήταν δυνατό να **zip-άρεις ένα plist στο `LaunchAgents/~$escape.plist`** και **να τοποθετήσεις** το zip αρχείο στο **`~/Library`** έτσι ώστε όταν αποσυμπιεστεί να φτάσει στον προορισμό επιμονής.

Δες την [**αρχική αναφορά εδώ**](https://objective-see.org/blog/blog\_0x4B.html).

### Word Sandbox bypass via Login Items and .zshenv

(Θυμήσου ότι από την πρώτη εκμετάλλευση, το Word μπορεί να γράψει αυθαίρετα αρχεία των οποίων το όνομα ξεκινά με `~$`).

Ωστόσο, η προηγούμενη τεχνική είχε έναν περιορισμό, αν ο φάκελος **`~/Library/LaunchAgents`** υπάρχει επειδή κάποιο άλλο λογισμικό τον δημιούργησε, θα αποτύχει. Έτσι, ανακαλύφθηκε μια διαφορετική αλυσίδα Login Items για αυτό.

Ένας επιτιθέμενος θα μπορούσε να δημιουργήσει τα αρχεία **`.bash_profile`** και **`.zshenv`** με το payload για εκτέλεση και στη συνέχεια να τα zip-άρει και **να γράψει το zip στον φάκελο του θύματος**: **`~/~$escape.zip`**.

Στη συνέχεια, πρόσθεσε το zip αρχείο στα **Login Items** και στη συνέχεια την εφαρμογή **`Terminal`**. Όταν ο χρήστης ξανασυνδεθεί, το zip αρχείο θα αποσυμπιεστεί στον φάκελο του χρήστη, αντικαθιστώντας τα **`.bash_profile`** και **`.zshenv`** και επομένως, το τερματικό θα εκτελέσει ένα από αυτά τα αρχεία (ανάλογα με το αν χρησιμοποιείται bash ή zsh).

Δες την [**αρχική αναφορά εδώ**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).

### Word Sandbox Bypass with Open and env variables

Από τις διαδικασίες που είναι sandboxed είναι ακόμα δυνατό να προσκαλέσεις άλλες διαδικασίες χρησιμοποιώντας το **`open`** utility. Επιπλέον, αυτές οι διαδικασίες θα εκτελούνται **μέσα στο δικό τους sandbox**.

Ανακαλύφθηκε ότι το open utility έχει την επιλογή **`--env`** για να εκτελέσει μια εφαρμογή με **συγκεκριμένες env** μεταβλητές. Επομένως, ήταν δυνατό να δημιουργηθεί το **`.zshenv` αρχείο** μέσα σε έναν φάκελο **μέσα** στο **sandbox** και να χρησιμοποιηθεί το `open` με `--env` ρυθμίζοντας τη **μεταβλητή `HOME`** σε αυτόν τον φάκελο ανοίγοντας την εφαρμογή `Terminal`, η οποία θα εκτελέσει το αρχείο `.zshenv` (για κάποιο λόγο ήταν επίσης απαραίτητο να ρυθμιστεί η μεταβλητή `__OSINSTALL_ENVIROMENT`).

Δες την [**αρχική αναφορά εδώ**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).

### Word Sandbox Bypass with Open and stdin

Το **`open`** utility υποστήριξε επίσης την παράμετρο **`--stdin`** (και μετά την προηγούμενη εκμετάλλευση δεν ήταν πλέον δυνατό να χρησιμοποιηθεί το `--env`).

Το θέμα είναι ότι ακόμα και αν το **`python`** ήταν υπογεγραμμένο από την Apple, **δεν θα εκτελέσει** ένα script με το **`quarantine`** χαρακτηριστικό. Ωστόσο, ήταν δυνατό να του περάσεις ένα script από stdin έτσι ώστε να μην ελέγξει αν ήταν καραντίνα ή όχι:&#x20;

1. Ρίξε ένα **`~$exploit.py`** αρχείο με αυθαίρετες εντολές Python.
2. Εκτέλεσε _open_ **`–stdin='~$exploit.py' -a Python`**, το οποίο εκτελεί την εφαρμογή Python με το ρίχτηκε αρχείο μας να χρησιμεύει ως τυπική είσοδος. Η Python εκτελεί ευτυχώς τον κώδικά μας, και καθώς είναι μια παιδική διαδικασία του _launchd_, δεν υπόκειται στους κανόνες sandbox του Word.

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
