# Αποτυπώματα Περιηγητή

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Red Team του HackTricks AWS)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=browser-artifacts) για να δημιουργήσετε εύκολα και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=browser-artifacts" %}

## Αποτυπώματα Περιηγητών <a href="#id-3def" id="id-3def"></a>

Τα αποτυπώματα των περιηγητών περιλαμβάνουν διάφορους τύπους δεδομένων που αποθηκεύονται από τους περιηγητές ιστού, όπως ιστορικό πλοήγησης, σελιδοδείκτες και δεδομένα cache. Αυτά τα αποτυπώματα αποθηκεύονται σε συγκεκριμένους φακέλους εντός του λειτουργικού συστήματος, διαφέροντας σε τοποθεσία και όνομα ανάμεσα στους περιηγητές, αλλά γενικά αποθηκεύοντας παρόμοιους τύπους δεδομένων.

Εδώ υπάρχει ένα σύνοψη των πιο κοινών αποτυπωμάτων περιηγητών:

* **Ιστορικό Πλοήγησης**: Καταγράφει τις επισκέψεις του χρήστη σε ιστότοπους, χρήσιμο για την αναγνώριση επισκέψεων σε κακόβουλους ιστότοπους.
* **Δεδομένα Αυτόματης Συμπλήρωσης**: Προτάσεις βασισμένες σε συχνές αναζητήσεις, προσφέροντας εισαγωγές όταν συνδυαστούν με το ιστορικό πλοήγησης.
* **Σελιδοδείκτες**: Ιστότοποι που έχουν αποθηκευτεί από τον χρήστη για γρήγορη πρόσβαση.
* **Επεκτάσεις και Πρόσθετα**: Επεκτάσεις περιηγητή ή πρόσθετα που έχουν εγκατασταθεί από τον χρήστη.
* **Cache**: Αποθηκεύει περιεχόμενο ιστού (π.χ. εικόνες, αρχεία JavaScript) για βελτίωση των χρόνων φόρτωσης του ιστότοπου, πολύτιμο για ανάλυση ψηφιακών αποτυπωμάτων.
* **Συνδρομές**: Αποθηκευμένα διαπιστευτήρια σύνδεσης.
* **Εικονίδια Αγαπημένων**: Εικονίδια που σχετίζονται με ιστότοπους, εμφανίζονται σε καρτέλες και σελιδοδείκτες, χρήσιμα για επιπλέον πληροφορίες σχετικά με τις επισκέψεις του χρήστη.
* **Συνεδρίες Περιηγητή**: Δεδομένα που σχετίζονται με ανοιχτές συνεδρίες περιηγητή.
* **Λήψεις**: Εγγραφές αρχείων που κατέβηκαν μέσω του περιηγητή.
* **Δεδομένα Φόρμας**: Πληροφορίες που εισήχθησαν σε φόρμες ιστού, αποθηκευμένες για μελλοντικές προτάσεις αυτόματης συμπλήρωσης.
* **Εικόνες Προεπισκόπησης**: Προεπισκόπηση ιστοτόπων.
* **Custom Dictionary.txt**: Λέξεις που προστέθηκαν από τον χρήστη στο λεξικό του περιηγητή.

## Firefox

Ο Firefox οργανώνει τα δεδομένα του χρήστη μέσα σε προφίλ, τα οποία αποθηκεύονται σε συγκεκριμένες τοποθεσίες ανάλογα με το λειτουργικό σύστημα:

* **Linux**: `~/.mozilla/firefox/`
* **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
* **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Ένα αρχείο `profiles.ini` μέσα σε αυτούς τους καταλόγους καταχωρεί τα προφίλ του χρήστη. Τα δεδομένα κάθε προφίλ αποθηκεύονται σε ένα φάκελο με το όνομα που αναφέρεται στη μεταβλητή `Path` μέσα στο `profiles.ini`, το οποίο βρίσκεται στον ίδιο κατάλογο με το `profiles.ini` ίδιο του. Αν ένας φάκελος προφίλ είναι απουσιάζει, μπορεί να έχει διαγραφεί.

Μέσα σε κάθε φάκελο προφίλ, μπορείτε να βρείτε αρκετά σημαντικά αρχεία:

* **places.sqlite**: Αποθηκεύει ιστορικό, σελιδοδείκτες και λήψεις. Εργαλεία όπως το [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html) στα Windows μπορούν να έχουν πρόσβαση στα δεδομένα ιστορικού.
* Χρησιμοποιήστε συγκεκριμένες ερωτήσεις SQL για να εξάγετε πληροφορίες ιστορικού και λήψεων.
* **bookmarkbackups**: Περιέχει αντίγραφα ασφαλείας των σελιδοδεικτών.
* **formhistory.sqlite**: Αποθηκεύει δεδομένα φορμών ιστού.
* **handlers.json**: Διαχειρίζεται τους χειριστές πρωτοκόλλων.
* **persdict.dat**: Λέξεις προσαρμοσμένου λεξικού.
* **addons.json** και **extensions.sqlite**: Πληροφορίες για εγκατεστημένα πρόσθετα και επεκτάσεις.
* **cookies.sqlite**: Αποθήκευση cookie, με το [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) διαθέσιμο για επιθεώρηση στα Windows.
* **cache2/entries** ή **startupCache**: Δεδομένα cache, προσβάσιμα μέσω εργαλείων όπως το [MozillaCacheView](https://www.nirsoft.net/utils/mozilla\_cache\_viewer.html).
* **favicons.sqlite**: Αποθηκεύει εικονίδια αγαπημένων.
* **prefs.js**: Ρυθμίσεις και προτιμήσεις χρήστη.
* **downloads.sqlite**: Παλαιότερη βάση δεδομένων λήψεων, πλέον ενσωματωμένη στο places.sqlite.
* **thumbnails**: Εικόνες προεπισκόπησης ιστοτόπων.
* **logins.json**: Κρυπτογραφημένες πληροφορίες σύνδεσης.
* **key4.db** ή **key3.db**: Αποθηκεύει κλειδιά κρυπτογράφησης για την προστασία ευαίσθητων πληροφοριών.

Επιπλέον, η έλεγχος των ρυθμίσεων αντι-φισικών του περιηγητή μπορεί να γίνει αναζητώντας τις καταχωρήσεις `browser.safebrowsing` στο `prefs.js`, που υποδηλώνουν εάν οι λειτουργίες ασφαλούς περιήγησης είναι ενεργοποιημένες ή απενεργοποιημένες.

Για να δοκ
```bash
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
{% endcode %}

![](<../../../.gitbook/assets/image (692).png>)

## Google Chrome

Ο Google Chrome αποθηκεύει τα προφίλ χρηστών σε συγκεκριμένες τοποθεσίες βάσει του λειτουργικού συστήματος:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Μέσα σε αυτούς τους καταλόγους, η πλειονότητα των δεδομένων του χρήστη μπορεί να βρεθεί στους φακέλους **Default/** ή **ChromeDefaultData/**. Τα ακόλουθα αρχεία περιέχουν σημαντικά δεδομένα:

- **History**: Περιέχει διευθύνσεις URL, λήψεις και λέξεις-κλειδιά αναζήτησης. Στα Windows, μπορεί να χρησιμοποιηθεί το [ChromeHistoryView](https://www.nirsoft.net/utils/chrome\_history\_view.html) για την ανάγνωση του ιστορικού. Η στήλη "Transition Type" έχει διάφορες σημασίες, συμπεριλαμβανομένων των κλικ του χρήστη σε συνδέσμους, την πληκτρολόγηση διευθύνσεων URL, τις υποβολές φόρμας και τις ανανεώσεις σελίδων.
- **Cookies**: Αποθηκεύει τα cookies. Για επιθεώρηση, είναι διαθέσιμο το [ChromeCookiesView](https://www.nirsoft.net/utils/chrome\_cookies\_view.html).
- **Cache**: Κρατά τα αποθηκευμένα δεδομένα. Για επιθεώρηση, οι χρήστες των Windows μπορούν να χρησιμοποιήσουν το [ChromeCacheView](https://www.nirsoft.net/utils/chrome\_cache\_view.html).
- **Bookmarks**: Σελιδοδείκτες του χρήστη.
- **Web Data**: Περιέχει το ιστορικό φόρμας.
- **Favicons**: Αποθηκεύει τα εικονίδια ιστότοπων.
- **Login Data**: Περιλαμβάνει διαπιστευτήρια σύνδεσης όπως ονόματα χρηστών και κωδικούς πρόσβασης.
- **Current Session**/**Current Tabs**: Δεδομένα σχετικά με την τρέχουσα συνεδρία περιήγησης και τις ανοιχτές καρτέλες.
- **Last Session**/**Last Tabs**: Πληροφορίες σχετικά με τις ιστοσελίδες που ήταν ενεργές κατά την τελευταία συνεδρία πριν το κλείσιμο του Chrome.
- **Extensions**: Κατάλογοι για πρόσθετα και επεκτάσεις περιήγησης.
- **Thumbnails**: Αποθηκεύει μικρογραφίες ιστοσελίδων.
- **Preferences**: Ένα αρχείο πλούσιο σε πληροφορίες, συμπεριλαμβανομένων ρυθμίσεων για πρόσθετα, επεκτάσεις, αναδυόμενα παράθυρα, ειδοποιήσεις και άλλα.
- **Ενσωματωμένο αντι-φισικά του προγράμματος περιήγησης**: Για να ελέγξετε αν η αντι-φισικά και η προστασία από κακόβουλο λογισμικό είναι ενεργοποιημένες, εκτελέστε `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Αναζητήστε το `{"enabled: true,"}` στην έξοδο.

## **Ανάκτηση Δεδομένων Βάσης Δεδομένων SQLite**

Όπως μπορείτε να παρατηρήσετε στις προηγούμενες ενότητες, τόσο ο Chrome όσο και ο Firefox χρησιμοποιούν βάσεις δεδομένων **SQLite** για την αποθήκευση των δεδομένων. Είναι δυνατή η **ανάκτηση διαγραμμένων καταχωρήσεων χρησιμοποιώντας το εργαλείο** [**sqlparse**](https://github.com/padfoot999/sqlparse) **ή** [**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Ο Internet Explorer 11 διαχειρίζεται τα δεδομένα και τα μεταδεδομένα του σε διάφορες τοποθεσίες, βοηθώντας στον διαχωρισμό των αποθηκευμένων πληροφοριών και των αντίστοιχων λεπτομερειών για εύκολη πρόσβαση και διαχείριση.

### Αποθήκευση Μεταδεδομένων

Τα μεταδεδομένα για τον Internet Explorer αποθηκεύονται στο `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (όπου το VX είναι V01, V16 ή V24). Συνοδευόμενο από αυτό, το αρχείο `V01.log` μπορεί να εμφανίσει αντιφάσεις στον χρόνο τροποποίησης με το `WebcacheVX.data`, υποδεικνύοντας την ανάγκη επισκευής χρησιμοποιώντας το `esentutl /r V01 /d`. Αυτά τα μεταδεδομένα, που φιλοξενούνται σε μια βάση δεδομένων ESE, μπορούν να ανακτηθούν και να επιθεωρηθούν χρησιμοποιώντας εργαλεία όπως το photorec και το [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html), αντίστοιχα. Μέσα στον πίνακα **Containers**, μπορεί κανείς να διακρίνει τους συγκεκριμένους πίνακες ή δοχεία όπου αποθηκεύεται κάθε τμήμα δεδομένων, συμπεριλαμβανομένων λεπτομερειών cache για άλλα εργαλεία της Microsoft, όπως το Skype.

### Επιθεώρηση Cache

Το εργαλείο [IECacheView](https://www.nirsoft.net/utils/ie\_cache\_viewer.html) επιτρέπει την επιθεώρηση της μνήμης cache, απαιτώντας την τοποθεσία φακέλου εξαγωγής δεδομένων cache. Τα μεταδεδομένα για την cache περιλαμβάνουν όνομα αρχείου, κατάλογο, αριθμό πρόσβασης, προέλευση URL και χρονικά σημεία που υποδεικνύουν τη δημιουργία, την πρόσβαση, την τροποποίηση και τους χρόνους λήξης της cache.

### Διαχείριση Cookies

Τα cookies μπορούν να εξερευνηθούν χρησιμοποιώντας το [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), με μεταδεδομένα που περιλαμβάνουν ονόματα, διευθύνσεις URL, αριθμούς πρόσβασης και διάφορες λεπτομέρειες σχετικές με το χρόνο. Τα μόνιμα cookies αποθηκεύονται στο `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, με τα session cookies να βρίσκονται στη μνήμη.

### Λεπτομέρειες Λήψης

Τα μεταδεδομένα λήψης είναι προσβάσιμα μέσω του [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html), με συγκεκριμένα δοχεία που κρατούν δεδομένα όπως URL, τύπο αρχείου και τοποθεσία λήψης. Τα φυσικά αρχεία μπορούν να βρεθούν στο `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Ιστορικό Περιήγησης

Για να ελέγξετε το ιστορικό περιήγησης, μπορεί να χρησιμοποιηθεί το [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html), απαιτώντας την τοποθεσία των εξαγόμενων αρχείων ιστορικού και τη διαμόρφωση για τον Internet Explorer. Τα μεταδεδομένα εδώ περιλαμβάνουν χρόνους τροποποίησης και πρόσβασης, μαζί με αριθμούς πρόσβασης. Τα αρχεία ιστορικού βρίσκονται στο `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Καταχωρημένες Διευθύνσεις URL

Οι καταχωρημένες διευθύνσεις URL και οι χρόνοι χρήσης τους αποθηκεύονται στο μητρώο στο `NTUSER.DAT` στις διαδρομές `Software\Microsoft\InternetExplorer\TypedURLs` και `Software\Microsoft\InternetExplorer\TypedURLsTime`, παρακολουθώντας τις τελευταίες 50 διευθύνσεις URL που εισήγαγε ο χρήστης και τους τελευταίους χρόνους εισαγωγής τους.

## Microsoft Edge

Τα δεδομένα του χρήστη στο Microsoft Edge αποθηκεύονται στο `%userprofile%\Appdata\Local\Packages`. Οι διαδρομές για διάφορους τύπους δεδομένων είναι:

- **Διαδρομή Προφίλ**: `C:\Users\XX
* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**Την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα κόλπα σας στο χάκινγκ υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.
