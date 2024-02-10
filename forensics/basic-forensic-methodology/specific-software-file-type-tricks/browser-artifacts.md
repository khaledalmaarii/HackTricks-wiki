# Αποτυπώματα Περιηγητή

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Αποτυπώματα Περιηγητών <a href="#id-3def" id="id-3def"></a>

Τα αποτυπώματα περιηγητών περιλαμβάνουν διάφορους τύπους δεδομένων που αποθηκεύονται από τους περιηγητές ιστού, όπως ιστορικό πλοήγησης, σελιδοδείκτες και δεδομένα προσωρινής μνήμης. Αυτά τα αποτυπώματα αποθηκεύονται σε συγκεκριμένους φακέλους εντός του λειτουργικού συστήματος, διαφέροντας σε τοποθεσία και όνομα ανάμεσα στους περιηγητές, αλλά γενικά αποθηκεύουν παρόμοιους τύπους δεδομένων.

Παρακάτω παρουσιάζεται ένα σύνολο των πιο κοινών αποτυπωμάτων περιηγητών:

- **Ιστορικό Πλοήγησης**: Καταγράφει τις επισκέψεις του χρήστη σε ιστότοπους, χρήσιμο για τον εντοπισμό επισκέψεων σε κακόβουλους ιστότοπους.
- **Δεδομένα Αυτόματης Συμπλήρωσης**: Προτάσεις βασισμένες σε συχνές αναζητήσεις, προσφέροντας ενδείξεις όταν συνδυαστούν με το ιστορικό πλοήγησης.
- **Σελιδοδείκτες**: Ιστότοποι που αποθηκεύονται από τον χρήστη για γρήγορη πρόσβαση.
- **Πρόσθετα και Επεκτάσεις**: Πρόσθετα ή επεκτάσεις περιηγητή που έχουν εγκατασταθεί από τον χρήστη.
- **Προσωρινή Μνήμη**: Αποθηκεύει περιεχόμενο ιστού (π.χ. εικόνες, αρχεία JavaScript) για τη βελτίωση των χρόνων φόρτωσης του ιστότοπου, αξιόλογο για δικαστική ανάλυση.
- **Συνδρομές**: Αποθηκευμένα διαπιστευτήρια σύνδεσης.
- **Εικονίδια Ιστοτόπων**: Εικονίδια που σχετίζονται με ιστότοπους, εμφανίζονται σε καρτέλες και σελιδοδείκτες, χρήσιμα για επιπλέον πληροφορίες για τις επισκέψεις του χρήστη.
- **Συνεδρίες Περιηγητή**: Δεδομένα που σχετίζονται με ανοιχτές συνεδρίες περιηγητή.
- **Λήψεις**: Εγγραφές αρχείων που έχουν ληφθεί μέσω του περιηγητή.
- **Δεδομένα Φόρμας**: Πληροφορίες που εισάγονται σε ιστοφόρμες, αποθηκεύονται για μελλοντικές προτάσεις αυτόματης συμπλήρωσης.
- **Μικρογραφίες**: Εικόνες προεπισκόπησης ιστότοπων.
- **Custom Dictionary.txt**: Λέξεις που προστίθενται από τον χρήστη στο λεξικό του περιηγητή.


## Firefox

Ο Firefox οργανώνει τα δεδομένα του χρήστη μέσα σε προφίλ, που αποθηκεύονται σε συγκεκριμένες τοποθεσίες ανάλογα με το λειτουργικό σύστημα:

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Ένα αρχείο `profiles.ini` μέσα σε αυτούς τους καταλόγους κατα
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

![](<../../../.gitbook/assets/image (417).png>)

## Google Chrome

Ο Google Chrome αποθηκεύει τα προφίλ χρηστών σε συγκεκριμένες τοποθεσίες βάσει του λειτουργικού συστήματος:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Μέσα σε αυτούς τους φακέλους, οι περισσότερες πληροφορίες των χρηστών μπορούν να βρεθούν στους φακέλους **Default/** ή **ChromeDefaultData/**. Τα ακόλουθα αρχεία περιέχουν σημαντικές πληροφορίες:

- **History**: Περιέχει τις διευθύνσεις URL, τις λήψεις και τις λέξεις-κλειδιά αναζήτησης. Στα Windows, μπορεί να χρησιμοποιηθεί το [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) για να διαβαστεί η ιστορία. Η στήλη "Transition Type" έχει διάφορες σημασίες, συμπεριλαμβανομένων των κλικ του χρήστη σε συνδέσμους, πληκτρολογημένες διευθύνσεις URL, υποβολές φορμών και ανανεώσεις σελίδων.
- **Cookies**: Αποθηκεύει τα cookies. Για επιθεώρηση, υπάρχει το [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: Περιέχει τα αποθηκευμένα δεδομένα. Για επιθεώρηση, οι χρήστες των Windows μπορούν να χρησιμοποιήσουν το [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).
- **Bookmarks**: Οι σελιδοδείκτες του χρήστη.
- **Web Data**: Περιέχει το ιστορικό των φορμών.
- **Favicons**: Αποθηκεύει τα εικονίδια των ιστότοπων.
- **Login Data**: Περιλαμβάνει τα διαπιστευτήρια σύνδεσης, όπως ονόματα χρηστών και κωδικούς πρόσβασης.
- **Current Session**/**Current Tabs**: Δεδομένα σχετικά με την τρέχουσα συνεδρία περιήγησης και τις ανοιχτές καρτέλες.
- **Last Session**/**Last Tabs**: Πληροφορίες για τις ιστοσελίδες που ήταν ενεργές κατά την τελευταία συνεδρία πριν το κλείσιμο του Chrome.
- **Extensions**: Φακέλους για πρόσθετα και επεκτάσεις του προγράμματος περιήγησης.
- **Thumbnails**: Αποθηκεύει μικρογραφίες ιστοσελίδων.
- **Preferences**: Ένα αρχείο πλούσιο σε πληροφορίες, περιλαμβάνοντας ρυθμίσεις για πρόσθετα, επεκτάσεις, αναδυόμενα παράθυρα, ειδοποιήσεις και άλλα.
- **Ενσωματωμένη αντι-φισινγκ του προγράμματος περιήγησης**: Για να ελέγξετε αν η αντι-φισινγκ και η προστασία από κακόβουλο λογισμικό είναι ενεργοποιημένες, εκτελέστε την εντολή `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Αναζητήστε το `{"enabled: true,"}` στην έξοδο.

## **Ανάκτηση Δεδομένων SQLite DB**

Όπως μπορείτε να παρατηρήσετε στις προηγούμενες ενότητες, τόσο ο Chrome όσο και ο Firefox χρησιμοποιούν βάσεις δεδομένων SQLite για την αποθήκευση των δεδομένων. Είναι δυνατή η **ανάκτηση διαγραμμένων καταχωρήσεων χρησιμοποιώντας το εργαλείο** [**sqlparse**](https://github.com/padfoot999/sqlparse) **ή** [**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Ο Internet Explorer 11 διαχειρίζεται τα δεδομένα και τα μεταδεδομένα του σε διάφορες τοποθεσίες, βοηθώ
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας για hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
