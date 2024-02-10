# Ανίχνευση Φισινγκ

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github.

</details>

## Εισαγωγή

Για να ανιχνεύσετε μια προσπάθεια φισινγκ, είναι σημαντικό να **κατανοήσετε τις τεχνικές φισινγκ που χρησιμοποιούνται σήμερα**. Στη γονική σελίδα αυτής της ανάρτησης, μπορείτε να βρείτε αυτές τις πληροφορίες, οπότε αν δεν γνωρίζετε ποιες τεχνικές χρησιμοποιούνται σήμερα, σας συνιστώ να πάτε στη γονική σελίδα και να διαβάσετε τουλάχιστον αυτήν την ενότητα.

Αυτή η ανάρτηση βασίζεται στην ιδέα ότι οι **επιτιθέμενοι θα προσπαθήσουν να μιμηθούν ή να χρησιμοποιήσουν το όνομα του τομέα του θύματος**. Εάν ο τομέας σας ονομάζεται `example.com` και γίνετε θύμα φισινγκ χρησιμοποιώντας έναν εντελώς διαφορετικό τομέα για κάποιο λόγο, όπως το `youwonthelottery.com`, αυτές οι τεχνικές δεν θα το αποκαλύψουν.

## Παραλλαγές ονομάτων τομέα

Είναι αρκετά **εύκολο** να **αποκαλύψετε** αυτές τις **προσπάθειες φισινγκ που θα χρησιμοποιήσουν ένα όνομα τομέα παρόμοιο** μέσα στο email.\
Είναι αρκετό να **δημιουργήσετε μια λίστα με τα πιο πιθανά ονόματα φισινγκ** που μπορεί να χρησιμοποιήσει ένας επιτιθέμενος και να **ελέγξετε** αν είναι **καταχωρημένο** ή απλά να ελέγξετε αν υπάρχει κάποια **IP** που το χρησιμοποιεί.

### Εύρεση ύποπτων τομέων

Για αυτόν τον σκοπό, μπορείτε να χρησιμοποιήσετε οποιοδήποτε από τα παρακάτω εργαλεία. Σημειώστε ότι αυτά τα εργαλεία θα πραγματοποιήσουν αυτόματα αιτήσεις DNS για να ελέγξουν αν ο τομέας έχει καταχωρηθεί σε κάποια IP:

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### Bitflipping

**Μπορείτε να βρείτε μια σύντομη εξήγηση αυτής της τεχνικής στη γονική σελίδα. Ή διαβάστε την αρχική έρευνα στο [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**

Για παράδειγμα, μια τροποποίηση 1 bit στον τομέα microsoft.com μπορεί να τον μετατρέψει σε _windnws.com._\
**Οι επιτιθέμενοι μπορεί να καταχωρίσουν όσους τομείς με τροποποίηση bit-flipping είναι δυνατόν σχετίζονται με το θύμα για να ανακατευθύνουν νόμιμους χρήστες στην υποδομή τους**.

**Όλα τα πιθανά ονόματα τομέων με τροποποίηση bit-flipping πρέπει επίσης να παρακολουθούνται.**

### Βασικοί έλεγχοι

Αφού
### **Νέοι τομείς**

**Μία τελευταία εναλλακτική λύση** είναι να συγκεντρώσετε μια λίστα με **νεοεγγεγραμμένους τομείς** για ορισμένα TLDs ([Το Whoxy](https://www.whoxy.com/newly-registered-domains/) παρέχει τέτοια υπηρεσία) και **να ελέγξετε τις λέξεις-κλειδιά σε αυτούς τους τομείς**. Ωστόσο, οι μακροπρόθεσμοι τομείς συνήθως χρησιμοποιούν έναν ή περισσότερους υποτομείς, επομένως η λέξη-κλειδί δεν θα εμφανίζεται μέσα στον FLD και δεν θα μπορείτε να βρείτε τον φαινομενικό υποτομέα phishing.

<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας για το hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
