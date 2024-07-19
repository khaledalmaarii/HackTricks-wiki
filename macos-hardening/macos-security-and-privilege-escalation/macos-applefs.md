# macOS AppleFS

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
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Apple Proprietary File System (APFS)

**Apple File System (APFS)** είναι ένα σύγχρονο σύστημα αρχείων που έχει σχεδιαστεί για να αντικαταστήσει το Hierarchical File System Plus (HFS+). Η ανάπτυξή του καθοδηγήθηκε από την ανάγκη για **βελτιωμένη απόδοση, ασφάλεια και αποδοτικότητα**.

Ορισμένα αξιοσημείωτα χαρακτηριστικά του APFS περιλαμβάνουν:

1. **Κοινή Χρήση Χώρου**: Το APFS επιτρέπει σε πολλαπλούς τόμους να **μοιράζονται την ίδια υποκείμενη ελεύθερη αποθήκευση** σε μια φυσική συσκευή. Αυτό επιτρέπει πιο αποδοτική χρήση του χώρου, καθώς οι τόμοι μπορούν να αναπτύσσονται και να συρρικνώνονται δυναμικά χωρίς την ανάγκη χειροκίνητης αλλαγής μεγέθους ή επανακατανομής.
1. Αυτό σημαίνει, σε σύγκριση με τις παραδοσιακές κατανομές σε δίσκους αρχείων, **ότι στο APFS διαφορετικές κατανομές (τόμοι) μοιράζονται όλο το χώρο του δίσκου**, ενώ μια κανονική κατανομή είχε συνήθως σταθερό μέγεθος.
2. **Στιγμιότυπα**: Το APFS υποστηρίζει **δημιουργία στιγμιότυπων**, τα οποία είναι **μόνο για ανάγνωση**, στιγμές του συστήματος αρχείων. Τα στιγμιότυπα επιτρέπουν αποδοτικά αντίγραφα ασφαλείας και εύκολες ανακλήσεις συστήματος, καθώς καταναλώνουν ελάχιστο επιπλέον χώρο αποθήκευσης και μπορούν να δημιουργηθούν ή να αναιρεθούν γρήγορα.
3. **Κλώνοι**: Το APFS μπορεί να **δημιουργήσει κλώνους αρχείων ή καταλόγων που μοιράζονται την ίδια αποθήκευση** με το πρωτότυπο μέχρι να τροποποιηθεί είτε ο κλώνος είτε το πρωτότυπο αρχείο. Αυτή η δυνατότητα παρέχει έναν αποδοτικό τρόπο δημιουργίας αντιγράφων αρχείων ή καταλόγων χωρίς να διπλασιάζεται ο χώρος αποθήκευσης.
4. **Κρυπτογράφηση**: Το APFS **υποστηρίζει εγγενώς την κρυπτογράφηση ολόκληρου του δίσκου** καθώς και την κρυπτογράφηση ανά αρχείο και ανά κατάλογο, ενισχύοντας την ασφάλεια των δεδομένων σε διάφορες περιπτώσεις χρήσης.
5. **Προστασία από Κρασάρισμα**: Το APFS χρησιμοποιεί ένα **σχέδιο μεταδεδομένων αντιγραφής κατά την εγγραφή που διασφαλίζει τη συνέπεια του συστήματος αρχείων** ακόμη και σε περιπτώσεις ξαφνικής απώλειας ρεύματος ή κρασάρισμα του συστήματος, μειώνοντας τον κίνδυνο διαφθοράς δεδομένων.

Συνολικά, το APFS προσφέρει ένα πιο σύγχρονο, ευέλικτο και αποδοτικό σύστημα αρχείων για τις συσκευές Apple, με έμφαση στη βελτιωμένη απόδοση, αξιοπιστία και ασφάλεια.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

Ο όγκος `Data` είναι προσαρτημένος στο **`/System/Volumes/Data`** (μπορείτε να το ελέγξετε με το `diskutil apfs list`).

Η λίστα των firmlinks μπορεί να βρεθεί στο αρχείο **`/usr/share/firmlinks`**.
```bash
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
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
