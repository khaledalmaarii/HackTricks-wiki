{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξη HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}


**Η αρχική ανάρτηση είναι** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Περίληψη

Δύο κλειδιά μητρώου βρέθηκαν ότι είναι εγγράψιμα από τον τρέχοντα χρήστη:

- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**

Προτάθηκε να ελεγχθούν οι άδειες του **RpcEptMapper** υπηρεσίας χρησιμοποιώντας το **regedit GUI**, συγκεκριμένα την καρτέλα **Effective Permissions** του παραθύρου **Advanced Security Settings**. Αυτή η προσέγγιση επιτρέπει την αξιολόγηση των παραχωρημένων αδειών σε συγκεκριμένους χρήστες ή ομάδες χωρίς την ανάγκη να εξεταστεί κάθε Access Control Entry (ACE) ξεχωριστά.

Μια στιγμιότυπη οθόνη έδειξε τις άδειες που αποδόθηκαν σε έναν χρήστη με χαμηλά προνόμια, μεταξύ των οποίων η άδεια **Create Subkey** ήταν αξιοσημείωτη. Αυτή η άδεια, που αναφέρεται επίσης ως **AppendData/AddSubdirectory**, αντιστοιχεί με τα ευρήματα του script.

Η αδυναμία τροποποίησης ορισμένων τιμών άμεσα, αλλά η ικανότητα δημιουργίας νέων υποκλειδιών, παρατηρήθηκε. Ένα παράδειγμα που τονίστηκε ήταν μια προσπάθεια να αλλάξει η τιμή **ImagePath**, η οποία είχε ως αποτέλεσμα ένα μήνυμα πρόσβασης απαγορευμένης.

Παρά αυτούς τους περιορισμούς, εντοπίστηκε μια πιθανότητα για κλιμάκωση προνομίων μέσω της δυνατότητας εκμετάλλευσης του υποκλειδιού **Performance** μέσα στη δομή μητρώου της υπηρεσίας **RpcEptMapper**, ένα υποκλειδί που δεν υπάρχει από προεπιλογή. Αυτό θα μπορούσε να επιτρέψει την εγγραφή DLL και την παρακολούθηση απόδοσης.

Συμβουλευτήκαμε τεκμηρίωση σχετικά με το υποκλειδί **Performance** και τη χρήση του για παρακολούθηση απόδοσης, οδηγώντας στην ανάπτυξη ενός proof-of-concept DLL. Αυτή η DLL, που αποδεικνύει την υλοποίηση των συναρτήσεων **OpenPerfData**, **CollectPerfData** και **ClosePerfData**, δοκιμάστηκε μέσω **rundll32**, επιβεβαιώνοντας την επιτυχία της λειτουργίας της.

Ο στόχος ήταν να αναγκαστεί η **RPC Endpoint Mapper service** να φορτώσει την κατασκευασμένη Performance DLL. Παρατηρήσεις αποκάλυψαν ότι η εκτέλεση ερωτημάτων WMI κλάσεων σχετικών με τα Performance Data μέσω PowerShell είχε ως αποτέλεσμα τη δημιουργία ενός αρχείου καταγραφής, επιτρέποντας την εκτέλεση αυθαίρετου κώδικα υπό το πλαίσιο **LOCAL SYSTEM**, παρέχοντας έτσι ανυψωμένα προνόμια.

Η επιμονή και οι πιθανές επιπτώσεις αυτής της ευπάθειας υπογραμμίστηκαν, τονίζοντας τη σημασία της για στρατηγικές μετά την εκμετάλλευση, πλευρική κίνηση και αποφυγή συστημάτων antivirus/EDR.

Αν και η ευπάθεια αποκαλύφθηκε αρχικά ακούσια μέσω του script, τονίστηκε ότι η εκμετάλλευσή της περιορίζεται σε παλαιότερες εκδόσεις των Windows (π.χ., **Windows 7 / Server 2008 R2**) και απαιτεί τοπική πρόσβαση.
