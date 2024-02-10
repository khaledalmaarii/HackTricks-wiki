# PsExec/Winexec/ScExec

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Πώς λειτουργούν

Η διαδικασία περιγράφεται στα παρακάτω βήματα, επιδεικνύοντας πώς τα δυαδικά αρχεία υπηρεσίας παραμορφώνονται για να επιτευχθεί απομακρυσμένη εκτέλεση σε έναν στόχο μηχανήματος μέσω του SMB:

1. Πραγματοποιείται **αντιγραφή ενός δυαδικού αρχείου υπηρεσίας στον κοινόχρηστο φάκελο ADMIN$ μέσω SMB**.
2. Πραγματοποιείται **δημιουργία μιας υπηρεσίας στο απομακρυσμένο μηχάνημα** δείχνοντας στο δυαδικό αρχείο.
3. Η υπηρεσία **ξεκινά απομακρυσμένα**.
4. Μετά τη λήξη, η υπηρεσία **σταματά και το δυαδικό αρχείο διαγράφεται**.

### **Διαδικασία Χειροκίνητης Εκτέλεσης του PsExec**

Υποθέτοντας ότι υπάρχει ένα εκτελέσιμο φορτίο (δημιουργημένο με το msfvenom και αποκρυπτογραφημένο χρησιμοποιώντας το Veil για να αποφευχθεί η ανίχνευση από το αντιιικό πρόγραμμα), με το όνομα 'met8888.exe', που αντιπροσωπεύει ένα αντίστροφο payload του meterpreter μέσω του reverse_http, πραγματοποιούνται τα παρακάτω βήματα:

- **Αντιγραφή του δυαδικού**: Το εκτελέσιμο αντιγράφεται στον κοινόχρηστο φάκελο ADMIN$ από ένα παράθυρο εντολών, αν και μπορεί να τοποθετηθεί οπουδήποτε στο σύστημα αρχείων για να παραμείνει κρυμμένο.

- **Δημιουργία μιας υπηρεσίας**: Χρησιμοποιώντας την εντολή `sc` των Windows, η οποία επιτρέπει τον αναζήτηση, τη δημιουργία και τη διαγραφή υπηρεσιών των Windows απομακρυσμένα, δημιουργείται μια υπηρεσία με το όνομα "meterpreter" που δείχνει στο ανεβασμένο δυαδικό αρχείο.

- **Έναρξη της υπηρεσίας**: Το τελικό βήμα περιλαμβάνει την έναρξη της υπηρεσίας, η οποία πιθανότατα θα οδηγήσει σε σφάλμα "time-out" λόγω του γεγονότος ότι το δυαδικό αρχείο δεν είναι γνήσιο δυαδικό αρχείο υπηρεσίας και αποτυγχάνει να επιστρέψει τον αναμενόμενο κωδικό απόκρισης. Αυτό το σφάλμα είναι ασήμαντο καθώς ο κύριος στόχος είναι η εκτέλεση του δυαδικού αρχείου.

Η παρατήρηση του ακροατή Metasploit θα αποκαλύψει ότι η συνεδρία έχει ξεκινήσει με επιτυχία.

[Μάθετε περισσότερα για την εντολή `sc`](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Βρείτε περισσότερα λεπτομερή βήματα στο: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Μπορείτε επίσης να χρησιμοποιήσετε το δυαδικό PsExec.exe των Windows Sysinternals:**

![](<../../.gitbook/assets/image (165).png>)

Μπορείτε επίσης να χρησιμοποιήσετε το [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
