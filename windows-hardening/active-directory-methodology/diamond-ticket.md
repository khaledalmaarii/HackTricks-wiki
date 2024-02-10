# Διαμαντένιο Εισιτήριο

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Διαμαντένιο Εισιτήριο

**Όπως ένα χρυσό εισιτήριο**, ένα διαμαντένιο εισιτήριο είναι ένα TGT που μπορεί να χρησιμοποιηθεί για να **έχετε πρόσβαση σε οποιαδήποτε υπηρεσία ως οποιοσδήποτε χρήστης**. Ένα χρυσό εισιτήριο δημιουργείται πλήρως εκτός σύνδεσης, κρυπτογραφείται με το hash του krbtgt της περιοχής και στη συνέχεια περνιέται σε μια συνεδρία σύνδεσης για χρήση. Επειδή οι ελεγκτές τομέων δεν καταγράφουν τα TGT που έχουν εκδοθεί νόμιμα, θα δεχθούν ευχαρίστως TGT που έχουν κρυπτογραφηθεί με το δικό τους krbtgt hash.

Υπάρχουν δύο κοινές τεχνικές για τον εντοπισμό της χρήσης χρυσών εισιτηρίων:

* Αναζήτηση για TGS-REQs που δεν έχουν αντίστοιχο AS-REQ.
* Αναζήτηση για TGTs που έχουν αστείες τιμές, όπως η προεπιλεγμένη διάρκεια ζωής 10 ετών του Mimikatz.

Ένα **διαμαντένιο εισιτήριο** δημιουργείται **τροποποιώντας τα πεδία ενός νόμιμου TGT που έχει εκδοθεί από έναν ελεγκτή τομέα**. Αυτό επιτυγχάνεται με το **ζήτημα** ενός **TGT**, την **αποκρυπτογράφησή** του με το hash krbtgt του τομέα, την **τροποποίηση** των επιθυμητών πεδίων του εισιτηρίου και στη συνέχεια την **επανακρυπτογράφησή** του. Αυτό **ξεπερνά τα δύο προαναφερθέντα μειονεκτήματα** ενός χρυσού εισιτηρίου επειδή:

* Τα TGS-REQs θα έχουν ένα προηγούμενο AS-REQ.
* Το TGT εκδόθηκε από έναν ελεγκτή τομέα, πράγμα που σημαίνει ότι θα έχει όλες τις σωστές λεπτομέρειες από την πολιτική Kerberos του τομέα. Αν και αυτές μπορούν να πλαστογραφηθούν με ακρίβεια σε ένα χρυσό εισιτήριο, είναι πιο περίπλοκο και ευάλωτο σε λάθη.
```bash
# Get user RID
powershell Get-DomainUser -Identity <username> -Properties objectsid

.\Rubeus.exe diamond /tgtdeleg /ticketuser:<username> /ticketuserid:<RID of username> /groups:512

# /tgtdeleg uses the Kerberos GSS-API to obtain a useable TGT for the user without needing to know their password, NTLM/AES hash, or elevation on the host.
# /ticketuser is the username of the principal to impersonate.
# /ticketuserid is the domain RID of that principal.
# /groups are the desired group RIDs (512 being Domain Admins).
# /krbkey is the krbtgt AES256 hash.
```
<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
