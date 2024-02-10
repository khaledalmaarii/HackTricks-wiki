# Ανάλυση αντιγράφου μνήμης

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Συμμετάσχετε** στην [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) είναι το πιο σημαντικό συνέδριο κυβερνοασφάλειας στην **Ισπανία** και ένα από τα πιο σημαντικά στην **Ευρώπη**. Με **αποστολή την προώθηση της τεχνικής γνώσης**, αυτό το συνέδριο είναι ένας ζωντανός σημείο συνάντησης για επαγγελματίες τεχνολογίας και κυβερνοασφάλειας σε κάθε ειδικότητα.

{% embed url="https://www.rootedcon.com/" %}

## Έναρξη

Ξεκινήστε την **αναζήτηση** για **κακόβουλο λογισμικό** μέσα στο pcap. Χρησιμοποιήστε τα **εργαλεία** που αναφέρονται στην [**Ανάλυση Κακόβουλου Λογισμικού**](../malware-analysis.md).

## [Volatility](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)

**Το Volatility είναι το κύριο πλαίσιο ανοιχτού κώδικα για την ανάλυση αντιγράφων μνήμης**. Αυτό το εργαλείο Python αναλύει αντίγραφα από εξωτερικές πηγές ή εικονικές μηχανές VMware, εντοπίζοντας δεδομένα όπως διεργασίες και κωδικούς πρόσβασης με βάση το προφίλ του λειτουργικού συστήματος του αντιγράφου. Είναι επεκτάσιμο με πρόσθετα, καθιστώντας το υψηλά ευέλικτο για διερευνητικές ερευνητικές εργασίες.

**[Βρείτε εδώ ένα cheatsheet](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)**


## Αναφορά κατάρρευσης μικρού αντιγράφου μνήμης

Όταν το αντίγραφο είναι μικρό (μόνο μερικά KB, ίσως μερικά MB) τότε πιθανότατα είναι μια αναφορά κατάρρευσης μικρού αντιγράφου και όχι ένα αντίγραφο μνήμης.

![](<../../../.gitbook/assets/image (216).png>)

Εάν έχετε εγκατεστημένο το Visual Studio, μπορείτε να ανοίξετε αυτό το αρχείο και να συνδέσετε μερικές βασικές πληροφορίες όπως το όνομα της διεργασίας, η αρχιτεκτονική, πληροφορίες εξαίρεσης και τα εκτελούμενα αρθρώματα:

![](<../../../.gitbook/assets/image (217).png>)

Μπορείτε επίσης να φορτώσετε την εξαίρεση και να δείτε τις αποκωδικοποιημένες οδηγίες

![](<../../../.gitbook/assets/image (219).png>)

![](<../../../.gitbook/assets/image (218) (1).png>)

Πάντως, το Visual Studio δεν είναι το καλύτερο εργαλείο για να πραγματοποιήσετε μια ανάλυση του βάθους του αντιγράφου.

Θα πρέπει να το **ανοίξετε** χρησιμοποιώντας το **IDA** ή το **Radare** για να το επιθεωρήσετε **λεπτομερώς**.



​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) είναι το πιο ση
