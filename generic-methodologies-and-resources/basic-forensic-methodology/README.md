# Βασική Μεθοδολογία Εγκληματολογικής Εξέτασης

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Συμμετάσχετε** στην [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Δημιουργία και Προσάρτηση Εικόνας

{% content-ref url="../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md" %}
[image-acquisition-and-mount.md](../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md)
{% endcontent-ref %}

## Ανάλυση Κακόβουλου Λογισμικού

Αυτό **δεν είναι απαραίτητο το πρώτο βήμα που πρέπει να γίνει μόλις έχετε την εικόνα**. Ωστόσο, μπορείτε να χρησιμοποιήσετε αυτές τις τεχνικές ανάλυσης κακόβουλου λογισμικού ανεξάρτητα αν έχετε ένα αρχείο, μια εικόνα αρχείου συστήματος, μια εικόνα μνήμης, pcap... οπότε είναι καλό να **έχετε αυτές τις ενέργειες υπόψη**:

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## Επιθεώρηση μιας Εικόνας

Αν σας δίνεται μια **εγκληματολογική εικόνα** ενός συσκευής, μπορείτε να αρχίσετε να **αναλύετε τις διαμερίσματα, το αρχείο-σύστημα** που χρησιμοποιήθηκε και να **ανακτήσετε** πιθανώς **ενδιαφέροντα αρχεία** (ακόμα και διαγραμμένα). Μάθετε πώς στο:

{% content-ref url="partitions-file-systems-carving/" %}
[partitions-file-systems-carving](partitions-file-systems-carving/)
{% endcontent-ref %}

Ανάλογα με τα χρησιμοποιούμενα λειτουργικά συστήματα και ακόμα και πλατφόρμες, πρέπει να αναζητηθούν διάφορα ενδιαφέροντα στοιχεία:

{% content-ref url="windows-forensics/" %}
[windows-forensics](windows-forensics/)
{% endcontent-ref %}

{% content-ref url="linux-forensics.md" %}
[linux-forensics.md](linux-forensics.md)
{% endcontent-ref %}

{% content-ref url="docker-forensics.md" %}
[docker-forensics.md](docker-forensics.md)
{% endcontent-ref %}

## Εμβάθυνση σε συγκεκριμένους τύπους αρχείων και Λογισμικό

Αν έχετε ένα πολύ **ύποπτο αρχείο**, τότε, **ανάλογα με τον τύπο αρχείου και το λογισμικό** που το δημιούργησε, μπορεί να είναι χρήσιμα διάφορα **κόλπα**.\
Διαβάστε την παρακάτω σελίδα για να μάθετε μερικά ενδιαφέροντα κόλπα:

{% content-ref url="specific-software-file-type-tricks/" %}
[specific-software-file-type-tricks](specific-software-file-type-tricks/)
{% endcontent-ref %}

Θέλω να κάνω μια ειδική αναφορά στη σελίδα:

{% content-ref url="specific-software-file-type-tricks/browser-artifacts.md" %}
[browser-artifacts.md](specific-software-file-type-tricks/browser-artifacts.md)
{% endcontent-ref %}

## Επιθεώρηση Αντιγράφου Μνήμης

{% content-ref url="memory-dump-analysis/" %}
[memory-dump-analysis](memory-dump-analysis/)
{% endcontent-ref %}

## Επιθεώρηση Pcap

{% content-ref url="pcap-inspection/" %}
[pcap-inspection](pcap-inspection/)
{% endcontent-ref %}

## **Τεχνικές Αντι-Εγκληματολογικής Ανάλυσης**

Να έχετε υπόψη την πιθανή χρήση τεχνικών αντι-εγκληματολογικής ανάλυσης:

{% content-ref url="anti-forensic-techniques.md" %}
[anti-forensic-techniques.md](anti-forensic-techniques.md)
{% endcontent-ref %}

## Κυνήγι Απειλών

{% content-ref url="file-integrity-monitoring.md" %}
[file-integrity-monitoring.md](file-integrity-monitoring.md)
{% endcontent-ref %}

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε π
