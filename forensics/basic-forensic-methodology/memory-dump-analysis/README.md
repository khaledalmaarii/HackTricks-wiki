# Ανάλυση μνήμης

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

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) είναι η πιο σχετική εκδήλωση κυβερνοασφάλειας στην **Ισπανία** και μία από τις πιο σημαντικές στην **Ευρώπη**. Με **αποστολή την προώθηση της τεχνικής γνώσης**, αυτό το συνέδριο είναι ένα καυτό σημείο συνάντησης για επαγγελματίες τεχνολογίας και κυβερνοασφάλειας σε κάθε πειθαρχία.

{% embed url="https://www.rootedcon.com/" %}

## Ξεκινήστε

Ξεκινήστε **αναζητώντας** **malware** μέσα στο pcap. Χρησιμοποιήστε τα **εργαλεία** που αναφέρονται στην [**Ανάλυση Malware**](../malware-analysis.md).

## [Volatility](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)

**Το Volatility είναι το κύριο ανοιχτού κώδικα πλαίσιο για την ανάλυση μνήμης**. Αυτό το εργαλείο Python αναλύει dumps από εξωτερικές πηγές ή VMware VMs, αναγνωρίζοντας δεδομένα όπως διαδικασίες και κωδικούς πρόσβασης με βάση το προφίλ OS του dump. Είναι επεκτάσιμο με plugins, καθιστώντας το εξαιρετικά ευέλικτο για εγκληματολογικές έρευνες.

**[Βρείτε εδώ ένα cheatsheet](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)**

## Αναφορά κρασάρισματος mini dump

Όταν το dump είναι μικρό (μόνο μερικά KB, ίσως μερικά MB) τότε πιθανότατα είναι μια αναφορά κρασάρισματος mini dump και όχι ένα memory dump.

![](<../../../.gitbook/assets/image (216).png>)

Αν έχετε εγκατεστημένο το Visual Studio, μπορείτε να ανοίξετε αυτό το αρχείο και να συνδέσετε κάποιες βασικές πληροφορίες όπως το όνομα διαδικασίας, αρχιτεκτονική, πληροφορίες εξαίρεσης και modules που εκτελούνται:

![](<../../../.gitbook/assets/image (217).png>)

Μπορείτε επίσης να φορτώσετε την εξαίρεση και να δείτε τις αποσυμπιεσμένες εντολές

![](<../../../.gitbook/assets/image (219).png>)

![](<../../../.gitbook/assets/image (218) (1).png>)

Ούτως ή άλλως, το Visual Studio δεν είναι το καλύτερο εργαλείο για να εκτελέσετε μια ανάλυση βάθους του dump.

Πρέπει να το **ανοίξετε** χρησιμοποιώντας **IDA** ή **Radare** για να το επιθεωρήσετε σε **βάθος**.
