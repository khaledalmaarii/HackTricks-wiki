# Οπλοποίηση του Distroless

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Συμμετάσχετε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) στο github.

</details>

## Τι είναι το Distroless

Ένας δοχείο τύπου distroless είναι ένας τύπος δοχείου που **περιέχει μόνο τις απαραίτητες εξαρτήσεις για να εκτελέσει μια συγκεκριμένη εφαρμογή**, χωρίς κανένα επιπλέον λογισμικό ή εργαλεία που δεν απαιτούνται. Αυτά τα δοχεία σχεδιάστηκαν για να είναι όσο **ελαφριά** και **ασφαλή** γίνεται και στοχεύουν να **ελαχιστοποιήσουν την επιφάνεια επίθεσης** αφαιρώντας οποιαδήποτε περιττή συνιστώσα.

Τα δοχεία distroless χρησιμοποιούνται συχνά σε **περιβάλλοντα παραγωγής όπου η ασφάλεια και η αξιοπιστία είναι κρίσιμες**.

Ορισμένα **παραδείγματα** δοχείων **distroless** είναι:

* Παρέχονται από την **Google**: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
* Παρέχονται από την **Chainguard**: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Οπλοποίηση του Distroless

Ο στόχος της οπλοποίησης ενός δοχείου distroless είναι να είναι δυνατή η **εκτέλεση αυθαίρετων δυαδικών αρχείων και φορτίων ακόμα και με τους περιορισμούς** που επιβάλλονται από το **distroless** (έλλειψη κοινών δυαδικών αρχείων στο σύστημα) και επίσης προστασίες που συνήθως βρίσκονται σε δοχεία, όπως **μόνο για ανάγνωση** ή **μη εκτέλεση** στο `/dev/shm`.

### Μέσω μνήμης

Έρχεται κάποια στιγμή το 2023...

### Μέσω υπαρχόντων δυαδικών αρχείων

#### openssl

****[**Σε αυτήν την ανάρτηση,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) εξηγείται ότι το δυαδικό αρχείο **`openssl`** βρίσκεται συχνά σε αυτά τα δοχεία, πιθανώς επειδή είναι **απαραίτητο** για το λογισμικό που θα εκτελεστεί μέσα στο δοχείο.

Με την κατάχρηση του δυαδικού αρχείου **`openssl`** είναι δυνατή η **εκτέλεση αυθαίρετων πραγμάτων**.

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Συμμετάσχετε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) στο github.

</details>
