# Κόλπα με αρχεία ZIP

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Συμμετάσχετε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα αποθετήρια του [**HackTricks**](https://github.com/carlospolop/hacktricks) και του [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) στο GitHub.

</details>

**Εργαλεία γραμμής εντολών** για τη διαχείριση **αρχείων ZIP** είναι απαραίτητα για τη διάγνωση, επισκευή και αποκρυπτογράφηση αρχείων ZIP. Παρακάτω παρουσιάζονται μερικά βασικά εργαλεία:

- **`unzip`**: Αποκαλύπτει τον λόγο για τον οποίο ένα αρχείο ZIP δεν αποσυμπιέζεται.
- **`zipdetails -v`**: Παρέχει λεπτομερή ανάλυση των πεδίων της μορφής του αρχείου ZIP.
- **`zipinfo`**: Καταγράφει τα περιεχόμενα ενός αρχείου ZIP χωρίς να τα εξάγει.
- **`zip -F input.zip --out output.zip`** και **`zip -FF input.zip --out output.zip`**: Προσπαθούν να επιδιορθώσουν κατεστραμμένα αρχεία ZIP.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Ένα εργαλείο για την αποτροπή βίαιης διάρρηξης κωδικών πρόσβασης αρχείων ZIP, αποτελεσματικό για κωδικούς πρόσβασης έως περίπου 7 χαρακτήρες.

Η [προδιαγραφή της μορφής αρχείου Zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) παρέχει λεπτομερείς πληροφορίες σχετικά με τη δομή και τα πρότυπα των αρχείων ZIP.

Είναι σημαντικό να σημειωθεί ότι τα αρχεία ZIP που προστατεύονται με κωδικό πρόσβασης **δεν κρυπτογραφούν τα ονόματα αρχείων ή το μέγεθος των αρχείων** που περιέχουν, μια ευπάθεια ασφαλείας που δεν μοιράζονται τα αρχεία RAR ή 7z που κρυπτογραφούν αυτές τις πληροφορίες. Επιπλέον, τα αρχεία ZIP που κρυπτογραφούνται με την παλαιότερη μέθοδο ZipCrypto είναι ευάλωτα σε μια **επίθεση κειμένου ανοικτού κειμένου** εάν υπάρχει διαθέσιμο ένα μη κρυπτογραφημένο αντίγραφο ενός συμπιεσμένου αρχείου. Αυτή η επίθεση εκμεταλλεύεται το γνωστό περιεχόμενο για να αποκρυπτογραφήσει τον κωδικό πρόσβασης του αρχείου ZIP, μια ευπάθεια που αναλύεται λεπτομερώς στο [άρθρο του HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) και εξηγείται περαιτέρω σε [αυτό το ακαδημαϊκό άρθρο](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf). Ωστόσο, τα αρχεία ZIP που προστατεύονται με κρυπτογράφηση **AES-256** είναι ανθεκτικά σε αυτήν την επίθεση κειμένου ανοικτού κειμένου, καθιστώντας σαφές τον σημαντικό ρόλο της επιλογής ασφαλών μεθόδων κρυπτογράφησης για ευαίσθητα δεδομένα.

## Αναφορές
* [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Συμμετάσχετε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα αποθετήρια του [**HackTricks**](https://github.com/carlospolop/hacktricks) και του [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) στο
