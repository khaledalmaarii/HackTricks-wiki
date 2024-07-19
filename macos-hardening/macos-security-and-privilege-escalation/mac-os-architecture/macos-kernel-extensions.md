# macOS Kernel Extensions

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

## Basic Information

Οι επεκτάσεις πυρήνα (Kexts) είναι **πακέτα** με κατάληξη **`.kext`** που **φορτώνονται απευθείας στον χώρο του πυρήνα macOS**, παρέχοντας επιπλέον λειτουργικότητα στο κύριο λειτουργικό σύστημα.

### Requirements

Προφανώς, αυτό είναι τόσο ισχυρό που είναι **περίπλοκο να φορτωθεί μια επέκταση πυρήνα**. Αυτές είναι οι **απαιτήσεις** που πρέπει να πληροί μια επέκταση πυρήνα για να φορτωθεί:

* Όταν **μπαίνετε σε λειτουργία ανάκτησης**, οι επεκτάσεις πυρήνα **πρέπει να επιτρέπεται** να φορτωθούν:

<figure><img src="../../../.gitbook/assets/image (327).png" alt=""><figcaption></figcaption></figure>

* Η επέκταση πυρήνα πρέπει να είναι **υπογεγραμμένη με πιστοποιητικό υπογραφής κώδικα πυρήνα**, το οποίο μπορεί να **χορηγηθεί μόνο από την Apple**. Ποιος θα εξετάσει λεπτομερώς την εταιρεία και τους λόγους για τους οποίους είναι απαραίτητο.
* Η επέκταση πυρήνα πρέπει επίσης να είναι **notarized**, η Apple θα μπορεί να την ελέγξει για κακόβουλο λογισμικό.
* Στη συνέχεια, ο χρήστης **root** είναι αυτός που μπορεί να **φορτώσει την επέκταση πυρήνα** και τα αρχεία μέσα στο πακέτο πρέπει να **ανήκουν στον root**.
* Κατά τη διαδικασία φόρτωσης, το πακέτο πρέπει να είναι προετοιμασμένο σε μια **προστατευμένη τοποθεσία μη root**: `/Library/StagedExtensions` (απαιτεί την χορήγηση `com.apple.rootless.storage.KernelExtensionManagement`).
* Τέλος, όταν προσπαθεί να το φορτώσει, ο χρήστης θα [**λάβει ένα αίτημα επιβεβαίωσης**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) και, αν γίνει αποδεκτό, ο υπολογιστής πρέπει να **επανεκκινήσει** για να το φορτώσει.

### Loading process

Στο Catalina ήταν έτσι: Είναι ενδιαφέρον να σημειωθεί ότι η **διαδικασία επαλήθευσης** συμβαίνει σε **userland**. Ωστόσο, μόνο οι εφαρμογές με την **χορήγηση `com.apple.private.security.kext-management`** μπορούν να **ζητήσουν από τον πυρήνα να φορτώσει μια επέκταση**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **ξεκινά** τη διαδικασία **επικύρωσης** για τη φόρτωση μιας επέκτασης
* Θα επικοινωνήσει με **`kextd`** στέλνοντας χρησιμοποιώντας μια **υπηρεσία Mach**.
2. **`kextd`** θα ελέγξει διάφορα πράγματα, όπως την **υπογραφή**
* Θα επικοινωνήσει με **`syspolicyd`** για να **ελέγξει** αν η επέκταση μπορεί να **φορτωθεί**.
3. **`syspolicyd`** θα **ζητήσει** από τον **χρήστη** αν η επέκταση δεν έχει φορτωθεί προηγουμένως.
* **`syspolicyd`** θα αναφέρει το αποτέλεσμα στον **`kextd`**
4. **`kextd`** θα είναι τελικά σε θέση να **πεί** στον πυρήνα να φορτώσει την επέκταση

Αν **`kextd`** δεν είναι διαθέσιμο, **`kextutil`** μπορεί να εκτελέσει τους ίδιους ελέγχους.

## Referencias

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

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
