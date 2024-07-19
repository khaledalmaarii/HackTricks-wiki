# macOS Apple Scripts

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

## Apple Scripts

Είναι μια γλώσσα scripting που χρησιμοποιείται για αυτοματοποίηση εργασιών **αλληλεπιδρώντας με απομακρυσμένες διαδικασίες**. Διευκολύνει πολύ το **να ζητάμε από άλλες διαδικασίες να εκτελούν κάποιες ενέργειες**. **Malware** μπορεί να εκμεταλλευτεί αυτές τις δυνατότητες για να καταχραστεί λειτουργίες που εξάγονται από άλλες διαδικασίες.\
Για παράδειγμα, ένα malware θα μπορούσε να **εισάγει αυθαίρετο κώδικα JS σε ανοιγμένες σελίδες του προγράμματος περιήγησης**. Ή να **κάνει αυτόματη κλικ** σε κάποιες επιτρεπόμενες άδειες που ζητούνται από τον χρήστη;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Εδώ έχετε μερικά παραδείγματα: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Βρείτε περισσότερες πληροφορίες σχετικά με το malware που χρησιμοποιεί applescripts [**εδώ**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

Τα Apple scripts μπορούν να "**συμπιεστούν**" εύκολα. Αυτές οι εκδόσεις μπορούν να "**αποσυμπιεστούν**" εύκολα με το `osadecompile`

Ωστόσο, αυτά τα scripts μπορούν επίσης να **εξαχθούν ως "Μόνο για ανάγνωση"** (μέσω της επιλογής "Εξαγωγή..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/.gitbook/assets/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
και σε αυτή την περίπτωση το περιεχόμενο δεν μπορεί να αποσυμπιεστεί ακόμη και με το `osadecompile`

Ωστόσο, υπάρχουν ακόμα μερικά εργαλεία που μπορούν να χρησιμοποιηθούν για να κατανοήσουν αυτούς τους τύπους εκτελέσιμων, [**διαβάστε αυτή την έρευνα για περισσότερες πληροφορίες**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). Το εργαλείο [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) με το [**aevt\_decompile**](https://github.com/SentineLabs/aevt\_decompile) θα είναι πολύ χρήσιμο για να κατανοήσετε πώς λειτουργεί το σενάριο.

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
