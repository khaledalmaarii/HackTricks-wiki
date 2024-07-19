# Over Pass the Hash/Pass the Key

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

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Overpass The Hash/Pass The Key (PTK)

Η επίθεση **Overpass The Hash/Pass The Key (PTK)** έχει σχεδιαστεί για περιβάλλοντα όπου το παραδοσιακό πρωτόκολλο NTLM είναι περιορισμένο και η αυθεντικοποίηση Kerberos έχει προτεραιότητα. Αυτή η επίθεση εκμεταλλεύεται το NTLM hash ή τα κλειδιά AES ενός χρήστη για να ζητήσει εισιτήρια Kerberos, επιτρέποντας μη εξουσιοδοτημένη πρόσβαση σε πόρους εντός ενός δικτύου.

Για να εκτελεστεί αυτή η επίθεση, το αρχικό βήμα περιλαμβάνει την απόκτηση του NTLM hash ή του κωδικού πρόσβασης του λογαριασμού του στοχευμένου χρήστη. Αφού εξασφαλιστεί αυτή η πληροφορία, μπορεί να αποκτηθεί ένα Ticket Granting Ticket (TGT) για τον λογαριασμό, επιτρέποντας στον επιτιθέμενο να έχει πρόσβαση σε υπηρεσίες ή μηχανές στις οποίες ο χρήστης έχει άδειες.

Η διαδικασία μπορεί να ξεκινήσει με τις παρακάτω εντολές:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Για σενάρια που απαιτούν AES256, η επιλογή `-aesKey [AES key]` μπορεί να χρησιμοποιηθεί. Επιπλέον, το αποκτηθέν εισιτήριο μπορεί να χρησιμοποιηθεί με διάφορα εργαλεία, συμπεριλαμβανομένων των smbexec.py ή wmiexec.py, διευρύνοντας την έκταση της επίθεσης.

Τα προβλήματα που συναντώνται, όπως το _PyAsn1Error_ ή το _KDC cannot find the name_, συνήθως επιλύονται με την ενημέρωση της βιβλιοθήκης Impacket ή με τη χρήση του ονόματος υπολογιστή αντί της διεύθυνσης IP, διασφαλίζοντας τη συμβατότητα με το Kerberos KDC.

Μια εναλλακτική ακολουθία εντολών χρησιμοποιώντας το Rubeus.exe δείχνει μια άλλη πτυχή αυτής της τεχνικής:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Αυτή η μέθοδος αντικατοπτρίζει την προσέγγιση **Pass the Key**, με έμφαση στην κατάληψη και τη χρήση του εισιτηρίου απευθείας για σκοπούς αυθεντικοποίησης. Είναι κρίσιμο να σημειωθεί ότι η έναρξη ενός αιτήματος TGT ενεργοποιεί το γεγονός `4768: A Kerberos authentication ticket (TGT) was requested`, υποδηλώνοντας τη χρήση RC4-HMAC από προεπιλογή, αν και τα σύγχρονα συστήματα Windows προτιμούν το AES256.

Για να συμμορφωθεί με την επιχειρησιακή ασφάλεια και να χρησιμοποιήσει το AES256, μπορεί να εφαρμοστεί η ακόλουθη εντολή:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## Αναφορές

* [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

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
