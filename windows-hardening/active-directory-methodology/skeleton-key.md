# Skeleton Key

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

## Skeleton Key Attack

Η **επίθεση Skeleton Key** είναι μια προηγμένη τεχνική που επιτρέπει στους επιτιθέμενους να **παρακάμψουν την αυθεντικοποίηση του Active Directory** μέσω της **εισαγωγής ενός κύριου κωδικού πρόσβασης** στον ελεγκτή τομέα. Αυτό επιτρέπει στον επιτιθέμενο να **αυθεντικοποιείται ως οποιοσδήποτε χρήστης** χωρίς τον κωδικό τους, παρέχοντας τους **απεριόριστη πρόσβαση** στον τομέα.

Μπορεί να εκτελεστεί χρησιμοποιώντας [Mimikatz](https://github.com/gentilkiwi/mimikatz). Για να πραγματοποιηθεί αυτή η επίθεση, **τα δικαιώματα Domain Admin είναι προαπαιτούμενα**, και ο επιτιθέμενος πρέπει να στοχεύσει κάθε ελεγκτή τομέα για να διασφαλίσει μια ολοκληρωμένη παραβίαση. Ωστόσο, η επίδραση της επίθεσης είναι προσωρινή, καθώς **η επανεκκίνηση του ελεγκτή τομέα εξαλείφει το κακόβουλο λογισμικό**, απαιτώντας μια επαναφορά για διαρκή πρόσβαση.

**Η εκτέλεση της επίθεσης** απαιτεί μια μόνο εντολή: `misc::skeleton`.

## Mitigations

Οι στρατηγικές μετριασμού κατά τέτοιων επιθέσεων περιλαμβάνουν την παρακολούθηση συγκεκριμένων αναγνωριστικών γεγονότων που υποδεικνύουν την εγκατάσταση υπηρεσιών ή τη χρήση ευαίσθητων δικαιωμάτων. Συγκεκριμένα, η αναζήτηση για το Αναγνωριστικό Γεγονότος Συστήματος 7045 ή το Αναγνωριστικό Γεγονότος Ασφαλείας 4673 μπορεί να αποκαλύψει ύποπτες δραστηριότητες. Επιπλέον, η εκτέλεση του `lsass.exe` ως προστατευμένη διαδικασία μπορεί να εμποδίσει σημαντικά τις προσπάθειες των επιτιθέμενων, καθώς αυτό απαιτεί από αυτούς να χρησιμοποιήσουν έναν οδηγό λειτουργικού πυρήνα, αυξάνοντας την πολυπλοκότητα της επίθεσης.

Ακολουθούν οι εντολές PowerShell για την ενίσχυση των μέτρων ασφαλείας:

- Για να ανιχνεύσετε την εγκατάσταση ύποπτων υπηρεσιών, χρησιμοποιήστε: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`

- Συγκεκριμένα, για να ανιχνεύσετε τον οδηγό του Mimikatz, μπορεί να χρησιμοποιηθεί η εξής εντολή: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`

- Για να ενισχύσετε το `lsass.exe`, συνιστάται να το ενεργοποιήσετε ως προστατευμένη διαδικασία: `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`

Η επαλήθευση μετά από μια επανεκκίνηση του συστήματος είναι κρίσιμη για να διασφαλιστεί ότι τα προστατευτικά μέτρα έχουν εφαρμοστεί επιτυχώς. Αυτό είναι εφικτό μέσω: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*`

## References
* [https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)

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
