# Επίθεση Skeleton Key

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Επίθεση Skeleton Key

Η επίθεση **Skeleton Key** είναι μια εξελιγμένη τεχνική που επιτρέπει στους επιτιθέμενους να **παρακάμπτουν την πιστοποίηση του Active Directory** με το **έγχυση ενός κύριου κωδικού πρόσβασης** στον ελεγκτή του τομέα. Αυτό επιτρέπει στον επιτιθέμενο να **πιστοποιηθεί ως οποιοσδήποτε χρήστης** χωρίς τον κωδικό τους, επιτρέποντάς του ανεξέλεγκτη πρόσβαση στον τομέα.

Μπορεί να πραγματοποιηθεί χρησιμοποιώντας το [Mimikatz](https://github.com/gentilkiwi/mimikatz). Για να πραγματοποιηθεί αυτή η επίθεση, είναι απαραίτητα τα **δικαιώματα Domain Admin**, και ο επιτιθέμενος πρέπει να στοχεύσει κάθε ελεγκτή του τομέα για να εξασφαλίσει μια ολοκληρωμένη παραβίαση. Ωστόσο, η επίδραση της επίθεσης είναι προσωρινή, καθώς η επανεκκίνηση του ελεγκτή του τομέα εξαλείφει το κακόβουλο λογισμικό, απαιτώντας μια επαναλειτουργία για μόνιμη πρόσβαση.

Η **εκτέλεση της επίθεσης** απαιτεί μια μόνο εντολή: `misc::skeleton`.

## Αντιμετώπιση

Οι στρατηγικές αντιμετώπισης αυτών των επιθέσεων περιλαμβάνουν την παρακολούθηση συγκεκριμένων αναγνωριστικών συμβάντων που υποδεικνύουν την εγκατάσταση υπηρεσιών ή τη χρήση ευαίσθητων προνομίων. Ειδικότερα, η ανίχνευση του συμβάντος συστήματος ID 7045 ή του συμβάντος ασφάλειας ID 4673 μπορεί να αποκαλύψει ύποπτες δραστηριότητες. Επιπλέον, η εκτέλεση του `lsass.exe` ως προστατευμένη διεργασία μπορεί να δυσχεράνει σημαντικά τις προσπάθειες των επιτιθέμενων, καθώς αυτό απαιτεί από αυτούς να χρησιμοποιήσουν έναν οδηγό λειτουργικού συστήματος πυρήνα, αυξάνοντας την πολυπλοκότητα της επίθεσης.

Οι παρακάτω είναι οι εντολές PowerShell για την ενίσχυση των μέτρων ασφαλείας:

- Για την ανίχνευση της εγκατάστασης ύποπτων υπηρεσιών, χρησιμοποιήστε: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`

- Ειδικότερα, για την ανίχνευση του οδηγού του Mimikatz, μπορεί να χρησιμοποιηθεί η παρακάτω εντολή: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`

- Για την ενίσχυση του `lsass.exe`, συνιστάται η ενεργοποίηση του ως προστατευμένης διεργασίας: `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`

Η επαλήθευση μετά από επανεκκίνηση του συστήματος είναι κρίσιμη για να εξασφαλιστεί ότι τα προστατευτικά μέτρα έχουν εφαρμοστεί με επιτυχία. Αυτό επιτυγχάνεται μέσω: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*`

## Αναφορές
* [https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΣΧ
