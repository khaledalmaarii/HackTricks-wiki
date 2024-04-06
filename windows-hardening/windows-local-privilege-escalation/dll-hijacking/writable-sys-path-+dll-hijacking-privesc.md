# Writable Sys Path +Dll Hijacking Privesc

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Εισαγωγή

Εάν ανακαλύψετε ότι μπορείτε να **γράψετε σε έναν φάκελο διαδρομής συστήματος** (σημειώστε ότι αυτό δεν θα λειτουργήσει εάν μπορείτε να γράψετε σε έναν φάκελο διαδρομής χρήστη), είναι πιθανό να μπορείτε να **αναβαθμίσετε τα δικαιώματά σας** στο σύστημα.

Για να το κάνετε αυτό, μπορείτε να καταχραστείτε μια **Διαδρομή Dll Hijacking**, όπου θα **καταχωρήσετε μια βιβλιοθήκη που φορτώνεται** από ένα υπηρεσία ή διεργασία με **περισσότερα δικαιώματα** από εσάς, και επειδή αυτή η υπηρεσία φορτώνει μια Dll που πιθανόν δεν υπάρχει καν στο σύστημα, θα προσπαθήσει να τη φορτώσει από τη Διαδρομή Συστήματος όπου μπορείτε να γράψετε.

Για περισσότερες πληροφορίες σχετικά με το **τι είναι η Διαδρομή Dll Hijacking** ελέγξτε:

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Ανέβασμα δικαιωμάτων με Dll Hijacking

### Εύρεση ελλιπούς Dll

Το πρώτο πράγμα που χρειάζεστε είναι να **αναγνωρίσετε μια διεργασία** που εκτελείται με **περισσότερα δικαιώματα** από εσάς και προσπαθεί να **φορτώσει μια Dll από τη Διαδρομή Συστήματος** στην οποία μπορείτε να γράψετε.

Το πρόβλημα σε αυτές τις περιπτώσεις είναι ότι πιθανόν αυτές οι διεργασίες ήδη εκτελούνται. Για να βρείτε ποιες Dll λείπουν από τις υπηρεσίες που χρειάζεστε, πρέπει να εκκινήσετε το procmon το συντομότερο δυνατόν (πριν φορτωθούν οι διεργασίες). Έτσι, για να βρείτε τις λείπουσες .dlls, κάντε τα εξής:

* **Δημιουργήστε** τον φάκελο `C:\privesc_hijacking` και προσθέστε τη διαδρομή `C:\privesc_hijacking` στη **μεταβλητή περιβάλλοντος System Path**. Μπορείτε να το κάνετε **χειροκίνητα** ή με **PS**:

```powershell
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```

* Εκκινήστε το **`procmon`** και πηγαίνετε στις **`Επιλογές`** --> **`Ενεργοποίηση καταγραφής εκκίνησης`** και πατήστε **`ΟΚ`** στην ειδοποίηση.
* Στη συνέχεια, **επανεκκινήστε**. Όταν ο υπολογιστής επανεκκινηθεί, το **`procmon`** θα αρχίσει να καταγράφει γεγονότα αμέσως.
* Μόλις ξεκινήσει τα **Windows**, εκτελέστε ξανά το **`procmon`**, θα σας πει ότι έχει τρέξει και θα σας **ζητήσει αν θέλετε να αποθηκεύσετε** τα γεγονότα σε ένα αρχείο. Πείτε **ναι** και **αποθηκεύστε τα γεγονότα σε ένα αρχείο**.
* **Αφού** δημιουργηθεί το **αρχείο**, **κλείστε** το ανοιχτό παράθυρο του **`procmon`** και **ανοίξτε το αρχείο με τα γεγονότα**.
* Προσθέστε αυτά τα **φίλτρα** και θα βρείτε όλες τις Dlls που κάποιη διεργασία προσπάθησε να φορτώσει από τον εγγράψιμο φάκελο της διαδρομής του συστήματος:

<figure><img src="../../../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

### Λείπουν Dlls

Εκτελώντας αυτό σε ένα εικονικό (vmware) μηχάνημα με **Windows 11**, πήρα αυτά τα αποτελέσματα:

<figure><img src="../../../.gitbook/assets/image (253).png" alt=""><figcaption></figcaption></figure>

Σε αυτήν την περίπτωση, τα .exe είναι άχρηστα, οι λείπουσες DLLs ήταν από:

| Υπηρεσία                        | Dll                | Εντολή CMD                                                           |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Αφού βρήκα αυτό, βρήκα αυτήν την ενδιαφέρουσα ανάρτηση σε ιστολόγιο που εξηγεί επίσης πώς να [**καταχραστείτε το WptsExtensions.dll για ανέλιξη προνομίων**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll). Αυτό είναι αυτό που **θα κάνουμε τώρα**.

### Εκμετάλλευση

Έτσι, για να **αναβαθμίσετε τα προνόμια**, θα καταχραστούμε τη βιβλιοθήκη **WptsExtensions.dll**. Έχοντας τη **διαδρομή** και το **όνομα**, απλά χρειάζεται να **δημιουργήσουμε την κακόβουλη dll**.

Μπορείτε [**να δοκιμάσετε οποιοδήποτε από αυτά τα παραδείγματα**](./#creating-and-compiling-dlls). Μπορείτε να εκτελέσετε φορτία όπως: να λάβετε ένα αντίστροφο κέλυφος, να προσθέσετε ένα χρήστη, να εκτελέσετε ένα beacon...

{% hint style="warning" %}
Σημειώστε ότι **όχι όλες οι υπηρεσίες τρέχουν** με **`NT AUTHORITY\SYSTEM`**, κάποιες τρέχουν επίσης με **`NT AUTHORITY\LOCAL SERVICE`** που έχει **λιγότερα προνόμια** και δεν θα μπορέσετε να δημιουργήσετε ένα νέο χρήστη καταχρώντας τα δικαιώματά του.\
Ωστόσο, αυτός ο χρήστης έχει το προνόμιο **`seImpersonate`**, οπότε μπορείτε να χρησιμοποιήσετε το [**potato suite για ανέλιξη προνομίων**](../roguepotato-and-printspoofer.md). Έτσι, σε αυτήν την περίπτωση, ένα αντίστροφο κέλυφος είναι μια καλύτερη επιλογή από το να προσπαθήσετε να δημιουργήσετε ένα χρήστη.
{% endhint %}

Τη στιγμή που γράφτηκε αυτό, η υπηρεσία **Task Scheduler** τρέχει με **Nt AUTHORITY\SYSTEM**.

Έχοντας **δημιουργήσει την κακόβουλη Dll** (_στην περίπτωσή μου χρησιμοποίησα ένα x64 αντίστροφο κέλυφος και πήρα ένα κέλυφος πίσω, αλλά ο Defender τον σκότωσε επειδή ήταν από το msfvenom_), αποθηκεύστε το στον εγγράψιμο φάκελο της διαδρομής του συστήματος με το όνομα **WptsExtensions.dll** και **επανεκκινήστε** τον υπολογιστή (ή επανεκκινήστε την υπηρεσία ή κάντε ό,τι χρειάζεται για να επανεκκινήσετε την επηρεασμένη υπηρεσία/πρόγραμμα).

Όταν η υπηρεσία επανεκκινηθεί, η **dll θα πρέπει να φορτωθεί και να εκτελεστεί** (μπορείτε να **επαναχρησιμοποιήσετε** το **κόλπο του procmon** για να ελέγξετε αν η βιβλιοθήκη φορτώθηκε όπως αναμενόταν).

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα \[\*\*ΣΧΕΔ

</details>
