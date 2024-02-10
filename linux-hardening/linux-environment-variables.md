# Variabili d'ambiente Linux

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di github.

</details>

## Variabili globali

Le variabili globali **verranno** ereditate dai **processi figlio**.

Puoi creare una variabile globale per la tua sessione corrente eseguendo:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Questa variabile sarà accessibile dalle tue sessioni correnti e dai relativi processi figli.

Puoi **rimuovere** una variabile facendo:
```bash
unset MYGLOBAL
```
## Variabili locali

Le **variabili locali** possono essere **accedute** solo dallo **shell/script corrente**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Elenco delle variabili correnti

To list the current environment variables in Linux, you can use the following command:

```bash
$ env
```

This command will display a list of all the environment variables currently set on your system.
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Variabili comuni

Da: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** - il display utilizzato da **X**. Questa variabile di solito è impostata su **:0.0**, il che significa il primo display sul computer corrente.
* **EDITOR** - l'editor di testo preferito dall'utente.
* **HISTFILESIZE** - il numero massimo di righe contenute nel file di cronologia.
* **HISTSIZE** - Numero di righe aggiunte al file di cronologia quando l'utente termina la sessione.
* **HOME** - la tua directory home.
* **HOSTNAME** - il nome host del computer.
* **LANG** - la tua lingua corrente.
* **MAIL** - la posizione della cassetta postale dell'utente. Di solito **/var/spool/mail/USER**.
* **MANPATH** - l'elenco delle directory in cui cercare le pagine del manuale.
* **OSTYPE** - il tipo di sistema operativo.
* **PS1** - il prompt predefinito in bash.
* **PATH** - memorizza il percorso di tutte le directory che contengono file binari che si desidera eseguire semplicemente specificando il nome del file e non il percorso relativo o assoluto.
* **PWD** - la directory di lavoro corrente.
* **SHELL** - il percorso della shell di comando corrente (ad esempio, **/bin/bash**).
* **TERM** - il tipo di terminale corrente (ad esempio, **xterm**).
* **TZ** - il tuo fuso orario.
* **USER** - il tuo nome utente corrente.

## Variabili interessanti per l'hacking

### **HISTFILESIZE**

Cambia il **valore di questa variabile a 0**, in modo che quando **termini la sessione**, il **file di cronologia** (\~/.bash\_history) **verrà eliminato**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Cambia il **valore di questa variabile a 0**, in modo che quando **termini la tua sessione** qualsiasi comando non venga aggiunto al **file di cronologia** (\~/.bash\_history).
```bash
export HISTSIZE=0
```
### http\_proxy & https\_proxy

I processi utilizzeranno il **proxy** dichiarato qui per connettersi a Internet tramite **http o https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL\_CERT\_FILE & SSL\_CERT\_DIR

I processi si affideranno ai certificati indicati in **queste variabili d'ambiente**.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

Cambia l'aspetto del tuo prompt.

[**Questo è un esempio**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../.gitbook/assets/image (87).png>)

Utente normale:

![](<../.gitbook/assets/image (88).png>)

Un, due e tre lavori in background:

![](<../.gitbook/assets/image (89).png>)

Un lavoro in background, uno fermo e l'ultimo comando non è stato eseguito correttamente:

![](<../.gitbook/assets/image (90).png>)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
