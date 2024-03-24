# Variabili d'Ambiente Linux

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Variabili Globali

Le variabili globali **saranno** ereditate dai **processi figlio**.

Puoi creare una variabile globale per la tua sessione corrente facendo:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Questa variabile sarà accessibile dalle tue sessioni attuali e dai suoi processi figlio.

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
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Variabili comuni

Da: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** – il display utilizzato da **X**. Di solito questa variabile è impostata su **:0.0**, il che significa il primo display sul computer corrente.
* **EDITOR** – l'editor di testo preferito dall'utente.
* **HISTFILESIZE** – il numero massimo di righe contenute nel file cronologia.
* **HISTSIZE** – Numero di righe aggiunte al file cronologia quando l'utente termina la sessione.
* **HOME** – la tua directory home.
* **HOSTNAME** – il nome host del computer.
* **LANG** – la tua lingua corrente.
* **MAIL** – la posizione della cassetta postale dell'utente. Di solito **/var/spool/mail/USER**.
* **MANPATH** – l'elenco delle directory in cui cercare le pagine del manuale.
* **OSTYPE** – il tipo di sistema operativo.
* **PS1** – il prompt predefinito in bash.
* **PATH** – memorizza il percorso di tutte le directory che contengono file binari che si desidera eseguire semplicemente specificando il nome del file e non il percorso relativo o assoluto.
* **PWD** – la directory di lavoro corrente.
* **SHELL** – il percorso della shell di comando corrente (ad esempio, **/bin/bash**).
* **TERM** – il tipo di terminale corrente (ad esempio, **xterm**).
* **TZ** – il tuo fuso orario.
* **USER** – il tuo nome utente corrente.

## Variabili interessanti per l'hacking

### **HISTFILESIZE**

Cambia il **valore di questa variabile a 0**, in modo che quando **termini la tua sessione** il **file cronologia** (\~/.bash\_history) **sarà eliminato**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Cambia il **valore di questa variabile a 0**, in modo che quando **termini la tua sessione** nessun comando verrà aggiunto al **file di cronologia** (\~/.bash\_history).
```bash
export HISTSIZE=0
```
### http\_proxy & https\_proxy

I processi utilizzeranno il **proxy** dichiarato qui per connettersi a Internet tramite **http o https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL_CERT_FILE & SSL_CERT_DIR

I processi si affideranno ai certificati indicati in **queste variabili d'ambiente**.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

Modifica l'aspetto del tuo prompt.

[**Questo è un esempio**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../.gitbook/assets/image (87).png>)

Utente regolare:

![](<../.gitbook/assets/image (88).png>)

Uno, due e tre lavori in background:

![](<../.gitbook/assets/image (89).png>)

Un lavoro in background, uno fermo e l'ultimo comando non è stato eseguito correttamente:

![](<../.gitbook/assets/image (90).png>)

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Impara l'hacking su AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di Github.

</details>
