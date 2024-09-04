# Variabili di Ambiente Linux

{% hint style="success" %}
Impara e pratica Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

</details>
{% endhint %}

## Variabili globali

Le variabili globali **saranno** ereditate dai **processi figli**.

Puoi creare una variabile globale per la tua sessione attuale facendo:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Questa variabile sarà accessibile dalle tue sessioni attuali e dai suoi processi figli.

Puoi **rimuovere** una variabile facendo:
```bash
unset MYGLOBAL
```
## Variabili locali

Le **variabili locali** possono essere **accessibili** solo dalla **shell/script corrente**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Elenca le variabili correnti
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Variabili comuni

Da: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** – il display utilizzato da **X**. Questa variabile è solitamente impostata su **:0.0**, il che significa il primo display sul computer attuale.
* **EDITOR** – l'editor di testo preferito dall'utente.
* **HISTFILESIZE** – il numero massimo di righe contenute nel file di cronologia.
* **HISTSIZE** – Numero di righe aggiunte al file di cronologia quando l'utente termina la sua sessione.
* **HOME** – la tua directory home.
* **HOSTNAME** – il nome host del computer.
* **LANG** – la tua lingua attuale.
* **MAIL** – la posizione della cassetta postale dell'utente. Di solito **/var/spool/mail/USER**.
* **MANPATH** – l'elenco delle directory da cercare per le pagine di manuale.
* **OSTYPE** – il tipo di sistema operativo.
* **PS1** – il prompt predefinito in bash.
* **PATH** – memorizza il percorso di tutte le directory che contengono file binari che desideri eseguire semplicemente specificando il nome del file e non il percorso relativo o assoluto.
* **PWD** – la directory di lavoro attuale.
* **SHELL** – il percorso della shell di comando attuale (ad esempio, **/bin/bash**).
* **TERM** – il tipo di terminale attuale (ad esempio, **xterm**).
* **TZ** – il tuo fuso orario.
* **USER** – il tuo nome utente attuale.

## Variabili interessanti per il hacking

### **HISTFILESIZE**

Cambia il **valore di questa variabile a 0**, in modo che quando **termini la tua sessione** il **file di cronologia** (\~/.bash\_history) **venga eliminato**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Cambia il **valore di questa variabile a 0**, così quando **termini la tua sessione** nessun comando verrà aggiunto al **file di cronologia** (\~/.bash\_history).
```bash
export HISTSIZE=0
```
### http\_proxy & https\_proxy

I processi utilizzeranno il **proxy** dichiarato qui per connettersi a internet tramite **http o https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL\_CERT\_FILE & SSL\_CERT\_DIR

I processi si fideranno dei certificati indicati in **queste variabili d'ambiente**.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

Cambia l'aspetto del tuo prompt.

[**Questo è un esempio**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../.gitbook/assets/image (897).png>)

Utente normale:

![](<../.gitbook/assets/image (740).png>)

Un, due e tre lavori in background:

![](<../.gitbook/assets/image (145).png>)

Un lavoro in background, uno fermato e l'ultimo comando non ha terminato correttamente:

![](<../.gitbook/assets/image (715).png>)


{% hint style="success" %}
Impara e pratica AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

</details>
{% endhint %}
