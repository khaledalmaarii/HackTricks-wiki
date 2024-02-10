# Forense di Docker

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>

## Modifica del contenitore

Ci sono sospetti che un qualche contenitore Docker sia stato compromesso:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
È possibile **trovare facilmente le modifiche apportate a questo contenitore rispetto all'immagine** con:
```bash
docker diff wordpress
C /var
C /var/lib
C /var/lib/mysql
A /var/lib/mysql/ib_logfile0
A /var/lib/mysql/ib_logfile1
A /var/lib/mysql/ibdata1
A /var/lib/mysql/mysql
A /var/lib/mysql/mysql/time_zone_leap_second.MYI
A /var/lib/mysql/mysql/general_log.CSV
...
```
Nel comando precedente, **C** significa **Modificato** e **A,** **Aggiunto**.\
Se scopri che un file interessante come `/etc/shadow` è stato modificato, puoi scaricarlo dal container per verificare la presenza di attività malevole con:
```bash
docker cp wordpress:/etc/shadow.
```
Puoi anche **confrontarlo con l'originale** eseguendo un nuovo container ed estraendo il file da esso:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Se trovi che **è stato aggiunto un file sospetto**, puoi accedere al container e controllarlo:
```bash
docker exec -it wordpress bash
```
## Modifiche alle immagini

Quando ti viene fornita un'immagine Docker esportata (probabilmente in formato `.tar`), puoi utilizzare [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) per **estrarre un riepilogo delle modifiche**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Quindi, puoi **decomprimere** l'immagine e **accedere ai blob** per cercare file sospetti che potresti aver trovato nella cronologia delle modifiche:
```bash
tar -xf image.tar
```
### Analisi di base

Puoi ottenere **informazioni di base** dall'immagine in esecuzione:
```bash
docker inspect <image>
```
Puoi ottenere un **riassunto della cronologia delle modifiche** con:
```bash
docker history --no-trunc <image>
```
È possibile generare un **dockerfile da un'immagine** anche con:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Per trovare file aggiunti/modificati nelle immagini Docker, puoi utilizzare anche l'utilità [**dive**](https://github.com/wagoodman/dive) (scaricala da [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)):
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Questo ti permette di **navigare attraverso i diversi blob delle immagini di Docker** e controllare quali file sono stati modificati/aggiunti. Il colore **rosso** indica un file aggiunto e il colore **giallo** indica un file modificato. Usa il tasto **tab** per spostarti alla vista successiva e **spazio** per comprimere/aprire le cartelle.

Con die non sarai in grado di accedere al contenuto delle diverse fasi dell'immagine. Per farlo, dovrai **decomprimere ogni livello e accedervi**.\
Puoi decomprimere tutti i livelli di un'immagine dalla directory in cui l'immagine è stata decompressa eseguendo:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Credenziali dalla memoria

Nota che quando esegui un container Docker all'interno di un host **puoi vedere i processi in esecuzione nel container dall'host** semplicemente eseguendo `ps -ef`

Pertanto (come root) puoi **dumpare la memoria dei processi** dall'host e cercare **credenziali** proprio [**come nell'esempio seguente**](../../linux-hardening/privilege-escalation/#process-memory).

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
