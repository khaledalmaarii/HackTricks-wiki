# Sicurezza di Docker

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per costruire facilmente e **automatizzare flussi di lavoro** supportati dagli strumenti della comunità più avanzati al mondo.\
Ottieni l'accesso oggi:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## **Sicurezza di Base del Motore Docker**

Il **motore Docker** utilizza i **Namespaces** e **Cgroups** del kernel Linux per isolare i container, offrendo uno strato di sicurezza di base. Una protezione aggiuntiva è fornita tramite il **dropping delle Capabilities**, **Seccomp**, e **SELinux/AppArmor**, migliorando l'isolamento del container. Un **plugin di autenticazione** può ulteriormente limitare le azioni dell'utente.

![Sicurezza di Docker](https://sreeninet.files.wordpress.com/2016/03/dockersec1.png)

### Accesso Sicuro al Motore Docker

Il motore Docker può essere accesso localmente tramite un socket Unix o remotamente utilizzando HTTP. Per l'accesso remoto, è essenziale utilizzare HTTPS e **TLS** per garantire riservatezza, integrità e autenticazione.

Il motore Docker, per impostazione predefinita, è in ascolto sul socket Unix a `unix:///var/run/docker.sock`. Nei sistemi Ubuntu, le opzioni di avvio di Docker sono definite in `/etc/default/docker`. Per abilitare l'accesso remoto all'API e al client Docker, esponi il demone Docker su un socket HTTP aggiungendo le seguenti impostazioni:
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Tuttavia, esporre il demone Docker su HTTP non è consigliato a causa di preoccupazioni per la sicurezza. È consigliabile proteggere le connessioni utilizzando HTTPS. Ci sono due approcci principali per garantire la connessione:

1. Il client verifica l'identità del server.
2. Sia il client che il server si autenticano reciprocamente.

I certificati vengono utilizzati per confermare l'identità di un server. Per esempi dettagliati di entrambi i metodi, fare riferimento a [**questa guida**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/).

### Sicurezza delle immagini dei container

Le immagini dei container possono essere memorizzate in repository privati o pubblici. Docker offre diverse opzioni di archiviazione per le immagini dei container:

* [**Docker Hub**](https://hub.docker.com): Un servizio di registro pubblico da Docker.
* [**Docker Registry**](https://github.com/docker/distribution): Un progetto open-source che consente agli utenti di ospitare il proprio registro.
* [**Docker Trusted Registry**](https://www.docker.com/docker-trusted-registry): Offerta commerciale di Docker, con autenticazione degli utenti basata sui ruoli e integrazione con servizi di directory LDAP.

### Scansione delle immagini

I container possono presentare **vulnerabilità di sicurezza** a causa dell'immagine di base o del software installato sopra l'immagine di base. Docker sta lavorando a un progetto chiamato **Nautilus** che esegue la scansione di sicurezza dei container e elenca le vulnerabilità. Nautilus funziona confrontando ciascuno strato dell'immagine del container con il repository delle vulnerabilità per identificare falle di sicurezza.

Per ulteriori [**informazioni leggi questo**](https://docs.docker.com/engine/scan/).

* **`docker scan`**

Il comando **`docker scan`** consente di eseguire la scansione delle immagini Docker esistenti utilizzando il nome o l'ID dell'immagine. Ad esempio, eseguire il seguente comando per eseguire la scansione dell'immagine hello-world:
```bash
docker scan hello-world

Testing hello-world...

Organization:      docker-desktop-test
Package manager:   linux
Project name:      docker-image|hello-world
Docker image:      hello-world
Licenses:          enabled

✓ Tested 0 dependencies for known issues, no vulnerable paths found.

Note that we do not currently have vulnerability data for your image.
```
* [**`trivy`**](https://github.com/aquasecurity/trivy)
```bash
trivy -q -f json <ontainer_name>:<tag>
```
* [**`snyk`**](https://docs.snyk.io/snyk-cli/getting-started-with-the-cli)
```bash
snyk container test <image> --json-file-output=<output file> --severity-threshold=high
```
* [**`clair-scanner`**](https://github.com/arminc/clair-scanner)
```bash
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
### Firma delle immagini Docker

La firma delle immagini Docker garantisce la sicurezza e l'integrità delle immagini utilizzate nei container. Ecco una spiegazione sintetica:

- **Fiducia dei contenuti Docker** utilizza il progetto Notary, basato su The Update Framework (TUF), per gestire la firma delle immagini. Per ulteriori informazioni, consulta [Notary](https://github.com/docker/notary) e [TUF](https://theupdateframework.github.io).
- Per attivare la fiducia dei contenuti Docker, imposta `export DOCKER_CONTENT_TRUST=1`. Questa funzionalità è disattivata per impostazione predefinita nelle versioni di Docker 1.10 e successive.
- Con questa funzionalità abilitata, è possibile scaricare solo immagini firmate. Il caricamento iniziale dell'immagine richiede di impostare passphrase per le chiavi di root e di tag, con Docker che supporta anche Yubikey per una sicurezza avanzata. Ulteriori dettagli possono essere trovati [qui](https://blog.docker.com/2015/11/docker-content-trust-yubikey/).
- Tentare di scaricare un'immagine non firmata con la fiducia dei contenuti abilitata porta a un errore "Nessun dato di fiducia per l'ultima versione".
- Per i caricamenti delle immagini successivi al primo, Docker richiede la passphrase della chiave del repository per firmare l'immagine.

Per eseguire il backup delle tue chiavi private, utilizza il comando:
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Quando si passa da un host Docker all'altro, è necessario spostare le chiavi di root e del repository per mantenere le operazioni.

***

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare e **automatizzare facilmente flussi di lavoro** supportati dagli strumenti della comunità più avanzati al mondo.\
Ottieni l'accesso oggi:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Funzionalità di Sicurezza dei Container

<details>

<summary>Riepilogo delle Funzionalità di Sicurezza dei Container</summary>

#### Principali Funzionalità di Isolamento dei Processi

Negli ambienti containerizzati, isolare i progetti e i loro processi è fondamentale per la sicurezza e la gestione delle risorse. Ecco una spiegazione semplificata dei concetti chiave:

**Namespaces**

* **Scopo**: Garantire l'isolamento delle risorse come processi, rete e filesystem. In particolare in Docker, i namespaces mantengono separati i processi di un container dall'host e dagli altri container.
* **Utilizzo di `unshare`**: Il comando `unshare` (o la syscall sottostante) viene utilizzato per creare nuovi namespaces, fornendo un ulteriore livello di isolamento. Tuttavia, mentre Kubernetes non blocca questo concetto in modo innato, Docker lo fa.
* **Limitazione**: Creare nuovi namespaces non consente a un processo di tornare ai namespaces predefiniti dell'host. Per penetrare nei namespaces dell'host, di solito è necessario accedere alla directory `/proc` dell'host, utilizzando `nsenter` per l'ingresso.

**Gruppi di Controllo (CGroups)**

* **Funzione**: Principalmente utilizzati per allocare risorse tra i processi.
* **Aspetto della Sicurezza**: I CGroups di per sé non offrono sicurezza di isolamento, tranne per la funzionalità `release_agent`, che, se configurata in modo errato, potrebbe essere potenzialmente sfruttata per l'accesso non autorizzato.

**Rinuncia alle Capacità (Capability Drop)**

* **Importanza**: È una funzionalità di sicurezza cruciale per l'isolamento dei processi.
* **Funzionalità**: Limita le azioni che un processo root può eseguire rinunciando a determinate capacità. Anche se un processo viene eseguito con privilegi di root, la mancanza delle capacità necessarie impedisce l'esecuzione di azioni privilegiate, poiché le syscall falliranno a causa di autorizzazioni insufficienti.

Queste sono le **capacità rimanenti** dopo che il processo ha rinunciato alle altre:

{% code overflow="wrap" %}
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
{% endcode %}

**Seccomp**

È abilitato per impostazione predefinita in Docker. Aiuta a **limitare ulteriormente le syscalls** che il processo può chiamare.\
Il **profilo Docker Seccomp predefinito** può essere trovato in [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)

**AppArmor**

Docker ha un modello che puoi attivare: [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

Questo permetterà di ridurre le capacità, le syscalls, l'accesso ai file e alle cartelle...

</details>

### Namespaces

**Namespaces** sono una caratteristica del kernel Linux che **partiziona le risorse del kernel** in modo che un insieme di **processi** **veda** un insieme di **risorse** mentre **un altro** insieme di **processi** vede un **diverso** insieme di risorse. La funzionalità funziona avendo lo stesso namespace per un insieme di risorse e processi, ma quei namespace si riferiscono a risorse distinte. Le risorse possono esistere in più spazi.

Docker fa uso dei seguenti Namespaces del kernel Linux per ottenere l'isolamento dei Container:

* namespace pid
* namespace mount
* namespace network
* namespace ipc
* namespace UTS

Per **ulteriori informazioni sui namespaces** controlla la seguente pagina:

{% content-ref url="namespaces/" %}
[namespaces](namespaces/)
{% endcontent-ref %}

### cgroups

La funzionalità del kernel Linux **cgroups** fornisce la capacità di **limitare risorse come cpu, memoria, io, larghezza di banda di rete tra** un insieme di processi. Docker consente di creare Container utilizzando la funzionalità cgroup che consente il controllo delle risorse per il Container specifico.\
Di seguito è riportato un Container creato con la memoria dello spazio utente limitata a 500m, la memoria del kernel limitata a 50m, la quota cpu a 512, il peso blkioweight a 400. La quota cpu è un rapporto che controlla l'utilizzo della CPU del Container. Ha un valore predefinito di 1024 e un intervallo tra 0 e 1024. Se tre Container hanno la stessa quota cpu di 1024, ogni Container può utilizzare fino al 33% della CPU in caso di contesa delle risorse della CPU. blkio-weight è un rapporto che controlla l'IO del Container. Ha un valore predefinito di 500 e un intervallo tra 10 e 1000.
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
Per ottenere il cgroup di un container puoi fare:
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
Per ulteriori informazioni controlla:

{% content-ref url="cgroups.md" %}
[cgroups.md](cgroups.md)
{% endcontent-ref %}

### Capacità

Le capacità consentono un **controllo più preciso delle capacità che possono essere consentite** per l'utente root. Docker utilizza la funzionalità di capacità del kernel Linux per **limitare le operazioni che possono essere eseguite all'interno di un contenitore** indipendentemente dal tipo di utente.

Quando viene eseguito un contenitore Docker, il **processo elimina le capacità sensibili che il processo potrebbe utilizzare per sfuggire all'isolamento**. Questo tenta di garantire che il processo non possa eseguire azioni sensibili e sfuggire:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

### Seccomp in Docker

Si tratta di una funzionalità di sicurezza che consente a Docker di **limitare le chiamate di sistema** che possono essere utilizzate all'interno del contenitore:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

### AppArmor in Docker

**AppArmor** è un potenziamento del kernel per confinare i **contenitori** a un **insieme limitato di **risorse** con **profili per programma**:

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

### SELinux in Docker

* **Sistema di etichettatura**: SELinux assegna un'etichetta univoca a ogni processo e oggetto del filesystem.
* **Esecuzione delle politiche**: Applica le politiche di sicurezza che definiscono quali azioni può eseguire un'etichetta di processo su altre etichette all'interno del sistema.
* **Etichette dei processi del contenitore**: Quando i motori dei contenitori avviano i processi del contenitore, vengono tipicamente assegnate loro un'etichetta SELinux confinata, comunemente `container_t`.
* **Etichettatura dei file all'interno dei contenitori**: I file all'interno del contenitore sono di solito etichettati come `container_file_t`.
* **Regole di politica**: La politica SELinux garantisce principalmente che i processi con l'etichetta `container_t` possano interagire solo (leggere, scrivere, eseguire) con i file etichettati come `container_file_t`.

Questo meccanismo garantisce che anche se un processo all'interno di un contenitore viene compromesso, è confinato nell'interagire solo con oggetti che hanno le etichette corrispondenti, limitando significativamente i danni potenziali da tali compromissioni.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

### AuthZ & AuthN

In Docker, un plugin di autorizzazione svolge un ruolo cruciale nella sicurezza decidendo se consentire o bloccare le richieste al demone Docker. Questa decisione viene presa esaminando due contesti chiave:

* **Contesto di autenticazione**: Questo include informazioni dettagliate sull'utente, come chi sono e come si sono autenticati.
* **Contesto del comando**: Questo comprende tutti i dati pertinenti relativi alla richiesta in corso.

Questi contesti contribuiscono a garantire che solo le richieste legittime da utenti autenticati vengano elaborate, migliorando la sicurezza delle operazioni di Docker.

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## DoS da un contenitore

Se non si limitano correttamente le risorse che un contenitore può utilizzare, un contenitore compromesso potrebbe causare un DoS all'host in cui è in esecuzione.

* DoS della CPU
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
* **Bandwidth DoS**

---

### Bandwidth DoS

Un attacco Bandwidth Denial of Service (DoS) mira a consumare tutta la larghezza di banda disponibile di un sistema, rendendolo inaccessibile agli utenti legittimi. Questo tipo di attacco può essere mitigato implementando controlli di sicurezza appropriati come firewall, sistemi di rilevamento delle intrusioni e limitazione della larghezza di banda.
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## Interessanti Flag di Docker

### Flag --privileged

Nella seguente pagina puoi apprendere **cosa implica il flag `--privileged`**:

{% content-ref url="docker-privileged.md" %}
[docker-privileged.md](docker-privileged.md)
{% endcontent-ref %}

### --security-opt

#### no-new-privileges

Se stai eseguendo un container in cui un attaccante riesce ad ottenere accesso come utente a bassi privilegi. Se hai un **binario suid mal configurato**, l'attaccante potrebbe abusarne e **escalare i privilegi all'interno** del container. Ciò potrebbe consentirgli di uscirne.

Eseguire il container con l'opzione **`no-new-privileges`** abilitata **impedirà questo tipo di escalation dei privilegi**.
```
docker run -it --security-opt=no-new-privileges:true nonewpriv
```
#### Altro
```bash
#You can manually add/drop capabilities with
--cap-add
--cap-drop

# You can manually disable seccomp in docker with
--security-opt seccomp=unconfined

# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined

# You can manually disable selinux in docker with
--security-opt label:disable
```
Per ulteriori opzioni **`--security-opt`** controlla: [https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

## Altre Considerazioni sulla Sicurezza

### Gestione dei Segreti: Migliori Pratiche

È cruciale evitare di incorporare segreti direttamente nelle immagini Docker o di utilizzare variabili d'ambiente, poiché questi metodi espongono le tue informazioni sensibili a chiunque abbia accesso al container tramite comandi come `docker inspect` o `exec`.

I **volumi Docker** sono un'alternativa più sicura, consigliata per accedere a informazioni sensibili. Possono essere utilizzati come filesystem temporaneo in memoria, mitigando i rischi associati a `docker inspect` e al logging. Tuttavia, gli utenti root e coloro con accesso `exec` al container potrebbero comunque accedere ai segreti.

I **segreti Docker** offrono un metodo ancora più sicuro per gestire informazioni sensibili. Per le istanze che richiedono segreti durante la fase di build dell'immagine, **BuildKit** presenta una soluzione efficiente con supporto per i segreti di build-time, migliorando la velocità di build e fornendo funzionalità aggiuntive.

Per sfruttare BuildKit, può essere attivato in tre modi:

1. Attraverso una variabile d'ambiente: `export DOCKER_BUILDKIT=1`
2. Prefissando i comandi: `DOCKER_BUILDKIT=1 docker build .`
3. Abilitandolo per impostazione predefinita nella configurazione di Docker: `{ "features": { "buildkit": true } }`, seguito da un riavvio di Docker.

BuildKit consente l'uso di segreti di build-time con l'opzione `--secret`, garantendo che questi segreti non siano inclusi nella cache di build dell'immagine o nell'immagine finale, utilizzando un comando come:
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
Per i segreti necessari in un container in esecuzione, **Docker Compose e Kubernetes** offrono soluzioni robuste. Docker Compose utilizza una chiave `secrets` nella definizione del servizio per specificare file segreti, come mostrato in un esempio di `docker-compose.yml`:
```yaml
version: "3.7"
services:
my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret
secrets:
my_secret:
file: ./my_secret_file.txt
```
Questa configurazione consente l'uso di segreti durante l'avvio dei servizi con Docker Compose.

Negli ambienti Kubernetes, i segreti sono supportati nativamente e possono essere ulteriormente gestiti con strumenti come [Helm-Secrets](https://github.com/futuresimple/helm-secrets). I controlli degli accessi basati sui ruoli (RBAC) di Kubernetes migliorano la sicurezza della gestione dei segreti, simile a Docker Enterprise.

### gVisor

**gVisor** è un kernel dell'applicazione, scritto in Go, che implementa una parte sostanziale della superficie di sistema Linux. Include un runtime [Open Container Initiative (OCI)](https://www.opencontainers.org) chiamato `runsc` che fornisce un **confine di isolamento tra l'applicazione e il kernel host**. Il runtime `runsc` si integra con Docker e Kubernetes, semplificando l'esecuzione di container sandbox.

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers** è una comunità open source che lavora per costruire un runtime di container sicuro con macchine virtuali leggere che si comportano e si esibiscono come container, ma forniscono un'**isolamento del carico di lavoro più forte utilizzando la tecnologia di virtualizzazione hardware** come secondo strato di difesa.

{% embed url="https://katacontainers.io/" %}

### Suggerimenti Riassuntivi

* **Non utilizzare il flag `--privileged` o montare un** [**socket Docker all'interno del container**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**.** Il socket Docker consente di avviare container, quindi è un modo semplice per assumere il pieno controllo dell'host, ad esempio, eseguendo un altro container con il flag `--privileged`.
* Non eseguire come root all'interno del container. Utilizzare un [**utente diverso**](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user) e [**spazi utente**](https://docs.docker.com/engine/security/userns-remap/)**.** Il root nel container è lo stesso dell'host a meno che non venga rimappato con spazi utente. È solo leggermente limitato principalmente da spazi dei nomi Linux, capacità e cgroups.
* [**Eliminare tutte le capacità**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`) e abilitare solo quelle necessarie** (`--cap-add=...`). Molti carichi di lavoro non necessitano di alcuna capacità e aggiungerle aumenta la portata di un potenziale attacco.
* [**Utilizzare l'opzione di sicurezza "no-new-privileges"**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) per impedire ai processi di acquisire più privilegi, ad esempio attraverso binari suid.
* [**Limitare le risorse disponibili al container**](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)**.** I limiti delle risorse possono proteggere la macchina da attacchi di denial of service.
* **Regolare** [**seccomp**](https://docs.docker.com/engine/security/seccomp/)**,** [**AppArmor**](https://docs.docker.com/engine/security/apparmor/) **(o SELinux)** i profili per limitare le azioni e le chiamate di sistema disponibili per il container al minimo richiesto.
* **Utilizzare** [**immagini docker ufficiali**](https://docs.docker.com/docker-hub/official_images/) **e richiedere firme** o creare le proprie basate su di esse. Non ereditare o utilizzare immagini [backdoored](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/). Conservare anche le chiavi root, passphrase in un luogo sicuro. Docker ha piani per gestire le chiavi con UCP.
* **Ricostruire regolarmente** le tue immagini per **applicare patch di sicurezza all'host e alle immagini.**
* Gestire i **segreti saggiamente** in modo che sia difficile per l'attaccante accedervi.
* Se **esponi il demone docker usa HTTPS** con autenticazione client e server.
* Nel tuo Dockerfile, **preferisci COPY invece di ADD**. ADD estrae automaticamente file zippati e può copiare file da URL. COPY non ha queste capacità. Quando possibile, evita di utilizzare ADD per non essere suscettibile ad attacchi attraverso URL remoti e file Zip.
* Avere **container separati per ogni micro-s**ervizio
* **Non inserire ssh** all'interno del container, "docker exec" può essere utilizzato per ssh al Container.
* Avere **immagini di container più piccole**

## Fuga da Docker / Escalation dei Privilegi

Se sei **all'interno di un container Docker** o hai accesso a un utente nel **gruppo docker**, potresti provare a **fuggire ed escalare i privilegi**:

{% content-ref url="docker-breakout-privilege-escalation/" %}
[docker-breakout-privilege-escalation](docker-breakout-privilege-escalation/)
{% endcontent-ref %}

## Bypass del Plugin di Autenticazione Docker

Se hai accesso al socket docker o hai accesso a un utente nel **gruppo docker ma le tue azioni sono limitate da un plugin di autenticazione docker**, controlla se puoi **bypassarlo:**

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## Hardenizzazione di Docker

* Lo strumento [**docker-bench-security**](https://github.com/docker/docker-bench-security) è uno script che controlla decine di pratiche comuni per il rilascio di container Docker in produzione. I test sono tutti automatizzati e si basano sul [CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/).\
È necessario eseguire lo strumento dall'host in esecuzione di Docker o da un container con sufficienti privilegi. Scopri **come eseguirlo nel README:** [**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security).

## Riferimenti

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/\_fel1x/status/1151487051986087936)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/)
* [https://en.wikipedia.org/wiki/Linux\_namespaces](https://en.wikipedia.org/wiki/Linux\_namespaces)
* [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)
* [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)
* [https://docs.docker.com/engine/extend/plugins\_authorization](https://docs.docker.com/engine/extend/plugins\_authorization)
* [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)
* [https://resources.experfy.com/bigdata-cloud/top-20-docker-security-tips/](https://resources.experfy.com/bigdata-cloud/top-20-docker-security-tips/)

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per costruire facilmente e **automatizzare flussi di lavoro** supportati dagli strumenti della comunità più avanzati al mondo.\
Ottieni l'accesso oggi:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>
<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di Github.

</details>
