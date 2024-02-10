# Sicurezza di Docker

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare e **automatizzare flussi di lavoro** con gli strumenti comunitari più avanzati al mondo.\
Ottieni l'accesso oggi stesso:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## **Sicurezza di base del motore Docker**

Il motore Docker utilizza i **Namespaces** e i **Cgroups** del kernel Linux per isolare i container, offrendo un livello di sicurezza di base. Una protezione aggiuntiva è fornita tramite **Capabilities dropping**, **Seccomp** e **SELinux/AppArmor**, migliorando l'isolamento dei container. Un **plugin di autenticazione** può limitare ulteriormente le azioni degli utenti.

![Sicurezza di Docker](https://sreeninet.files.wordpress.com/2016/03/dockersec1.png)

### Accesso sicuro al motore Docker

Il motore Docker può essere accessibile sia localmente tramite un socket Unix che in remoto utilizzando HTTP. Per l'accesso remoto, è essenziale utilizzare HTTPS e **TLS** per garantire la riservatezza, l'integrità e l'autenticazione.

Il motore Docker, per impostazione predefinita, è in ascolto sul socket Unix `unix:///var/run/docker.sock`. Nei sistemi Ubuntu, le opzioni di avvio di Docker sono definite in `/etc/default/docker`. Per abilitare l'accesso remoto all'API e al client Docker, esponi il demone Docker su un socket HTTP aggiungendo le seguenti impostazioni:
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Tuttavia, esporre il demone Docker tramite HTTP non è consigliato a causa di preoccupazioni per la sicurezza. È consigliabile proteggere le connessioni utilizzando HTTPS. Ci sono due approcci principali per garantire la connessione:
1. Il client verifica l'identità del server.
2. Sia il client che il server si autenticano reciprocamente.

I certificati vengono utilizzati per confermare l'identità di un server. Per esempi dettagliati di entrambi i metodi, consulta [**questa guida**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/).

### Sicurezza delle immagini dei container

Le immagini dei container possono essere archiviate in repository privati o pubblici. Docker offre diverse opzioni di archiviazione per le immagini dei container:

* **[Docker Hub](https://hub.docker.com)**: Un servizio di registro pubblico di Docker.
* **[Docker Registry](https://github.com/docker/distribution)**: Un progetto open-source che consente agli utenti di ospitare il proprio registro.
* **[Docker Trusted Registry](https://www.docker.com/docker-trusted-registry)**: L'offerta commerciale di Docker per i registri, che include l'autenticazione degli utenti basata sui ruoli e l'integrazione con i servizi di directory LDAP.

### Scansione delle immagini

I container possono presentare **vulnerabilità di sicurezza** sia a causa dell'immagine di base sia a causa del software installato sopra l'immagine di base. Docker sta lavorando a un progetto chiamato **Nautilus** che effettua la scansione di sicurezza dei container e elenca le vulnerabilità. Nautilus funziona confrontando ciascun livello dell'immagine del container con un repository di vulnerabilità per identificare falle di sicurezza.

Per ulteriori [**informazioni leggi questo**](https://docs.docker.com/engine/scan/).

* **`docker scan`**

Il comando **`docker scan`** consente di eseguire la scansione delle immagini Docker esistenti utilizzando il nome o l'ID dell'immagine. Ad esempio, esegui il seguente comando per eseguire la scansione dell'immagine hello-world:
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

- **Docker Content Trust** utilizza il progetto Notary, basato su The Update Framework (TUF), per gestire la firma delle immagini. Per ulteriori informazioni, consulta [Notary](https://github.com/docker/notary) e [TUF](https://theupdateframework.github.io).
- Per attivare la fiducia nel contenuto di Docker, imposta `export DOCKER_CONTENT_TRUST=1`. Questa funzionalità è disattivata per impostazione predefinita nella versione di Docker 1.10 e successive.
- Con questa funzionalità abilitata, è possibile scaricare solo immagini firmate. Il caricamento iniziale dell'immagine richiede l'impostazione di passphrase per le chiavi di root e di tag, con Docker che supporta anche Yubikey per una maggiore sicurezza. Ulteriori dettagli possono essere trovati [qui](https://blog.docker.com/2015/11/docker-content-trust-yubikey/).
- Tentare di scaricare un'immagine non firmata con la fiducia nel contenuto abilitata provoca un errore "Nessun dato di fiducia per l'ultima versione".
- Per i caricamenti delle immagini successivi al primo, Docker richiede la passphrase della chiave del repository per firmare l'immagine.

Per eseguire il backup delle tue chiavi private, utilizza il comando:
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Quando si passa da un host Docker all'altro, è necessario spostare le chiavi di root e del repository per mantenere le operazioni.

***

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilizza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare facilmente e automatizzare flussi di lavoro supportati dagli strumenti della comunità più avanzati al mondo.\
Ottieni l'accesso oggi stesso:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Funzionalità di sicurezza dei container

<details>

<summary>Riepilogo delle funzionalità di sicurezza dei container</summary>

### Principali funzionalità di isolamento del processo principale

In ambienti containerizzati, isolare i progetti e i loro processi è fondamentale per la sicurezza e la gestione delle risorse. Ecco una spiegazione semplificata dei concetti chiave:

#### **Namespaces**
- **Scopo**: Garantire l'isolamento delle risorse come processi, rete e filesystem. In particolare, in Docker, i namespaces mantengono separati i processi di un container dall'host e dagli altri container.
- **Utilizzo di `unshare`**: Il comando `unshare` (o la syscall sottostante) viene utilizzato per creare nuovi namespaces, fornendo un ulteriore livello di isolamento. Tuttavia, mentre Kubernetes non blocca questo concetto in modo intrinseco, Docker lo fa.
- **Limitazione**: La creazione di nuovi namespaces non consente a un processo di tornare ai namespaces predefiniti dell'host. Per penetrare nei namespaces dell'host, di solito è necessario avere accesso alla directory `/proc` dell'host, utilizzando `nsenter` per l'ingresso.

#### **Control Groups (CGroups)**
- **Funzione**: Utilizzati principalmente per allocare risorse tra i processi.
- **Aspetto di sicurezza**: I CGroups stessi non offrono sicurezza di isolamento, ad eccezione della funzionalità `release_agent`, che, se configurata in modo errato, potrebbe essere potenzialmente sfruttata per l'accesso non autorizzato.

#### **Capability Drop**
- **Importanza**: È una funzionalità di sicurezza fondamentale per l'isolamento dei processi.
- **Funzionalità**: Limita le azioni che un processo root può eseguire eliminando determinate capacità. Anche se un processo viene eseguito con privilegi di root, la mancanza delle capacità necessarie impedisce l'esecuzione di azioni privilegiate, poiché le syscall falliranno a causa di autorizzazioni insufficienti.

Queste sono le **capacità rimanenti** dopo che il processo ha eliminato le altre:

{% code overflow="wrap" %}
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
{% endcode %}

**Seccomp**

È abilitato di default in Docker. Aiuta a **limitare ancora di più le syscalls** che il processo può chiamare.\
Il **profilo Seccomp predefinito di Docker** può essere trovato in [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)

**AppArmor**

Docker ha un modello che puoi attivare: [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

Questo permetterà di ridurre le capacità, le syscalls, l'accesso ai file e alle cartelle...

</details>

### Namespaces

**I Namespaces** sono una caratteristica del kernel Linux che **partiziona le risorse del kernel** in modo che un insieme di **processi** veda un insieme di **risorse** mentre un altro insieme di **processi** vede un insieme **diverso** di risorse. La caratteristica funziona avendo lo stesso namespace per un insieme di risorse e processi, ma quei namespace si riferiscono a risorse distinte. Le risorse possono esistere in più spazi.

Docker fa uso dei seguenti Namespaces del kernel Linux per ottenere l'isolamento dei Container:

* namespace pid
* namespace mount
* namespace network
* namespace ipc
* namespace UTS

Per **ulteriori informazioni sui namespaces** consulta la seguente pagina:

{% content-ref url="namespaces/" %}
[namespaces](namespaces/)
{% endcontent-ref %}

### cgroups

La caratteristica del kernel Linux **cgroups** fornisce la capacità di **limitare le risorse come cpu, memoria, io, larghezza di banda di rete tra** un insieme di processi. Docker consente di creare Container utilizzando la funzionalità cgroup che consente il controllo delle risorse per il Container specifico.\
Di seguito è riportato un esempio di creazione di un Container con una memoria dello spazio utente limitata a 500m, una memoria del kernel limitata a 50m, una quota cpu di 512 e un peso blkioweight di 400. La quota cpu è un rapporto che controlla l'utilizzo della CPU del Container. Ha un valore predefinito di 1024 e un intervallo compreso tra 0 e 1024. Se tre Container hanno la stessa quota cpu di 1024, ogni Container può utilizzare fino al 33% della CPU in caso di conflitto di risorse della CPU. Il peso blkioweight è un rapporto che controlla l'IO del Container. Ha un valore predefinito di 500 e un intervallo compreso tra 10 e 1000.
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
Per ottenere il cgroup di un container puoi fare:
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
Per ulteriori informazioni, controlla:

{% content-ref url="cgroups.md" %}
[cgroups.md](cgroups.md)
{% endcontent-ref %}

### Capabilities

Le capacità consentono un **controllo più preciso delle capacità che possono essere consentite** per l'utente root. Docker utilizza la funzionalità di capacità del kernel Linux per **limitare le operazioni che possono essere eseguite all'interno di un contenitore** indipendentemente dal tipo di utente.

Quando viene eseguito un contenitore Docker, il **processo abbandona le capacità sensibili che il processo potrebbe utilizzare per sfuggire all'isolamento**. Ciò cerca di garantire che il processo non sia in grado di eseguire azioni sensibili e di sfuggire:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

### Seccomp in Docker

Questa è una funzionalità di sicurezza che consente a Docker di **limitare le syscalls** che possono essere utilizzate all'interno del contenitore:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

### AppArmor in Docker

**AppArmor** è un miglioramento del kernel per confinare i **contenitori** a un **insieme limitato di risorse** con **profilo per programma**.:

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

### SELinux in Docker

- **Sistema di etichettatura**: SELinux assegna un'etichetta univoca a ogni processo e oggetto del filesystem.
- **Esecuzione delle politiche**: impone le politiche di sicurezza che definiscono quali azioni può eseguire un'etichetta di processo su altre etichette all'interno del sistema.
- **Etichette dei processi del contenitore**: quando i motori dei contenitori avviano processi dei contenitori, di solito viene loro assegnata un'etichetta SELinux confinata, comunemente `container_t`.
- **Etichettatura dei file all'interno dei contenitori**: i file all'interno del contenitore di solito sono etichettati come `container_file_t`.
- **Regole di politica**: la politica SELinux garantisce principalmente che i processi con l'etichetta `container_t` possano interagire solo (leggere, scrivere, eseguire) con i file etichettati come `container_file_t`.

Questo meccanismo garantisce che anche se un processo all'interno di un contenitore viene compromesso, è confinato a interagire solo con oggetti che hanno le etichette corrispondenti, limitando significativamente i danni potenziali di tali compromissioni.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

### AuthZ & AuthN

In Docker, un plugin di autorizzazione svolge un ruolo cruciale nella sicurezza decidendo se consentire o bloccare le richieste al demone Docker. Questa decisione viene presa esaminando due contesti chiave:

- **Contesto di autenticazione**: questo include informazioni complete sull'utente, come chi sono e come si sono autenticati.
- **Contesto del comando**: questo comprende tutti i dati pertinenti relativi alla richiesta in corso.

Questi contesti contribuiscono a garantire che vengano elaborate solo richieste legittime da utenti autenticati, migliorando la sicurezza delle operazioni di Docker.

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## DoS da un contenitore

Se non si limitano correttamente le risorse che un contenitore può utilizzare, un contenitore compromesso potrebbe causare un DoS all'host in cui viene eseguito.

* CPU DoS
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
* Denial of Service (DoS) della larghezza di banda

Un attacco di Denial of Service (DoS) della larghezza di banda è un tipo di attacco informatico in cui l'obiettivo è sovraccaricare la larghezza di banda di un sistema o di una rete, rendendola inaccessibile agli utenti legittimi. Questo tipo di attacco può essere eseguito in diversi modi, come ad esempio inviando un'enorme quantità di dati verso il sistema bersaglio o sfruttando vulnerabilità nella gestione della larghezza di banda.

Per proteggere un sistema da un attacco di DoS della larghezza di banda, è possibile adottare alcune misure di sicurezza, come l'implementazione di firewall, l'utilizzo di sistemi di rilevamento degli attacchi DoS e l'adozione di politiche di gestione del traffico per limitare la quantità di dati che possono essere inviati o ricevuti da un singolo indirizzo IP.

È importante monitorare costantemente la larghezza di banda del sistema e la sua capacità di gestire il traffico in modo da poter rilevare eventuali anomalie o attacchi in corso. Inoltre, è consigliabile mantenere il sistema sempre aggiornato con le ultime patch di sicurezza e utilizzare password complesse per evitare l'accesso non autorizzato.
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## Interessanti flag di Docker

### Flag --privileged

Nella seguente pagina puoi imparare **cosa implica il flag `--privileged`**:

{% content-ref url="docker-privileged.md" %}
[docker-privileged.md](docker-privileged.md)
{% endcontent-ref %}

### --security-opt

#### no-new-privileges

Se stai eseguendo un container in cui un attaccante riesce ad ottenere accesso come utente a bassi privilegi. Se hai un **binario suid mal configurato**, l'attaccante potrebbe sfruttarlo e **aumentare i privilegi all'interno** del container. Ciò potrebbe consentirgli di sfuggirne.

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
Per ulteriori opzioni **`--security-opt`** consulta: [https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

## Altre considerazioni sulla sicurezza

### Gestione dei segreti: Best Practices

È fondamentale evitare di incorporare direttamente i segreti nelle immagini Docker o di utilizzare variabili d'ambiente, poiché questi metodi espongono le informazioni sensibili a chiunque abbia accesso al contenitore tramite comandi come `docker inspect` o `exec`.

I **volumi Docker** sono un'alternativa più sicura, consigliata per accedere alle informazioni sensibili. Possono essere utilizzati come un filesystem temporaneo in memoria, mitigando i rischi associati a `docker inspect` e al logging. Tuttavia, gli utenti root e coloro che hanno accesso `exec` al contenitore potrebbero comunque accedere ai segreti.

I **segnreti Docker** offrono un metodo ancora più sicuro per gestire le informazioni sensibili. Per le istanze che richiedono segreti durante la fase di creazione dell'immagine, **BuildKit** presenta una soluzione efficiente con il supporto per i segreti di build-time, migliorando la velocità di creazione e fornendo funzionalità aggiuntive.

Per sfruttare BuildKit, può essere attivato in tre modi:

1. Tramite una variabile d'ambiente: `export DOCKER_BUILDKIT=1`
2. Aggiungendo un prefisso ai comandi: `DOCKER_BUILDKIT=1 docker build .`
3. Abilitandolo per impostazione predefinita nella configurazione di Docker: `{ "features": { "buildkit": true } }`, seguito da un riavvio di Docker.

BuildKit consente l'utilizzo di segreti di build-time con l'opzione `--secret`, garantendo che questi segreti non siano inclusi nella cache di creazione dell'immagine o nell'immagine finale, utilizzando un comando come:
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
Per i segreti necessari in un container in esecuzione, **Docker Compose e Kubernetes** offrono soluzioni robuste. Docker Compose utilizza una chiave `secrets` nella definizione del servizio per specificare i file segreti, come mostrato nell'esempio di un file `docker-compose.yml`:
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
Questa configurazione consente l'utilizzo di segreti durante l'avvio dei servizi con Docker Compose.

Negli ambienti Kubernetes, i segreti sono supportati nativamente e possono essere ulteriormente gestiti con strumenti come [Helm-Secrets](https://github.com/futuresimple/helm-secrets). I controlli di accesso basati sui ruoli (RBAC) di Kubernetes migliorano la sicurezza della gestione dei segreti, simile a Docker Enterprise.

### gVisor

**gVisor** è un kernel dell'applicazione, scritto in Go, che implementa una parte sostanziale della superficie del sistema Linux. Include un runtime [Open Container Initiative (OCI)](https://www.opencontainers.org) chiamato `runsc` che fornisce un **limite di isolamento tra l'applicazione e il kernel host**. Il runtime `runsc` si integra con Docker e Kubernetes, semplificando l'esecuzione di container sandbox.

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers** è una comunità open source che lavora per costruire un runtime di container sicuro con macchine virtuali leggere che si comportano e si eseguono come container, ma forniscono un'**isolamento del carico di lavoro più forte utilizzando la virtualizzazione hardware** come secondo livello di difesa.

{% embed url="https://katacontainers.io/" %}

### Suggerimenti riassuntivi

* **Non utilizzare il flag `--privileged` o montare un** [**socket Docker all'interno del container**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**.** Il socket Docker consente di generare container, quindi è un modo semplice per ottenere il pieno controllo dell'host, ad esempio, eseguendo un altro container con il flag `--privileged`.
* **Non eseguire come root all'interno del container. Utilizzare un** [**utente diverso**](https://docs.docker.com/develop/develop-images/dockerfile\_best-practices/#user) **e** [**spazi dei nomi utente**](https://docs.docker.com/engine/security/userns-remap/)**.** La root nel container è la stessa dell'host a meno che non venga mappata con spazi dei nomi utente. È solo leggermente limitata principalmente da spazi dei nomi Linux, capacità e cgroups.
* [**Eliminare tutte le capacità**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`) e abilitare solo quelle necessarie** (`--cap-add=...`). Molti carichi di lavoro non hanno bisogno di alcuna capacità e aggiungerle aumenta la portata di un potenziale attacco.
* [**Utilizzare l'opzione di sicurezza "no-new-privileges"**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) per impedire ai processi di ottenere ulteriori privilegi, ad esempio attraverso binari suid.
* [**Limitare le risorse disponibili per il container**](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)**.** I limiti delle risorse possono proteggere la macchina da attacchi di negazione del servizio.
* **Regolare** [**seccomp**](https://docs.docker.com/engine/security/seccomp/)**,** [**AppArmor**](https://docs.docker.com/engine/security/apparmor/) **(o SELinux)** i profili per limitare le azioni e le chiamate di sistema disponibili per il container al minimo necessario.
* **Utilizzare immagini Docker** [**ufficiali**](https://docs.docker.com/docker-hub/official\_images/) **e richiedere firme** o creare le proprie basate su di esse. Non ereditare o utilizzare immagini [con backdoor](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/). Conservare anche le chiavi di root e la passphrase in un luogo sicuro. Docker ha piani per gestire le chiavi con UCP.
* **Ricostruire regolarmente** le immagini per **applicare patch di sicurezza all'host e alle immagini**.
* Gestire i **segnreti in modo oculato** in modo che sia difficile per l'attaccante accedervi.
* Se **si espone il demone Docker, utilizzare HTTPS** con autenticazione client e server.
* Nel Dockerfile, **preferire COPY invece di ADD**. ADD estrae automaticamente file zippati e può copiare file da URL. COPY non ha queste capacità. Quando possibile, evitare di utilizzare ADD per non essere vulnerabili ad attacchi tramite URL remoti e file Zip.
* Avere **container separati per ogni micro-servizio**.
* **Non inserire ssh** all'interno del container, "docker exec" può essere utilizzato per ssh al container.
* Avere **immagini di container più piccole**.

## Fuga da Docker / Escalation dei privilegi

Se sei **all'interno di un container Docker** o hai accesso a un utente nel **gruppo docker**, puoi provare a **fuggire ed elevare i privilegi**:

{% content-ref url="docker-breakout-privilege-escalation/" %}
[docker-breakout-privilege-escalation](docker-breakout-privilege-escalation/)
{% endcontent-ref %}

## Bypass del plugin di autenticazione Docker

Se hai accesso al socket Docker o hai accesso a un utente nel **gruppo docker ma le tue azioni sono limitate da un plugin di autenticazione Docker**, verifica se puoi **bypassarlo**:

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## Harden Docker

* Lo strumento [**docker-bench-security**](https://github.com/docker/docker-bench-security) è uno script che verifica decine di best practice comuni per il deployment di container Docker in produzione. I test sono tutti automatizzati e si basano sul [CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/).\
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
* [https://towardsdatascience.com/top-20-docker-security-tips-81c
Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in formato PDF**, consulta i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Acquista il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su GitHub.

</details>
