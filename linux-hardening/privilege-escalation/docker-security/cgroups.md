# CGroups

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>

## Informazioni di base

**Linux Control Groups**, o **cgroups**, sono una caratteristica del kernel Linux che consente l'allocazione, la limitazione e la prioritizzazione delle risorse di sistema come CPU, memoria e I/O del disco tra gruppi di processi. Offrono un meccanismo per **gestire e isolare l'utilizzo delle risorse** di collezioni di processi, utili per scopi come la limitazione delle risorse, l'isolamento del carico di lavoro e la prioritizzazione delle risorse tra diversi gruppi di processi.

Ci sono **due versioni di cgroups**: versione 1 e versione 2. Entrambe possono essere utilizzate contemporaneamente su un sistema. La distinzione principale è che **cgroups versione 2** introduce una **struttura gerarchica a forma di albero**, consentendo una distribuzione delle risorse più sfumata e dettagliata tra i gruppi di processi. Inoltre, la versione 2 porta diverse migliorie, tra cui:

Oltre alla nuova organizzazione gerarchica, la versione 2 di cgroups ha introdotto anche **diverse altre modifiche e miglioramenti**, come il supporto a **nuovi controller delle risorse**, un miglior supporto per le applicazioni legacy e prestazioni migliorate.

In generale, cgroups **versione 2 offre più funzionalità e migliori prestazioni** rispetto alla versione 1, ma quest'ultima può ancora essere utilizzata in determinati scenari in cui è necessaria la compatibilità con sistemi più vecchi.

È possibile elencare i cgroups v1 e v2 per qualsiasi processo guardando il suo file cgroup in /proc/\<pid>. Puoi iniziare guardando i cgroups della tua shell con questo comando:
```shell-session
$ cat /proc/self/cgroup
12:rdma:/
11:net_cls,net_prio:/
10:perf_event:/
9:cpuset:/
8:cpu,cpuacct:/user.slice
7:blkio:/user.slice
6:memory:/user.slice 5:pids:/user.slice/user-1000.slice/session-2.scope 4:devices:/user.slice
3:freezer:/
2:hugetlb:/testcgroup
1:name=systemd:/user.slice/user-1000.slice/session-2.scope
0::/user.slice/user-1000.slice/session-2.scope
```
La struttura dell'output è la seguente:

- **Numeri da 2 a 12**: cgroups v1, con ogni riga che rappresenta un cgroup diverso. I controller per questi sono specificati accanto al numero.
- **Numero 1**: Anche cgroups v1, ma solo per scopi di gestione (impostato, ad esempio, da systemd) e senza un controller.
- **Numero 0**: Rappresenta cgroups v2. Non vengono elencati controller e questa riga è esclusiva per i sistemi che eseguono solo cgroups v2.
- I **nomi sono gerarchici**, simili ai percorsi dei file, indicando la struttura e la relazione tra i diversi cgroups.
- **Nomi come /user.slice o /system.slice** specificano la categorizzazione dei cgroups, con user.slice tipicamente per sessioni di accesso gestite da systemd e system.slice per servizi di sistema.

### Visualizzazione dei cgroups

Il filesystem viene tipicamente utilizzato per accedere ai **cgroups**, divergendo dall'interfaccia di chiamata di sistema Unix tradizionalmente utilizzata per le interazioni con il kernel. Per indagare sulla configurazione del cgroup di una shell, è necessario esaminare il file **/proc/self/cgroup**, che rivela il cgroup della shell. Successivamente, navigando nella directory **/sys/fs/cgroup** (o **`/sys/fs/cgroup/unified`**) e individuando una directory che condivide il nome del cgroup, è possibile osservare diverse impostazioni e informazioni sull'utilizzo delle risorse pertinenti al cgroup.

![Filesystem dei cgroup](../../../.gitbook/assets/image%20(10)%20(2)%20(2).png)

I file di interfaccia chiave per i cgroups sono preceduti da **cgroup**. Il file **cgroup.procs**, che può essere visualizzato con comandi standard come cat, elenca i processi all'interno del cgroup. Un altro file, **cgroup.threads**, include informazioni sui thread.

![Cgroup Procs](../../../.gitbook/assets/image%20(1)%20(1)%20(5).png)

I cgroups che gestiscono le shell comprendono tipicamente due controller che regolano l'utilizzo della memoria e il conteggio dei processi. Per interagire con un controller, è necessario consultare i file che portano il prefisso del controller. Ad esempio, **pids.current** verrebbe consultato per verificare il conteggio dei thread nel cgroup.

![Cgroup Memory](../../../.gitbook/assets/image%20(3)%20(5).png)

L'indicazione di **max** in un valore suggerisce l'assenza di un limite specifico per il cgroup. Tuttavia, a causa della natura gerarchica dei cgroups, potrebbero essere imposti limiti da un cgroup a un livello inferiore nella gerarchia delle directory.


### Manipolazione e creazione di cgroups

I processi vengono assegnati ai cgroups scrivendo il loro ID di processo (PID) nel file `cgroup.procs`. Ciò richiede privilegi di root. Ad esempio, per aggiungere un processo:
```bash
echo [pid] > cgroup.procs
```
Allo stesso modo, **la modifica degli attributi del cgroup, come impostare un limite PID**, viene effettuata scrivendo il valore desiderato nel file pertinente. Per impostare un massimo di 3.000 PID per un cgroup:
```bash
echo 3000 > pids.max
```
**Creare nuovi cgroups** comporta la creazione di una nuova sottodirectory all'interno della gerarchia dei cgroup, il che induce il kernel a generare automaticamente i file di interfaccia necessari. Anche se i cgroup senza processi attivi possono essere rimossi con `rmdir`, è necessario tenere presente alcune limitazioni:

- **I processi possono essere inseriti solo nei cgroup foglia** (cioè quelli più nidificati in una gerarchia).
- **Un cgroup non può possedere un controller assente nel suo genitore**.
- **I controller per i cgroup figlio devono essere dichiarati esplicitamente** nel file `cgroup.subtree_control`. Ad esempio, per abilitare i controller CPU e PID in un cgroup figlio:
```bash
echo "+cpu +pids" > cgroup.subtree_control
```
Il **root cgroup** è un'eccezione a queste regole, che consente la posizionamento diretto dei processi. Ciò può essere utilizzato per rimuovere i processi dalla gestione di systemd.

**Monitorare l'utilizzo della CPU** all'interno di un cgroup è possibile tramite il file `cpu.stat`, che mostra il tempo totale della CPU consumato, utile per tenere traccia dell'utilizzo tra i sottoprocessi di un servizio:

<figure><img src="../../../.gitbook/assets/image (2) (6) (3).png" alt=""><figcaption>Statistiche sull'utilizzo della CPU come mostrato nel file cpu.stat</figcaption></figure>

## Riferimenti
* **Libro: How Linux Works, 3rd Edition: What Every Superuser Should Know di Brian Ward**

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
