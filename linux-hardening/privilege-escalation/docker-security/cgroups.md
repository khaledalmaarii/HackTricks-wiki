# CGroups

{% hint style="success" %}
Impara e pratica l'hacking su AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}

## Informazioni di Base

**Linux Control Groups**, o **cgroups**, sono una caratteristica del kernel Linux che consente l'allocazione, limitazione e prioritizzazione delle risorse di sistema come CPU, memoria e I/O disco tra gruppi di processi. Offrono un meccanismo per **gestire e isolare l'utilizzo delle risorse** di collezioni di processi, utile per scopi come limitazione delle risorse, isolamento del carico di lavoro e prioritizzazione delle risorse tra diversi gruppi di processi.

Ci sono **due versioni di cgroups**: versione 1 e versione 2. Entrambe possono essere utilizzate contemporaneamente su un sistema. La distinzione principale è che **cgroups versione 2** introduce una **struttura gerarchica a forma di albero**, consentendo una distribuzione delle risorse più sfumata e dettagliata tra i gruppi di processi. Inoltre, la versione 2 porta varie migliorie, tra cui:

Oltre alla nuova organizzazione gerarchica, cgroups versione 2 ha introdotto **diverse altre modifiche e miglioramenti**, come il supporto per **nuovi controller di risorse**, un miglior supporto per le applicazioni legacy e prestazioni migliorate.

Complessivamente, cgroups **versione 2 offre più funzionalità e migliori prestazioni** rispetto alla versione 1, ma quest'ultima potrebbe essere comunque utilizzata in determinati scenari in cui è importante la compatibilità con sistemi più vecchi.

È possibile elencare i cgroups v1 e v2 per qualsiasi processo guardando il suo file cgroup in /proc/\<pid>. Si può iniziare guardando i cgroups della tua shell con questo comando:
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

* **Numeri da 2 a 12**: cgroups v1, con ogni riga che rappresenta un cgroup diverso. I controller per questi sono specificati accanto al numero.
* **Numero 1**: Anche cgroups v1, ma solo a fini di gestione (impostato, ad esempio, da systemd), e manca di un controller.
* **Numero 0**: Rappresenta cgroups v2. Non sono elencati controller, e questa riga è esclusiva per i sistemi che eseguono solo cgroups v2.
* I **nomi sono gerarchici**, simili ai percorsi dei file, indicando la struttura e la relazione tra i diversi cgroups.
* **Nomi come /user.slice o /system.slice** specificano la categorizzazione dei cgroups, con user.slice tipicamente per sessioni di accesso gestite da systemd e system.slice per servizi di sistema.

### Visualizzazione dei cgroups

Il filesystem è tipicamente utilizzato per accedere ai **cgroups**, divergendo dall'interfaccia di chiamata di sistema Unix tradizionalmente utilizzata per le interazioni con il kernel. Per investigare la configurazione di un cgroup di una shell, si dovrebbe esaminare il file **/proc/self/cgroup**, che rivela il cgroup della shell. Quindi, navigando nella directory **/sys/fs/cgroup** (o **`/sys/fs/cgroup/unified`**) e individuando una directory che condivide il nome del cgroup, si possono osservare varie impostazioni e informazioni sull'utilizzo delle risorse pertinenti al cgroup.

![Filesystem Cgroup](<../../../.gitbook/assets/image (1128).png>)

I file di interfaccia chiave per i cgroups sono prefissati con **cgroup**. Il file **cgroup.procs**, che può essere visualizzato con comandi standard come cat, elenca i processi all'interno del cgroup. Un altro file, **cgroup.threads**, include informazioni sui thread.

![Cgroup Procs](<../../../.gitbook/assets/image (281).png>)

I cgroups che gestiscono le shell di solito comprendono due controller che regolano l'uso della memoria e il conteggio dei processi. Per interagire con un controller, si dovrebbero consultare i file che portano il prefisso del controller. Ad esempio, **pids.current** sarebbe consultato per verificare il conteggio dei thread nel cgroup.

![Memoria Cgroup](<../../../.gitbook/assets/image (677).png>)

L'indicazione di **max** in un valore suggerisce l'assenza di un limite specifico per il cgroup. Tuttavia, a causa della natura gerarchica dei cgroups, potrebbero essere imposti limiti da un cgroup a un livello inferiore nella gerarchia delle directory.

### Manipolazione e Creazione dei cgroups

I processi vengono assegnati ai cgroups scrivendo il loro ID di processo (PID) nel file `cgroup.procs`. Questo richiede privilegi di root. Ad esempio, per aggiungere un processo:
```bash
echo [pid] > cgroup.procs
```
Allo stesso modo, **modificare gli attributi del cgroup, come impostare un limite di PID**, viene fatto scrivendo il valore desiderato nel file pertinente. Per impostare un massimo di 3.000 PID per un cgroup:
```bash
echo 3000 > pids.max
```
**Creazione di nuovi cgroups** comporta la creazione di una nuova sottodirectory all'interno della gerarchia cgroup, che induce il kernel a generare automaticamente i file di interfaccia necessari. Anche se i cgroups senza processi attivi possono essere rimossi con `rmdir`, fai attenzione a determinati vincoli:

* **I processi possono essere collocati solo nei cgroups foglia** (cioè, quelli più nidificati in una gerarchia).
* **Un cgroup non può possedere un controller assente nel suo genitore**.
* **I controller per i cgroups figlio devono essere dichiarati esplicitamente** nel file `cgroup.subtree_control`. Ad esempio, per abilitare i controller CPU e PID in un cgroup figlio:
```bash
echo "+cpu +pids" > cgroup.subtree_control
```
Il **cgroup radice** è un'eccezione a queste regole, che consente il posizionamento diretto dei processi. Questo può essere utilizzato per rimuovere i processi dalla gestione di systemd.

**Monitorare l'utilizzo della CPU** all'interno di un cgroup è possibile tramite il file `cpu.stat`, che mostra il tempo totale di CPU consumato, utile per tracciare l'utilizzo tra i sotto-processi di un servizio:

<figure><img src="../../../.gitbook/assets/image (908).png" alt=""><figcaption><p>Statistiche sull'utilizzo della CPU come mostrato nel file cpu.stat</p></figcaption></figure>

## Riferimenti

* **Libro: How Linux Works, 3rd Edition: What Every Superuser Should Know di Brian Ward**
