# Threat Modeling

## Modellazione delle minacce

Benvenuti alla guida completa di HackTricks sulla modellazione delle minacce! Intraprendi un'esplorazione di questo aspetto critico della sicurezza informatica, in cui identifichiamo, comprendiamo e pianifichiamo contro le potenziali vulnerabilità di un sistema. Questo thread serve come guida passo-passo ricca di esempi reali, software utili e spiegazioni facili da comprendere. Ideale sia per i principianti che per i professionisti esperti che desiderano rafforzare le proprie difese informatiche.

### Scenari comunemente utilizzati

1. **Sviluppo software**: Come parte del ciclo di vita dello sviluppo software sicuro (SSDLC), la modellazione delle minacce aiuta a **identificare potenziali fonti di vulnerabilità** nelle prime fasi dello sviluppo.
2. **Penetration Testing**: Il framework Penetration Testing Execution Standard (PTES) richiede la **modellazione delle minacce per comprendere le vulnerabilità del sistema** prima di effettuare il test.

### Modello delle minacce in breve

Un modello delle minacce è tipicamente rappresentato come un diagramma, un'immagine o una qualche altra forma di illustrazione visiva che rappresenta l'architettura pianificata o la struttura esistente di un'applicazione. Ha somiglianze con un **diagramma di flusso dei dati**, ma la differenza chiave risiede nel suo design orientato alla sicurezza.

I modelli delle minacce spesso presentano elementi contrassegnati in rosso, che simboleggiano potenziali vulnerabilità, rischi o barriere. Per semplificare il processo di identificazione dei rischi, viene utilizzata la triade CIA (Confidenzialità, Integrità, Disponibilità), che costituisce la base di molte metodologie di modellazione delle minacce, con STRIDE come una delle più comuni. Tuttavia, la metodologia scelta può variare a seconda del contesto e dei requisiti specifici.

### La triade CIA

La triade CIA è un modello ampiamente riconosciuto nel campo della sicurezza delle informazioni, che sta per Confidenzialità, Integrità e Disponibilità. Questi tre pilastri costituiscono la base su cui sono costruite molte misure di sicurezza e politiche, comprese le metodologie di modellazione delle minacce.

1. **Confidenzialità**: Garantire che i dati o il sistema non siano accessibili da individui non autorizzati. Questo è un aspetto centrale della sicurezza, che richiede controlli di accesso appropriati, crittografia e altre misure per prevenire violazioni dei dati.
2. **Integrità**: L'accuratezza, la coerenza e l'affidabilità dei dati nel corso del loro ciclo di vita. Questo principio garantisce che i dati non vengano modificati o manomessi da parti non autorizzate. Spesso coinvolge checksum, hashing e altri metodi di verifica dei dati.
3. **Disponibilità**: Garantisce che i dati e i servizi siano accessibili agli utenti autorizzati quando necessario. Spesso coinvolge la ridondanza, la tolleranza ai guasti e le configurazioni ad alta disponibilità per mantenere i sistemi in funzione anche di fronte a interruzioni.

### Metodologie di modellazione delle minacce

1. **STRIDE**: Sviluppato da Microsoft, STRIDE è un acronimo per **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service e Elevation of Privilege**. Ogni categoria rappresenta un tipo di minaccia e questa metodologia viene comunemente utilizzata nella fase di progettazione di un programma o di un sistema per identificare le minacce potenziali.
2. **DREAD**: Questa è un'altra metodologia di Microsoft utilizzata per la valutazione del rischio delle minacce identificate. DREAD sta per **Damage potential, Reproducibility, Exploitability, Affected users e Discoverability**. Ciascuno di questi fattori viene valutato e il risultato viene utilizzato per dare priorità alle minacce identificate.
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Si tratta di una metodologia **centrata sul rischio** in sette fasi. Include la definizione e l'identificazione degli obiettivi di sicurezza, la creazione di un ambito tecnico, la decomposizione dell'applicazione, l'analisi delle minacce, l'analisi delle vulnerabilità e la valutazione del rischio/triage.
4. **Trike**: Si tratta di una metodologia basata sul rischio che si concentra sulla difesa degli asset. Parte da una prospettiva di **gestione del rischio** e analizza le minacce e le vulnerabilità in quel contesto.
5. **VAST** (Visual, Agile e Simple Threat modeling): Questo approccio mira a essere più accessibile e si integra negli ambienti di sviluppo Agile. Combina elementi delle altre metodologie e si concentra sulle **rappresentazioni visive delle minacce**.
6. **OCTAVE** (Operationally Critical Threat, Asset e Vulnerability Evaluation): Sviluppato dal CERT Coordination Center, questo framework è orientato alla **valutazione del rischio organizzativo piuttosto che a sistemi o software specifici**.

## Strumenti

Ci sono diversi strumenti e soluzioni software disponibili che possono **aiutare** nella creazione e gestione dei modelli delle minacce. Ecco alcuni che potresti considerare.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

Un avanzato web spider/crawler GUI multi-piattaforma per professionisti della sicurezza informatica. Spider Suite può essere utilizzato per il mappaggio e l'analisi della superficie di attacco.

**Utilizzo**

1. Scegli un URL e fai lo spider

<figure><img src="../.gitbook/assets/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Visualizza il grafico

<figure><img src="../.gitbook/assets/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

Un progetto open-source di OWASP, Threat Dragon è sia un'applicazione web che desktop che include la creazione di diagrammi di sistema e un motore di regole per generare automaticamente minacce/mitigazioni.

**Utilizzo**

1. Crea un nuovo progetto

<figure><img src="../.gitbook/assets/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

A volte potrebbe apparire così:

<figure><img src="../.gitbook/assets/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Avvia il nuovo progetto

<figure><img src="../.gitbook/assets/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Salva il nuovo progetto

<figure><img src="../.gitbook/assets/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Crea il tuo modello

Puoi utilizzare strumenti come SpiderSuite Crawler per farti ispirare, un modello di base avrebbe un aspetto simile a questo

<figure><img src="../.gitbook/assets/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Solo una breve spiegazione sulle entità:

* Processo (L'entità stessa come un server web o una funzionalità web)
* Attore (Una persona come un visitatore del sito web, un utente o un amministratore)
* Linea di flusso dei dati (Indicatore di interazione)
* Confine di fiducia (Segmenti di rete o ambiti diversi)
* Archiviazione (Cose in cui vengono archiviati i dati come database)

5. Crea una minaccia (Passaggio 1)

Prima devi scegliere il livello a cui desideri aggiungere una minaccia

<figure><img src="../.gitbook/assets/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Ora puoi creare la minaccia

<figure><img src="../.gitbook/assets/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Tieni presente che c'è una differenza tra le minacce degli attori e le minacce dei processi. Se aggiungi una minaccia a un attore, potrai scegliere solo "Spoofing" e "Repudiation". Tuttavia, nel nostro esempio aggiungiamo una minaccia a un'entità di processo, quindi vedremo questo nella casella di creazione della minaccia:

<figure><img src="../.gitbook/assets/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Fatto

Ora il tuo modello finito dovrebbe avere un aspetto simile a questo. Ecco come creare un semplice modello delle minacce con OWASP Threat Dragon.

<figure><img src="../.gitbook/assets/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Questo è uno strumento gratuito di Microsoft che aiuta a individuare le minacce nella fase di progettazione dei progetti software. Utilizza la metodologia STRIDE ed è particolarmente adatto per coloro che sviluppano sulla piattaforma Microsoft.
