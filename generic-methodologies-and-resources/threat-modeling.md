# Modellazione delle Minacce

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) è un motore di ricerca alimentato dal **dark web** che offre funzionalità **gratuite** per verificare se un'azienda o i suoi clienti sono stati **compromessi** da **malware ruba-informazioni**.

L'obiettivo principale di WhiteIntel è contrastare i takeover di account e gli attacchi ransomware derivanti da malware che ruba informazioni.

Puoi visitare il loro sito web e provare il loro motore **gratuitamente** su:

{% embed url="https://whiteintel.io" %}

***

## Modellazione delle Minacce

Benvenuto alla guida completa di HackTricks sulla Modellazione delle Minacce! Imbarcati in un'esplorazione di questo aspetto critico della sicurezza informatica, dove identifichiamo, comprendiamo e pianifichiamo contro le potenziali vulnerabilità in un sistema. Questo thread serve come guida passo dopo passo ricca di esempi reali, software utile e spiegazioni facili da comprendere. Ideale sia per i principianti che per i professionisti esperti che desiderano rafforzare le loro difese informatiche.

### Scenari Comunemente Utilizzati

1. **Sviluppo Software**: Come parte del Ciclo di Vita dello Sviluppo Software Sicuro (SSDLC), la modellazione delle minacce aiuta nell'**identificare potenziali fonti di vulnerabilità** nelle fasi iniziali dello sviluppo.
2. **Penetration Testing**: Il framework Penetration Testing Execution Standard (PTES) richiede la **modellazione delle minacce per comprendere le vulnerabilità del sistema** prima di effettuare il test.

### Modello delle Minacce in Breve

Un Modello delle Minacce è tipicamente rappresentato come un diagramma, un'immagine o qualche altra forma di illustrazione visiva che rappresenta l'architettura pianificata o l'implementazione esistente di un'applicazione. Ha somiglianze con un **diagramma di flusso dati**, ma la distinzione chiave risiede nel suo design orientato alla sicurezza.

I modelli delle minacce spesso presentano elementi contrassegnati in rosso, simboleggiando potenziali vulnerabilità, rischi o barriere. Per semplificare il processo di identificazione dei rischi, viene impiegato il triade CIA (Confidenzialità, Integrità, Disponibilità), che costituisce la base di molte metodologie di modellazione delle minacce, con STRIDE che è una delle più comuni. Tuttavia, la metodologia scelta può variare a seconda del contesto specifico e dei requisiti.

### La Triade CIA

La Triade CIA è un modello ampiamente riconosciuto nel campo della sicurezza informatica, che sta per Confidenzialità, Integrità e Disponibilità. Questi tre pilastri costituiscono la base su cui sono costruite molte misure di sicurezza e politiche, inclusi i metodi di modellazione delle minacce.

1. **Confidenzialità**: Garantire che i dati o il sistema non siano accessibili da individui non autorizzati. Questo è un aspetto centrale della sicurezza, che richiede controlli di accesso appropriati, crittografia e altre misure per prevenire violazioni dei dati.
2. **Integrità**: L'accuratezza, la coerenza e l'affidabilità dei dati durante il loro ciclo di vita. Questo principio garantisce che i dati non siano alterati o manomessi da parti non autorizzate. Spesso coinvolge checksum, hash e altri metodi di verifica dei dati.
3. **Disponibilità**: Questo garantisce che i dati e i servizi siano accessibili agli utenti autorizzati quando necessario. Spesso coinvolge ridondanza, tolleranza ai guasti e configurazioni ad alta disponibilità per mantenere i sistemi in funzione anche di fronte a interruzioni.

### Metodologie di Modellazione delle Minacce

1. **STRIDE**: Sviluppato da Microsoft, STRIDE è un acronimo per **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service e Elevation of Privilege**. Ogni categoria rappresenta un tipo di minaccia, e questa metodologia è comunemente utilizzata nella fase di progettazione di un programma o sistema per identificare minacce potenziali.
2. **DREAD**: Questa è un'altra metodologia di Microsoft utilizzata per la valutazione del rischio delle minacce identificate. DREAD sta per **Damage potential, Reproducibility, Exploitability, Affected users e Discoverability**. Ciascuno di questi fattori viene valutato e il risultato viene utilizzato per prioritizzare le minacce identificate.
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Si tratta di una metodologia a sette passaggi, **centrata sul rischio**. Include la definizione e l'identificazione degli obiettivi di sicurezza, la creazione di un ambito tecnico, la decomposizione dell'applicazione, l'analisi delle minacce, l'analisi delle vulnerabilità e la valutazione del rischio/triage.
4. **Trike**: Si tratta di una metodologia basata sul rischio che si concentra sulla difesa degli asset. Parte da una prospettiva di **gestione del rischio** e analizza minacce e vulnerabilità in quel contesto.
5. **VAST** (Visual, Agile e Simple Threat modeling): Questo approccio mira ad essere più accessibile e si integra negli ambienti di sviluppo Agile. Combina elementi delle altre metodologie e si concentra sulle **rappresentazioni visive delle minacce**.
6. **OCTAVE** (Operationally Critical Threat, Asset e Vulnerability Evaluation): Sviluppato dal CERT Coordination Center, questo framework è orientato alla **valutazione del rischio organizzativo piuttosto che a sistemi o software specifici**.

## Strumenti

Ci sono diversi strumenti e soluzioni software disponibili che possono **aiutare** nella creazione e gestione dei modelli delle minacce. Ecco alcuni che potresti prendere in considerazione.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

Un avanzato web spider/crawler GUI multi-piattaforma per professionisti della sicurezza informatica. Spider Suite può essere utilizzato per il mapping e l'analisi della superficie di attacco.

**Utilizzo**

1. Scegli un URL e Fai lo Spider

<figure><img src="../.gitbook/assets/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Visualizza il Grafico

<figure><img src="../.gitbook/assets/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

Un progetto open-source di OWASP, Threat Dragon è sia un'applicazione web che desktop che include la creazione di diagrammi di sistema e un motore di regole per generare automaticamente minacce/mitigazioni.

**Utilizzo**

1. Crea un Nuovo Progetto

<figure><img src="../.gitbook/assets/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

A volte potrebbe apparire così:

<figure><img src="../.gitbook/assets/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Avvia il Nuovo Progetto

<figure><img src="../.gitbook/assets/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Salva il Nuovo Progetto

<figure><img src="../.gitbook/assets/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Crea il tuo modello

Puoi utilizzare strumenti come SpiderSuite Crawler per ispirarti, un modello di base assomiglierebbe a qualcosa del genere

<figure><img src="../.gitbook/assets/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Solo un breve spiegazione sulle entità:

* Processo (L'entità stessa come un Webserver o una funzionalità web)
* Attore (Una persona come un Visitatore del Sito Web, Utente o Amministratore)
* Linea di Flusso dei Dati (Indicatore di Interazione)
* Limite di Fiducia (Diverse segmenti di rete o ambiti.)
* Archiviazione (Cose dove i dati sono memorizzati come ad esempio Database)

5. Crea una Minaccia (Passaggio 1)

Prima devi scegliere lo strato a cui desideri aggiungere una minaccia

<figure><img src="../.gitbook/assets/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Ora puoi creare la minaccia

<figure><img src="../.gitbook/assets/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Tieni presente che c'è una differenza tra le Minacce degli Attori e le Minacce dei Processi. Se aggiungessi una minaccia a un Attore, potresti scegliere solo "Spoofing" e "Repudiation". Tuttavia, nel nostro esempio aggiungiamo una minaccia a un'entità di Processo quindi vedremo questo nella casella di creazione della minaccia:

<figure><img src="../.gitbook/assets/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Fatto

Ora il tuo modello finito dovrebbe assomigliare a qualcosa del genere. E così si crea un semplice modello delle minacce con OWASP Threat Dragon.

<figure><img src="../.gitbook/assets/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>
### [Strumento di Threat Modeling di Microsoft](https://aka.ms/threatmodelingtool)

Si tratta di uno strumento gratuito di Microsoft che aiuta a individuare minacce nella fase di progettazione dei progetti software. Utilizza la metodologia STRIDE ed è particolarmente adatto a coloro che sviluppano sulla piattaforma Microsoft.

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) è un motore di ricerca alimentato dal **dark web** che offre funzionalità **gratuite** per verificare se un'azienda o i suoi clienti sono stati **compromessi** da **malware ruba-informazioni**.

Il loro obiettivo principale è contrastare le violazioni degli account e gli attacchi ransomware derivanti da malware che rubano informazioni.

Puoi visitare il loro sito web e provare il loro motore **gratuitamente** su:

{% embed url="https://whiteintel.io" %}
