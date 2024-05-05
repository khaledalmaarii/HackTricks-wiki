# Il Protocollo Modbus

## Introduzione al Protocollo Modbus

Il protocollo Modbus è un protocollo ampiamente utilizzato nei Sistemi di Automazione e Controllo Industriale. Modbus consente la comunicazione tra vari dispositivi come controllori logici programmabili (PLC), sensori, attuatori e altri dispositivi industriali. Comprendere il Protocollo Modbus è essenziale poiché è il protocollo di comunicazione più utilizzato nei Sistemi di Automazione e Controllo Industriale e presenta molte potenzialità di attacco per lo sniffing e persino l'iniezione di comandi nei PLC.

Qui, i concetti sono esposti punto per punto fornendo contesto sul protocollo e sulla sua natura di funzionamento. La sfida più grande nella sicurezza dei sistemi ICS è il costo di implementazione e aggiornamento. Questi protocolli e standard sono stati progettati nei primi anni '80 e '90 e sono ancora ampiamente utilizzati. Poiché un'industria dispone di molti dispositivi e connessioni, l'aggiornamento dei dispositivi è molto difficile, il che fornisce agli hacker un vantaggio nel gestire protocolli obsoleti. Gli attacchi al Modbus sono praticamente inevitabili poiché verrà utilizzato senza aggiornamenti e il suo funzionamento è critico per l'industria.

## L'Architettura Client-Server

Il Protocollo Modbus è tipicamente utilizzato nell'Architettura Client-Server in cui un dispositivo master (client) avvia la comunicazione con uno o più dispositivi slave (server). Questo è anche definito come architettura Master-Slave, ampiamente utilizzata in elettronica e IoT con SPI, I2C, ecc.

## Versioni Seriale ed Ethernet

Il Protocollo Modbus è progettato sia per la Comunicazione Seriale che per la Comunicazione Ethernet. La Comunicazione Seriale è ampiamente utilizzata nei sistemi legacy, mentre i dispositivi moderni supportano l'Ethernet che offre elevate velocità di trasferimento dati ed è più adatto per le reti industriali moderne.

## Rappresentazione dei Dati

I dati vengono trasmessi nel protocollo Modbus come ASCII o Binario, anche se il formato binario è utilizzato per la sua compatibilità con i dispositivi più vecchi.

## Codici di Funzione

Il Protocollo ModBus funziona con la trasmissione di specifici codici di funzione che vengono utilizzati per operare sui PLC e sui vari dispositivi di controllo. Questa parte è importante da comprendere poiché gli attacchi di ripetizione possono essere effettuati ritrasmettendo i codici di funzione. I dispositivi legacy non supportano alcuna crittografia per la trasmissione dei dati e di solito hanno cavi lunghi che li collegano, il che porta alla manipolazione di questi cavi e alla cattura/iniezione di dati.

## Indirizzamento del Modbus

Ogni dispositivo nella rete ha un indirizzo univoco essenziale per la comunicazione tra dispositivi. Protocolli come Modbus RTU, Modbus TCP, ecc. sono utilizzati per implementare l'indirizzamento e fungono da strato di trasporto per la trasmissione dei dati. I dati trasferiti sono nel formato del protocollo Modbus che contiene il messaggio.

Inoltre, Modbus implementa anche controlli degli errori per garantire l'integrità dei dati trasmessi. Ma soprattutto, Modbus è uno Standard Aperto e chiunque può implementarlo nei propri dispositivi. Questo ha reso questo protocollo uno standard globale ed è ampiamente diffuso nell'industria dell'automazione industriale.

A causa del suo ampio utilizzo e della mancanza di aggiornamenti, attaccare il Modbus fornisce un significativo vantaggio con la sua superficie di attacco. Gli ICS dipendono fortemente dalla comunicazione tra dispositivi e qualsiasi attacco su di essi può essere pericoloso per il funzionamento dei sistemi industriali. Gli attacchi come ripetizione, iniezione di dati, sniffing e leaking di dati, Denial of Service, falsificazione di dati, ecc. possono essere effettuati se il mezzo di trasmissione è identificato dall'attaccante.
