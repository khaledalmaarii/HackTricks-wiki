# FISSURE - Il framework RF

**Comprensione e reverse engineering dei segnali basati su SDR indipendenti dalla frequenza**

FISSURE è un framework open-source per RF e reverse engineering progettato per tutti i livelli di competenza, con funzioni per la rilevazione e classificazione dei segnali, la scoperta dei protocolli, l'esecuzione degli attacchi, la manipolazione dell'IQ, l'analisi delle vulnerabilità, l'automazione e l'IA/ML. Il framework è stato creato per favorire l'integrazione rapida di moduli software, radio, protocolli, dati di segnale, script, flussi di lavoro, materiale di riferimento e strumenti di terze parti. FISSURE è un facilitatore di workflow che mantiene il software in un'unica posizione e consente alle squadre di mettersi rapidamente al passo condividendo la stessa configurazione di base provata per distribuzioni specifiche di Linux.

Il framework e gli strumenti inclusi in FISSURE sono progettati per rilevare la presenza di energia RF, comprendere le caratteristiche di un segnale, raccogliere e analizzare campioni, sviluppare tecniche di trasmissione e/o di iniezione e creare payload o messaggi personalizzati. FISSURE contiene una libreria in continua crescita di informazioni sui protocolli e sui segnali per aiutare nell'identificazione, nella creazione di pacchetti e nel fuzzing. Esistono funzionalità di archiviazione online per scaricare file di segnale e creare playlist per simulare il traffico e testare i sistemi.

Il codice Python amichevole e l'interfaccia utente consentono ai principianti di imparare rapidamente gli strumenti e le tecniche popolari riguardanti RF e reverse engineering. Gli educatori di sicurezza informatica e ingegneria possono approfittare del materiale integrato o utilizzare il framework per dimostrare le proprie applicazioni reali. Sviluppatori e ricercatori possono utilizzare FISSURE per le proprie attività quotidiane o per esporre le loro soluzioni all'avanguardia a un pubblico più ampio. Con l'aumentare della consapevolezza e dell'utilizzo di FISSURE nella comunità, aumenteranno anche le sue capacità e la portata della tecnologia che comprende.

**Informazioni aggiuntive**

* [Pagina AIS](https://www.ainfosec.com/technologies/fissure/)
* [Diapositive GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [Articolo GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [Video GRCon22](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Trascrizione Hack Chat](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Primi passi

**Supportati**

Ci sono tre branch all'interno di FISSURE per facilitare la navigazione dei file e ridurre la ridondanza del codice. Il branch Python2\_maint-3.7 contiene una base di codice costruita attorno a Python2, PyQt4 e GNU Radio 3.7; il branch Python3\_maint-3.8 è costruito attorno a Python3, PyQt5 e GNU Radio 3.8; e il branch Python3\_maint-3.10 è costruito attorno a Python3, PyQt5 e GNU Radio 3.10.

| Sistema operativo | Branch FISSURE |
| :---------------: | :------------: |
| Ubuntu 18.04 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
| KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**In corso (beta)**

Questi sistemi operativi sono ancora in fase beta. Sono in fase di sviluppo e alcune funzionalità sono note per essere mancanti. Gli elementi nell'installer potrebbero entrare in conflitto con programmi esistenti o potrebbero non riuscire a installarsi fino a quando lo stato non viene rimosso.

| Sistema operativo | Branch FISSURE |
| :---------------: | :------------: |
| DragonOS Focal (x86\_64) | Python3\_maint-3.8 |
| Ubuntu 22.04 (x64) | Python3\_maint-3.10 |

Nota: Alcuni strumenti software non funzionano per ogni sistema operativo. Fare riferimento a [Software e conflitti](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)

**Installazione**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
Questo installerà le dipendenze del software PyQt necessarie per avviare le interfacce di installazione se non vengono trovate.

Successivamente, selezionare l'opzione che corrisponde meglio al proprio sistema operativo (dovrebbe essere rilevato automaticamente se il sistema operativo corrisponde a un'opzione).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Si consiglia di installare FISSURE su un sistema operativo pulito per evitare conflitti esistenti. Selezionare tutte le caselle di controllo consigliate (pulsante Predefinito) per evitare errori durante l'utilizzo degli strumenti all'interno di FISSURE. Durante l'installazione ci saranno più prompt, principalmente per richiedere autorizzazioni elevate e nomi utente. Se un elemento contiene una sezione "Verifica" alla fine, l'installatore eseguirà il comando che segue e evidenzierà la casella di controllo in verde o rosso a seconda se il comando produce errori. Gli elementi selezionati senza una sezione "Verifica" rimarranno neri dopo l'installazione.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Utilizzo**

Aprire un terminale e digitare:
```
fissure
```
Fai riferimento al menu di aiuto di FISSURE per ulteriori dettagli sull'utilizzo.

## Dettagli

**Componenti**

* Dashboard
* Central Hub (HIPRFISR)
* Identificazione del segnale target (TSI)
* Scoperta del protocollo (PD)
* Flow Graph & Script Executor (FGE)

![componenti](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Funzionalità**

| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Rilevatore di segnale**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**Manipolazione IQ**_      | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Ricerca segnale**_          | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Riconoscimento del pattern**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Attacchi**_           | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Playlist dei segnali**_       | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Galleria di immagini**_  |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Creazione di pacchetti**_   | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Integrazione di Scapy**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**Calcolatore CRC**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Logging**_            |

**Hardware**

Di seguito è riportato un elenco di hardware "supportato" con diversi livelli di integrazione:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* Adattatori 802.11
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## Lezioni

FISSURE è dotato di diverse guide utili per familiarizzare con diverse tecnologie e tecniche. Molte includono passaggi per l'utilizzo di vari strumenti integrati in FISSURE.

* [Lezione1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Lezione2: Dissettore Lua](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Lezione3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Lezione4: Schede ESP](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Lezione5: Tracciamento Radiosonde](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Lezione6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Lezione7: Tipi di dati](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Lezione8: Blocchi GNU Radio personalizzati](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Lezione9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Lezione10: Esami radioamatoriali](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Lezione11: Strumenti Wi-Fi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## Roadmap

* [ ] Aggiungere più tipi di hardware, protocolli RF, parametri di segnale, strumenti di analisi
* [ ] Supportare più sistemi operativi
* [ ] Sviluppare materiale didattico su FISSURE (Attacchi RF, Wi-Fi, GNU Radio, PyQt, ecc.)
* [ ] Creare un condizionatore di segnale, un estrattore di caratteristiche e un classificatore di segnale con tecniche AI/ML selezionabili
* [ ] Implementare meccanismi di demodulazione ricorsiva per produrre un flusso di bit da segnali sconosciuti
* [ ] Trasformare i principali componenti di FISSURE in uno schema di distribuzione di nodi sensoriali generico

## Contributi

Sono fortemente incoraggiate le proposte per migliorare FISSURE. Lascia un commento nella pagina delle [Discussioni](https://github.com/ainfosec/FISSURE/discussions) o nel server Discord se hai pensieri riguardo ai seguenti argomenti:

* Nuove proposte di funzionalità e modifiche di design
* Strumenti software con istruzioni di installazione
* Nuove lezioni o materiale aggiuntivo per le lezioni esistenti
* Protocolli RF di interesse
* Più hardware e tipi di SDR per l'integrazione
* Script di analisi IQ in Python
* Correzioni e miglioramenti all'installazione

I contributi per migliorare FISSURE sono fondamentali per accelerare il suo sviluppo. Ogni contributo che fai è molto apprezzato. Se desideri contribuire attraverso lo sviluppo del codice, per favore fork il repository e crea una pull request:

1. Forka il progetto
2. Crea il tuo branch di funzionalità (`git checkout -b feature/AmazingFeature`)
3. Fai commit delle tue modifiche (`git commit -m 'Aggiungi una fantastica funzionalità'`)
4. Pusha il branch (`git push origin feature/AmazingFeature`)
5. Apri una pull request

È anche possibile creare [Issue](https://github.com/ainfosec/FISSURE/issues) per segnalare bug.

## Collaborazione

Contatta lo sviluppo aziendale di Assured Information Security, Inc. (AIS) per proporre e formalizzare opportunità di collaborazione con FISSURE, che sia dedicando tempo all'integrazione del tuo software, facendo sviluppare soluzioni per le tue sfide tecniche da parte delle persone talentuose di AIS o integrando FISSURE in altre piattaforme/applicazioni.

## Licenza

GPL-3.0

Per i dettagli sulla licenza, consulta il file LICENSE.
## Contatti

Unisciti al server Discord: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Segui su Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Sviluppo Aziendale - Assured Information Security, Inc. - bd@ainfosec.com

## Crediti

Riconosciamo e siamo grati a questi sviluppatori:

[Crediti](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Riconoscimenti

Un ringraziamento speciale al Dr. Samuel Mantravadi e a Joseph Reith per il loro contributo a questo progetto.
