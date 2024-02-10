<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) di GitHub.

</details>


#

# JTAG

JTAG consente di eseguire una scansione del limite. La scansione del limite analizza determinati circuiti, inclusi celle di scansione del limite incorporate e registri per ogni pin.

Lo standard JTAG definisce **comandi specifici per condurre scansioni del limite**, tra cui i seguenti:

* **BYPASS** consente di testare un chip specifico senza il sovraccarico di passare attraverso altri chip.
* **SAMPLE/PRELOAD** prende un campione dei dati in ingresso e in uscita dal dispositivo quando è in modalità di funzionamento normale.
* **EXTEST** imposta e legge gli stati dei pin.

Può anche supportare altri comandi come:

* **IDCODE** per l'identificazione di un dispositivo
* **INTEST** per il test interno del dispositivo

Potresti incontrare queste istruzioni quando utilizzi uno strumento come il JTAGulator.

## La porta di accesso al test

Le scansioni del limite includono test della porta di accesso al test a quattro fili (**TAP**), una porta a uso generale che fornisce **accesso al supporto di test JTAG** incorporato in un componente. TAP utilizza i seguenti cinque segnali:

* Ingresso del clock di test (**TCK**) Il TCK è il **clock** che definisce con quale frequenza il controller TAP prenderà una singola azione (in altre parole, passerà allo stato successivo nella macchina a stati).
* Selezione della modalità di test (**TMS**) input TMS controlla la **macchina a stati finiti**. Ad ogni battito del clock, il controller TAP JTAG del dispositivo controlla la tensione sul pin TMS. Se la tensione è al di sotto di una certa soglia, il segnale viene considerato basso e interpretato come 0, mentre se la tensione è al di sopra di una certa soglia, il segnale viene considerato alto e interpretato come 1.
* Ingresso dei dati di test (**TDI**) TDI è il pin che invia **dati al chip attraverso le celle di scansione**. Ogni fornitore è responsabile della definizione del protocollo di comunicazione su questo pin, perché JTAG non lo definisce.
* Uscita dei dati di test (**TDO**) TDO è il pin che invia **dati fuori dal chip**.
* Reset del test (**TRST**) input Il reset opzionale TRST riporta la macchina a stati finiti **a uno stato noto buono**. In alternativa, se il TMS viene mantenuto a 1 per cinque cicli di clock consecutivi, viene richiamato un reset, allo stesso modo in cui farebbe il pin TRST, motivo per cui TRST è opzionale.

A volte sarà possibile trovare questi pin contrassegnati sulla PCB. In altre occasioni potrebbe essere necessario **trovarli**.

## Identificazione dei pin JTAG

Il modo più veloce ma più costoso per rilevare le porte JTAG è utilizzare il **JTAGulator**, un dispositivo creato appositamente per questo scopo (anche se può **rilevare anche i pinout UART**).

Ha **24 canali** a cui è possibile collegare i pin delle schede. Quindi esegue un **attacco BF** di tutte le possibili combinazioni inviando comandi di scansione del limite **IDCODE** e **BYPASS**. Se riceve una risposta, visualizza il canale corrispondente a ciascun segnale JTAG.

Un modo più economico ma molto più lento per identificare i pinout JTAG è utilizzare il [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) caricato su un microcontrollore compatibile con Arduino.

Utilizzando **JTAGenum**, dovresti prima **definire i pin della sonda** che utilizzerai per l'enumerazione. Dovrai fare riferimento al diagramma dei pin del dispositivo e quindi collegare questi pin ai punti di test sul tuo dispositivo target.

Un **terzo modo** per identificare i pin JTAG è **ispezionare la PCB** per uno dei pinout. In alcuni casi, le PCB potrebbero fornire comodamente l'interfaccia **Tag-Connect**, che è un'indicazione chiara che la scheda ha un connettore JTAG. Puoi vedere come appare quell'interfaccia su [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Inoltre, ispezionando **i datasheet dei chipset sulla PCB** potrebbero essere rivelati diagrammi dei pinout che indicano le interfacce JTAG.

# SDW

SWD è un protocollo specifico per ARM progettato per il debug.

L'interfaccia SWD richiede **due pin**: un segnale bidirezionale **SWDIO**, che è l'equivalente dei pin **TDI e TDO di JTAG e un clock**, e **SWCLK**, che è l'equivalente di **TCK** in JTAG. Molti dispositivi supportano la **Serial Wire o JTAG Debug Port (SWJ-DP)**, un'interfaccia combinata JTAG e SWD che consente di collegare una sonda SWD o JTAG al target.


<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) di GitHub.

</details>
