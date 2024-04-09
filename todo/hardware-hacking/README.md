# Hacking Hardware

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di Github.

</details>

## JTAG

JTAG consente di eseguire una scansione dei limiti. La scansione dei limiti analizza determinati circuiti, inclusi le celle di scansione dei limiti incorporate e i registri per ciascun pin.

Lo standard JTAG definisce **comandi specifici per condurre scansioni dei limiti**, tra cui i seguenti:

* **BYPASS** consente di testare un chip specifico senza il sovraccarico di passare attraverso altri chip.
* **SAMPLE/PRELOAD** prende un campione dei dati che entrano e escono dal dispositivo quando è in modalità di funzionamento normale.
* **EXTEST** imposta e legge gli stati dei pin.

Può anche supportare altri comandi come:

* **IDCODE** per identificare un dispositivo
* **INTEST** per il test interno del dispositivo

Potresti imbatterti in queste istruzioni quando utilizzi uno strumento come il JTAGulator.

### Il Porta di Accesso ai Test

Le scansioni dei limiti includono test del **Porta di Accesso ai Test (TAP)** a quattro fili, una porta a uso generale che fornisce **accesso al supporto ai test JTAG** incorporato in un componente. Il TAP utilizza i seguenti cinque segnali:

* Ingresso del clock di test (**TCK**) Il TCK è il **clock** che definisce con quale frequenza il controller TAP prenderà una singola azione (in altre parole, passerà allo stato successivo nella macchina a stati).
* Ingresso di selezione della modalità di test (**TMS**) TMS controlla la **macchina a stati finiti**. Ad ogni battito del clock, il controller TAP JTAG del dispositivo controlla la tensione sul pin TMS. Se la tensione è al di sotto di una certa soglia, il segnale è considerato basso e interpretato come 0, mentre se la tensione è al di sopra di una certa soglia, il segnale è considerato alto e interpretato come 1.
* Ingresso dei dati di test (**TDI**) TDI è il pin che invia **dati al chip attraverso le celle di scansione**. Ogni fornitore è responsabile della definizione del protocollo di comunicazione su questo pin, poiché JTAG non lo definisce.
* Uscita dei dati di test (**TDO**) TDO è il pin che invia **dati fuori dal chip**.
* Ingresso di reset di test (**TRST**) L'opzionale TRST reimposta la macchina a stati finiti **a uno stato noto buono**. In alternativa, se il TMS viene mantenuto a 1 per cinque cicli di clock consecutivi, invoca un reset, allo stesso modo in cui farebbe il pin TRST, motivo per cui TRST è facoltativo.

A volte potresti trovare quei pin marcati sulla PCB. In altre occasioni potresti aver bisogno di **trovarli**.

### Identificazione dei pin JTAG

Il modo più veloce ma più costoso per rilevare le porte JTAG è utilizzando il **JTAGulator**, un dispositivo creato appositamente per questo scopo (anche se può **rilevare anche le configurazioni dei pin UART**).

Ha **24 canali** a cui puoi collegare i pin delle schede. Quindi esegue un **attacco BF** di tutte le combinazioni possibili inviando comandi di scansione dei limiti **IDCODE** e **BYPASS**. Se riceve una risposta, visualizza il canale corrispondente a ciascun segnale JTAG.

Un modo più economico ma molto più lento per identificare le configurazioni dei pin JTAG è utilizzando il [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) caricato su un microcontrollore compatibile con Arduino.

Utilizzando **JTAGenum**, dovresti prima **definire i pin del dispositivo di sonda** che utilizzerai per l'enumerazione. Dovresti fare riferimento al diagramma dei pin del dispositivo e quindi collegare questi pin ai punti di test sul tuo dispositivo target.

Un **terzo modo** per identificare i pin JTAG è **ispezionare la PCB** per una delle configurazioni dei pin. In alcuni casi, le PCB potrebbero fornire in modo conveniente l'**interfaccia Tag-Connect**, che è un'indicazione chiara che la scheda ha un connettore JTAG, troppo. Puoi vedere com'è fatta quell'interfaccia su [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Inoltre, ispezionare i **datasheet dei chipset sulla PCB** potrebbe rivelare diagrammi delle configurazioni dei pin che indicano le interfacce JTAG.

## SDW

SWD è un protocollo specifico per ARM progettato per il debug.

L'interfaccia SWD richiede **due pin**: un segnale bidirezionale **SWDIO**, che è l'equivalente dei pin **TDI e TDO di JTAG e un clock**, e **SWCLK**, che è l'equivalente di **TCK** in JTAG. Molti dispositivi supportano il **Porta di Debug Seriale Wire o JTAG (SWJ-DP)**, un'interfaccia combinata JTAG e SWD che consente di collegare una sonda SWD o JTAG al target. 

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di Github.

</details>
