# Hardware Hacking

{% hint style="success" %}
Impara e pratica AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

</details>
{% endhint %}

## JTAG

JTAG consente di eseguire una scansione di confine. La scansione di confine analizza alcuni circuiti, inclusi i circuiti integrati di scansione e i registri per ogni pin.

Lo standard JTAG definisce **comandi specifici per condurre scansioni di confine**, inclusi i seguenti:

* **BYPASS** consente di testare un chip specifico senza il sovraccarico di passare attraverso altri chip.
* **SAMPLE/PRELOAD** prende un campione dei dati che entrano ed escono dal dispositivo quando è nella sua modalità di funzionamento normale.
* **EXTEST** imposta e legge gli stati dei pin.

Può anche supportare altri comandi come:

* **IDCODE** per identificare un dispositivo
* **INTEST** per il test interno del dispositivo

Potresti imbatterti in queste istruzioni quando utilizzi uno strumento come il JTAGulator.

### La Porta di Accesso al Test

Le scansioni di confine includono test della porta di accesso al test a quattro fili **Test Access Port (TAP)**, una porta di uso generale che fornisce **accesso alle funzioni di supporto al test JTAG** integrate in un componente. TAP utilizza i seguenti cinque segnali:

* Ingresso del clock di test (**TCK**) Il TCK è il **clock** che definisce quanto spesso il controller TAP eseguirà un'azione singola (in altre parole, salta al prossimo stato nella macchina a stati).
* Ingresso di selezione della modalità di test (**TMS**) Il TMS controlla la **macchina a stati finiti**. Ad ogni battito del clock, il controller TAP JTAG del dispositivo controlla la tensione sul pin TMS. Se la tensione è al di sotto di una certa soglia, il segnale è considerato basso e interpretato come 0, mentre se la tensione è al di sopra di una certa soglia, il segnale è considerato alto e interpretato come 1.
* Ingresso dei dati di test (**TDI**) Il TDI è il pin che invia **dati nel chip attraverso le celle di scansione**. Ogni fornitore è responsabile della definizione del protocollo di comunicazione su questo pin, poiché JTAG non lo definisce.
* Uscita dei dati di test (**TDO**) Il TDO è il pin che invia **dati fuori dal chip**.
* Ingresso di reset di test (**TRST**) Il TRST opzionale resetta la macchina a stati finiti **in uno stato noto buono**. In alternativa, se il TMS è mantenuto a 1 per cinque cicli di clock consecutivi, invoca un reset, nello stesso modo in cui farebbe il pin TRST, motivo per cui TRST è opzionale.

A volte sarai in grado di trovare quei pin contrassegnati nel PCB. In altre occasioni potresti dover **trovarli**.

### Identificazione dei pin JTAG

Il modo più veloce ma più costoso per rilevare le porte JTAG è utilizzare il **JTAGulator**, un dispositivo creato specificamente per questo scopo (anche se può **anche rilevare le pinout UART**).

Ha **24 canali** che puoi collegare ai pin delle schede. Poi esegue un **attacco BF** di tutte le possibili combinazioni inviando comandi di scansione di confine **IDCODE** e **BYPASS**. Se riceve una risposta, visualizza il canale corrispondente a ciascun segnale JTAG.

Un modo più economico ma molto più lento per identificare le pinout JTAG è utilizzare il [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) caricato su un microcontrollore compatibile con Arduino.

Utilizzando **JTAGenum**, dovresti prima **definire i pin del dispositivo di sondaggio** che utilizzerai per l'enumerazione. Dovresti fare riferimento al diagramma dei pin del dispositivo e poi collegare questi pin ai punti di test sul tuo dispositivo target.

Un **terzo modo** per identificare i pin JTAG è **ispezionare il PCB** per uno dei pinout. In alcuni casi, i PCB potrebbero fornire convenientemente l'**interfaccia Tag-Connect**, che è un chiaro indicativo che la scheda ha anche un connettore JTAG. Puoi vedere come appare quell'interfaccia su [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Inoltre, ispezionare i **datasheet dei chip sul PCB** potrebbe rivelare diagrammi di pinout che puntano alle interfacce JTAG.

## SDW

SWD è un protocollo specifico per ARM progettato per il debug.

L'interfaccia SWD richiede **due pin**: un segnale bidirezionale **SWDIO**, che è l'equivalente dei pin **TDI e TDO** di JTAG e un clock, e **SWCLK**, che è l'equivalente di **TCK** in JTAG. Molti dispositivi supportano il **Serial Wire o JTAG Debug Port (SWJ-DP)**, un'interfaccia combinata JTAG e SWD che ti consente di collegare un sondaggio SWD o JTAG al target.

{% hint style="success" %}
Impara e pratica AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

</details>
{% endhint %}
