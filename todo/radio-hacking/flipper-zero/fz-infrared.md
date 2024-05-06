# FZ - Infrarossi

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la **tua azienda pubblicizzata su HackTricks**? o vuoi avere accesso all'**ultima versione del PEASS o scaricare HackTricks in PDF**? Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo di hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo di hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Introduzione <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Per ulteriori informazioni su come funziona l'infrarosso, controlla:

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## Ricevitore Segnale IR in Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper utilizza un ricevitore di segnale IR digitale TSOP, che **consente di intercettare segnali dai telecomandi IR**. Ci sono alcuni **smartphone** come Xiaomi, che hanno anche una porta IR, ma tieni presente che **la maggior parte di essi può solo trasmettere** segnali e non è in grado di riceverli.

Il ricevitore infrarosso di Flipper è piuttosto sensibile. Puoi anche **catturare il segnale** rimanendo **in mezzo** al telecomando e alla TV. Puntare direttamente il telecomando verso la porta IR di Flipper è superfluo. Questo è utile quando qualcuno sta cambiando canale stando vicino alla TV, e sia tu che Flipper siete a distanza.

Poiché la **decodifica del segnale infrarosso** avviene sul lato **software**, Flipper Zero supporta potenzialmente la **ricezione e la trasmissione di qualsiasi codice remoto IR**. Nel caso di **protocolli sconosciuti** che non possono essere riconosciuti, **registra e riproduce** il segnale grezzo esattamente come ricevuto.

## Azioni

### Telecomandi Universali

Flipper Zero può essere utilizzato come un **telecomando universale per controllare qualsiasi TV, condizionatore d'aria o centro multimediale**. In questa modalità, Flipper **forza bruta** tutti i **codici conosciuti** di tutti i produttori supportati **in base al dizionario dalla scheda SD**. Non è necessario scegliere un telecomando particolare per spegnere una TV in un ristorante.

Basta premere il pulsante di accensione in modalità Telecomando Universale, e Flipper invierà **sequenzialmente comandi "Spegni"** di tutte le TV che conosce: Sony, Samsung, Panasonic... e così via. Quando la TV riceve il suo segnale, reagirà e si spegnerà.

Questa forza bruta richiede tempo. Più grande è il dizionario, più tempo ci vorrà per finire. È impossibile scoprire quale segnale esattamente la TV ha riconosciuto poiché non c'è feedback dalla TV.

### Apprendi Nuovo Telecomando

È possibile **catturare un segnale infrarosso** con Flipper Zero. Se **trova il segnale nel database**, Flipper saprà automaticamente **di quale dispositivo si tratta** e ti permetterà di interagire con esso.\
Se non lo fa, Flipper può **memorizzare** il **segnale** e ti permetterà di **riprodurlo**.

## Riferimenti

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)
