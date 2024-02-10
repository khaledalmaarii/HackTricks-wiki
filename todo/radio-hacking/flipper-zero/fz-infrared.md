# FZ - Infrarossi

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata in HackTricks**? O vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Introduzione <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Per ulteriori informazioni su come funzionano gli infrarossi, consulta:

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## Ricevitore di segnali IR in Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper utilizza un ricevitore di segnali IR digitale TSOP, che **consente di intercettare segnali dai telecomandi IR**. Ci sono alcuni **smartphone** come Xiaomi, che hanno anche una porta IR, ma tieni presente che **la maggior parte di essi può solo trasmettere** segnali e non è in grado di riceverli.

Il ricevitore infrarossi di Flipper è piuttosto sensibile. Puoi anche **intercettare il segnale** rimanendo **in mezzo** al telecomando e alla TV. Non è necessario puntare direttamente il telecomando alla porta IR di Flipper. Questo è utile quando qualcuno sta cambiando canali stando vicino alla TV, e sia tu che Flipper siete a una certa distanza.

Poiché la **decodifica del segnale infrarosso** avviene sul lato **software**, Flipper Zero supporta potenzialmente la **ricezione e la trasmissione di qualsiasi codice remoto IR**. Nel caso di **protocolli sconosciuti** che non possono essere riconosciuti, Flipper registra e riproduce il segnale grezzo esattamente come ricevuto.

## Azioni

### Telecomandi universali

Flipper Zero può essere utilizzato come un **telecomando universale per controllare qualsiasi TV, condizionatore d'aria o centro multimediale**. In questa modalità, Flipper **forza bruta** tutti i **codici noti** di tutti i produttori supportati **in base al dizionario dalla scheda SD**. Non è necessario scegliere un telecomando specifico per spegnere una TV di un ristorante.

È sufficiente premere il pulsante di accensione in modalità Telecomando Universale, e Flipper invierà **sequenzialmente i comandi "Spegni"** di tutte le TV che conosce: Sony, Samsung, Panasonic... e così via. Quando la TV riceve il suo segnale, reagirà e si spegnerà.

Questa forza bruta richiede tempo. Più grande è il dizionario, più tempo ci vorrà per completare. Non è possibile scoprire quale segnale esattamente la TV ha riconosciuto poiché non c'è alcun feedback dalla TV.

### Impara un nuovo telecomando

È possibile **catturare un segnale infrarosso** con Flipper Zero. Se **trova il segnale nel database**, Flipper saprà automaticamente **di quale dispositivo si tratta** e ti permetterà di interagire con esso.\
Se non lo trova, Flipper può **memorizzare** il **segnale** e ti permetterà di **riproducirlo**.

## Riferimenti

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata in HackTricks**? O vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
