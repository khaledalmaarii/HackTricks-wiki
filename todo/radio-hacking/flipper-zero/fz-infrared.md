# FZ - Infrarossi

{% hint style="success" %}
Impara e pratica il hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}

## Introduzione <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Per ulteriori informazioni su come funziona l'infrarosso, controlla:

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## Ricevitore di segnale IR in Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper utilizza un ricevitore di segnale IR digitale TSOP, che **consente di intercettare segnali da telecomandi IR**. Ci sono alcuni **smartphone** come Xiaomi, che hanno anche una porta IR, ma tieni presente che **la maggior parte di essi può solo trasmettere** segnali e non è **in grado di riceverli**.

Il ricevitore infrarosso di Flipper è **abbastanza sensibile**. Puoi anche **catturare il segnale** rimanendo **da qualche parte in mezzo** al telecomando e alla TV. Puntare il telecomando direttamente sulla porta IR di Flipper non è necessario. Questo è utile quando qualcuno sta cambiando canale mentre si trova vicino alla TV, e sia tu che Flipper siete a una certa distanza.

Poiché la **decodifica del segnale infrarosso** avviene sul lato **software**, Flipper Zero supporta potenzialmente la **ricezione e trasmissione di qualsiasi codice remoto IR**. Nel caso di protocolli **sconosciuti** che non possono essere riconosciuti - **registra e riproduce** il segnale grezzo esattamente come ricevuto.

## Azioni

### Telecomandi Universali

Flipper Zero può essere utilizzato come un **telecomando universale per controllare qualsiasi TV, condizionatore d'aria o centro multimediale**. In questa modalità, Flipper **bruteforza** tutti i **codici noti** di tutti i produttori supportati **secondo il dizionario della scheda SD**. Non è necessario scegliere un telecomando particolare per spegnere una TV in un ristorante.

È sufficiente premere il pulsante di accensione nella modalità Telecomando Universale, e Flipper **invierà sequenzialmente i comandi "Power Off"** di tutte le TV che conosce: Sony, Samsung, Panasonic... e così via. Quando la TV riceve il suo segnale, reagirà e si spegnerà.

Tale brute-force richiede tempo. Più grande è il dizionario, più tempo ci vorrà per completarlo. È impossibile scoprire quale segnale esattamente la TV ha riconosciuto poiché non c'è feedback dalla TV.

### Impara Nuovo Telecomando

È possibile **catturare un segnale infrarosso** con Flipper Zero. Se **trova il segnale nel database**, Flipper saprà automaticamente **di quale dispositivo si tratta** e ti permetterà di interagire con esso.\
Se non lo trova, Flipper può **memorizzare** il **segnale** e ti permetterà di **riprodurlo**.

## Riferimenti

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

{% hint style="success" %}
Impara e pratica il hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}
