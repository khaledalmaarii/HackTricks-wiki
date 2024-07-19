# macOS Defensive Apps

{% hint style="success" %}
Impara e pratica il hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Firewalls

* [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Monitorerà ogni connessione effettuata da ciascun processo. A seconda della modalità (consenti connessioni silenziose, nega connessione silenziosa e avvisa) **ti mostrerà un avviso** ogni volta che viene stabilita una nuova connessione. Ha anche un'interfaccia grafica molto bella per vedere tutte queste informazioni.
* [**LuLu**](https://objective-see.org/products/lulu.html): Firewall di Objective-See. Questo è un firewall di base che ti avviserà per connessioni sospette (ha un'interfaccia grafica ma non è così elegante come quella di Little Snitch).

## Rilevamento della persistenza

* [**KnockKnock**](https://objective-see.org/products/knockknock.html): Applicazione di Objective-See che cercherà in diverse posizioni dove **il malware potrebbe persistere** (è uno strumento a colpo singolo, non un servizio di monitoraggio).
* [**BlockBlock**](https://objective-see.org/products/blockblock.html): Come KnockKnock, monitora i processi che generano persistenza.

## Rilevamento dei keylogger

* [**ReiKey**](https://objective-see.org/products/reikey.html): Applicazione di Objective-See per trovare **keylogger** che installano "event taps" della tastiera.
