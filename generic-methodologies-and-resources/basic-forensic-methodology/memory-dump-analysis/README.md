# Analisi del dump di memoria

{% hint style="success" %}
Impara e pratica AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) è l'evento di cybersecurity più rilevante in **Spagna** e uno dei più importanti in **Europa**. Con **la missione di promuovere la conoscenza tecnica**, questo congresso è un punto di incontro fervente per professionisti della tecnologia e della cybersecurity in ogni disciplina.

{% embed url="https://www.rootedcon.com/" %}

## Inizio

Inizia a **cercare** **malware** all'interno del pcap. Usa gli **strumenti** menzionati in [**Analisi del Malware**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Volatility è il principale framework open-source per l'analisi dei dump di memoria**. Questo strumento Python analizza i dump provenienti da fonti esterne o VM VMware, identificando dati come processi e password in base al profilo OS del dump. È estensibile con plugin, rendendolo altamente versatile per indagini forensi.

[**Trova qui un cheatsheet**](volatility-cheatsheet.md)

## Rapporto di crash mini dump

Quando il dump è piccolo (solo alcuni KB, forse qualche MB) allora probabilmente è un rapporto di crash mini dump e non un dump di memoria.

![](<../../../.gitbook/assets/image (532).png>)

Se hai Visual Studio installato, puoi aprire questo file e legare alcune informazioni di base come nome del processo, architettura, informazioni sull'eccezione e moduli in esecuzione:

![](<../../../.gitbook/assets/image (263).png>)

Puoi anche caricare l'eccezione e vedere le istruzioni decompilate

![](<../../../.gitbook/assets/image (142).png>)

![](<../../../.gitbook/assets/image (610).png>)

Comunque, Visual Studio non è il miglior strumento per eseguire un'analisi approfondita del dump.

Dovresti **aprirlo** usando **IDA** o **Radare** per ispezionarlo in **profondità**.

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) è l'evento di cybersecurity più rilevante in **Spagna** e uno dei più importanti in **Europa**. Con **la missione di promuovere la conoscenza tecnica**, questo congresso è un punto di incontro fervente per professionisti della tecnologia e della cybersecurity in ogni disciplina.

{% embed url="https://www.rootedcon.com/" %}

{% hint style="success" %}
Impara e pratica AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}
