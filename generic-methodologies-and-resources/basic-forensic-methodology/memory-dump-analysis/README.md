# Analisi del dump di memoria

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la **tua azienda pubblicizzata su HackTricks**? o vuoi avere accesso all'**ultima versione del PEASS o scaricare HackTricks in PDF**? Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo di hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo di hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) è l'evento di sicurezza informatica più rilevante in **Spagna** e uno dei più importanti in **Europa**. Con **la missione di promuovere la conoscenza tecnica**, questo congresso è un punto di incontro bollente per professionisti della tecnologia e della sicurezza informatica in ogni disciplina.

{% embed url="https://www.rootedcon.com/" %}

## Inizio

Inizia a **cercare** **malware** all'interno del pcap. Utilizza gli **strumenti** menzionati in [**Analisi del malware**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Volatility è il principale framework open-source per l'analisi del dump di memoria**. Questo strumento Python analizza i dump da fonti esterne o da macchine virtuali VMware, identificando dati come processi e password in base al profilo OS del dump. È estensibile con plugin, rendendolo altamente versatile per indagini forensi.

[**Trova qui un cheatsheet**](volatility-cheatsheet.md)

## Rapporto di crash del mini dump

Quando il dump è piccolo (solo alcuni KB, forse alcuni MB) allora è probabilmente un rapporto di crash del mini dump e non un dump di memoria.

![](<../../../.gitbook/assets/image (532).png>)

Se hai Visual Studio installato, puoi aprire questo file e associare alcune informazioni di base come nome del processo, architettura, informazioni sull'eccezione e moduli in esecuzione:

![](<../../../.gitbook/assets/image (263).png>)

Puoi anche caricare l'eccezione e vedere le istruzioni decompilate

![](<../../../.gitbook/assets/image (142).png>)

![](<../../../.gitbook/assets/image (610).png>)

In ogni caso, Visual Studio non è lo strumento migliore per eseguire un'analisi approfondita del dump.

Dovresti **aprilo** utilizzando **IDA** o **Radare** per ispezionarlo in **profondità**.

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) è l'evento di sicurezza informatica più rilevante in **Spagna** e uno dei più importanti in **Europa**. Con **la missione di promuovere la conoscenza tecnica**, questo congresso è un punto di incontro bollente per professionisti della tecnologia e della sicurezza informatica in ogni disciplina.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la **tua azienda pubblicizzata su HackTricks**? o vuoi avere accesso all'**ultima versione del PEASS o scaricare HackTricks in PDF**? Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo di hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo di hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
