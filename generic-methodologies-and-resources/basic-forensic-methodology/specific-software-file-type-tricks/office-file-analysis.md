# Analisi dei file di Office

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per costruire e **automatizzare facilmente flussi di lavoro** supportati dagli strumenti della comunità più avanzati al mondo.\
Ottieni l'accesso oggi:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

Per ulteriori informazioni consulta [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Questo è solo un riassunto:

Microsoft ha creato molti formati di documenti di Office, con due tipi principali che sono i **formati OLE** (come RTF, DOC, XLS, PPT) e i **formati Office Open XML (OOXML)** (come DOCX, XLSX, PPTX). Questi formati possono includere macro, rendendoli bersagli per phishing e malware. I file OOXML sono strutturati come contenitori zip, consentendo l'ispezione tramite l'estrazione, rivelando la struttura dei file e delle cartelle e i contenuti dei file XML.

Per esplorare le strutture dei file OOXML, vengono forniti il comando per estrarre un documento e la struttura di output. Sono state documentate tecniche per nascondere dati in questi file, indicando un'innovazione continua nella dissimulazione dei dati nelle sfide CTF.

Per l'analisi, **oletools** e **OfficeDissector** offrono set di strumenti completi per esaminare sia i documenti OLE che OOXML. Questi strumenti aiutano nell'identificare e analizzare le macro incorporate, che spesso fungono da vettori per la distribuzione di malware, scaricando e eseguendo tipicamente payload dannosi aggiuntivi. L'analisi delle macro VBA può essere condotta senza Microsoft Office utilizzando Libre Office, che consente il debug con punti di interruzione e variabili di watch.

L'installazione e l'uso di **oletools** sono semplici, con comandi forniti per l'installazione tramite pip e l'estrazione delle macro dai documenti. L'esecuzione automatica delle macro è attivata da funzioni come `AutoOpen`, `AutoExec`, o `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare facilmente e **automatizzare flussi di lavoro** supportati dagli strumenti della community **più avanzati al mondo**.\
Ottieni l'accesso oggi:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione esclusiva di [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di github.

</details>
