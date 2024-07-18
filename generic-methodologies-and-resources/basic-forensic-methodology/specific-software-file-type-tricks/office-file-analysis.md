# Analisi dei file Office

{% hint style="success" %}
Impara e pratica il hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository github.

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=office-file-analysis) per costruire e **automatizzare flussi di lavoro** alimentati dagli **strumenti comunitari più avanzati** al mondo.\
Ottieni accesso oggi:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=office-file-analysis" %}

Per ulteriori informazioni controlla [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Questo è solo un riassunto:

Microsoft ha creato molti formati di documenti office, con due tipi principali che sono i **formati OLE** (come RTF, DOC, XLS, PPT) e i **formati Office Open XML (OOXML)** (come DOCX, XLSX, PPTX). Questi formati possono includere macro, rendendoli obiettivi per phishing e malware. I file OOXML sono strutturati come contenitori zip, consentendo l'ispezione tramite decompressione, rivelando la gerarchia di file e cartelle e i contenuti dei file XML.

Per esplorare le strutture dei file OOXML, viene fornito il comando per decomprimere un documento e la struttura di output. Tecniche per nascondere dati in questi file sono state documentate, indicando un'innovazione continua nella dissimulazione dei dati all'interno delle sfide CTF.

Per l'analisi, **oletools** e **OfficeDissector** offrono set di strumenti completi per esaminare sia i documenti OLE che OOXML. Questi strumenti aiutano a identificare e analizzare le macro incorporate, che spesso fungono da vettori per la consegna di malware, tipicamente scaricando ed eseguendo payload dannosi aggiuntivi. L'analisi delle macro VBA può essere condotta senza Microsoft Office utilizzando Libre Office, che consente il debug con punti di interruzione e variabili di osservazione.

L'installazione e l'uso di **oletools** sono semplici, con comandi forniti per l'installazione tramite pip e l'estrazione di macro dai documenti. L'esecuzione automatica delle macro è attivata da funzioni come `AutoOpen`, `AutoExec` o `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=office-file-analysis) per costruire e **automatizzare flussi di lavoro** facilmente, alimentati dagli **strumenti** della comunità **più avanzati** al mondo.\
Accedi oggi:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=office-file-analysis" %}

{% hint style="success" %}
Impara e pratica Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}
