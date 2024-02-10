<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


Per una valutazione di phishing, a volte può essere utile **clonare completamente un sito web**.

Nota che puoi anche aggiungere alcuni payload al sito web clonato, come un hook BeEF per "controllare" la scheda dell'utente.

Ci sono diversi strumenti che puoi utilizzare per questo scopo:

## wget
```text
wget -mk -nH
```
## goclone

Il comando `goclone` è uno strumento molto utile per clonare un sito web. Questo strumento semplifica il processo di creazione di una copia esatta di un sito web esistente, consentendo di creare facilmente una versione identica del sito da utilizzare per scopi di phishing.

### Installazione

Per installare `goclone`, è possibile eseguire il seguente comando:

```bash
go get -u github.com/malcomvetter/goclone
```

### Utilizzo

Una volta installato `goclone`, è possibile utilizzarlo per clonare un sito web specificando l'URL del sito da clonare e il percorso in cui si desidera salvare la copia del sito. Ecco un esempio di come utilizzare il comando `goclone`:

```bash
goclone -url https://www.example.com -output /path/to/save/clone
```

Dopo aver eseguito questo comando, `goclone` inizierà a scaricare tutti i file del sito web specificato e a salvarli nella directory specificata come output. Sarà creata una copia esatta del sito web, compresi tutti i file HTML, CSS, JavaScript e immagini.

### Considerazioni sulla sicurezza

È importante notare che l'utilizzo di `goclone` per clonare un sito web senza il consenso del proprietario è un'attività illegale e può comportare conseguenze legali. Questo strumento dovrebbe essere utilizzato solo a fini educativi o con il consenso esplicito del proprietario del sito web.

Inoltre, è fondamentale comprendere che il phishing è un'attività illegale e altamente dannosa. L'utilizzo di una copia clonata di un sito web per scopi di phishing può causare gravi danni alle persone coinvolte. Si consiglia vivamente di utilizzare queste informazioni solo per scopi legittimi e legali.
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Kit di Social Engineering

### Clonare un Sito Web

La clonazione di un sito web è una tecnica comune utilizzata nel social engineering per ingannare le vittime e ottenere informazioni sensibili. Questo metodo coinvolge la creazione di una copia identica di un sito web legittimo, al fine di indurre le persone a inserire le proprie credenziali o altre informazioni riservate.

#### Passo 1: Identificare il Sito Web da Clonare

Prima di tutto, è necessario identificare il sito web che si desidera clonare. Questo può essere un sito di social media, una piattaforma di e-commerce o qualsiasi altro sito che potrebbe contenere informazioni utili per il vostro scopo.

#### Passo 2: Scaricare il Contenuto del Sito Web

Una volta identificato il sito web, è possibile scaricare il suo contenuto utilizzando strumenti come `wget` o `httrack`. Questi strumenti consentono di scaricare l'intero sito web, inclusi file HTML, immagini e altri elementi.

```bash
wget -r -np -k https://www.sito-web-da-clonare.com
```

#### Passo 3: Modificare il Contenuto del Sito Web

Dopo aver scaricato il contenuto del sito web, è possibile apportare le modifiche necessarie per creare una copia personalizzata. Questo potrebbe includere l'aggiunta di un modulo di accesso falso o la modifica di alcune pagine per indurre le vittime a condividere le proprie informazioni.

#### Passo 4: Configurare un Server Web

Una volta apportate le modifiche al sito web clonato, è necessario configurare un server web per ospitare la copia. Questo può essere fatto utilizzando strumenti come Apache o Nginx.

#### Passo 5: Invio di E-mail di Phishing

Infine, è possibile utilizzare l'indirizzo e-mail di destinazione per inviare e-mail di phishing contenenti un link alla copia clonata del sito web. Questo può essere fatto utilizzando strumenti di phishing come GoPhish o SET (Social Engineering Toolkit).

```bash
gophish
```

Una volta che la vittima clicca sul link nella e-mail di phishing, verrà reindirizzata alla copia clonata del sito web, dove potrà essere ingannata per inserire le proprie informazioni sensibili.

Ricordate che la clonazione di un sito web è un'attività illegale e può comportare conseguenze legali. Questa tecnica dovrebbe essere utilizzata solo a fini educativi o con il consenso esplicito del proprietario del sito web.
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
