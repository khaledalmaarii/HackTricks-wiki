# macOS Dirty NIB

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository GitHub di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Per ulteriori dettagli sulla tecnica, consulta il post originale su: [https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/).** Ecco un riassunto:

I file NIB, parte dell'ecosistema di sviluppo di Apple, sono destinati a definire **elementi dell'interfaccia utente** e le loro interazioni nelle applicazioni. Comprendono oggetti serializzati come finestre e pulsanti e vengono caricati durante l'esecuzione. Nonostante il loro utilizzo continuo, Apple ora consiglia l'uso di Storyboard per una visualizzazione più completa del flusso dell'interfaccia utente.

### Preoccupazioni per la sicurezza con i file NIB
È importante notare che i file NIB possono rappresentare un rischio per la sicurezza. Hanno il potenziale per **eseguire comandi arbitrari** e le modifiche ai file NIB all'interno di un'app non impediscono a Gatekeeper di eseguire l'app, rappresentando una minaccia significativa.

### Processo di iniezione di Dirty NIB
#### Creazione e configurazione di un file NIB
1. **Configurazione iniziale**:
- Crea un nuovo file NIB utilizzando XCode.
- Aggiungi un oggetto all'interfaccia, impostando la sua classe su `NSAppleScript`.
- Configura la proprietà `source` iniziale tramite gli attributi di runtime definiti dall'utente.

2. **Gadget di esecuzione del codice**:
- La configurazione facilita l'esecuzione di AppleScript su richiesta.
- Integra un pulsante per attivare l'oggetto `Apple Script`, che attiva specificamente il selettore `executeAndReturnError:`.

3. **Test**:
- Uno script Apple semplice per scopi di test:
```bash
set theDialogText to "PWND"
display dialog theDialogText
```
- Prova eseguendo il debug in XCode e facendo clic sul pulsante.

#### Individuazione di un'applicazione di destinazione (Esempio: Pages)
1. **Preparazione**:
- Copia l'applicazione di destinazione (ad esempio, Pages) in una directory separata (ad esempio, `/tmp/`).
- Avvia l'applicazione per evitare problemi con Gatekeeper e memorizzala nella cache.

2. **Sovrascrittura del file NIB**:
- Sostituisci un file NIB esistente (ad esempio, About Panel NIB) con il file DirtyNIB creato.

3. **Esecuzione**:
- Avvia l'esecuzione interagendo con l'applicazione (ad esempio, selezionando la voce di menu `About`).

#### Proof of Concept: Accesso ai dati dell'utente
- Modifica lo script Apple per accedere ed estrarre i dati dell'utente, come le foto, senza il consenso dell'utente.

### Esempio di codice: File .xib maligno
- Accedi e esamina un [**esempio di un file .xib maligno**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4) che dimostra l'esecuzione di codice arbitrario.

### Affrontare i vincoli di avvio
- I vincoli di avvio impediscono l'esecuzione dell'applicazione da posizioni impreviste (ad esempio, `/tmp`).
- È possibile identificare le app non protette dai vincoli di avvio e prendere di mira l'iniezione di file NIB su di esse.

### Ulteriori protezioni macOS
A partire da macOS Sonoma, le modifiche all'interno dei pacchetti delle app sono limitate. Tuttavia, i metodi precedenti prevedevano:
1. Copiare l'applicazione in una posizione diversa (ad esempio, `/tmp/`).
2. Rinominare le directory all'interno del pacchetto dell'app per aggirare le protezioni iniziali.
3. Dopo aver eseguito l'applicazione per registrarsi con Gatekeeper, modificare il pacchetto dell'app (ad esempio, sostituendo MainMenu.nib con Dirty.nib).
4. Rinominare nuovamente le directory e rieseguire l'applicazione per eseguire il file NIB iniettato.

**Nota**: Gli aggiornamenti recenti di macOS hanno mitigato questa vulnerabilità impedendo le modifiche ai file all'interno dei pacchetti delle app dopo la memorizzazione nella cache di Gatekeeper, rendendo la vulnerabilità inefficace.


<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository GitHub di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
