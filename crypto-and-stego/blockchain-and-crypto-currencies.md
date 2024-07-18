{% hint style="success" %}
Impara e pratica l'Hacking su AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'Hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di Github.

</details>
{% endhint %}


## Concetti di Base

- I **Contratti Intelligenti** sono definiti come programmi che si eseguono su una blockchain quando vengono soddisfatte determinate condizioni, automatizzando l'esecuzione degli accordi senza intermediari.
- Le **Applicazioni Decentralizzate (dApps)** si basano sui contratti intelligenti, presentando un'interfaccia utente amichevole e un backend trasparente e verificabile.
- **Token e Monete** differiscono dove le monete fungono da denaro digitale, mentre i token rappresentano valore o proprietà in contesti specifici.
- I **Token Utility** concedono l'accesso a servizi, e i **Token di Sicurezza** indicano la proprietà di asset.
- **DeFi** sta per Finanza Decentralizzata, offrendo servizi finanziari senza autorità centrali.
- **DEX** e **DAOs** si riferiscono rispettivamente alle Piattaforme di Scambio Decentralizzate e alle Organizzazioni Autonome Decentralizzate.

## Meccanismi di Consenso

I meccanismi di consenso garantiscono la validazione sicura e concordata delle transazioni sulla blockchain:
- Il **Proof of Work (PoW)** si basa sulla potenza computazionale per la verifica delle transazioni.
- Il **Proof of Stake (PoS)** richiede ai validatori di possedere una certa quantità di token, riducendo il consumo energetico rispetto al PoW.

## Concetti Essenziali di Bitcoin

### Transazioni

Le transazioni Bitcoin coinvolgono il trasferimento di fondi tra indirizzi. Le transazioni vengono validate attraverso firme digitali, garantendo che solo il proprietario della chiave privata possa avviare trasferimenti.

#### Componenti Chiave:

- Le **Transazioni Multifirma** richiedono firme multiple per autorizzare una transazione.
- Le transazioni sono composte da **input** (origine dei fondi), **output** (destinazione), **commissioni** (pagate ai minatori) e **script** (regole della transazione).

### Rete Lightning

Mirata a migliorare la scalabilità di Bitcoin consentendo molteplici transazioni all'interno di un canale, inviando solo lo stato finale alla blockchain.

## Preoccupazioni sulla Privacy di Bitcoin

Gli attacchi alla privacy, come la **Proprietà Comune degli Input** e il **Rilevamento dell'Indirizzo di Cambio UTXO**, sfruttano i modelli di transazione. Strategie come i **Mixers** e il **CoinJoin** migliorano l'anonimato oscurando i collegamenti tra le transazioni tra gli utenti.

## Acquisizione di Bitcoin in Modo Anonimo

I metodi includono scambi in contanti, mining e l'uso di mixers. **CoinJoin** mescola più transazioni per complicare la tracciabilità, mentre **PayJoin** maschera i CoinJoin come transazioni regolari per una maggiore privacy.


# Attacchi alla Privacy di Bitcoin

# Riassunto degli Attacchi alla Privacy di Bitcoin

Nel mondo di Bitcoin, la privacy delle transazioni e l'anonimato degli utenti sono spesso oggetto di preoccupazione. Ecco una panoramica semplificata di diversi metodi comuni attraverso i quali gli attaccanti possono compromettere la privacy di Bitcoin.

## **Assunzione della Proprietà Comune degli Input**

È generalmente raro che gli input di diversi utenti vengano combinati in una singola transazione a causa della complessità coinvolta. Quindi, **due indirizzi di input nella stessa transazione sono spesso considerati appartenenti allo stesso proprietario**.

## **Rilevamento dell'Indirizzo di Cambio UTXO**

Un UTXO, o **Unspent Transaction Output**, deve essere interamente speso in una transazione. Se solo una parte viene inviata a un altro indirizzo, il resto va a un nuovo indirizzo di cambio. Gli osservatori possono assumere che questo nuovo indirizzo appartenga al mittente, compromettendo la privacy.

### Esempio
Per mitigare questo, i servizi di mixing o l'uso di più indirizzi possono aiutare a oscurare la proprietà.

## **Esposizione su Social Network e Forum**

Gli utenti a volte condividono i loro indirizzi Bitcoin online, rendendo **facile collegare l'indirizzo al suo proprietario**.

## **Analisi del Grafo delle Transazioni**

Le transazioni possono essere visualizzate come grafi, rivelando potenziali connessioni tra gli utenti in base al flusso di fondi.

## **Euristica dell'Input Non Necessario (Euristica del Cambio Ottimale)**

Questa euristica si basa sull'analisi delle transazioni con input e output multipli per indovinare quale output sia il cambio che ritorna al mittente.

### Esempio
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Se aggiungere più input fa sì che l'output cambia diventi più grande di qualsiasi singolo input, può confondere l'euristica.

### **Riutilizzo Forzato degli Indirizzi**

Gli attaccanti possono inviare piccole quantità a indirizzi già utilizzati, sperando che il destinatario li combini con altri input in transazioni future, collegando così gli indirizzi tra loro.

### Comportamento Corretto del Portafoglio
I portafogli dovrebbero evitare di utilizzare monete ricevute su indirizzi già utilizzati e vuoti per evitare questa fuga di privacy.

## **Altre Tecniche di Analisi della Blockchain**

- **Importi di Pagamento Esatti:** Le transazioni senza resto sono probabilmente tra due indirizzi appartenenti allo stesso utente.
- **Numeri Tondi:** Un numero tondo in una transazione suggerisce che si tratti di un pagamento, con l'output non tondo che probabilmente rappresenta il resto.
- **Fingerprinting del Portafoglio:** I diversi portafogli hanno schemi unici di creazione delle transazioni, consentendo agli analisti di identificare il software utilizzato e potenzialmente l'indirizzo del resto.
- **Correlazioni tra Importo e Tempistica:** Rivelare tempi o importi delle transazioni può rendere le transazioni tracciabili.

## **Analisi del Traffico**

Monitorando il traffico di rete, gli attaccanti possono potenzialmente collegare transazioni o blocchi a indirizzi IP, compromettendo la privacy dell'utente. Questo è particolarmente vero se un'entità gestisce molti nodi Bitcoin, potenziando la loro capacità di monitorare le transazioni.

## Altro
Per una lista completa degli attacchi e delle difese della privacy, visita [Bitcoin Privacy su Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).


# Transazioni Bitcoin Anonime

## Modi per Ottenere Bitcoin in Modo Anonimo

- **Transazioni in Contanti**: Acquisire bitcoin tramite contanti.
- **Alternative in Contanti**: Acquistare carte regalo e scambiarle online per bitcoin.
- **Mining**: Il metodo più privato per guadagnare bitcoin è attraverso il mining, specialmente quando fatto da soli poiché i pool di mining potrebbero conoscere l'indirizzo IP del minatore. [Informazioni sui Pool di Mining](https://en.bitcoin.it/wiki/Pooled_mining)
- **Furto**: Teoricamente, rubare bitcoin potrebbe essere un altro metodo per acquisirli in modo anonimo, anche se è illegale e non raccomandato.

## Servizi di Mixing

Utilizzando un servizio di mixing, un utente può **inviare bitcoin** e ricevere **bitcoin diversi in cambio**, rendendo difficile tracciare il proprietario originale. Tuttavia, ciò richiede fiducia nel servizio per non conservare log e restituire effettivamente i bitcoin. Le opzioni di mixing alternative includono i casinò Bitcoin.

## CoinJoin

**CoinJoin** unisce multiple transazioni da diversi utenti in una sola, complicando il processo per chiunque cerchi di abbinare gli input agli output. Nonostante la sua efficacia, le transazioni con dimensioni di input e output uniche potrebbero ancora essere tracciabili.

Esempi di transazioni che potrebbero aver utilizzato CoinJoin includono `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` e `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Per ulteriori informazioni, visita [CoinJoin](https://coinjoin.io/en). Per un servizio simile su Ethereum, dai un'occhiata a [Tornado Cash](https://tornado.cash), che anonimizza le transazioni con fondi dai minatori.

## PayJoin

Una variante di CoinJoin, **PayJoin** (o P2EP), maschera la transazione tra due parti (ad esempio, un cliente e un commerciante) come una transazione regolare, senza la caratteristica distintiva di output uguali di CoinJoin. Questo rende estremamente difficile rilevare e potrebbe invalidare l'euristica comune di proprietà degli input utilizzata dalle entità di sorveglianza delle transazioni.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Le transazioni come quella sopra potrebbero essere PayJoin, migliorando la privacy rimanendo indistinguibili dalle transazioni standard di bitcoin.

**L'utilizzo di PayJoin potrebbe interrompere significativamente i metodi tradizionali di sorveglianza**, rendendolo uno sviluppo promettente nella ricerca della privacy delle transazioni.


# Migliori pratiche per la privacy nelle criptovalute

## **Tecniche di sincronizzazione del portafoglio**

Per mantenere la privacy e la sicurezza, è cruciale sincronizzare i portafogli con la blockchain. Due metodi si distinguono:

- **Nodo completo**: Scaricando l'intera blockchain, un nodo completo garantisce la massima privacy. Tutte le transazioni mai effettuate sono memorizzate localmente, rendendo impossibile agli avversari identificare quali transazioni o indirizzi l'utente è interessato.
- **Filtraggio dei blocchi lato client**: Questo metodo prevede la creazione di filtri per ogni blocco nella blockchain, consentendo ai portafogli di identificare le transazioni rilevanti senza esporre interessi specifici agli osservatori di rete. I portafogli leggeri scaricano questi filtri, recuperando solo i blocchi completi quando viene trovata una corrispondenza con gli indirizzi dell'utente.

## **Utilizzo di Tor per l'anonimato**

Dato che Bitcoin opera su una rete peer-to-peer, è consigliabile utilizzare Tor per mascherare il proprio indirizzo IP, migliorando la privacy durante l'interazione con la rete.

## **Prevenire il riutilizzo degli indirizzi**

Per salvaguardare la privacy, è vitale utilizzare un nuovo indirizzo per ogni transazione. Il riutilizzo degli indirizzi può compromettere la privacy collegando le transazioni alla stessa entità. I portafogli moderni scoraggiano il riutilizzo degli indirizzi attraverso il loro design.

## **Strategie per la privacy delle transazioni**

- **Transazioni multiple**: Suddividere un pagamento in diverse transazioni può oscurare l'importo della transazione, ostacolando gli attacchi alla privacy.
- **Evitare il resto**: Optare per transazioni che non richiedono output di resto migliora la privacy interrompendo i metodi di rilevamento del resto.
- **Output di resto multipli**: Se evitare il resto non è fattibile, generare output di resto multipli può comunque migliorare la privacy.

# **Monero: Un Faro dell'Anonimato**

Monero affronta la necessità di anonimato assoluto nelle transazioni digitali, stabilendo uno standard elevato per la privacy.

# **Ethereum: Gas e Transazioni**

## **Comprensione del Gas**

Il Gas misura lo sforzo computazionale necessario per eseguire operazioni su Ethereum, con un prezzo in **gwei**. Ad esempio, una transazione che costa 2.310.000 gwei (o 0,00231 ETH) coinvolge un limite di gas e una tassa di base, con una mancia per incentivare i minatori. Gli utenti possono impostare una tassa massima per garantire di non pagare troppo, con l'eccedenza rimborsata.

## **Esecuzione delle Transazioni**

Le transazioni su Ethereum coinvolgono un mittente e un destinatario, che possono essere indirizzi utente o contratti intelligenti. Richiedono una tassa e devono essere minate. Le informazioni essenziali in una transazione includono il destinatario, la firma del mittente, il valore, i dati opzionali, il limite di gas e le tasse. In particolare, l'indirizzo del mittente è dedotto dalla firma, eliminando la necessità di includerlo nei dati della transazione.

Queste pratiche e meccanismi sono fondamentali per chiunque voglia interagire con le criptovalute privilegiando la privacy e la sicurezza.


## Riferimenti

* [https://en.wikipedia.org/wiki/Proof\_of\_stake](https://en.wikipedia.org/wiki/Proof\_of\_stake)
* [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
* [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
* [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
* [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
* [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced\_address\_reuse)
