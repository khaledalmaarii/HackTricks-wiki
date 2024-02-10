<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>


## Concetti di base

- I **Contratti Intelligenti** sono definiti come programmi che vengono eseguiti su una blockchain quando vengono soddisfatte determinate condizioni, automatizzando l'esecuzione degli accordi senza intermediari.
- Le **Applicazioni Decentralizzate (dApp)** si basano sui contratti intelligenti, presentando un'interfaccia utente amichevole e un backend trasparente e verificabile.
- **Token e Monete** differiscono in cui le monete fungono da denaro digitale, mentre i token rappresentano valore o proprietà in contesti specifici.
- I **Token di Utilità** concedono l'accesso a servizi, mentre i **Token di Sicurezza** indicano la proprietà di un asset.
- **DeFi** sta per Finanza Decentralizzata, offrendo servizi finanziari senza autorità centrali.
- **DEX** e **DAO** si riferiscono rispettivamente a Piattaforme di Scambio Decentralizzate e Organizzazioni Autonome Decentralizzate.

## Meccanismi di Consenso

I meccanismi di consenso garantiscono la validazione sicura e concordata delle transazioni sulla blockchain:
- **Proof of Work (PoW)** si basa sulla potenza di calcolo per la verifica delle transazioni.
- **Proof of Stake (PoS)** richiede ai validatori di possedere una determinata quantità di token, riducendo il consumo di energia rispetto a PoW.

## Concetti Essenziali di Bitcoin

### Transazioni

Le transazioni Bitcoin coinvolgono il trasferimento di fondi tra indirizzi. Le transazioni vengono validate attraverso firme digitali, garantendo che solo il proprietario della chiave privata possa avviare trasferimenti.

#### Componenti Chiave:

- Le **Transazioni Multifirma** richiedono firme multiple per autorizzare una transazione.
- Le transazioni sono composte da **input** (origine dei fondi), **output** (destinazione), **commissioni** (pagate ai minatori) e **script** (regole di transazione).

### Lightning Network

Mirata a migliorare la scalabilità di Bitcoin consentendo più transazioni all'interno di un canale, inviando solo lo stato finale alla blockchain.

## Preoccupazioni sulla Privacy di Bitcoin

Gli attacchi alla privacy, come **Common Input Ownership** e **UTXO Change Address Detection**, sfruttano i modelli di transazione. Strategie come **Mixers** e **CoinJoin** migliorano l'anonimato oscurando i collegamenti tra le transazioni tra gli utenti.

## Acquisizione di Bitcoin in Modo Anonimo

I metodi includono scambi in contanti, mining e l'uso di mixers. **CoinJoin** mescola più transazioni per complicare la tracciabilità, mentre **PayJoin** maschera CoinJoin come transazioni regolari per una maggiore privacy.


# Attacchi alla Privacy di Bitcoin

# Riassunto degli Attacchi alla Privacy di Bitcoin

Nel mondo di Bitcoin, la privacy delle transazioni e l'anonimato degli utenti sono spesso oggetto di preoccupazione. Ecco una panoramica semplificata di diversi metodi comuni attraverso i quali gli attaccanti possono compromettere la privacy di Bitcoin.

## **Assunzione di Proprietà Comune degli Input**

È generalmente raro che gli input di utenti diversi vengano combinati in una singola transazione a causa della complessità coinvolta. Pertanto, **due indirizzi di input nella stessa transazione sono spesso considerati appartenenti allo stesso proprietario**.

## **Rilevamento dell'Indirizzo di Cambio UTXO**

Un UTXO, o **Unspent Transaction Output**, deve essere completamente speso in una transazione. Se solo una parte di esso viene inviata a un altro indirizzo, il resto va a un nuovo indirizzo di cambio. Gli osservatori possono presumere che questo nuovo indirizzo appartenga al mittente, compromettendo la privacy.

### Esempio
Per mitigare questo problema, i servizi di mixing o l'uso di indirizzi multipli possono aiutare a oscurare la proprietà.

## **Esposizione su Social Network e Forum**

Gli utenti a volte condividono i loro indirizzi Bitcoin online, rendendo **facile collegare l'indirizzo al suo proprietario**.

## **Analisi del Grafo delle Transazioni**

Le transazioni possono essere visualizzate come grafi, rivelando potenziali connessioni tra gli utenti in base al flusso di fondi.

## **Euristica di Input Non Necessario (Euristica di Cambio Ottimale)**

Questa euristica si basa sull'analisi delle transazioni con input e output multipli per indovinare quale output è il cambio che ritorna al mittente.

### Esempio
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Se l'aggiunta di ulteriori input rende l'output del cambio più grande di qualsiasi singolo input, può confondere l'euristica.

## **Riutilizzo forzato degli indirizzi**

Gli attaccanti possono inviare piccole quantità agli indirizzi utilizzati in precedenza, sperando che il destinatario li combini con altri input in transazioni future, collegando così gli indirizzi tra loro.

### Comportamento corretto del portafoglio
I portafogli dovrebbero evitare di utilizzare monete ricevute su indirizzi vuoti già utilizzati per evitare questa perdita di privacy.

## **Altre tecniche di analisi della blockchain**

- **Importi di pagamento esatti:** Le transazioni senza resto sono probabilmente tra due indirizzi appartenenti allo stesso utente.
- **Numeri tondi:** Un numero tondo in una transazione suggerisce che si tratta di un pagamento, con l'output non tondo probabilmente rappresentante il resto.
- **Fingerprinting del portafoglio:** I diversi portafogli hanno modelli unici di creazione delle transazioni, consentendo agli analisti di identificare il software utilizzato e potenzialmente l'indirizzo di cambio.
- **Correlazioni di importo e timing:** La divulgazione di tempi o importi delle transazioni può renderle tracciabili.

## **Analisi del traffico**

Monitorando il traffico di rete, gli attaccanti possono potenzialmente collegare transazioni o blocchi a indirizzi IP, compromettendo la privacy dell'utente. Questo è particolarmente vero se un'entità gestisce molti nodi Bitcoin, aumentando la loro capacità di monitorare le transazioni.

## Altro
Per una lista completa di attacchi e difese della privacy, visita [Bitcoin Privacy su Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).


# Transazioni Bitcoin anonime

## Modi per ottenere Bitcoin in modo anonimo

- **Transazioni in contanti**: Acquisizione di bitcoin tramite contanti.
- **Alternative in contanti**: Acquisto di carte regalo e scambio online con bitcoin.
- **Mining**: Il metodo più privato per guadagnare bitcoin è attraverso il mining, specialmente quando viene effettuato da soli perché i pool di mining potrebbero conoscere l'indirizzo IP del minatore. [Informazioni sui pool di mining](https://en.bitcoin.it/wiki/Pooled_mining)
- **Furto**: Teoricamente, rubare bitcoin potrebbe essere un altro metodo per acquisirli in modo anonimo, anche se è illegale e non raccomandato.

## Servizi di mixing

Utilizzando un servizio di mixing, un utente può **inviare bitcoin** e ricevere **bitcoin diversi in cambio**, rendendo difficile risalire al proprietario originale. Tuttavia, ciò richiede fiducia nel servizio affinché non conservi registri e restituisca effettivamente i bitcoin. Altre opzioni di mixing includono i casinò Bitcoin.

## CoinJoin

**CoinJoin** unisce più transazioni di diversi utenti in una sola, complicando il processo per chiunque cerchi di abbinare gli input con gli output. Nonostante la sua efficacia, le transazioni con dimensioni di input e output uniche possono ancora essere potenzialmente tracciate.

Esempi di transazioni che potrebbero aver utilizzato CoinJoin includono `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` e `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Per ulteriori informazioni, visita [CoinJoin](https://coinjoin.io/en). Per un servizio simile su Ethereum, dai un'occhiata a [Tornado Cash](https://tornado.cash), che anonimizza le transazioni con fondi provenienti dai minatori.

## PayJoin

Una variante di CoinJoin, **PayJoin** (o P2EP), maschera la transazione tra due parti (ad esempio, un cliente e un commerciante) come una transazione regolare, senza la caratteristica distintiva di output uguali di CoinJoin. Ciò rende estremamente difficile rilevarla e potrebbe invalidare l'euristica comune di proprietà degli input utilizzata dalle entità di sorveglianza delle transazioni.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Le transazioni come quella sopra potrebbero essere PayJoin, migliorando la privacy pur rimanendo indistinguibili dalle transazioni standard di bitcoin.

**L'utilizzo di PayJoin potrebbe interrompere significativamente i metodi di sorveglianza tradizionali**, rendendolo uno sviluppo promettente nella ricerca della privacy delle transazioni.


# Best Practices per la Privacy nelle Criptovalute

## **Tecniche di Sincronizzazione del Portafoglio**

Per mantenere la privacy e la sicurezza, è fondamentale sincronizzare i portafogli con la blockchain. Due metodi si distinguono:

- **Nodo completo**: Scaricando l'intera blockchain, un nodo completo garantisce la massima privacy. Tutte le transazioni mai effettuate vengono memorizzate localmente, rendendo impossibile per gli avversari identificare quali transazioni o indirizzi interessano all'utente.
- **Filtraggio dei blocchi lato client**: Questo metodo prevede la creazione di filtri per ogni blocco nella blockchain, consentendo ai portafogli di identificare le transazioni rilevanti senza esporre interessi specifici agli osservatori di rete. I portafogli leggeri scaricano questi filtri, recuperando solo i blocchi completi quando viene trovata una corrispondenza con gli indirizzi dell'utente.

## **Utilizzo di Tor per l'Anonimato**

Dato che Bitcoin opera su una rete peer-to-peer, è consigliabile utilizzare Tor per mascherare il proprio indirizzo IP, migliorando la privacy durante l'interazione con la rete.

## **Prevenire il Riutilizzo degli Indirizzi**

Per salvaguardare la privacy, è fondamentale utilizzare un nuovo indirizzo per ogni transazione. Il riutilizzo degli indirizzi può compromettere la privacy collegando le transazioni alla stessa entità. I portafogli moderni scoraggiano il riutilizzo degli indirizzi attraverso il loro design.

## **Strategie per la Privacy delle Transazioni**

- **Transazioni multiple**: Suddividere un pagamento in diverse transazioni può oscurare l'importo della transazione, ostacolando gli attacchi alla privacy.
- **Evitare il resto**: Optare per transazioni che non richiedono output di resto migliora la privacy interrompendo i metodi di rilevamento del resto.
- **Output di resto multipli**: Se non è possibile evitare il resto, generare output di resto multipli può comunque migliorare la privacy.

# **Monero: Un Faro dell'Anonimato**

Monero affronta la necessità di assoluta anonimato nelle transazioni digitali, stabilendo uno standard elevato per la privacy.

# **Ethereum: Gas e Transazioni**

## **Comprensione del Gas**

Il Gas misura lo sforzo computazionale necessario per eseguire operazioni su Ethereum, con un prezzo espresso in **gwei**. Ad esempio, una transazione che costa 2.310.000 gwei (o 0,00231 ETH) comporta un limite di gas e una commissione di base, con una mancia per incentivare i minatori. Gli utenti possono impostare una commissione massima per assicurarsi di non pagare troppo, con l'eccesso rimborsato.

## **Esecuzione delle Transazioni**

Le transazioni su Ethereum coinvolgono un mittente e un destinatario, che possono essere indirizzi utente o smart contract. Richiedono una commissione e devono essere estratte. Le informazioni essenziali in una transazione includono il destinatario, la firma del mittente, il valore, i dati opzionali, il limite di gas e le commissioni. In particolare, l'indirizzo del mittente viene dedotto dalla firma, eliminando la necessità di includerlo nei dati della transazione.

Queste pratiche e meccanismi sono fondamentali per chiunque voglia interagire con le criptovalute, dando priorità alla privacy e alla sicurezza.


## Riferimenti

* [https://en.wikipedia.org/wiki/Proof\_of\_stake](https://en.wikipedia.org/wiki/Proof\_of\_stake)
* [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
* [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
* [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
* [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
* [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced\_address\_reuse)


<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) **e a** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
