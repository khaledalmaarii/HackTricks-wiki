# BloodHound e Altri Strumenti di Enumerazione AD

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata su HackTricks**? O vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al [repo hacktricks](https://github.com/carlospolop/hacktricks) e al [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) fa parte di Sysinternal Suite:

> Un visualizzatore e editor avanzato di Active Directory (AD). Puoi utilizzare AD Explorer per navigare facilmente in un database AD, definire posizioni preferite, visualizzare le proprietà degli oggetti e gli attributi senza aprire finestre di dialogo, modificare le autorizzazioni, visualizzare lo schema di un oggetto ed eseguire ricerche sofisticate che puoi salvare e ripetere.

### Snapshot

AD Explorer può creare snapshot di un AD in modo da poterlo controllare offline.\
Può essere utilizzato per scoprire vulnerabilità offline o confrontare diversi stati del database AD nel tempo.

Ti verranno richiesti il nome utente, la password e la direzione per la connessione (è richiesto qualsiasi utente AD).

Per fare uno snapshot di AD, vai su `File` --> `Crea Snapshot` e inserisci un nome per lo snapshot.

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon) è uno strumento che estrae e combina vari artefatti da un ambiente AD. Le informazioni possono essere presentate in un **report** Microsoft Excel **formattato in modo speciale** che include viste di riepilogo con metriche per facilitare l'analisi e fornire un quadro completo dello stato attuale dell'ambiente AD di destinazione.
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

Da [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

> BloodHound è un'applicazione web Javascript a pagina singola, costruita su [Linkurious](http://linkurio.us/), compilata con [Electron](http://electron.atom.io/), con un database [Neo4j](https://neo4j.com/) alimentato da un raccoglitore di dati C#.

BloodHound utilizza la teoria dei grafi per rivelare le relazioni nascoste e spesso non intenzionali all'interno di un ambiente Active Directory o Azure. Gli attaccanti possono utilizzare BloodHound per identificare facilmente percorsi di attacco altamente complessi che altrimenti sarebbe impossibile identificare rapidamente. I difensori possono utilizzare BloodHound per identificare ed eliminare gli stessi percorsi di attacco. Sia le squadre blu che le squadre rosse possono utilizzare BloodHound per ottenere facilmente una comprensione più approfondita delle relazioni di privilegio in un ambiente Active Directory o Azure.

Quindi, [Bloodhound](https://github.com/BloodHoundAD/BloodHound) è uno strumento incredibile che può enumerare automaticamente un dominio, salvare tutte le informazioni, trovare possibili percorsi di escalation dei privilegi e mostrare tutte le informazioni utilizzando grafici.

Bloodhound è composto da 2 parti principali: **ingestors** e l'**applicazione di visualizzazione**.

Gli **ingestors** vengono utilizzati per **enumerare il dominio ed estrarre tutte le informazioni** in un formato che l'applicazione di visualizzazione comprenderà.

L'**applicazione di visualizzazione utilizza neo4j** per mostrare come tutte le informazioni sono correlate e per mostrare diversi modi per scalare i privilegi nel dominio.

### Installazione
Dopo la creazione di BloodHound CE, l'intero progetto è stato aggiornato per facilitarne l'uso con Docker. Il modo più semplice per iniziare è utilizzare la configurazione preconfigurata di Docker Compose.

1. Installa Docker Compose. Dovrebbe essere incluso nell'installazione di [Docker Desktop](https://www.docker.com/products/docker-desktop/).
2. Esegui:
```
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. Trova la password generata casualmente nell'output del terminale di Docker Compose.
4. In un browser, vai su http://localhost:8080/ui/login. Accedi con un nome utente di admin e la password generata casualmente dai log.

Dopo questo dovrai cambiare la password generata casualmente e avrai la nuova interfaccia pronta, da cui puoi scaricare direttamente gli ingestori.

### SharpHound

Hanno diverse opzioni, ma se vuoi eseguire SharpHound da un PC connesso al dominio, utilizzando il tuo utente corrente ed estrarre tutte le informazioni possibili, puoi fare:
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> Puoi leggere ulteriori informazioni su **CollectionMethod** e sul loop di sessione [qui](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained)

Se desideri eseguire SharpHound utilizzando credenziali diverse, puoi creare una sessione CMD netonly e eseguire SharpHound da lì:
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**Scopri di più su Bloodhound su ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)


## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) è uno strumento per trovare **vulnerabilità** nell'Active Directory associate alle **Group Policy**. \
È necessario **eseguire group3r** da un host all'interno del dominio utilizzando **qualsiasi utente di dominio**.
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

[**PingCastle**](https://www.pingcastle.com/documentation/) **valuta la postura di sicurezza di un ambiente AD** e fornisce un bel **report** con grafici.

Per eseguirlo, puoi eseguire il file binario `PingCastle.exe` e avvierà una **sessione interattiva** presentando un menu di opzioni. L'opzione predefinita da utilizzare è **`healthcheck`** che stabilirà una **panoramica** di base del **dominio**, e troverà **configurazioni errate** e **vulnerabilità**.&#x20;

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata in HackTricks**? o vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al [repo hacktricks](https://github.com/carlospolop/hacktricks) e al [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
