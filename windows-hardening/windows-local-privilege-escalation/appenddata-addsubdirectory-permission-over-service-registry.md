<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository GitHub di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


**Il post originale è** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Sommario

Sono state trovate due chiavi di registro scrivibili dall'utente corrente:

- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**

Si è suggerito di verificare i permessi del servizio **RpcEptMapper** utilizzando l'interfaccia grafica di **regedit**, in particolare la scheda **Permessi effettivi** delle **Impostazioni di sicurezza avanzate**. Questo approccio consente di valutare i permessi concessi a utenti o gruppi specifici senza la necessità di esaminare singolarmente ogni voce di controllo di accesso (ACE).

È stata mostrata una schermata con i permessi assegnati a un utente con privilegi limitati, tra cui spiccava il permesso **Crea sottocartella**. Questo permesso, anche chiamato **AppendData/AddSubdirectory**, corrisponde alle scoperte dello script.

È stata notata l'incapacità di modificare direttamente determinati valori, ma la capacità di creare nuove sottocartelle. È stato evidenziato un esempio di tentativo di modificare il valore **ImagePath**, che ha prodotto un messaggio di accesso negato.

Nonostante queste limitazioni, è stata identificata la possibilità di un'escalation dei privilegi attraverso l'utilizzo della sottocartella **Performance** all'interno della struttura di registro del servizio **RpcEptMapper**, una sottocartella non presente di default. Ciò potrebbe consentire la registrazione di DLL e il monitoraggio delle prestazioni.

È stata consultata la documentazione sulla sottocartella **Performance** e il suo utilizzo per il monitoraggio delle prestazioni, il che ha portato allo sviluppo di una DLL di prova. Questa DLL, che dimostra l'implementazione delle funzioni **OpenPerfData**, **CollectPerfData** e **ClosePerfData**, è stata testata tramite **rundll32**, confermando il suo successo operativo.

L'obiettivo era costringere il servizio **RPC Endpoint Mapper** a caricare la DLL di Performance creata. Le osservazioni hanno rivelato che l'esecuzione di query di classe WMI relative ai dati di prestazione tramite PowerShell ha comportato la creazione di un file di log, consentendo l'esecuzione di codice arbitrario nel contesto di **LOCAL SYSTEM**, garantendo così privilegi elevati.

È stata sottolineata la persistenza e le potenziali implicazioni di questa vulnerabilità, evidenziando la sua rilevanza per le strategie di post-exploitation, il movimento laterale e l'evasione dei sistemi antivirus/EDR.

Sebbene la vulnerabilità sia stata inizialmente divulgata involontariamente tramite lo script, è stato sottolineato che la sua sfruttabilità è limitata a versioni obsolete di Windows (ad esempio, **Windows 7 / Server 2008 R2**) e richiede l'accesso locale.

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository GitHub di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
