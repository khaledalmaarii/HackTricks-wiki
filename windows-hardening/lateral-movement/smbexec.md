# SmbExec/ScExec

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Come Funziona

**Smbexec** è uno strumento utilizzato per l'esecuzione remota di comandi su sistemi Windows, simile a **Psexec**, ma evita di inserire file dannosi nel sistema di destinazione.

### Punti Chiave su **SMBExec**

- Funziona creando un servizio temporaneo (ad esempio, "BTOBTO") sulla macchina di destinazione per eseguire comandi tramite cmd.exe (%COMSPEC%), senza rilasciare alcun binario.
- Nonostante il suo approccio stealthy, genera log degli eventi per ogni comando eseguito, offrendo una forma di "shell" non interattiva.
- Il comando per connettersi utilizzando **Smbexec** è simile a questo:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Esecuzione di comandi senza binari

- **Smbexec** consente l'esecuzione diretta di comandi tramite binPaths del servizio, eliminando la necessità di binari fisici nel target.
- Questo metodo è utile per l'esecuzione di comandi one-time su un target Windows. Ad esempio, abbinandolo al modulo `web_delivery` di Metasploit, consente l'esecuzione di un payload Meterpreter inverso mirato a PowerShell.
- Creando un servizio remoto sulla macchina dell'attaccante con binPath impostato per eseguire il comando fornito tramite cmd.exe, è possibile eseguire con successo il payload, ottenendo il callback e l'esecuzione del payload con il listener di Metasploit, anche se si verificano errori di risposta del servizio.

### Esempio di comandi

La creazione e l'avvio del servizio possono essere realizzati con i seguenti comandi:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
Per ulteriori dettagli, consulta [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)


## Riferimenti
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
