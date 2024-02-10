# PsExec/Winexec/ScExec

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github.

</details>

## Come funzionano

Il processo è descritto nei seguenti passaggi, illustrando come i binari dei servizi vengono manipolati per ottenere l'esecuzione remota su una macchina di destinazione tramite SMB:

1. **Copia di un binario di servizio nella condivisione ADMIN$ tramite SMB**.
2. **Creazione di un servizio sulla macchina remota** puntando al binario.
3. Il servizio viene **avviato in remoto**.
4. Alla chiusura, il servizio viene **arrestato e il binario viene eliminato**.

### **Processo di esecuzione manuale di PsExec**

Assumendo l'esistenza di un payload eseguibile (creato con msfvenom e offuscato usando Veil per eludere la rilevazione dell'antivirus), chiamato 'met8888.exe', che rappresenta un payload meterpreter reverse_http, vengono eseguiti i seguenti passaggi:

- **Copia del binario**: L'eseguibile viene copiato nella condivisione ADMIN$ da un prompt dei comandi, anche se può essere posizionato ovunque nel filesystem per rimanere nascosto.

- **Creazione di un servizio**: Utilizzando il comando `sc` di Windows, che consente di interrogare, creare ed eliminare servizi Windows in remoto, viene creato un servizio chiamato "meterpreter" che punta al binario caricato.

- **Avvio del servizio**: L'ultimo passaggio prevede l'avvio del servizio, che probabilmente si tradurrà in un errore "time-out" a causa del binario che non è un vero binario di servizio e non restituisce il codice di risposta previsto. Questo errore è irrilevante poiché l'obiettivo principale è l'esecuzione del binario.

L'osservazione del listener di Metasploit rivelerà che la sessione è stata avviata con successo.

[Scopri di più sul comando `sc`](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Trova passaggi più dettagliati su: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**È anche possibile utilizzare il binario PsExec.exe di Windows Sysinternals:**

![](<../../.gitbook/assets/image (165).png>)

È anche possibile utilizzare [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
