# PsExec/Winexec/ScExec

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Come funzionano

Il processo è descritto nei passaggi seguenti, illustrando come i binari dei servizi vengono manipolati per ottenere l'esecuzione remota su una macchina di destinazione tramite SMB:

1. Viene eseguita la **copia di un binario di servizio sulla condivisione ADMIN$ tramite SMB**.
2. Viene effettuata la **creazione di un servizio sulla macchina remota** puntando al binario.
3. Il servizio viene **avviato in remoto**.
4. All'uscita, il servizio viene **arrestato e il binario viene eliminato**.

### **Processo di Esecuzione Manuale di PsExec**

Assumendo che ci sia un payload eseguibile (creato con msfvenom e offuscato usando Veil per evitare la rilevazione dell'antivirus), chiamato 'met8888.exe', che rappresenta un payload meterpreter reverse\_http, vengono eseguiti i seguenti passaggi:

* **Copia del binario**: L'eseguibile viene copiato sulla condivisione ADMIN$ da un prompt dei comandi, anche se può essere posizionato ovunque nel filesystem per rimanere nascosto.
* **Creazione di un servizio**: Utilizzando il comando Windows `sc`, che consente di interrogare, creare ed eliminare servizi Windows in remoto, viene creato un servizio chiamato "meterpreter" per puntare al binario caricato.
* **Avvio del servizio**: Il passaggio finale prevede l'avvio del servizio, che probabilmente comporterà un errore "time-out" a causa del binario che non è un vero binario di servizio e non restituisce il codice di risposta atteso. Questo errore è trascurabile poiché l'obiettivo principale è l'esecuzione del binario.

L'osservazione del listener di Metasploit rivelerà che la sessione è stata avviata con successo.

[Scopri di più sul comando `sc`](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Trova passaggi più dettagliati in: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Potresti anche utilizzare il binario Windows Sysinternals PsExec.exe:**

![](<../../.gitbook/assets/image (928).png>)

Potresti anche utilizzare [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e ai repository github di [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
