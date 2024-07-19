# PsExec/Winexec/ScExec

{% hint style="success" %}
Impara e pratica il hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}

## Come funzionano

Il processo è delineato nei passaggi seguenti, illustrando come i binari di servizio vengono manipolati per ottenere l'esecuzione remota su una macchina target tramite SMB:

1. **Copia del binario di servizio nella condivisione ADMIN$ tramite SMB** viene eseguita.
2. **Creazione di un servizio sulla macchina remota** viene effettuata puntando al binario.
3. Il servizio viene **avviato remotamente**.
4. Al termine, il servizio viene **interrotto e il binario viene eliminato**.

### **Processo di Esecuzione Manuale di PsExec**

Assumendo che ci sia un payload eseguibile (creato con msfvenom e offuscato usando Veil per eludere la rilevazione antivirus), chiamato 'met8888.exe', che rappresenta un payload meterpreter reverse\_http, vengono eseguiti i seguenti passaggi:

* **Copia del binario**: L'eseguibile viene copiato nella condivisione ADMIN$ da un prompt dei comandi, anche se può essere posizionato ovunque nel filesystem per rimanere nascosto.
* **Creazione di un servizio**: Utilizzando il comando Windows `sc`, che consente di interrogare, creare ed eliminare servizi Windows in remoto, viene creato un servizio chiamato "meterpreter" che punta al binario caricato.
* **Avvio del servizio**: L'ultimo passaggio comporta l'avvio del servizio, che probabilmente risulterà in un errore di "timeout" a causa del binario che non è un vero binario di servizio e non riesce a restituire il codice di risposta atteso. Questo errore è irrilevante poiché l'obiettivo principale è l'esecuzione del binario.

L'osservazione del listener di Metasploit rivelerà che la sessione è stata avviata con successo.

[Scopri di più sul comando `sc`](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Trova passaggi più dettagliati in: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Puoi anche utilizzare il binario PsExec.exe di Windows Sysinternals:**

![](<../../.gitbook/assets/image (928).png>)

Puoi anche utilizzare [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

{% hint style="success" %}
Impara e pratica il hacking su AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository su github.

</details>
{% endhint %}
