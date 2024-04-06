# Altri Trucchi Web

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su GitHub.

</details>

### Header Host

Spesso il back-end si fida dell'**header Host** per eseguire alcune azioni. Ad esempio, potrebbe utilizzarne il valore come **dominio per inviare un reset della password**. Quindi, quando ricevi una email con un link per reimpostare la password, il dominio utilizzato è quello inserito nell'header Host. Quindi, puoi richiedere il reset della password di altri utenti e cambiare il dominio con uno controllato da te per rubare i loro codici di reset della password. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
Nota che potrebbe non essere necessario aspettare che l'utente faccia clic sul link di reset della password per ottenere il token, poiché potrebbero anche **i filtri antispam o altri dispositivi/bot intermediari faranno clic su di esso per analizzarlo**.
{% endhint %}

### Booleani di sessione

A volte, quando completi correttamente una verifica, il back-end **aggiunge semplicemente un booleano con il valore "True" a un attributo di sicurezza della tua sessione**. Successivamente, un endpoint diverso saprà se hai superato con successo quel controllo.\
Tuttavia, se **superi il controllo** e alla tua sessione viene assegnato quel valore "True" nell'attributo di sicurezza, puoi provare ad **accedere ad altre risorse** che **dipendono dallo stesso attributo** ma a cui **non dovresti avere le autorizzazioni** per accedere. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Funzionalità di registrazione

Prova a registrarti come utente già esistente. Prova anche a utilizzare caratteri equivalenti (punti, molti spazi e Unicode).

### Acquisizione di email

Registra un'email, prima di confermarla cambia l'email, quindi, se la nuova email di conferma viene inviata alla prima email registrata, puoi acquisire qualsiasi email. Oppure, se puoi abilitare la seconda email confermando la prima, puoi anche acquisire qualsiasi account.

### Accesso al servicedesk interno delle aziende che utilizzano Atlassian

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### Metodo TRACE

Gli sviluppatori potrebbero dimenticare di disabilitare varie opzioni di debug nell'ambiente di produzione. Ad esempio, il metodo HTTP `TRACE` è progettato per scopi diagnostici. Se abilitato, il server web risponderà alle richieste che utilizzano il metodo `TRACE` ripetendo nella risposta la richiesta esatta ricevuta. Questo comportamento è spesso innocuo, ma talvolta porta alla divulgazione di informazioni, come il nome degli header di autenticazione interni che possono essere aggiunti alle richieste dai proxy inversi.![Image for post](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su GitHub.

</details>
