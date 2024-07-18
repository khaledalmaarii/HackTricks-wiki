# Altri Trucchi Web

{% hint style="success" %}
Impara e pratica l'Hacking su AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'Hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e ai repository di [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

### Header Host

Molte volte il back-end si fida dell'**header Host** per eseguire alcune azioni. Ad esempio, potrebbe utilizzarne il valore come **dominio per inviare un reset della password**. Quindi, quando ricevi una email con un link per reimpostare la password, il dominio utilizzato è quello inserito nell'header Host. Quindi, puoi richiedere il reset della password di altri utenti e cambiare il dominio con uno controllato da te per rubare i codici di reset delle loro password. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
Nota che potrebbe non essere necessario aspettare che l'utente faccia clic sul link di reset della password per ottenere il token, poiché potrebbero farlo anche **filtri antispam o altri dispositivi/bot intermedi per analizzarlo**.
{% endhint %}

### Booleani di Sessione

A volte, quando completi correttamente una verifica, il back-end **aggiungerà semplicemente un booleano con il valore "True" a un attributo di sicurezza della tua sessione**. Quindi, un endpoint diverso saprà se hai superato con successo quel controllo.\
Tuttavia, se **superi il controllo** e alla tua sessione viene assegnato quel valore "True" nell'attributo di sicurezza, puoi provare ad **accedere ad altre risorse** che **dipendono dallo stesso attributo** ma a cui **non dovresti avere autorizzazioni** per accedere. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Funzionalità di Registrazione

Prova a registrarti come utente già esistente. Prova anche a utilizzare caratteri equivalenti (punti, molti spazi e Unicode).

### Acquisizione di Email

Registra un'email, prima di confermarla cambia l'email, quindi, se la nuova email di conferma viene inviata alla prima email registrata, puoi acquisire qualsiasi email. Oppure se puoi abilitare la seconda email confermando la prima, puoi anche acquisire qualsiasi account.

### Accesso al servizio di assistenza interno delle aziende che utilizzano Atlassian

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### Metodo TRACE

Gli sviluppatori potrebbero dimenticare di disabilitare varie opzioni di debug nell'ambiente di produzione. Ad esempio, il metodo HTTP `TRACE` è progettato per scopi diagnostici. Se abilitato, il server web risponderà alle richieste che utilizzano il metodo `TRACE` ripetendo nella risposta l'esatta richiesta ricevuta. Questo comportamento è spesso innocuo, ma talvolta porta a una divulgazione di informazioni, come il nome degli header di autenticazione interni che potrebbero essere aggiunti alle richieste dai proxy inversi.![Immagine per post](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Immagine per post](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


{% hint style="success" %}
Impara e pratica l'Hacking su AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'Hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e ai repository di [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
