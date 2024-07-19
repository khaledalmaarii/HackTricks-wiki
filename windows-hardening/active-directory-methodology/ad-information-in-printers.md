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


Ci sono diversi blog su Internet che **mettono in evidenza i pericoli di lasciare le stampanti configurate con LDAP con credenziali di accesso predefinite/deboli**.\
Questo perché un attaccante potrebbe **ingannare la stampante per autenticarsi contro un server LDAP malevolo** (tipicamente un `nc -vv -l -p 444` è sufficiente) e catturare le **credenziali della stampante in chiaro**.

Inoltre, diverse stampanti conterranno **log con nomi utente** o potrebbero persino essere in grado di **scaricare tutti i nomi utente** dal Domain Controller.

Tutte queste **informazioni sensibili** e la comune **mancanza di sicurezza** rendono le stampanti molto interessanti per gli attaccanti.

Alcuni blog sull'argomento:

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## Configurazione della Stampante
- **Posizione**: L'elenco dei server LDAP si trova in: `Network > LDAP Setting > Setting Up LDAP`.
- **Comportamento**: L'interfaccia consente modifiche al server LDAP senza reinserire le credenziali, mirando alla comodità dell'utente ma ponendo rischi per la sicurezza.
- **Sfruttamento**: Lo sfruttamento comporta il reindirizzamento dell'indirizzo del server LDAP a una macchina controllata e l'utilizzo della funzione "Test Connection" per catturare le credenziali.

## Cattura delle Credenziali

**Per passaggi più dettagliati, fare riferimento alla [fonte](https://grimhacker.com/2018/03/09/just-a-printer/).**

### Metodo 1: Netcat Listener
Un semplice listener netcat potrebbe essere sufficiente:
```bash
sudo nc -k -v -l -p 386
```
Tuttavia, il successo di questo metodo varia.

### Metodo 2: Server LDAP Completo con Slapd
Un approccio più affidabile prevede l'impostazione di un server LDAP completo perché la stampante esegue un null bind seguito da una query prima di tentare il binding delle credenziali.

1. **Impostazione del Server LDAP**: La guida segue i passaggi da [questa fonte](https://www.server-world.info/en/note?os=Fedora_26&p=openldap).
2. **Passaggi Chiave**:
- Installare OpenLDAP.
- Configurare la password di amministrazione.
- Importare schemi di base.
- Impostare il nome di dominio nel DB LDAP.
- Configurare LDAP TLS.
3. **Esecuzione del Servizio LDAP**: Una volta impostato, il servizio LDAP può essere eseguito utilizzando:
```bash
slapd -d 2
```
## Riferimenti
* [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)


{% hint style="success" %}
Impara e pratica AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

</details>
{% endhint %}
