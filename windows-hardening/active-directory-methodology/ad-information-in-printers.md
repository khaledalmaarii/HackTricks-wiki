<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


Ci sono diversi blog su Internet che **evidenziano i pericoli di lasciare le stampanti configurate con LDAP con credenziali di accesso predefinite/deboli**.\
Questo perché un attaccante potrebbe **ingannare la stampante per autenticarsi contro un server LDAP falso** (tipicamente un `nc -vv -l -p 444` è sufficiente) e catturare le **credenziali della stampante in chiaro**.

Inoltre, diverse stampanti conterranno **registri con nomi utente** o potrebbero persino essere in grado di **scaricare tutti i nomi utente** dal Domain Controller.

Tutte queste **informazioni sensibili** e la comune **mancanza di sicurezza** rendono le stampanti molto interessanti per gli attaccanti.

Alcuni blog sull'argomento:

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## Configurazione della stampante
- **Posizione**: L'elenco dei server LDAP si trova in: `Rete > Impostazioni LDAP > Configurazione LDAP`.
- **Comportamento**: L'interfaccia consente modifiche al server LDAP senza reinserire le credenziali, mirando alla comodità dell'utente ma comportando rischi per la sicurezza.
- **Sfruttamento**: Lo sfruttamento prevede il reindirizzamento dell'indirizzo del server LDAP verso una macchina controllata e l'utilizzo della funzione "Test connessione" per catturare le credenziali.

## Cattura delle credenziali

**Per passaggi più dettagliati, fare riferimento alla [fonte](https://grimhacker.com/2018/03/09/just-a-printer/) originale.**

### Metodo 1: Netcat Listener
Potrebbe essere sufficiente un semplice listener di netcat:
```bash
sudo nc -k -v -l -p 386
```
Tuttavia, il successo di questo metodo varia.

### Metodo 2: Server LDAP completo con Slapd
Un approccio più affidabile prevede l'installazione di un server LDAP completo perché la stampante esegue una connessione null bind seguita da una query prima di tentare il binding delle credenziali.

1. **Configurazione del server LDAP**: La guida segue i passaggi di [questa fonte](https://www.server-world.info/en/note?os=Fedora_26&p=openldap).
2. **Passaggi chiave**:
- Installare OpenLDAP.
- Configurare la password dell'amministratore.
- Importare gli schemi di base.
- Impostare il nome di dominio sul database LDAP.
- Configurare il TLS LDAP.
3. **Esecuzione del servizio LDAP**: Una volta configurato, il servizio LDAP può essere avviato utilizzando:
```bash
slapd -d 2
```
## Riferimenti
* [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)


<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
