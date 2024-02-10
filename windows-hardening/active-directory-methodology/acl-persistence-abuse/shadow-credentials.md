# Credenziali Shadow

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata su HackTricks**? O vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al [repo hacktricks](https://github.com/carlospolop/hacktricks) e al [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Introduzione <a href="#3f17" id="3f17"></a>

**Consulta il post originale per [tutte le informazioni su questa tecnica](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**

In sintesi: se puoi scrivere sulla proprietà **msDS-KeyCredentialLink** di un utente/computer, puoi recuperare l'**hash NT di quell'oggetto**.

Nel post viene descritto un metodo per configurare credenziali di autenticazione **chiave pubblica-privata** per acquisire un **Service Ticket** unico che include l'hash NTLM del bersaglio. Questo processo coinvolge l'NTLM_SUPPLEMENTAL_CREDENTIAL crittografato all'interno del Privilege Attribute Certificate (PAC), che può essere decifrato.

### Requisiti

Per applicare questa tecnica, devono essere soddisfatte determinate condizioni:
- È necessario almeno un Domain Controller di Windows Server 2016.
- Il Domain Controller deve avere installato un certificato digitale di autenticazione del server.
- Active Directory deve essere al livello funzionale di Windows Server 2016.
- È richiesto un account con diritti delegati per modificare l'attributo msDS-KeyCredentialLink dell'oggetto di destinazione.

## Abuso

L'abuso di Key Trust per gli oggetti computer comprende passaggi oltre all'ottenimento di un Ticket Granting Ticket (TGT) e all'hash NTLM. Le opzioni includono:
1. Creazione di un **RC4 silver ticket** per agire come utenti privilegiati sull'host previsto.
2. Utilizzo del TGT con **S4U2Self** per l'impersonificazione di **utenti privilegiati**, che richiede modifiche al Service Ticket per aggiungere una classe di servizio al nome del servizio.

Un vantaggio significativo dell'abuso di Key Trust è la limitazione alla chiave privata generata dall'attaccante, evitando la delega a account potenzialmente vulnerabili e non richiedendo la creazione di un account computer, che potrebbe essere difficile da rimuovere.

## Strumenti

### [**Whisker**](https://github.com/eladshamir/Whisker)

Si basa su DSInternals fornendo un'interfaccia C# per questo attacco. Whisker e il suo corrispettivo in Python, **pyWhisker**, consentono la manipolazione dell'attributo `msDS-KeyCredentialLink` per ottenere il controllo sugli account di Active Directory. Questi strumenti supportano varie operazioni come aggiunta, elenco, rimozione e cancellazione delle credenziali chiave dall'oggetto di destinazione.

Le funzioni di **Whisker** includono:
- **Add**: Genera una coppia di chiavi e aggiunge una credenziale chiave.
- **List**: Visualizza tutte le voci delle credenziali chiave.
- **Remove**: Elimina una credenziale chiave specificata.
- **Clear**: Cancella tutte le credenziali chiave, interrompendo potenzialmente l'uso legittimo di WHfB.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Estende la funzionalità di Whisker ai sistemi basati su UNIX, sfruttando Impacket e PyDSInternals per capacità di sfruttamento complete, inclusa la visualizzazione, l'aggiunta e la rimozione di KeyCredentials, nonché l'importazione ed esportazione in formato JSON.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray mira a **sfruttare le autorizzazioni GenericWrite/GenericAll che i gruppi di utenti ampi possono avere sugli oggetti di dominio** per applicare ampiamente ShadowCredentials. Comprende l'accesso al dominio, la verifica del livello funzionale del dominio, l'enumerazione degli oggetti di dominio e il tentativo di aggiungere KeyCredentials per l'acquisizione di TGT e la rivelazione dell'hash NT. Le opzioni di pulizia e le tattiche di sfruttamento ricorsivo ne migliorano l'utilità.


## Riferimenti

* [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
* [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)
* [https://github.com/ShutdownRepo/pywhisker](https://github.com/ShutdownRepo/pywhisker)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata su HackTricks**? o vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al [repo hacktricks](https://github.com/carlospolop/hacktricks) e al [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
