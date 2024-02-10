# Persistenza del dominio AD CS

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

**Questo è un riassunto delle tecniche di persistenza del dominio condivise in [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**. Consultalo per ulteriori dettagli.

## Falsificazione di certificati con certificati CA rubati - DPERSIST1

Come puoi capire se un certificato è un certificato CA?

È possibile determinare se un certificato è un certificato CA se si verificano diverse condizioni:

- Il certificato è memorizzato sul server CA, con la sua chiave privata protetta dal DPAPI della macchina, o da hardware come un TPM/HSM se il sistema operativo lo supporta.
- I campi Issuer e Subject del certificato corrispondono al nome distintivo del CA.
- È presente un'estensione "CA Version" esclusivamente nei certificati CA.
- Il certificato non ha campi di utilizzo esteso della chiave (EKU).

Per estrarre la chiave privata di questo certificato, lo strumento `certsrv.msc` sul server CA è il metodo supportato tramite l'interfaccia grafica integrata. Tuttavia, questo certificato non differisce dagli altri memorizzati nel sistema; pertanto, possono essere applicati metodi come la tecnica [THEFT2](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) per l'estrazione.

Il certificato e la chiave privata possono anche essere ottenuti utilizzando Certipy con il seguente comando:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Una volta acquisito il certificato CA e la sua chiave privata nel formato `.pfx`, è possibile utilizzare strumenti come [ForgeCert](https://github.com/GhostPack/ForgeCert) per generare certificati validi:
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
{% hint style="warning" %}
L'utente preso di mira per la falsificazione del certificato deve essere attivo e in grado di autenticarsi in Active Directory affinché il processo abbia successo. La falsificazione di un certificato per account speciali come krbtgt è inefficace.
{% endhint %}

Questo certificato falsificato sarà **valido** fino alla data di scadenza specificata e **finché il certificato CA radice è valido** (di solito da 5 a **10+ anni**). È anche valido per le **macchine**, quindi combinato con **S4U2Self**, un attaccante può **mantenere la persistenza su qualsiasi macchina di dominio** finché il certificato CA è valido.\
Inoltre, i **certificati generati** con questo metodo **non possono essere revocati** poiché la CA non ne è a conoscenza.

## Affidarsi a Certificati CA Rogue - DPERSIST2

L'oggetto `NTAuthCertificates` è definito per contenere uno o più **certificati CA** nel suo attributo `cacertificate`, che Active Directory (AD) utilizza. Il processo di verifica da parte del **domain controller** prevede il controllo dell'oggetto `NTAuthCertificates` per una voce corrispondente alla **CA specificata** nel campo Issuer del certificato di autenticazione. L'autenticazione procede se viene trovata una corrispondenza.

Un certificato CA autogenerato può essere aggiunto all'oggetto `NTAuthCertificates` da un attaccante, a condizione che abbia il controllo su questo oggetto AD. Normalmente, solo i membri del gruppo **Enterprise Admin**, insieme a **Domain Admins** o **Amministratori** nel **dominio radice della foresta**, hanno il permesso di modificare questo oggetto. Possono modificare l'oggetto `NTAuthCertificates` utilizzando `certutil.exe` con il comando `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126`, o utilizzando lo [**Strumento di salute PKI**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Questa capacità è particolarmente rilevante quando viene utilizzata in combinazione con un metodo precedentemente descritto che coinvolge ForgeCert per generare dinamicamente i certificati.

## Configurazione Maliziosa - DPERSIST3

Le opportunità di **persistenza** attraverso **modifiche dei descrittori di sicurezza dei componenti AD CS** sono abbondanti. Le modifiche descritte nella sezione "[Escalation di Dominio](domain-escalation.md)" possono essere implementate in modo malizioso da un attaccante con accesso elevato. Ciò include l'aggiunta di "diritti di controllo" (ad esempio, WriteOwner/WriteDACL, ecc.) a componenti sensibili come:

- L'oggetto computer AD del **server CA**
- Il server **RPC/DCOM del server CA**
- Qualsiasi oggetto o contenitore AD discendente in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (ad esempio, il contenitore dei modelli di certificato, il contenitore delle autorità di certificazione, l'oggetto NTAuthCertificates, ecc.)
- **Gruppi AD delegati con diritti di controllo su AD CS** di default o dall'organizzazione (come il gruppo Cert Publishers incorporato e i suoi membri)

Un esempio di implementazione maliziosa potrebbe coinvolgere un attaccante, che ha **permessi elevati** nel dominio, aggiungendo il permesso **`WriteOwner`** al modello di certificato **`User`** predefinito, con l'attaccante come principale per il diritto. Per sfruttare ciò, l'attaccante dovrebbe prima cambiare la proprietà del modello **`User`** a se stesso. Successivamente, il valore **`mspki-certificate-name-flag`** verrebbe impostato su **1** nel modello per abilitare **`ENROLLEE_SUPPLIES_SUBJECT`**, consentendo a un utente di fornire un Nome alternativo del soggetto nella richiesta. Successivamente, l'attaccante potrebbe **registrarsi** utilizzando il **modello**, scegliendo un nome di **amministratore di dominio** come nome alternativo e utilizzare il certificato acquisito per l'autenticazione come DA.


<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
