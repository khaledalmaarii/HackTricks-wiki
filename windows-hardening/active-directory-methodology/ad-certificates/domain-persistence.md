# AD CS Domain Persistence

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

**Questo è un riepilogo delle tecniche di persistenza del dominio condivise in [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**. Controllalo per ulteriori dettagli.

## Forging Certificates with Stolen CA Certificates - DPERSIST1

Come puoi sapere se un certificato è un certificato CA?

Si può determinare che un certificato è un certificato CA se sono soddisfatte diverse condizioni:

- Il certificato è memorizzato sul server CA, con la sua chiave privata protetta dal DPAPI della macchina, o da hardware come un TPM/HSM se il sistema operativo lo supporta.
- I campi Issuer e Subject del certificato corrispondono al nome distinto della CA.
- È presente un'estensione "CA Version" esclusivamente nei certificati CA.
- Il certificato non ha campi Extended Key Usage (EKU).

Per estrarre la chiave privata di questo certificato, il tool `certsrv.msc` sul server CA è il metodo supportato tramite l'interfaccia grafica integrata. Tuttavia, questo certificato non differisce da altri memorizzati all'interno del sistema; pertanto, possono essere applicati metodi come la [tecnica THEFT2](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) per l'estrazione.

Il certificato e la chiave privata possono anche essere ottenuti utilizzando Certipy con il seguente comando:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Una volta acquisito il certificato CA e la sua chiave privata in formato `.pfx`, strumenti come [ForgeCert](https://github.com/GhostPack/ForgeCert) possono essere utilizzati per generare certificati validi:
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
L'utente mirato per la falsificazione del certificato deve essere attivo e in grado di autenticarsi in Active Directory affinché il processo abbia successo. Falsificare un certificato per account speciali come krbtgt è inefficace.
{% endhint %}

Questo certificato falsificato sarà **valido** fino alla data di scadenza specificata e **finché il certificato CA radice è valido** (di solito da 5 a **10+ anni**). È anche valido per **macchine**, quindi combinato con **S4U2Self**, un attaccante può **mantenere la persistenza su qualsiasi macchina di dominio** finché il certificato CA è valido.\
Inoltre, i **certificati generati** con questo metodo **non possono essere revocati** poiché la CA non ne è a conoscenza.

## Fiducia nei certificati CA non autorizzati - DPERSIST2

L'oggetto `NTAuthCertificates` è definito per contenere uno o più **certificati CA** all'interno del suo attributo `cacertificate`, che Active Directory (AD) utilizza. Il processo di verifica da parte del **controller di dominio** prevede il controllo dell'oggetto `NTAuthCertificates` per un'entrata che corrisponde alla **CA specificata** nel campo Issuer del **certificato** di autenticazione. L'autenticazione procede se viene trovata una corrispondenza.

Un certificato CA autofirmato può essere aggiunto all'oggetto `NTAuthCertificates` da un attaccante, a condizione che abbia il controllo su questo oggetto AD. Normalmente, solo i membri del gruppo **Enterprise Admin**, insieme a **Domain Admins** o **Administrators** nel **dominio radice della foresta**, hanno il permesso di modificare questo oggetto. Possono modificare l'oggetto `NTAuthCertificates` utilizzando `certutil.exe` con il comando `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126`, oppure impiegando il [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Questa capacità è particolarmente rilevante quando utilizzata in combinazione con un metodo precedentemente descritto che coinvolge ForgeCert per generare certificati dinamicamente.

## Configurazione malevola - DPERSIST3

Le opportunità di **persistenza** attraverso **modifiche ai descrittori di sicurezza dei componenti AD CS** sono abbondanti. Le modifiche descritte nella sezione "[Domain Escalation](domain-escalation.md)" possono essere implementate in modo malevolo da un attaccante con accesso elevato. Questo include l'aggiunta di "diritti di controllo" (ad es., WriteOwner/WriteDACL/etc.) a componenti sensibili come:

- L'oggetto computer AD del **server CA**
- Il **server RPC/DCOM del server CA**
- Qualsiasi **oggetto o contenitore AD discendente** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (ad esempio, il contenitore dei modelli di certificato, il contenitore delle autorità di certificazione, l'oggetto NTAuthCertificates, ecc.)
- **Gruppi AD a cui sono delegati diritti per controllare AD CS** per impostazione predefinita o dall'organizzazione (come il gruppo Cert Publishers integrato e qualsiasi dei suoi membri)

Un esempio di implementazione malevola coinvolgerebbe un attaccante, che ha **permessi elevati** nel dominio, nell'aggiungere il permesso **`WriteOwner`** al modello di certificato **`User`** predefinito, con l'attaccante che è il principale per il diritto. Per sfruttare questo, l'attaccante cambierebbe prima la proprietà del modello **`User`** a se stesso. Successivamente, il **`mspki-certificate-name-flag`** verrebbe impostato su **1** sul modello per abilitare **`ENROLLEE_SUPPLIES_SUBJECT`**, consentendo a un utente di fornire un Subject Alternative Name nella richiesta. Successivamente, l'attaccante potrebbe **iscriversi** utilizzando il **modello**, scegliendo un nome di **amministratore di dominio** come nome alternativo, e utilizzare il certificato acquisito per l'autenticazione come DA.


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
