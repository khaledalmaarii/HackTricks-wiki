# Furto di certificati AD CS

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository GitHub di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Questo è un breve riassunto dei capitoli sul furto dei certificati dell'interessante ricerca di [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**


## Cosa posso fare con un certificato

Prima di vedere come rubare i certificati, ecco alcune informazioni su come scoprire a cosa serve il certificato:
```powershell
# Powershell
$CertPath = "C:\path\to\cert.pfx"
$CertPass = "P@ssw0rd"
$Cert = New-Object
System.Security.Cryptography.X509Certificates.X509Certificate2 @($CertPath, $CertPass)
$Cert.EnhancedKeyUsageList

# cmd
certutil.exe -dump -v cert.pfx
```
## Esportazione dei certificati utilizzando le API crittografiche - FURTO1

In una **sessione desktop interattiva**, l'estrazione di un certificato utente o di una macchina, insieme alla chiave privata, può essere facilmente eseguita, in particolare se la **chiave privata è esportabile**. Ciò può essere ottenuto navigando nel certificato in `certmgr.msc`, facendo clic con il pulsante destro del mouse su di esso e selezionando `Tutte le attività → Esporta` per generare un file .pfx protetto da password.

Per un **approccio programmato**, sono disponibili strumenti come il cmdlet PowerShell `ExportPfxCertificate` o progetti come [CertStealer di TheWover](https://github.com/TheWover/CertStealer). Questi utilizzano il **Microsoft CryptoAPI** (CAPI) o la Cryptography API: Next Generation (CNG) per interagire con il deposito dei certificati. Queste API forniscono una serie di servizi crittografici, inclusi quelli necessari per la memorizzazione e l'autenticazione dei certificati.

Tuttavia, se una chiave privata è impostata come non esportabile, sia CAPI che CNG bloccheranno normalmente l'estrazione di tali certificati. Per aggirare questa restrizione, è possibile utilizzare strumenti come **Mimikatz**. Mimikatz offre i comandi `crypto::capi` e `crypto::cng` per modificare le rispettive API, consentendo l'esportazione delle chiavi private. In particolare, `crypto::capi` modifica il CAPI all'interno del processo corrente, mentre `crypto::cng` prende di mira la memoria di **lsass.exe** per la modifica.

## Furto del certificato utente tramite DPAPI - FURTO2

Ulteriori informazioni su DPAPI in:

{% content-ref url="../../windows-local-privilege-escalation/dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](../../windows-local-privilege-escalation/dpapi-extracting-passwords.md)
{% endcontent-ref %}

In Windows, le **chiavi private dei certificati sono protette da DPAPI**. È fondamentale riconoscere che le **posizioni di archiviazione delle chiavi private utente e macchina** sono diverse e le strutture dei file variano a seconda dell'API crittografica utilizzata dal sistema operativo. **SharpDPAPI** è uno strumento che può navigare automaticamente queste differenze durante la decrittazione dei blocchi DPAPI.

I **certificati utente** sono principalmente conservati nel registro di sistema in `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, ma alcuni possono essere trovati anche nella directory `%APPDATA%\Microsoft\SystemCertificates\My\Certificates`. Le **chiavi private corrispondenti** per questi certificati sono di solito memorizzate in `%APPDATA%\Microsoft\Crypto\RSA\User SID\` per le chiavi **CAPI** e `%APPDATA%\Microsoft\Crypto\Keys\` per le chiavi **CNG**.

Per **estrapolare un certificato e la relativa chiave privata**, il processo prevede:

1. **Selezionare il certificato di destinazione** dallo store dell'utente e recuperare il nome dello store delle chiavi.
2. **Individuare la masterkey DPAPI richiesta** per decrittare la chiave privata corrispondente.
3. **Decrittare la chiave privata** utilizzando la masterkey DPAPI in chiaro.

Per **acquisire la masterkey DPAPI in chiaro**, è possibile utilizzare i seguenti approcci:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Per semplificare la decrittografia dei file masterkey e dei file di chiavi private, il comando `certificates` di [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) risulta utile. Accetta `/pvk`, `/mkfile`, `/password` o `{GUID}:KEY` come argomenti per decrittografare le chiavi private e i certificati collegati, generando successivamente un file `.pem`.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Furto di certificati di macchina tramite DPAPI - THEFT3

I certificati di macchina memorizzati da Windows nel registro a `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` e le chiavi private associate situate in `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (per CAPI) e `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (per CNG) sono crittografati utilizzando le chiavi master DPAPI della macchina. Queste chiavi non possono essere decifrate con la chiave di backup DPAPI del dominio; è invece necessario utilizzare il **segreto LSA DPAPI_SYSTEM**, a cui solo l'utente SYSTEM può accedere.

La decrittografia manuale può essere ottenuta eseguendo il comando `lsadump::secrets` in **Mimikatz** per estrarre il segreto LSA DPAPI_SYSTEM e successivamente utilizzando questa chiave per decrittografare le chiavi master della macchina. In alternativa, è possibile utilizzare il comando `crypto::certificates /export /systemstore:LOCAL_MACHINE` di Mimikatz dopo aver applicato le patch a CAPI/CNG come descritto in precedenza.

**SharpDPAPI** offre un approccio più automatizzato con il suo comando certificates. Quando viene utilizzata l'opzione `/machine` con le autorizzazioni elevate, si passa a SYSTEM, si esegue il dump del segreto LSA DPAPI_SYSTEM, lo si utilizza per decrittografare le chiavi master DPAPI della macchina e quindi si utilizzano queste chiavi in testo normale come tabella di ricerca per decrittografare eventuali chiavi private dei certificati di macchina.


## Ricerca dei file di certificato - THEFT4

I certificati vengono talvolta trovati direttamente nel filesystem, ad esempio in condivisioni di file o nella cartella Download. I tipi di file di certificato più comuni destinati agli ambienti Windows sono i file `.pfx` e `.p12`. Anche se meno frequentemente, compaiono anche file con estensioni `.pkcs12` e `.pem`. Altre estensioni di file relative ai certificati degne di nota includono:
- `.key` per le chiavi private,
- `.crt`/`.cer` solo per i certificati,
- `.csr` per le richieste di firma dei certificati, che non contengono certificati o chiavi private,
- `.jks`/`.keystore`/`.keys` per i Keystore Java, che possono contenere certificati insieme a chiavi private utilizzate dalle applicazioni Java.

È possibile cercare questi file utilizzando PowerShell o il prompt dei comandi cercando le estensioni menzionate.

Nei casi in cui viene trovato un file di certificato PKCS#12 e questo è protetto da una password, è possibile estrarre un hash utilizzando `pfx2john.py`, disponibile su [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html). Successivamente, è possibile utilizzare JohnTheRipper per tentare di craccare la password.
```powershell
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## Furto delle credenziali NTLM tramite PKINIT - THEFT5

Il seguente contenuto spiega un metodo per il furto delle credenziali NTLM tramite PKINIT, nello specifico attraverso il metodo di furto denominato THEFT5. Ecco una riepilogo in forma passiva, con il contenuto anonimizzato e riassunto quando possibile:

Per supportare l'autenticazione NTLM [MS-NLMP] per le applicazioni che non facilitano l'autenticazione Kerberos, il KDC è progettato per restituire la funzione unidirezionale NTLM (OWF) dell'utente all'interno del certificato degli attributi privilegiati (PAC), nello specifico nel buffer `PAC_CREDENTIAL_INFO`, quando viene utilizzato PKCA. Di conseguenza, se un account autentica e ottiene un Ticket-Granting Ticket (TGT) tramite PKINIT, viene fornito un meccanismo che consente all'host corrente di estrarre l'hash NTLM dal TGT per supportare i protocolli di autenticazione legacy. Questo processo comporta la decrittografia della struttura `PAC_CREDENTIAL_DATA`, che è essenzialmente una rappresentazione serializzata NDR del testo in chiaro NTLM.

Viene menzionata l'utilità **Kekeo**, accessibile all'indirizzo [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo), in grado di richiedere un TGT contenente questi dati specifici, facilitando così il recupero dell'NTLM dell'utente. Il comando utilizzato a tale scopo è il seguente:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
Inoltre, si osserva che Kekeo può elaborare certificati protetti da smart card, a condizione che sia possibile recuperare il pin, facendo riferimento a [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe). La stessa funzionalità è indicata come supportata da **Rubeus**, disponibile su [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus).

Questa spiegazione riassume il processo e gli strumenti coinvolti nel furto delle credenziali NTLM tramite PKINIT, concentrandosi sul recupero degli hash NTLM attraverso il TGT ottenuto tramite PKINIT e sulle utility che facilitano questo processo.

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
