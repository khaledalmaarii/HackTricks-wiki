# Controllo del processo di connessione XPC su macOS

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Controllo del processo di connessione XPC

Quando viene stabilita una connessione a un servizio XPC, il server verifica se la connessione è consentita. Di seguito sono riportati i controlli che solitamente vengono eseguiti:

1. Verifica se il **processo di connessione è firmato con un certificato firmato da Apple** (concesso solo da Apple).
* Se ciò **non viene verificato**, un attaccante potrebbe creare un **certificato falso** per corrispondere a qualsiasi altro controllo.
2. Verifica se il processo di connessione è firmato con il **certificato dell'organizzazione** (verifica dell'ID del team).
* Se ciò **non viene verificato**, **qualsiasi certificato di sviluppatore** di Apple può essere utilizzato per la firma e la connessione al servizio.
3. Verifica se il processo di connessione **contiene un bundle ID corretto**.
* Se ciò **non viene verificato**, qualsiasi strumento **firmato dalla stessa organizzazione** potrebbe essere utilizzato per interagire con il servizio XPC.
4. (4 o 5) Verifica se il processo di connessione ha un **numero di versione del software corretto**.
* Se ciò **non viene verificato**, potrebbe essere utilizzato un client obsoleto e non sicuro, vulnerabile all'iniezione di processo, per connettersi al servizio XPC anche con gli altri controlli in atto.
5. (4 o 5) Verifica se il processo di connessione ha un runtime protetto senza entitlement pericolosi (come quelli che consentono di caricare librerie arbitrarie o utilizzare variabili di ambiente DYLD).
1. Se ciò **non viene verificato**, il client potrebbe essere **vulnerabile all'iniezione di codice**.
6. Verifica se il processo di connessione ha un **entitlement** che gli consente di connettersi al servizio. Questo si applica alle applicazioni Apple.
7. La **verifica** deve essere **basata** sul **token di audit del client** di connessione **anziché** sul suo ID di processo (**PID**) poiché il primo previene gli attacchi di **riutilizzo del PID**.
* Gli sviluppatori **raramente utilizzano** la chiamata API del token di audit poiché è **privata**, quindi Apple potrebbe **modificarla** in qualsiasi momento. Inoltre, l'uso di API private non è consentito nelle app del Mac App Store.
* Se viene utilizzato il metodo **`processIdentifier`**, potrebbe essere vulnerabile
* Dovrebbe essere utilizzato **`xpc_dictionary_get_audit_token`** invece di **`xpc_connection_get_audit_token`**, poiché quest'ultimo potrebbe anche essere [vulnerabile in determinate situazioni](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).

### Attacchi di comunicazione

Per ulteriori informazioni sull'attacco di riutilizzo del PID, controlla:

{% content-ref url="macos-pid-reuse.md" %}
[macos-pid-reuse.md](macos-pid-reuse.md)
{% endcontent-ref %}

Per ulteriori informazioni sull'attacco **`xpc_connection_get_audit_token`**, controlla:

{% content-ref url="macos-xpc_connection_get_audit_token-attack.md" %}
[macos-xpc\_connection\_get\_audit\_token-attack.md](macos-xpc\_connection\_get\_audit\_token-attack.md)
{% endcontent-ref %}

### Trustcache - Prevenzione degli attacchi di declassamento

Trustcache è un metodo difensivo introdotto nelle macchine Apple Silicon che memorizza un database di CDHSAH dei binari Apple in modo che solo i binari non modificati consentiti possano essere eseguiti. Ciò impedisce l'esecuzione di versioni di declassamento.

### Esempi di codice

Il server implementerà questa **verifica** in una funzione chiamata **`shouldAcceptNewConnection`**.

{% code overflow="wrap" %}
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
{% endcode %}

L'oggetto NSXPCConnection ha una proprietà **privata** chiamata **`auditToken`** (quella che dovrebbe essere utilizzata ma potrebbe cambiare) e una proprietà **pubblica** chiamata **`processIdentifier`** (quella che non dovrebbe essere utilizzata).

Il processo di connessione potrebbe essere verificato con qualcosa del genere:

{% code overflow="wrap" %}
```objectivec
[...]
SecRequirementRef requirementRef = NULL;
NSString requirementString = @"anchor apple generic and identifier \"xyz.hacktricks.service\" and certificate leaf [subject.CN] = \"TEAMID\" and info [CFBundleShortVersionString] >= \"1.0\"";
/* Check:
- Signed by a cert signed by Apple
- Check the bundle ID
- Check the TEAMID of the signing cert
- Check the version used
*/

// Check the requirements with the PID (vulnerable)
SecRequirementCreateWithString(requirementString, kSecCSDefaultFlags, &requirementRef);
SecCodeCheckValidity(code, kSecCSDefaultFlags, requirementRef);

// Check the requirements wuing the auditToken (secure)
SecTaskRef taskRef = SecTaskCreateWithAuditToken(NULL, ((ExtendedNSXPCConnection*)newConnection).auditToken);
SecTaskValidateForRequirement(taskRef, (__bridge CFStringRef)(requirementString))
```
Se uno sviluppatore non vuole controllare la versione del client, potrebbe almeno verificare che il client non sia vulnerabile all'iniezione di processo:

{% code overflow="wrap" %}
```objectivec
[...]
CFDictionaryRef csInfo = NULL;
SecCodeCopySigningInformation(code, kSecCSDynamicInformation, &csInfo);
uint32_t csFlags = [((__bridge NSDictionary *)csInfo)[(__bridge NSString *)kSecCodeInfoStatus] intValue];
const uint32_t cs_hard = 0x100;        // don't load invalid page.
const uint32_t cs_kill = 0x200;        // Kill process if page is invalid
const uint32_t cs_restrict = 0x800;    // Prevent debugging
const uint32_t cs_require_lv = 0x2000; // Library Validation
const uint32_t cs_runtime = 0x10000;   // hardened runtime
if ((csFlags & (cs_hard | cs_require_lv)) {
return Yes; // Accept connection
}
```
{% endcode %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
