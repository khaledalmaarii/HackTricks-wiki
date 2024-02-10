# Iniezione di librerie su macOS

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

{% hint style="danger" %}
Il codice di **dyld è open source** e può essere trovato in [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) e può essere scaricato come un tar utilizzando un **URL come** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)
{% endhint %}

## **DYLD\_INSERT\_LIBRARIES**

Questo è simile a [**LD\_PRELOAD su Linux**](../../../../linux-hardening/privilege-escalation#ld\_preload). Consente di indicare a un processo che verrà eseguito per caricare una libreria specifica da un percorso (se la variabile di ambiente è abilitata).

Questa tecnica può essere anche **utilizzata come tecnica ASEP** poiché ogni applicazione installata ha un plist chiamato "Info.plist" che consente l'**assegnazione di variabili ambientali** utilizzando una chiave chiamata `LSEnvironmental`.

{% hint style="info" %}
Dal 2012 **Apple ha drasticamente ridotto il potere** di **`DYLD_INSERT_LIBRARIES`**.

Vai al codice e **controlla `src/dyld.cpp`**. Nella funzione **`pruneEnvironmentVariables`** puoi vedere che le variabili **`DYLD_*`** vengono rimosse.

Nella funzione **`processRestricted`** viene impostato il motivo della restrizione. Controllando quel codice puoi vedere che i motivi sono:

* Il binario è `setuid/setgid`
* Esistenza della sezione `__RESTRICT/__restrict` nel binario macho.
* Il software ha entitlement (runtime protetto) senza l'entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables)
* Controlla gli **entitlement** di un binario con: `codesign -dv --entitlements :- </path/to/bin>`

Nelle versioni più aggiornate è possibile trovare questa logica nella seconda parte della funzione **`configureProcessRestrictions`.** Tuttavia, ciò che viene eseguito nelle versioni più recenti sono i **controlli iniziali della funzione** (puoi rimuovere gli if relativi a iOS o simulazione poiché non verranno utilizzati in macOS.
{% endhint %}

### Validazione delle librerie

Anche se il binario consente di utilizzare la variabile di ambiente **`DYLD_INSERT_LIBRARIES`**, se il binario controlla la firma della libreria da caricare, non caricherà una libreria personalizzata.

Per caricare una libreria personalizzata, il binario deve avere **uno dei seguenti entitlement**:

* &#x20;[`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
* [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

o il binario **non deve** avere il **flag di runtime protetto** o il flag di **validazione della libreria**.

È possibile verificare se un binario ha il **runtime protetto** con `codesign --display --verbose <bin>` controllando il flag runtime in **`CodeDirectory`** come: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

È anche possibile caricare una libreria se è **firmata con lo stesso certificato del binario**.

Trova un esempio su come (ab)usare questo e controllare le restrizioni in:

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dylib Hijacking

{% hint style="danger" %}
Ricorda che si applicano anche le **restrizioni di validazione delle librerie** precedenti per eseguire attacchi di Dylib hijacking.
{% endhint %}

Come in Windows, su MacOS è possibile **hijack dylibs** per far eseguire **codice arbitrario** alle **applicazioni** (in realtà, da un utente normale ciò potrebbe non essere possibile in quanto potrebbe essere necessaria un'autorizzazione TCC per scrivere all'interno di un pacchetto `.app` e hijack di una libreria).\
Tuttavia, il modo in cui le **applicazioni MacOS** caricano le librerie è **più restrittivo** rispetto a Windows. Ciò implica che gli sviluppatori di malware possono comunque utilizzare questa tecnica per **nascondersi**, ma la probabilità di poter **abusare di questa tecnica per l'escalation dei privilegi è molto più bassa**.

Innanzitutto, è **più comune** trovare che i **binari MacOS indicano il percorso completo** delle librerie da caricare. E in secondo luogo, **MacOS non cerca mai** nelle cartelle del **$PATH** le librerie.

La **parte principale** del **codice** relativo a questa funzionalità si trova in **`ImageLoader::recursiveLoadLibraries`** in `ImageLoader.cpp`.

Ci sono **4 diversi comandi dell'header** che un binario macho può utilizzare per caricare librerie:

* Il comando **`LC_LOAD_DYLIB`** è il comando comune per caricare una dylib.
* Il comando **`LC_LOAD_WEAK_DYLIB`** funziona come il precedente, ma se la dylib non viene trovata, l'esecuzione continua senza errori.
* Il comando **`LC_REEXPORT_DYLIB`** fa da proxy (o re-esporta) i simboli da una libreria diversa.
* Il comando **`LC_LOAD_UPWARD_DYLIB`** viene utilizzato quando due librerie dipendono l'una dall'altra (questo viene chiamato una _dipendenza ascendente_).

Tuttavia, ci sono **2 tipi di Dylib hijacking**:

* **Librerie con collegamento debole mancanti**: ciò significa che l'applicazione cercherà di caricare una libreria che non esiste configurata con **LC\_LOAD\_WEAK\_DYLIB**. Quindi, **se un attaccante posiziona una dy
* Se **`LC_LOAD_DYLIB`** contiene `@rpath/library.dylib` e **`LC_RPATH`** contiene `/application/app.app/Contents/Framework/v1/` e `/application/app.app/Contents/Framework/v2/`. Entrambe le cartelle verranno utilizzate per caricare `library.dylib`**.** Se la libreria non esiste in `[...]/v1/` e l'attaccante può inserirla lì per dirottare il caricamento della libreria in `[...]/v2/` poiché viene seguito l'ordine dei percorsi in **`LC_LOAD_DYLIB`**.
* **Trova i percorsi rpath e le librerie** nei binari con: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

{% hint style="info" %}
**`@executable_path`**: È il **percorso** alla directory che contiene il **file eseguibile principale**.

**`@loader_path`**: È il **percorso** alla **directory** che contiene il **binario Mach-O** che contiene il comando di caricamento.

* Quando viene utilizzato in un eseguibile, **`@loader_path`** è effettivamente lo **stesso** di **`@executable_path`**.
* Quando viene utilizzato in una **dylib**, **`@loader_path`** fornisce il **percorso** alla **dylib**.
{% endhint %}

Il modo per **aumentare i privilegi** sfruttando questa funzionalità sarebbe nel raro caso in cui un'applicazione in esecuzione **da** **root** sta cercando una **libreria in una cartella in cui l'attaccante ha le autorizzazioni di scrittura**.

{% hint style="success" %}
Uno scanner utile per trovare **librerie mancanti** nelle applicazioni è [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) o una [**versione CLI**](https://github.com/pandazheng/DylibHijack).\
Un bel **rapporto con dettagli tecnici** su questa tecnica può essere trovato [**qui**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).
{% endhint %}

**Esempio**

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dlopen Hijacking

{% hint style="danger" %}
Ricorda che si applicano anche le **restrizioni di convalida delle librerie precedenti** per eseguire attacchi di Dlopen hijacking.
{% endhint %}

Da **`man dlopen`**:

* Quando il percorso **non contiene il carattere slash** (cioè è solo un nome di foglia), **dlopen() effettuerà una ricerca**. Se **`$DYLD_LIBRARY_PATH`** è stato impostato all'avvio, dyld cercherà prima in quella directory. Successivamente, se il file mach-o chiamante o l'eseguibile principale specificano un **`LC_RPATH`**, quindi dyld cercherà in quelle directory. Successivamente, se il processo è **non limitato**, dyld cercherà nella **directory di lavoro corrente**. Infine, per i binari più vecchi, dyld proverà alcune alternative. Se **`$DYLD_FALLBACK_LIBRARY_PATH`** è stato impostato all'avvio, dyld cercherà in **quelle directory**, altrimenti dyld cercherà in **`/usr/local/lib/`** (se il processo non è limitato), e quindi in **`/usr/lib/`** (queste informazioni sono state prese da **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(se non limitato)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (se non limitato)
6. `/usr/lib/`

{% hint style="danger" %}
Se non ci sono slash nel nome, ci sarebbero 2 modi per effettuare un dirottamento:

* Se **qualsiasi `LC_RPATH`** è **scrivibile** (ma la firma viene verificata, quindi per questo è necessario che anche il binario non sia limitato)
* Se il binario è **non limitato** e quindi è possibile caricare qualcosa dalla CWD (o sfruttando una delle variabili di ambiente menzionate)
{% endhint %}

* Quando il percorso **sembra un percorso di framework** (ad esempio `/stuff/foo.framework/foo`), se **`$DYLD_FRAMEWORK_PATH`** è stato impostato all'avvio, dyld cercherà prima in quella directory per il **percorso parziale del framework** (ad esempio `foo.framework/foo`). Successivamente, dyld proverà il **percorso fornito così com'è** (usando la directory di lavoro corrente per i percorsi relativi). Infine, per i binari più vecchi, dyld proverà alcune alternative. Se **`$DYLD_FALLBACK_FRAMEWORK_PATH`** è stato impostato all'avvio, dyld cercherà in quelle directory. In caso contrario, cercherà in **`/Library/Frameworks`** (su macOS se il processo non è limitato), quindi in **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. percorso fornito (usando la directory di lavoro corrente per i percorsi relativi se non limitato)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (se non limitato)
5. `/System/Library/Frameworks`

{% hint style="danger" %}
Se si tratta di un percorso di framework, il modo per dirottarlo sarebbe:

* Se il processo è **non limitato**, sfruttando il **percorso relativo dalla CWD** o le variabili di ambiente menzionate (anche se non è detto nella documentazione se il processo è limitato, le variabili di ambiente DYLD\_\* vengono rimosse)
{% endhint %}

* Quando il percorso **contiene uno slash ma non è un percorso di framework** (cioè un percorso completo o un percorso parziale a una dylib), dlopen() cerca prima (se impostato) in **`$DYLD_LIBRARY_PATH`** (con la parte finale del percorso). Successivamente, dyld **prova il percorso fornito** (usando la directory di lavoro corrente per i percorsi relativi (ma solo per i processi non limitati)). Infine, per i binari più vecchi, dyld proverà alcune alternative. Se **`$DYLD_FALLBACK_LIBRARY_PATH`** è stato impostato all'avvio, dyld cercherà in quelle directory, altrimenti dyld cercherà in **`/usr/local/lib/`** (se il processo non è limitato), e quindi in **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. percorso fornito (usando la directory di lavoro corrente per i percorsi relativi se non limitato)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (se non limitato)
5. `/usr/lib/`

{% hint style="danger" %}
Se ci sono slash nel nome e non è un framework, il modo per dirottarlo sarebbe:

* Se il binario è **non limitato** e quindi è possibile caricare qualcosa dalla CWD o da `/usr/local/lib` (o sfruttando una delle variabili di ambiente menzionate)
{% endhint %}

{% hint style="info" %}
Nota: Non ci sono file di configurazione per **controllare la ricerca di dlopen**.

Nota: Se l'eseguibile principale è un binario **set\[ug]id o firmato con entitlements**, allora **tutte le variabili di ambiente vengono ignorate**, e può essere utilizzato solo un percorso completo (controlla le restrizioni di DYLD\_INSERT\_LIBRARIES per informazioni più dettagliate)

Nota: Le piattaforme Apple utilizzano file "universal" per combinare librerie a 32 bit e a 64 bit. Ciò significa che non ci sono **percorsi di ricerca separati per 32 bit e 64 bit**.

Nota: Sulle piattaforme Apple, la maggior parte delle dylib di sistema è **combinata nella cache dyld** e non esiste su disco. Pertanto, chiamare **`stat()`** per verificare preventivamente se una dylib di sistema esiste **non funzionerà**. Tuttavia, **`dlopen_preflight()`** utilizza gli stessi passaggi di **`dlopen()`** per trovare un file mach-o compatibile.
{% endhint %}

**Controlla i percorsi**

Verifichiamo tutte le opzioni con il seguente codice:
```c
// gcc dlopentest.c -o dlopentest -Wl,-rpath,/tmp/test
#include <dlfcn.h>
#include <stdio.h>

int main(void)
{
void* handle;

fprintf("--- No slash ---\n");
handle = dlopen("just_name_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Relative framework ---\n");
handle = dlopen("a/framework/rel_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Abs framework ---\n");
handle = dlopen("/a/abs/framework/abs_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Relative Path ---\n");
handle = dlopen("a/folder/rel_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Abs Path ---\n");
handle = dlopen("/a/abs/folder/abs_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

return 0;
}
```
Se si compila ed esegue, è possibile vedere **dove ogni libreria è stata cercata senza successo**. Inoltre, è possibile **filtrare i log del file system**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Hijacking del percorso relativo

Se un **binario/app privilegiato** (come un SUID o un binario con potenti entitlement) sta **caricando una libreria con percorso relativo** (ad esempio utilizzando `@executable_path` o `@loader_path`) e ha **disabilitata la convalida delle librerie**, potrebbe essere possibile spostare il binario in una posizione in cui l'attaccante potrebbe **modificare la libreria caricata con percorso relativo** e sfruttarla per iniettare codice nel processo.

## Eliminazione delle variabili d'ambiente `DYLD_*` e `LD_LIBRARY_PATH`

Nel file `dyld-dyld-832.7.1/src/dyld2.cpp` è possibile trovare la funzione **`pruneEnvironmentVariables`**, che rimuoverà qualsiasi variabile d'ambiente che **inizia con `DYLD_`** e **`LD_LIBRARY_PATH=`**.

Inoltre, imposterà specificamente a **null** le variabili d'ambiente **`DYLD_FALLBACK_FRAMEWORK_PATH`** e **`DYLD_FALLBACK_LIBRARY_PATH`** per i binari **suid** e **sgid**.

Questa funzione viene chiamata dalla funzione **`_main`** dello stesso file se si sta mirando a OSX in questo modo:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
e questi flag booleani vengono impostati nello stesso file nel codice:
```cpp
#if TARGET_OS_OSX
// support chrooting from old kernel
bool isRestricted = false;
bool libraryValidation = false;
// any processes with setuid or setgid bit set or with __RESTRICT segment is restricted
if ( issetugid() || hasRestrictedSegment(mainExecutableMH) ) {
isRestricted = true;
}
bool usingSIP = (csr_check(CSR_ALLOW_TASK_FOR_PID) != 0);
uint32_t flags;
if ( csops(0, CS_OPS_STATUS, &flags, sizeof(flags)) != -1 ) {
// On OS X CS_RESTRICT means the program was signed with entitlements
if ( ((flags & CS_RESTRICT) == CS_RESTRICT) && usingSIP ) {
isRestricted = true;
}
// Library Validation loosens searching but requires everything to be code signed
if ( flags & CS_REQUIRE_LV ) {
isRestricted = false;
libraryValidation = true;
}
}
gLinkContext.allowAtPaths                = !isRestricted;
gLinkContext.allowEnvVarsPrint           = !isRestricted;
gLinkContext.allowEnvVarsPath            = !isRestricted;
gLinkContext.allowEnvVarsSharedCache     = !libraryValidation || !usingSIP;
gLinkContext.allowClassicFallbackPaths   = !isRestricted;
gLinkContext.allowInsertFailures         = false;
gLinkContext.allowInterposing         	 = true;
```
Ciò significa essenzialmente che se il binario è **suid** o **sgid**, o ha un segmento **RESTRICT** negli header o è stato firmato con il flag **CS\_RESTRICT**, allora **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** è vero e le variabili di ambiente vengono eliminate.

Si noti che se CS\_REQUIRE\_LV è vero, le variabili non verranno eliminate, ma la validazione della libreria verificherà che stiano utilizzando lo stesso certificato del binario originale.

## Verifica delle restrizioni

### SUID & SGID
```bash
# Make it owned by root and suid
sudo chown root hello
sudo chmod +s hello
# Insert the library
DYLD_INSERT_LIBRARIES=inject.dylib ./hello

# Remove suid
sudo chmod -s hello
```
### Sezione `__RESTRICT` con segmento `__restrict`

La sezione `__RESTRICT` è un segmento di memoria speciale presente nei binari macOS. Questo segmento viene utilizzato per proteggere le librerie condivise da modifiche non autorizzate. Quando una libreria viene caricata in memoria, il segmento `__RESTRICT` viene creato per contenere i dati sensibili della libreria.

Il segmento `__restrict` impedisce l'iniezione di codice malevolo all'interno delle librerie condivise. Questo rende più difficile per un attaccante sfruttare vulnerabilità di sicurezza per ottenere privilegi elevati o compromettere il sistema.

È importante notare che non tutte le librerie condivise utilizzano il segmento `__RESTRICT`. Alcune librerie potrebbero non essere protette da questo meccanismo di sicurezza e potrebbero essere vulnerabili ad attacchi di iniezione di codice.

Per verificare se una libreria utilizza il segmento `__RESTRICT`, è possibile utilizzare il comando `otool` con l'opzione `-l` seguita dal percorso della libreria. Nell'output del comando, cercare la sezione `__RESTRICT` per determinare se la libreria è protetta o meno.

In conclusione, il segmento `__RESTRICT` è un meccanismo di sicurezza importante per proteggere le librerie condivise da modifiche non autorizzate. Tuttavia, è fondamentale verificare se una libreria specifica utilizza questo segmento per garantire una protezione adeguata.
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Runtime sicuro

Crea un nuovo certificato nella Keychain e utilizzalo per firmare il binario:

{% code overflow="wrap" %}
```bash
# Apply runtime proetction
codesign -s <cert-name> --option=runtime ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello #Library won't be injected

# Apply library validation
codesign -f -s <cert-name> --option=library ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed #Will throw an error because signature of binary and library aren't signed by same cert (signs must be from a valid Apple-signed developer certificate)

# Sign it
## If the signature is from an unverified developer the injection will still work
## If it's from a verified developer, it won't
codesign -f -s <cert-name> inject.dylib
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed

# Apply CS_RESTRICT protection
codesign -f -s <cert-name> --option=restrict hello-signed
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed # Won't work
```
{% endcode %}

{% hint style="danger" %}
Nota che anche se ci sono binari firmati con il flag **`0x0(none)`**, possono ottenere dinamicamente il flag **`CS_RESTRICT`** quando vengono eseguiti e quindi questa tecnica non funzionerà su di essi.

Puoi verificare se un processo ha questo flag con (scarica [**csops qui**](https://github.com/axelexic/CSOps)):&#x20;
```bash
csops -status <pid>
```
e quindi controlla se il flag 0x800 è abilitato.
{% endhint %}

## Riferimenti
* [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
