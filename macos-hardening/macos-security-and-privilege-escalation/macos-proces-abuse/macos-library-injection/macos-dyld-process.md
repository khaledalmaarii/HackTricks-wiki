# Processo Dyld di macOS

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>

## Informazioni di Base

Il vero **punto di ingresso** di un binario Mach-o è il collegamento dinamico, definito in `LC_LOAD_DYLINKER` di solito è `/usr/lib/dyld`.

Questo linker dovrà individuare tutte le librerie eseguibili, mapparle in memoria e collegare tutte le librerie non pigre. Solo dopo questo processo, il punto di ingresso del binario verrà eseguito.

Naturalmente, **`dyld`** non ha dipendenze (utilizza chiamate di sistema ed estratti di libSystem).

{% hint style="danger" %}
Se questo linker contiene una qualsiasi vulnerabilità, poiché viene eseguito prima di eseguire qualsiasi binario (anche quelli altamente privilegiati), sarebbe possibile **escalare i privilegi**.
{% endhint %}

### Flusso

Dyld verrà caricato da **`dyldboostrap::start`**, che caricherà anche cose come il **canary dello stack**. Questo perché questa funzione riceverà nel suo argomento **`apple`** questo e altri **valori** **sensibili**.

**`dyls::_main()`** è il punto di ingresso di dyld e il suo primo compito è eseguire `configureProcessRestrictions()`, che di solito limita le variabili di ambiente **`DYLD_*`** spiegate in:

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

Quindi, mappa la cache condivisa di dyld che prelinka tutte le importanti librerie di sistema e quindi mappa le librerie di cui il binario dipende e continua ricorsivamente fino a quando tutte le librerie necessarie sono caricate. Pertanto:

1. inizia a caricare le librerie inserite con `DYLD_INSERT_LIBRARIES` (se consentito)
2. Poi quelle della cache condivisa
3. Poi quelle importate
4. Poi continua a importare librerie ricorsivamente

Una volta che tutte sono caricate, vengono eseguiti gli **inizializzatori** di queste librerie. Questi sono codificati utilizzando **`__attribute__((constructor))`** definiti in `LC_ROUTINES[_64]` (ora deprecati) o tramite puntatore in una sezione contrassegnata con `S_MOD_INIT_FUNC_POINTERS` (di solito: **`__DATA.__MOD_INIT_FUNC`**).

I terminatori sono codificati con **`__attribute__((destructor))`** e si trovano in una sezione contrassegnata con `S_MOD_TERM_FUNC_POINTERS` (**`__DATA.__mod_term_func`**).

### Stub

Tutti i binari su macOS sono collegati dinamicamente. Pertanto, contengono alcune sezioni stub che aiutano il binario a saltare al codice corretto in diverse macchine e contesti. È dyld quando il binario viene eseguito il cervello che deve risolvere questi indirizzi (almeno quelli non pigri).

Alcune sezioni stub nel binario:

* **`__TEXT.__[auth_]stubs`**: Puntatori dalle sezioni `__DATA`
* **`__TEXT.__stub_helper`**: Piccolo codice che invoca il collegamento dinamico con informazioni sulla funzione da chiamare
* **`__DATA.__[auth_]got`**: Tabella degli offset globali (indirizzi delle funzioni importate, risolti durante il tempo di caricamento poiché è contrassegnata con il flag `S_NON_LAZY_SYMBOL_POINTERS`)
* **`__DATA.__nl_symbol_ptr`**: Puntatori ai simboli non pigri (risolti durante il tempo di caricamento poiché è contrassegnata con il flag `S_NON_LAZY_SYMBOL_POINTERS`)
* **`__DATA.__la_symbol_ptr`**: Puntatori ai simboli pigri (risolti al primo accesso)

{% hint style="warning" %}
Nota che i puntatori con il prefisso "auth\_" utilizzano una chiave di crittografia in-process per proteggerli (PAC). Inoltre, è possibile utilizzare l'istruzione arm64 `BLRA[A/B]` per verificare il puntatore prima di seguirlo. E il RETA\[A/B\] può essere utilizzato al posto di un indirizzo RET.\
In realtà, il codice in **`__TEXT.__auth_stubs`** utilizzerà **`braa`** invece di **`bl`** per chiamare la funzione richiesta per autenticare il puntatore.

Nota anche che le versioni attuali di dyld caricano **tutto come non pigro**.
{% endhint %}

### Trovare simboli pigri
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
Parte interessante dello smontaggio:
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
È possibile vedere che il salto per chiamare printf va a **`__TEXT.__stubs`**:
```bash
objdump --section-headers ./load

./load:	file format mach-o arm64

Sections:
Idx Name          Size     VMA              Type
0 __text        00000038 0000000100003f60 TEXT
1 __stubs       0000000c 0000000100003f98 TEXT
2 __cstring     00000004 0000000100003fa4 DATA
3 __unwind_info 00000058 0000000100003fa8 DATA
4 __got         00000008 0000000100004000 DATA
```
Nell'analisi della sezione **`__stubs`**:
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
Puoi vedere che stiamo **saltando all'indirizzo del GOT**, che in questo caso viene risolto in modo non lazy e conterrà l'indirizzo della funzione printf.

In altre situazioni invece di saltare direttamente al GOT, potrebbe saltare a **`__DATA.__la_symbol_ptr`** che caricherà un valore che rappresenta la funzione che si sta cercando di caricare, quindi saltare a **`__TEXT.__stub_helper`** che salta il **`__DATA.__nl_symbol_ptr`** che contiene l'indirizzo di **`dyld_stub_binder`** che prende come parametri il numero della funzione e un indirizzo.\
Questa ultima funzione, dopo aver trovato l'indirizzo della funzione cercata, lo scrive nella posizione corrispondente in **`__TEXT.__stub_helper`** per evitare ricerche future.

{% hint style="success" %}
Tuttavia notare che le versioni attuali di dyld caricano tutto come non lazy.
{% endhint %}

#### Opcodes di Dyld

Infine, **`dyld_stub_binder`** deve trovare la funzione indicata e scriverla nell'indirizzo corretto per non cercarla nuovamente. Per farlo utilizza opcode (una macchina a stati finiti) all'interno di dyld.

## Vettore degli argomenti apple\[]

In macOS la funzione principale riceve effettivamente 4 argomenti invece di 3. Il quarto è chiamato apple e ogni voce è nella forma `chiave=valore`. Ad esempio:
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
Il Dynamic Linker (dyld) è il componente principale responsabile del caricamento dei file condivisi in macOS. È possibile sfruttare il processo dyld per iniettare librerie malevole in processi legittimi. Una volta iniettata con successo, la libreria malevola può essere utilizzata per eseguire codice dannoso all'interno del contesto del processo legittimo, consentendo così a un attaccante di ottenere privilegi elevati o compromettere il sistema.
```
0: executable_path=./a
1:
2:
3:
4: ptr_munge=
5: main_stack=
6: executable_file=0x1a01000012,0x5105b6a
7: dyld_file=0x1a01000012,0xfffffff0009834a
8: executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b
9: executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa
10: arm64e_abi=os
11: th_port=
```
{% hint style="success" %}
Quando questi valori raggiungono la funzione principale, le informazioni sensibili sono già state rimosse da essi o ci sarebbe stata una fuga di dati.
{% endhint %}

È possibile visualizzare tutti questi valori interessanti durante il debug prima di entrare nella funzione principale con:

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>Esecuzione del programma impostata su '/tmp/a' (arm64).
(lldb) process launch -s
[..]

<strong>(lldb) mem read $sp
</strong>0x16fdff510: 00 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00  ................
0x16fdff520: d8 f6 df 6f 01 00 00 00 00 00 00 00 00 00 00 00  ...o............

<strong>(lldb) x/55s 0x016fdff6d8
</strong>[...]
0x16fdffd6a: "TERM_PROGRAM=WarpTerminal"
0x16fdffd84: "WARP_USE_SSH_WRAPPER=1"
0x16fdffd9b: "WARP_IS_LOCAL_SHELL_SESSION=1"
0x16fdffdb9: "SDKROOT=/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX14.4.sdk"
0x16fdffe24: "NVM_DIR=/Users/carlospolop/.nvm"
0x16fdffe44: "CONDA_CHANGEPS1=false"
0x16fdffe5a: ""
0x16fdffe5b: ""
0x16fdffe5c: ""
0x16fdffe5d: ""
0x16fdffe5e: ""
0x16fdffe5f: ""
0x16fdffe60: "pfz=0xffeaf0000"
0x16fdffe70: "stack_guard=0x8af2b510e6b800b5"
0x16fdffe8f: "malloc_entropy=0xf2349fbdea53f1e4,0x3fd85d7dcf817101"
0x16fdffec4: "ptr_munge=0x983e2eebd2f3e746"
0x16fdffee1: "main_stack=0x16fe00000,0x7fc000,0x16be00000,0x4000000"
0x16fdfff17: "executable_file=0x1a01000012,0x5105b6a"
0x16fdfff3e: "dyld_file=0x1a01000012,0xfffffff0009834a"
0x16fdfff67: "executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b"
0x16fdfffa2: "executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa"
0x16fdfffdf: "arm64e_abi=os"
0x16fdfffed: "th_port=0x103"
0x16fdffffb: ""
</code></pre>

## dyld\_all\_image\_infos

Si tratta di una struttura esportata da dyld con informazioni sullo stato di dyld che possono essere trovate nel [**codice sorgente**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld\_images.h.auto.html) con informazioni come la versione, il puntatore all'array dyld\_image\_info, al dyld\_image\_notifier, se il processo è staccato dalla cache condivisa, se l'inizializzatore di libSystem è stato chiamato, il puntatore all'intestazione Mach di dyld, il puntatore alla stringa della versione di dyld...

## Variabili d'ambiente dyld

### debug dyld

Variabili d'ambiente interessanti che aiutano a capire cosa sta facendo dyld:

* **DYLD\_PRINT\_LIBRARIES**

Controlla ogni libreria che viene caricata:
```
DYLD_PRINT_LIBRARIES=1 ./apple
dyld[19948]: <9F848759-9AB8-3BD2-96A1-C069DC1FFD43> /private/tmp/a
dyld[19948]: <F0A54B2D-8751-35F1-A3CF-F1A02F842211> /usr/lib/libSystem.B.dylib
dyld[19948]: <C683623C-1FF6-3133-9E28-28672FDBA4D3> /usr/lib/system/libcache.dylib
dyld[19948]: <BFDF8F55-D3DC-3A92-B8A1-8EF165A56F1B> /usr/lib/system/libcommonCrypto.dylib
dyld[19948]: <B29A99B2-7ADE-3371-A774-B690BEC3C406> /usr/lib/system/libcompiler_rt.dylib
dyld[19948]: <65612C42-C5E4-3821-B71D-DDE620FB014C> /usr/lib/system/libcopyfile.dylib
dyld[19948]: <B3AC12C0-8ED6-35A2-86C6-0BFA55BFF333> /usr/lib/system/libcorecrypto.dylib
dyld[19948]: <8790BA20-19EC-3A36-8975-E34382D9747C> /usr/lib/system/libdispatch.dylib
dyld[19948]: <4BB77515-DBA8-3EDF-9AF7-3C9EAE959EA6> /usr/lib/system/libdyld.dylib
dyld[19948]: <F7CE9486-FFF5-3CB8-B26F-75811EF4283A> /usr/lib/system/libkeymgr.dylib
dyld[19948]: <1A7038EC-EE49-35AE-8A3C-C311083795FB> /usr/lib/system/libmacho.dylib
[...]
```
* **DYLD\_PRINT\_SEGMENTS**

Controlla come viene caricata ogni libreria:
```
DYLD_PRINT_SEGMENTS=1 ./apple
dyld[21147]: re-using existing shared cache (/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e):
dyld[21147]:         0x181944000->0x1D5D4BFFF init=5, max=5 __TEXT
dyld[21147]:         0x1D5D4C000->0x1D5EC3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x1D7EC4000->0x1D8E23FFF init=3, max=3 __DATA
dyld[21147]:         0x1D8E24000->0x1DCEBFFFF init=3, max=3 __AUTH
dyld[21147]:         0x1DCEC0000->0x1E22BFFFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x1E42C0000->0x1E5457FFF init=1, max=1 __LINKEDIT
dyld[21147]:         0x1E5458000->0x22D173FFF init=5, max=5 __TEXT
dyld[21147]:         0x22D174000->0x22D9E3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x22F9E4000->0x230F87FFF init=3, max=3 __DATA
dyld[21147]:         0x230F88000->0x234EC3FFF init=3, max=3 __AUTH
dyld[21147]:         0x234EC4000->0x237573FFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x239574000->0x270BE3FFF init=1, max=1 __LINKEDIT
dyld[21147]: Kernel mapped /private/tmp/a
dyld[21147]:     __PAGEZERO (...) 0x000000904000->0x000101208000
dyld[21147]:         __TEXT (r.x) 0x000100904000->0x000100908000
dyld[21147]:   __DATA_CONST (rw.) 0x000100908000->0x00010090C000
dyld[21147]:     __LINKEDIT (r..) 0x00010090C000->0x000100910000
dyld[21147]: Using mapping in dyld cache for /usr/lib/libSystem.B.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E59D000->0x00018E59F000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDB98->0x0001D5DFDBA8
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE015A8->0x0001DDE01878
dyld[21147]:         __AUTH (rw.) 0x0001D9688650->0x0001D9688658
dyld[21147]:         __DATA (rw.) 0x0001D808AD60->0x0001D808AD68
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
dyld[21147]: Using mapping in dyld cache for /usr/lib/system/libcache.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E597000->0x00018E59D000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDAF0->0x0001D5DFDB98
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE014D0->0x0001DDE015A8
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
[...]
```
* **DYLD\_PRINT\_INITIALIZERS**

Stampa quando viene eseguito ciascun inizializzatore della libreria:
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### Altri

* `DYLD_BIND_AT_LAUNCH`: I collegamenti ritardati vengono risolti con quelli non ritardati
* `DYLD_DISABLE_PREFETCH`: Disabilita il prefetching dei contenuti \_\_DATA e \_\_LINKEDIT
* `DYLD_FORCE_FLAT_NAMESPACE`: Collegamenti a livello singolo
* `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Percorsi di risoluzione
* `DYLD_INSERT_LIBRARIES`: Carica una libreria specifica
* `DYLD_PRINT_TO_FILE`: Scrive il debug di dyld in un file
* `DYLD_PRINT_APIS`: Stampa le chiamate API di libdyld
* `DYLD_PRINT_APIS_APP`: Stampa le chiamate API di libdyld effettuate da main
* `DYLD_PRINT_BINDINGS`: Stampa i simboli quando vengono collegati
* `DYLD_WEAK_BINDINGS`: Stampa solo i simboli deboli quando vengono collegati
* `DYLD_PRINT_CODE_SIGNATURES`: Stampa le operazioni di registrazione della firma del codice
* `DYLD_PRINT_DOFS`: Stampa le sezioni del formato oggetto D-Trace caricate
* `DYLD_PRINT_ENV`: Stampa l'ambiente visto da dyld
* `DYLD_PRINT_INTERPOSTING`: Stampa le operazioni di interposizione
* `DYLD_PRINT_LIBRARIES`: Stampa le librerie caricate
* `DYLD_PRINT_OPTS`: Stampa le opzioni di caricamento
* `DYLD_REBASING`: Stampa le operazioni di ricollocazione dei simboli
* `DYLD_RPATHS`: Stampa le espansioni di @rpath
* `DYLD_PRINT_SEGMENTS`: Stampa il mapping dei segmenti Mach-O
* `DYLD_PRINT_STATISTICS`: Stampa le statistiche sui tempi
* `DYLD_PRINT_STATISTICS_DETAILS`: Stampa statistiche dettagliate sui tempi
* `DYLD_PRINT_WARNINGS`: Stampa messaggi di avviso
* `DYLD_SHARED_CACHE_DIR`: Percorso da utilizzare per la cache delle librerie condivise
* `DYLD_SHARED_REGION`: "use", "private", "avoid"
* `DYLD_USE_CLOSURES`: Abilita le chiusure

È possibile trovarne di più con qualcosa del genere:
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
Oppure scaricare il progetto dyld da [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) e eseguire all'interno della cartella:
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## Riferimenti

* [**\*OS Internals, Volume I: User Mode. Di Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

<details>

<summary><strong>Impara l'hacking su AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
