<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

# Guida alla decompilazione di Wasm e alla compilazione di Wat

Nel campo di **WebAssembly**, gli strumenti per la **decompilazione** e la **compilazione** sono essenziali per gli sviluppatori. Questa guida introduce alcune risorse online e software per gestire i file **Wasm (WebAssembly binario)** e **Wat (WebAssembly testo)**.

## Strumenti online

- Per **decompilare** Wasm in Wat, lo strumento disponibile presso [la demo di wasm2wat di Wabt](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) è molto utile.
- Per **compilare** Wat in Wasm, [la demo di wat2wasm di Wabt](https://webassembly.github.io/wabt/demo/wat2wasm/) serve allo scopo.
- Un'altra opzione di decompilazione può essere trovata su [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

## Soluzioni software

- Per una soluzione più robusta, [JEB di PNF Software](https://www.pnfsoftware.com/jeb/demo) offre funzionalità estese.
- Il progetto open-source [wasmdec](https://github.com/wwwg/wasmdec) è disponibile anche per compiti di decompilazione.

# Risorse per la decompilazione di .Net

La decompilazione degli assembly .Net può essere realizzata con strumenti come:

- [ILSpy](https://github.com/icsharpcode/ILSpy), che offre anche un [plugin per Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode), consentendo l'utilizzo multipiattaforma.
- Per compiti di **decompilazione**, **modifica** e **ricompilazione**, è altamente consigliato [dnSpy](https://github.com/0xd4d/dnSpy/releases). Fare clic con il tasto destro su un metodo e scegliere **Modify Method** consente di apportare modifiche al codice.
- [dotPeek di JetBrains](https://www.jetbrains.com/es-es/decompiler/) è un'altra alternativa per la decompilazione degli assembly .Net.

## Miglioramento del debug e del logging con DNSpy

### Logging di DNSpy
Per registrare informazioni su un file utilizzando DNSpy, incorporare il seguente frammento di codice .Net:

%%%cpp
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
%%%

### Debugging di DNSpy
Per un debugging efficace con DNSpy, si consiglia una sequenza di passaggi per regolare gli **attributi dell'Assembly** per il debugging, assicurandosi che le ottimizzazioni che potrebbero ostacolare il debugging siano disabilitate. Questo processo include la modifica delle impostazioni di `DebuggableAttribute`, la ricompilazione dell'assembly e il salvataggio delle modifiche.

Inoltre, per eseguire il debug di un'applicazione .Net eseguita da **IIS**, l'esecuzione di `iisreset /noforce` riavvia IIS. Per collegare DNSpy al processo IIS per il debugging, la guida fornisce istruzioni su come selezionare il processo **w3wp.exe** all'interno di DNSpy e avviare la sessione di debugging.

Per una visione completa dei moduli caricati durante il debugging, si consiglia di accedere alla finestra **Modules** in DNSpy, seguita dall'apertura di tutti i moduli e dalla classificazione delle assembly per una navigazione e un debugging più semplici.

Questa guida racchiude l'essenza della decompilazione di WebAssembly e .Net, offrendo un percorso per gli sviluppatori per affrontare queste attività con facilità.

## **Decompilatore Java**
Per decompilare il bytecode Java, questi strumenti possono essere molto utili:
- [jadx](https://github.com/skylot/jadx)
- [JD-GUI](https://github.com/java-decompiler/jd-gui/releases)

## **Debugging delle DLL**
### Utilizzando IDA
- **Rundll32** viene caricato da percorsi specifici per le versioni a 64 bit e a 32 bit.
- **Windbg** viene selezionato come debugger con l'opzione di sospendere il caricamento/spegnimento delle librerie abilitata.
- I parametri di esecuzione includono il percorso della DLL e il nome della funzione. Questa configurazione interrompe l'esecuzione ad ogni caricamento delle DLL.

### Utilizzando x64dbg/x32dbg
- Similmente a IDA, **rundll32** viene caricato con modifiche alla riga di comando per specificare la DLL e la funzione.
- Le impostazioni vengono regolate per interrompere l'esecuzione all'ingresso della DLL, consentendo di impostare un punto di interruzione al punto di ingresso desiderato della DLL.

### Immagini
- I punti di interruzione dell'esecuzione e le configurazioni sono illustrati attraverso screenshot.

## **ARM & MIPS**
- Per l'emulazione, [arm_now](https://github.com/nongiach/arm_now) è una risorsa utile.

## **Shellcode**
### Tecniche di debugging
- **Blobrunner** e **jmp2it** sono strumenti per allocare shellcode in memoria e debuggarli con Ida o x64dbg.
- Blobrunner [versioni](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)
- jmp2it [versione compilata](https://github.com/adamkramer/jmp2it/releases/)
- **Cutter** offre un'emulazione e ispezione del shellcode basata su GUI, evidenziando le differenze nella gestione del shellcode come file rispetto al shellcode diretto.

### Deobfuscation e analisi
- **scdbg** fornisce informazioni sulle funzioni del shellcode e capacità di deobfuscation.
%%%bash
scdbg.exe -f shellcode # Informazioni di base
scdbg.exe -f shellcode -r # Rapporto di analisi
scdbg.exe -f shellcode -i -r # Hooks interattivi
scdbg.exe -f shellcode -d # Dump del shellcode decodificato
scdbg.exe -f shellcode /findsc # Trova l'offset di inizio
scdbg.exe -f shellcode /foff 0x0000004D # Esegui dall'offset
%%%

- **CyberChef** per disassemblare il shellcode: [Ricetta CyberChef](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

## **Movfuscator**
- Un obfuscator che sostituisce tutte le istruzioni con `mov`.
- Risorse utili includono una [spiegazione su YouTube](https://www.youtube.com/watch?v=2VF_wPkiBJY) e [slide in PDF](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf).
- **demovfuscator** potrebbe invertire l'obfuscation di movfuscator, richiedendo dipendenze come `libcapstone-dev` e `libz3-dev`, e l'installazione di [keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md).
## **Delphi**
- Per i file binari Delphi, si consiglia l'uso di [IDR](https://github.com/crypto2011/IDR).


# Corsi

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(Deobfuscation binaria\)



<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
