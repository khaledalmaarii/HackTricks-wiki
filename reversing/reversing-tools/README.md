{% hint style="success" %}
Impara e pratica l'Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

</details>
{% endhint %}

# Guida alla Decompilazione Wasm e Compilazione Wat

Nel campo del **WebAssembly**, gli strumenti per **decompilare** e **compilare** sono essenziali per gli sviluppatori. Questa guida introduce alcune risorse online e software per gestire i file **Wasm (WebAssembly binary)** e **Wat (WebAssembly text)**.

## Strumenti Online

- Per **decompilare** Wasm in Wat, lo strumento disponibile nella [demo wasm2wat di Wabt](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) è utile.
- Per **compilare** Wat di nuovo in Wasm, la [demo wat2wasm di Wabt](https://webassembly.github.io/wabt/demo/wat2wasm/) serve allo scopo.
- Un'altra opzione di decompilazione può essere trovata su [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

## Soluzioni Software

- Per una soluzione più robusta, [JEB di PNF Software](https://www.pnfsoftware.com/jeb/demo) offre funzionalità estese.
- Il progetto open-source [wasmdec](https://github.com/wwwg/wasmdec) è anche disponibile per compiti di decompilazione.

# Risorse per la Decompilazione .Net

Decompilare assembly .Net può essere realizzato con strumenti come:

- [ILSpy](https://github.com/icsharpcode/ILSpy), che offre anche un [plugin per Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode), consentendo l'uso multipiattaforma.
- Per compiti che coinvolgono **decompilazione**, **modifica** e **ricompilazione**, [dnSpy](https://github.com/0xd4d/dnSpy/releases) è altamente raccomandato. **Facendo clic con il tasto destro** su un metodo e scegliendo **Modifica Metodo** consente modifiche al codice.
- [dotPeek di JetBrains](https://www.jetbrains.com/es-es/decompiler/) è un'altra alternativa per decompilare assembly .Net.

## Migliorare il Debugging e il Logging con DNSpy

### Logging DNSpy
Per registrare informazioni in un file utilizzando DNSpy, integra il seguente frammento di codice .Net:

%%%cpp
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
%%%

### Debugging DNSpy
Per un debugging efficace con DNSpy, si raccomanda una sequenza di passaggi per regolare gli **attributi dell'Assembly** per il debugging, assicurandosi che le ottimizzazioni che potrebbero ostacolare il debugging siano disabilitate. Questo processo include la modifica delle impostazioni di `DebuggableAttribute`, la ricompilazione dell'assembly e il salvataggio delle modifiche.

Inoltre, per eseguire il debug di un'applicazione .Net eseguita da **IIS**, eseguire `iisreset /noforce` riavvia IIS. Per allegare DNSpy al processo IIS per il debugging, la guida istruisce sulla selezione del processo **w3wp.exe** all'interno di DNSpy e sull'avvio della sessione di debugging.

Per una visione completa dei moduli caricati durante il debugging, è consigliato accedere alla finestra **Moduli** in DNSpy, seguita dall'apertura di tutti i moduli e dall'ordinamento degli assembly per una navigazione e un debugging più facili.

Questa guida racchiude l'essenza della decompilazione di WebAssembly e .Net, offrendo un percorso per gli sviluppatori per affrontare questi compiti con facilità.

## **Decompilatore Java**
Per decompilare bytecode Java, questi strumenti possono essere molto utili:
- [jadx](https://github.com/skylot/jadx)
- [JD-GUI](https://github.com/java-decompiler/jd-gui/releases)

## **Debugging DLL**
### Utilizzando IDA
- **Rundll32** viene caricato da percorsi specifici per versioni a 64 bit e 32 bit.
- **Windbg** è selezionato come debugger con l'opzione di sospendere il caricamento/scaricamento della libreria abilitata.
- I parametri di esecuzione includono il percorso DLL e il nome della funzione. Questa configurazione interrompe l'esecuzione al caricamento di ogni DLL.

### Utilizzando x64dbg/x32dbg
- Simile a IDA, **rundll32** viene caricato con modifiche alla riga di comando per specificare la DLL e la funzione.
- Le impostazioni vengono modificate per interrompere l'ingresso nella DLL, consentendo di impostare un breakpoint nel punto di ingresso desiderato della DLL.

### Immagini
- I punti di arresto dell'esecuzione e le configurazioni sono illustrati tramite screenshot.

## **ARM & MIPS**
- Per l'emulazione, [arm_now](https://github.com/nongiach/arm_now) è una risorsa utile.

## **Shellcodes**
### Tecniche di Debugging
- **Blobrunner** e **jmp2it** sono strumenti per allocare shellcode in memoria e debugarli con Ida o x64dbg.
- Blobrunner [rilasci](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)
- jmp2it [versione compilata](https://github.com/adamkramer/jmp2it/releases/)
- **Cutter** offre emulazione e ispezione di shellcode basata su GUI, evidenziando le differenze nella gestione del shellcode come file rispetto al shellcode diretto.

### Deobfuscazione e Analisi
- **scdbg** fornisce informazioni sulle funzioni del shellcode e capacità di deobfuscazione.
%%%bash
scdbg.exe -f shellcode # Info di base
scdbg.exe -f shellcode -r # Rapporto di analisi
scdbg.exe -f shellcode -i -r # Hook interattivi
scdbg.exe -f shellcode -d # Dump del shellcode decodificato
scdbg.exe -f shellcode /findsc # Trova offset di inizio
scdbg.exe -f shellcode /foff 0x0000004D # Esegui dall'offset
%%%

- **CyberChef** per disassemblare shellcode: [Ricetta CyberChef](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

## **Movfuscator**
- Un offuscante che sostituisce tutte le istruzioni con `mov`.
- Risorse utili includono una [spiegazione su YouTube](https://www.youtube.com/watch?v=2VF_wPkiBJY) e [diapositive PDF](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf).
- **demovfuscator** potrebbe invertire l'offuscamento di movfuscator, richiedendo dipendenze come `libcapstone-dev` e `libz3-dev`, e installando [keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md).

## **Delphi**
- Per i binari Delphi, si raccomanda [IDR](https://github.com/crypto2011/IDR).


# Corsi

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(Deobfuscazione binaria\)



{% hint style="success" %}
Impara e pratica l'Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

</details>
{% endhint %}
