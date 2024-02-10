# Strumenti di Reverse Engineering e Metodi di Base

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trova le vulnerabilità che contano di più in modo da poterle correggere più velocemente. Intruder traccia la tua superficie di attacco, esegue scansioni proattive delle minacce, trova problemi in tutta la tua infrastruttura tecnologica, dalle API alle applicazioni web e ai sistemi cloud. [**Provalo gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) oggi stesso.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Strumenti di Reverse Engineering basati su ImGui

Software:

* ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Decompilatore Wasm / Compilatore Wat

Online:

* Usa [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) per **decompilare** da wasm (binario) a wat (testo chiaro)
* Usa [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) per **compilare** da wat a wasm
* Puoi anche provare ad usare [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) per decompilare

Software:

* [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
* [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Decompilatore .Net

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek è un decompilatore che **decompila ed esamina diversi formati**, inclusi **librerie** (.dll), file di **metadati di Windows** (.winmd) ed **eseguibili** (.exe). Una volta decompilato, un assembly può essere salvato come progetto di Visual Studio (.csproj).

Il merito qui è che se un codice sorgente perso richiede il ripristino da un assembly legacy, questa azione può risparmiare tempo. Inoltre, dotPeek offre una navigazione comoda all'interno del codice decompilato, rendendolo uno degli strumenti perfetti per l'analisi degli algoritmi Xamarin.

### [.Net Reflector](https://www.red-gate.com/products/reflector/)

Con un modello di add-in completo e un'API che estende lo strumento per adattarlo alle tue esigenze specifiche, .NET reflector risparmia tempo e semplifica lo sviluppo. Diamo un'occhiata alla moltitudine di servizi di reverse engineering che questo strumento offre:

* Fornisce una visione di come i dati fluiscono attraverso una libreria o un componente
* Fornisce una visione dell'implementazione e dell'utilizzo dei linguaggi e dei framework .NET
* Trova funzionalità non documentate e non esposte per ottenere il massimo dalle API e dalle tecnologie utilizzate.
* Trova dipendenze e diverse librerie
* Trova l'esatta posizione degli errori nel tuo codice, nei componenti di terze parti e nelle librerie.
* Esegue il debug del codice .NET con la sorgente completa con cui stai lavorando.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Plugin ILSpy per Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Puoi averlo su qualsiasi sistema operativo (puoi installarlo direttamente da VSCode, non è necessario scaricare il git. Fai clic su **Estensioni** e **cerca ILSpy**).\
Se hai bisogno di **decompilare**, **modificare** e **ricompilare** nuovamente puoi usare: [**https://github.com/0xd4d/dnSpy/releases**](https://github.com/0xd4d/dnSpy/releases) (**Fai clic destro -> Modifica Metodo** per cambiare qualcosa all'interno di una funzione).\
Puoi anche provare [https://www.jetbrains.com/es-es/decompiler/](https://www.jetbrains.com/es-es/decompiler/)

### DNSpy Logging

Per fare in modo che **DNSpy registri alcune informazioni su un file**, puoi utilizzare queste righe di codice .Net:
```bash
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Debugging con DNSpy

Per poter eseguire il debug del codice utilizzando DNSpy, è necessario:

Innanzitutto, modificare gli **attributi dell'Assembly** relativi al **debugging**:

![](<../../.gitbook/assets/image (278).png>)
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
A: 

# Strumenti di Reverse Engineering - Metodi di base

In questa sezione, esamineremo alcuni strumenti di base utilizzati nel reverse engineering. Questi strumenti sono essenziali per analizzare e comprendere il funzionamento interno di un software.

## Decompilatori

I decompilatori sono strumenti che traducono il codice macchina in un linguaggio di programmazione ad alto livello. Questo permette agli analisti di comprendere meglio il codice sorgente di un programma. Alcuni esempi di decompilatori popolari sono:

- **Ghidra**: un potente strumento di reverse engineering sviluppato dalla National Security Agency (NSA).
- **IDA Pro**: un altro strumento di reverse engineering ampiamente utilizzato con una vasta gamma di funzionalità.
- **Radare2**: un framework di reverse engineering open source che offre molte funzionalità avanzate.

## Debugger

I debugger sono strumenti che consentono agli analisti di eseguire un programma passo dopo passo, monitorando il suo stato e il valore delle variabili. Questo aiuta a comprendere il flusso di esecuzione del programma e a individuare eventuali bug o vulnerabilità. Alcuni esempi di debugger comuni sono:

- **GDB**: un debugger ampiamente utilizzato nel mondo Unix.
- **OllyDbg**: un debugger per Windows con molte funzionalità avanzate.
- **x64dbg**: un debugger open source per Windows con un'interfaccia utente intuitiva.

## Disassemblatori

I disassemblatori sono strumenti che traducono il codice macchina in un formato leggibile dall'uomo. Questo permette agli analisti di esaminare il flusso di esecuzione del programma e di identificare le istruzioni specifiche che vengono eseguite. Alcuni esempi di disassemblatori sono:

- **IDA Pro**: oltre ad essere un decompiler, IDA Pro offre anche funzionalità di disassemblaggio.
- **Radare2**: come menzionato in precedenza, Radare2 è un framework di reverse engineering che include anche un disassemblatore.
- **objdump**: un disassemblatore incluso nel pacchetto binutils, comunemente utilizzato nel mondo Unix.

## Strumenti di analisi statica

Gli strumenti di analisi statica consentono agli analisti di esaminare il codice sorgente o il codice macchina senza eseguire effettivamente il programma. Questo può essere utile per individuare vulnerabilità o comportamenti indesiderati. Alcuni esempi di strumenti di analisi statica sono:

- **Cppcheck**: uno strumento di analisi statica per il codice C e C++.
- **FindBugs**: uno strumento di analisi statica per il codice Java.
- **Pylint**: uno strumento di analisi statica per il codice Python.

## Strumenti di analisi dinamica

Gli strumenti di analisi dinamica consentono agli analisti di eseguire il programma e monitorare il suo comportamento in tempo reale. Questo può essere utile per individuare vulnerabilità o comportamenti anomali. Alcuni esempi di strumenti di analisi dinamica sono:

- **Wireshark**: uno strumento di analisi del traffico di rete.
- **Burp Suite**: una suite di strumenti per il test di sicurezza delle applicazioni web.
- **Frida**: un framework di analisi dinamica per applicazioni mobili.

## Conclusioni

Questi sono solo alcuni degli strumenti di base utilizzati nel reverse engineering. Ogni strumento ha le sue caratteristiche e funzionalità uniche, quindi è importante scegliere quelli più adatti alle proprie esigenze. Sperimentare con diversi strumenti e metodi è fondamentale per diventare un esperto nel campo del reverse engineering.
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
E clicca su **compila**:

![](<../../.gitbook/assets/image (314) (1) (1).png>)

Quindi salva il nuovo file su _**File >> Salva modulo...**_:

![](<../../.gitbook/assets/image (279).png>)

Questo è necessario perché se non lo fai, durante l'**esecuzione** verranno applicate diverse **ottimizzazioni** al codice e potrebbe essere possibile che durante il debug un **punto di interruzione non venga mai raggiunto** o alcune **variabili non esistano**.

Successivamente, se la tua applicazione .Net viene **eseguita** da **IIS**, puoi **riavviarla** con:
```
iisreset /noforce
```
Successivamente, per iniziare il debug, è necessario chiudere tutti i file aperti e selezionare **Attach to Process...** nella scheda **Debug**:

![](<../../.gitbook/assets/image (280).png>)

Successivamente, selezionare **w3wp.exe** per collegarsi al server **IIS** e fare clic su **attach**:

![](<../../.gitbook/assets/image (281).png>)

Ora che stiamo effettuando il debug del processo, è il momento di fermarlo e caricare tutti i moduli. Prima fare clic su _Debug >> Break All_ e quindi fare clic su _**Debug >> Windows >> Modules**_:

![](<../../.gitbook/assets/image (286).png>)

![](<../../.gitbook/assets/image (283).png>)

Fare clic su qualsiasi modulo in **Modules** e selezionare **Open All Modules**:

![](<../../.gitbook/assets/image (284).png>)

Fare clic con il pulsante destro del mouse su qualsiasi modulo in **Assembly Explorer** e fare clic su **Sort Assemblies**:

![](<../../.gitbook/assets/image (285).png>)

## Decompilatore Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLL

### Utilizzando IDA

* **Caricare rundll32** (64 bit in C:\Windows\System32\rundll32.exe e 32 bit in C:\Windows\SysWOW64\rundll32.exe)
* Selezionare il debugger **Windbg**
* Selezionare "**Suspend on library load/unload**"

![](<../../.gitbook/assets/image (135).png>)

* Configurare i **parametri** dell'esecuzione inserendo il **percorso della DLL** e la funzione che si desidera chiamare:

![](<../../.gitbook/assets/image (136).png>)

Quindi, quando si avvia il debug, **l'esecuzione verrà interrotta quando ogni DLL viene caricata**, quindi, quando rundll32 carica la DLL, l'esecuzione verrà interrotta.

Ma come si può accedere al codice della DLL che è stata caricata? Utilizzando questo metodo, non lo so.

### Utilizzando x64dbg/x32dbg

* **Caricare rundll32** (64 bit in C:\Windows\System32\rundll32.exe e 32 bit in C:\Windows\SysWOW64\rundll32.exe)
* **Cambiare la riga di comando** ( _File --> Change Command Line_ ) e impostare il percorso della DLL e la funzione che si desidera chiamare, ad esempio: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii\_2.dll",DLLMain
* Cambiare _Options --> Settings_ e selezionare "**DLL Entry**".
* Quindi **avviare l'esecuzione**, il debugger si fermerà ad ogni dll main, ad un certo punto ti fermerai nella dll Entry della tua dll. Da lì, cerca i punti in cui desideri impostare un punto di interruzione.

Si noti che quando l'esecuzione viene interrotta per qualsiasi motivo in win64dbg, è possibile vedere **in quale codice si trova** guardando nella **parte superiore della finestra win64dbg**:

![](<../../.gitbook/assets/image (137).png>)

Quindi, guardando questo, è possibile vedere quando l'esecuzione è stata interrotta nella dll che si desidera eseguire il debug.

## App GUI / Videogiochi

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) è un programma utile per trovare dove vengono salvati i valori importanti nella memoria di un gioco in esecuzione e modificarli. Ulteriori informazioni su:

{% content-ref url="cheat-engine.md" %}
[cheat-engine.md](cheat-engine.md)
{% endcontent-ref %}

## ARM & MIPS

{% embed url="https://github.com/nongiach/arm_now" %}

## Shellcode

### Debugging di uno shellcode con blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) allocherà lo **shellcode** all'interno di uno spazio di memoria, indicherà l'indirizzo di memoria in cui è stato allocato lo shellcode e interromperà l'esecuzione.\
Successivamente, è necessario **collegare un debugger** (Ida o x64dbg) al processo e impostare un **punto di interruzione all'indirizzo di memoria indicato** e riprendere l'esecuzione. In questo modo si effettuerà il debug dello shellcode.

La pagina dei rilasci su GitHub contiene file zip contenenti i rilasci compilati: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
È possibile trovare una versione leggermente modificata di Blobrunner al seguente link. Per compilarlo, basta **creare un progetto C/C++ in Visual Studio Code, copiare e incollare il codice e compilarlo**.

{% content-ref url="blobrunner.md" %}
[blobrunner.md](blobrunner.md)
{% endcontent-ref %}

### Debugging di uno shellcode con jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)è molto simile a blobrunner. Allocherà lo **shellcode** all'interno di uno spazio di memoria e avvierà un **loop eterno**. Successivamente, è necessario **collegare il debugger** al processo, **avviare l'esecuzione, attendere 2-5 secondi e premere stop** e ci si troverà all'interno del **loop eterno**. Saltare all'istruzione successiva del loop eterno poiché sarà una chiamata allo shellcode e infine ci si troverà ad eseguire lo shellcode.

![](<../../.gitbook/assets/image (397).png>)

È possibile scaricare una versione compilata di [jmp2it nella pagina dei rilasci](https://github.com/adamkramer/jmp2it/releases/).

### Debugging dello shellcode utilizzando Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) è l'interfaccia grafica di radare. Utilizzando Cutter è possibile emulare lo shellcode e ispezionarlo in modo dinamico.

Si noti che Cutter consente di "Aprire file" e "Aprire shellcode". Nel mio caso, quando ho aperto lo shellcode come file, lo ha decompilato correttamente, ma quando l'ho aperto come shellcode non l'ha fatto:

![](<../../.gitbook/assets/image (400).png>)

Per avviare l'emulazione nel punto desiderato, impostare un bp lì e apparentemente Cutter avvierà automaticamente l'emulazione da lì:

![](<../../.gitbook/assets/image (399).png>)

È possibile visualizzare lo stack, ad esempio, all'interno di un dump esadecimale:

![](<../../.gitbook/assets/image (402).png>)

### Deobfuscating dello shellcode e ottenere le funzioni eseguite

Si consiglia di provare [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7\&pid=152).\
Fornirà informazioni su **quali funzioni** utilizza lo shellcode e se lo shellcode si sta **decodificando** in memoria.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg conta anche con un launcher grafico in cui è possibile selezionare le opzioni desiderate ed eseguire lo shellcode

![](<../../.gitbook/assets/image (398).png>)

L'opzione **Create Dump** effettuerà il dump dello shellcode finale se viene apportata qualsiasi modifica allo shellcode in modo dinamico in memoria (utile per scaricare lo shellcode decodificato). L'**offset di avvio** può essere utile per avviare lo shellcode a un offset specifico. L'opzione **Debug Shell** è utile per il debug dello shellcode utilizzando il terminale scDbg (tuttavia trovo che una delle opzioni spiegate in precedenza sia migliore per questa questione in quanto sarà possibile utilizzare Ida o x64dbg).

### Disassemblaggio utilizzando CyberChef

Carica il file dello shellcode come input e utilizza la seguente ricetta per decompilarlo: [https://gchq.github.io/CyberChef/#recipe=To\_Hex('Space',0)Disassemble\_x86('32','Full%20x86%20architecture',16,0,true,true)](https://gchq.github.io/CyberChef/#recipe=To\_Hex\('Space',0\)Disassemble\_x86\('32','Full%20x86%20architecture',16,0,true,true\))

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Questo obfuscator **modifica tutte le istruzioni per `mov`** (sì, davvero cool). Utilizza anche interruzioni per cambiare i flussi di esecuzione. Per ulteriori informazioni su come funziona:

* [https://www.youtube.com/watch?v=2VF\_wPkiBJY](https://www.youtube.com/watch?v=2VF\_wPkiBJY)
* [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf)

Se hai fortuna, [demovfuscator](https://github.com/kirschju/demovfuscator) deofuscherà il binario. Ha diverse dipendenze.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
E [installa keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Se stai giocando a un **CTF, questo workaround per trovare la flag** potrebbe essere molto utile: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trova le vulnerabilità più importanti in modo da poterle correggere più velocemente. Intruder traccia la tua superficie di attacco, esegue scansioni proattive delle minacce, trova problemi in tutta la tua infrastruttura tecnologica, dalle API alle applicazioni web e ai sistemi cloud. [**Provalo gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) oggi stesso.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Rust

Per trovare il **punto di ingresso**, cerca le funzioni con `::main` come in:

![](<../../.gitbook/assets/image (612).png>)

In questo caso il binario si chiamava authenticator, quindi è abbastanza ovvio che questa sia l'interessante funzione principale.\
Avendo il **nome** delle **funzioni** chiamate, cercali su **Internet** per conoscere i loro **input** e **output**.

## **Delphi**

Per i binari compilati in Delphi puoi utilizzare [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Se devi invertire un binario Delphi ti consiglio di utilizzare il plugin IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Basta premere **ATL+f7** (importa il plugin python in IDA) e selezionare il plugin python.

Questo plugin eseguirà il binario e risolverà dinamicamente i nomi delle funzioni all'inizio del debug. Dopo aver avviato il debug, premi nuovamente il pulsante Start (quello verde o f9) e verrà colpito un punto di interruzione all'inizio del codice reale.

È anche molto interessante perché se premi un pulsante nell'applicazione grafica, il debugger si fermerà nella funzione eseguita da quel pulsante.

## Golang

Se devi invertire un binario Golang ti consiglio di utilizzare il plugin IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Basta premere **ATL+f7** (importa il plugin python in IDA) e selezionare il plugin python.

Questo risolverà i nomi delle funzioni.

## Python compilato

In questa pagina puoi trovare come ottenere il codice python da un binario compilato ELF/EXE:

{% content-ref url="../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## GBA - Game Body Advance

Se ottieni il **binario** di un gioco GBA puoi utilizzare diversi strumenti per **emularlo** e **debuggarlo**:

* [**no$gba**](https://problemkaputt.de/gba.htm) (_Scarica la versione di debug_) - Contiene un debugger con interfaccia
* [**mgba** ](https://mgba.io)- Contiene un debugger CLI
* [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin Ghidra
* [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin Ghidra

In [**no$gba**](https://problemkaputt.de/gba.htm), in _**Options --> Emulation Setup --> Controls**_\*\* \*\* puoi vedere come premere i **pulsanti** del Game Boy Advance

![](<../../.gitbook/assets/image (578).png>)

Quando premuti, ogni **tasto ha un valore** per identificarlo:
```
A = 1
B = 2
SELECT = 4
START = 8
RIGHT = 16
LEFT = 32
UP = 64
DOWN = 128
R = 256
L = 256
```
Quindi, in questo tipo di programmi, una parte interessante sarà **come il programma gestisce l'input dell'utente**. All'indirizzo **0x4000130** troverai la funzione comunemente trovata: **KEYINPUT**.

![](<../../.gitbook/assets/image (579).png>)

Nell'immagine precedente puoi vedere che la funzione viene chiamata da **FUN\_080015a8** (indirizzi: _0x080015fa_ e _0x080017ac_).

In quella funzione, dopo alcune operazioni di inizializzazione (senza alcuna importanza):
```c
void FUN_080015a8(void)

{
ushort uVar1;
undefined4 uVar2;
undefined4 uVar3;
ushort uVar4;
int iVar5;
ushort *puVar6;
undefined *local_2c;

DISPCNT = 0x1140;
FUN_08000a74();
FUN_08000ce4(1);
DISPCNT = 0x404;
FUN_08000dd0(&DAT_02009584,0x6000000,&DAT_030000dc);
FUN_08000354(&DAT_030000dc,0x3c);
uVar4 = DAT_030004d8;
```
È stato trovato questo codice:
```c
do {
DAT_030004da = uVar4; //This is the last key pressed
DAT_030004d8 = KEYINPUT | 0xfc00;
puVar6 = &DAT_0200b03c;
uVar4 = DAT_030004d8;
do {
uVar2 = DAT_030004dc;
uVar1 = *puVar6;
if ((uVar1 & DAT_030004da & ~uVar4) != 0) {
```
L'ultimo if controlla se **`uVar4`** è presente nelle **ultime chiavi** e non è la chiave corrente, anche chiamata rilascio di un pulsante (la chiave corrente è memorizzata in **`uVar1`**).
```c
if (uVar1 == 4) {
DAT_030000d4 = 0;
uVar3 = FUN_08001c24(DAT_030004dc);
FUN_08001868(uVar2,0,uVar3);
DAT_05000000 = 0x1483;
FUN_08001844(&DAT_0200ba18);
FUN_08001844(&DAT_0200ba20,&DAT_0200ba40);
DAT_030000d8 = 0;
uVar4 = DAT_030004d8;
}
else {
if (uVar1 == 8) {
if (DAT_030000d8 == 0xf3) {
DISPCNT = 0x404;
FUN_08000dd0(&DAT_02008aac,0x6000000,&DAT_030000dc);
FUN_08000354(&DAT_030000dc,0x3c);
uVar4 = DAT_030004d8;
}
}
else {
if (DAT_030000d4 < 8) {
DAT_030000d4 = DAT_030000d4 + 1;
FUN_08000864();
if (uVar1 == 0x10) {
DAT_030000d8 = DAT_030000d8 + 0x3a;
```
Nel codice precedente è possibile vedere che stiamo confrontando **uVar1** (il luogo in cui si trova il **valore del pulsante premuto**) con alcuni valori:

* Prima, viene confrontato con il **valore 4** (pulsante **SELECT**): In questa sfida questo pulsante cancella lo schermo.
* Successivamente, viene confrontato con il **valore 8** (pulsante **START**): In questa sfida viene verificato se il codice è valido per ottenere la bandiera.
* In questo caso, la variabile **`DAT_030000d8`** viene confrontata con 0xf3 e se il valore è lo stesso viene eseguito del codice.
* In tutti gli altri casi, viene controllato un cont (`DAT_030000d4`). È un cont perché viene incrementato di 1 subito dopo l'ingresso nel codice.\
Se è inferiore a 8, viene eseguita un'operazione che coinvolge l'**aggiunta** di valori a \*\*`DAT_030000d8` \*\* (in pratica vengono aggiunti i valori dei pulsanti premuti in questa variabile finché il cont è inferiore a 8).

Quindi, in questa sfida, conoscendo i valori dei pulsanti, era necessario **premere una combinazione con una lunghezza inferiore a 8 in modo che l'addizione risultante fosse 0xf3**.

**Riferimento per questo tutorial:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy

{% embed url="https://www.youtube.com/watch?v=VVbRe7wr3G4" %}

## Corsi

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Deobfuscation binario)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trova le vulnerabilità che contano di più in modo da poterle correggere più velocemente. Intruder traccia la tua superficie di attacco, esegue scansioni proattive delle minacce, trova problemi in tutta la tua infrastruttura tecnologica, dalle API alle applicazioni web e ai sistemi cloud. [**Provalo gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) oggi stesso.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
