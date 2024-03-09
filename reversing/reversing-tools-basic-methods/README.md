# Strumenti e Metodi di Reverse Engineering

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Strumenti di Reverse Engineering basati su ImGui

Software:

* ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Decompilatore Wasm / Compilatore Wat

Online:

* Usa [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) per **decompilare** da wasm (binario) a wat (testo chiaro)
* Usa [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) per **compilare** da wat a wasm
* Puoi anche provare a usare [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) per decompilare

Software:

* [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
* [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Decompilatore .Net

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek è un decompilatore che **decompila ed esamina vari formati**, inclusi **librerie** (.dll), file di metadati di Windows (.winmd) ed **eseguibili** (.exe). Una volta decompilato, un assembly può essere salvato come progetto Visual Studio (.csproj).

Il merito qui è che se un codice sorgente perso richiede il ripristino da un assembly legacy, questa azione può risparmiare tempo. Inoltre, dotPeek fornisce una comoda navigazione all'interno del codice decompilato, rendendolo uno degli strumenti perfetti per l'analisi degli algoritmi Xamarin.

### [.Net Reflector](https://www.red-gate.com/products/reflector/)

Con un modello di add-in completo e un'API che estende lo strumento per adattarlo alle tue esigenze esatte, .NET Reflector risparmia tempo e semplifica lo sviluppo. Diamo un'occhiata alla moltitudine di servizi di reverse engineering che questo strumento fornisce:

* Fornisce una visione di come i dati scorrono attraverso una libreria o un componente
* Fornisce una visione dell'implementazione e dell'uso di linguaggi e framework .NET
* Trova funzionalità non documentate e non esposte per ottenere di più dalle API e dalle tecnologie utilizzate.
* Trova dipendenze e diverse librerie
* Rintraccia l'esatta posizione degli errori nel tuo codice, nei componenti di terze parti e nelle librerie.
* Esegue il debug del codice .NET con cui lavori.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin per Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Puoi averlo su qualsiasi OS (puoi installarlo direttamente da VSCode, non c'è bisogno di scaricare il git. Clicca su **Estensioni** e **cerca ILSpy**).\
Se hai bisogno di **decompilare**, **modificare** e **ricompilare** di nuovo puoi usare: [**https://github.com/0xd4d/dnSpy/releases**](https://github.com/0xd4d/dnSpy/releases) (**Fai clic destro -> Modifica Metodo** per cambiare qualcosa all'interno di una funzione).\
Puoi anche provare [https://www.jetbrains.com/es-es/decompiler/](https://www.jetbrains.com/es-es/decompiler/)

### Registrazione DNSpy

Per fare in modo che **DNSpy registri alcune informazioni in un file**, potresti usare queste righe di codice .Net:
```bash
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Debugging con DNSpy

Per eseguire il debug del codice utilizzando DNSpy è necessario:

Prima di tutto, modificare gli **attributi dell'Assembly** relativi al **debugging**:

![](<../../.gitbook/assets/image (278).png>)
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
A:
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
E clicca su **compile**:

![](<../../.gitbook/assets/image (314) (1) (1).png>)

Quindi salva il nuovo file su _**File >> Salva modulo...**_:

![](<../../.gitbook/assets/image (279).png>)

Questo è necessario perché se non lo fai, durante l'**esecuzione** verranno applicate diverse **ottimizzazioni** al codice e potrebbe essere possibile che durante il debug un **punto di interruzione non venga mai raggiunto** o alcune **variabili non esistano**.

Quindi, se la tua applicazione .Net viene **eseguita** da **IIS**, puoi **riavviarla** con:
```
iisreset /noforce
```
Quindi, per iniziare il debug, dovresti chiudere tutti i file aperti e selezionare **Allega al processo...** nella **scheda Debug**:

![](<../../.gitbook/assets/image (280).png>)

Successivamente, seleziona **w3wp.exe** per allegarti al **server IIS** e clicca su **allega**:

![](<../../.gitbook/assets/image (281).png>)

Ora che stiamo effettuando il debug del processo, è il momento di fermarlo e caricare tutti i moduli. Prima fai clic su _Debug >> Interrompi tutto_ e poi fai clic su _**Debug >> Finestre >> Moduli**_:

![](<../../.gitbook/assets/image (286).png>)

![](<../../.gitbook/assets/image (283).png>)

Fai clic su qualsiasi modulo su **Moduli** e seleziona **Apri tutti i moduli**:

![](<../../.gitbook/assets/image (284).png>)

Fai clic con il pulsante destro su qualsiasi modulo in **Esplora assembly** e seleziona **Ordina assembly**:

![](<../../.gitbook/assets/image (285).png>)

## Decompilatore Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging delle DLL

### Utilizzando IDA

* **Carica rundll32** (64 bit in C:\Windows\System32\rundll32.exe e 32 bit in C:\Windows\SysWOW64\rundll32.exe)
* Seleziona il debugger **Windbg**
* Seleziona "**Sospendi al caricamento/spegnimento della libreria**"

![](<../../.gitbook/assets/image (135).png>)

* Configura i **parametri** dell'esecuzione inserendo il **percorso della DLL** e la funzione che desideri chiamare:

![](<../../.gitbook/assets/image (136).png>)

Quindi, quando inizi il debug, l'esecuzione si interromperà quando ogni DLL viene caricata, quindi, quando rundll32 carica la tua DLL, l'esecuzione si interromperà.

Ma, come puoi accedere al codice della DLL che è stata caricata? Utilizzando questo metodo, non lo so.

### Utilizzando x64dbg/x32dbg

* **Carica rundll32** (64 bit in C:\Windows\System32\rundll32.exe e 32 bit in C:\Windows\SysWOW64\rundll32.exe)
* **Modifica la riga di comando** ( _File --> Modifica riga di comando_ ) e imposta il percorso della dll e la funzione che desideri chiamare, ad esempio: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii\_2.dll",DLLMain
* Cambia _Opzioni --> Impostazioni_ e seleziona "**Ingresso DLL**".
* Quindi **avvia l'esecuzione**, il debugger si fermerà a ogni dll principale, a un certo punto ti **fermerai nell'ingresso della DLL della tua dll**. Da lì, cerca i punti in cui desideri impostare un breakpoint.

Nota che quando l'esecuzione viene interrotta per qualsiasi motivo in win64dbg, puoi vedere **in quale codice ti trovi** guardando nella **parte superiore della finestra di win64dbg**:

![](<../../.gitbook/assets/image (137).png>)

Quindi, guardando questo, puoi vedere quando l'esecuzione è stata interrotta nella dll che desideri eseguire il debug.

## App GUI / Videogiochi

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) è un programma utile per trovare dove sono salvati i valori importanti nella memoria di un gioco in esecuzione e modificarli. Ulteriori informazioni in:

{% content-ref url="cheat-engine.md" %}
[cheat-engine.md](cheat-engine.md)
{% endcontent-ref %}

## ARM & MIPS

{% embed url="https://github.com/nongiach/arm_now" %}

## Shellcode

### Debugging di uno shellcode con blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) **alloca** lo **shellcode** all'interno di uno spazio di memoria, ti **indica** l'**indirizzo di memoria** in cui lo shellcode è stato allocato e **ferma** l'esecuzione.\
Successivamente, è necessario **collegare un debugger** (Ida o x64dbg) al processo e impostare un **breakpoint all'indirizzo di memoria indicato** e **riprendere** l'esecuzione. In questo modo sarai in grado di eseguire il debug dello shellcode.

La pagina dei rilasci su GitHub contiene zippati contenenti i rilasci compilati: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Puoi trovare una versione leggermente modificata di Blobrunner nel seguente link. Per compilarlo, basta **creare un progetto C/C++ in Visual Studio Code, copiare e incollare il codice e compilarlo**.

{% content-ref url="blobrunner.md" %}
[blobrunner.md](blobrunner.md)
{% endcontent-ref %}

### Debugging di uno shellcode con jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)è molto simile a blobrunner. **Alloca** lo **shellcode** all'interno di uno spazio di memoria e avvia un **loop eterno**. Successivamente, è necessario **collegare il debugger** al processo, **avviare l'esecuzione, attendere 2-5 secondi e premere stop** e ti troverai all'interno del **loop eterno**. Salta alla prossima istruzione del loop eterno poiché sarà una chiamata allo shellcode e infine ti troverai ad eseguire lo shellcode.

![](<../../.gitbook/assets/image (397).png>)

Puoi scaricare una versione compilata di [jmp2it nella pagina dei rilasci](https://github.com/adamkramer/jmp2it/releases/).

### Debugging dello shellcode utilizzando Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) è l'interfaccia grafica di radare. Utilizzando Cutter puoi emulare lo shellcode e ispezionarlo dinamicamente.

Nota che Cutter ti consente di "Aprire file" e "Aprire shellcode". Nel mio caso, quando ho aperto lo shellcode come file, lo ha decompilato correttamente, ma quando l'ho aperto come shellcode no:

![](<../../.gitbook/assets/image (400).png>)

Per avviare l'emulazione nel punto desiderato, imposta un bp lì e apparentemente Cutter avvierà automaticamente l'emulazione da lì:

![](<../../.gitbook/assets/image (399).png>)

![](<../../.gitbook/assets/image (401).png>)

Puoi vedere lo stack ad esempio all'interno di un dump esadecimale:

![](<../../.gitbook/assets/image (402).png>)

### Deobfuscating dello shellcode e ottenere le funzioni eseguite

Dovresti provare [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7\&pid=152).\
Ti dirà quali funzioni sta utilizzando lo shellcode e se lo shellcode si sta **decodificando** in memoria.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg conta anche con un launcher grafico in cui puoi selezionare le opzioni desiderate ed eseguire lo shellcode

![](<../../.gitbook/assets/image (398).png>)

L'opzione **Create Dump** scaricherà lo shellcode finale se viene apportata una modifica dinamica allo shellcode in memoria (utile per scaricare lo shellcode decodificato). L'**offset di avvio** può essere utile per avviare lo shellcode a un offset specifico. L'opzione **Debug Shell** è utile per eseguire il debug dello shellcode utilizzando il terminale scDbg (tuttavia trovo che una qualsiasi delle opzioni spiegate prima sia migliore per questa questione in quanto sarà possibile utilizzare Ida o x64dbg).

### Disassemblaggio utilizzando CyberChef

Carica il file dello shellcode come input e utilizza la seguente ricetta per decompilarlo: [https://gchq.github.io/CyberChef/#recipe=To\_Hex('Space',0)Disassemble\_x86('32','Full%20x86%20architecture',16,0,true,true)](https://gchq.github.io/CyberChef/#recipe=To\_Hex\('Space',0\)Disassemble\_x86\('32','Full%20x86%20architecture',16,0,true,true\))

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Questo offuscatore **modifica tutte le istruzioni per `mov`** (sì, davvero cool). Utilizza anche interruzioni per cambiare i flussi di esecuzione. Per ulteriori informazioni su come funziona:

* [https://www.youtube.com/watch?v=2VF\_wPkiBJY](https://www.youtube.com/watch?v=2VF\_wPkiBJY)
* [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf)

Se sei fortunato, [demovfuscator](https://github.com/kirschju/demovfuscator) deofuscherà il binario. Ha diverse dipendenze
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
E [installa keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Se stai partecipando a un **CTF, questo workaround per trovare la flag** potrebbe essere molto utile: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Per trovare il **punto di ingresso** cerca le funzioni con `::main` come in:

![](<../../.gitbook/assets/image (612).png>)

In questo caso il binario si chiamava authenticator, quindi è abbastanza ovvio che questa sia la funzione main interessante.\
Avendo il **nome** delle **funzioni** chiamate, cerca su **Internet** per apprendere i loro **input** e **output**.

## **Delphi**

Per i binari compilati in Delphi puoi utilizzare [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Se devi invertire un binario Delphi ti consiglio di utilizzare il plugin di IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Basta premere **ATL+f7** (importa il plugin python in IDA) e selezionare il plugin python.

Questo plugin eseguirà il binario e risolverà dinamicamente i nomi delle funzioni all'inizio del debug. Dopo aver avviato il debug, premi nuovamente il pulsante Start (quello verde o f9) e verrà colpito un breakpoint all'inizio del codice reale.

È anche molto interessante perché se premi un pulsante nell'applicazione grafica il debugger si fermerà nella funzione eseguita da quel pulsante.

## Golang

Se devi invertire un binario Golang ti consiglio di utilizzare il plugin di IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Basta premere **ATL+f7** (importa il plugin python in IDA) e selezionare il plugin python.

Questo risolverà i nomi delle funzioni.

## Python compilato

In questa pagina puoi trovare come ottenere il codice Python da un binario compilato ELF/EXE:

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

Quando premuto, ogni **tasto ha un valore** per identificarlo:
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
Quindi, in questo tipo di programmi, una parte interessante sarà **come il programma gestisce l'input dell'utente**. All'indirizzo **0x4000130** troverai la funzione comunemente trovata: **KEYINPUT.**

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
L'ultimo if sta controllando se **`uVar4`** è tra gli **ultimi tasti** e non è il tasto corrente, chiamato anche rilascio di un pulsante (il tasto corrente è memorizzato in **`uVar1`**).
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
Nel codice precedente puoi vedere che stiamo confrontando **uVar1** (il luogo dove si trova il **valore del pulsante premuto**) con alcuni valori:

* Prima, viene confrontato con il **valore 4** (pulsante **SELECT**): In questa sfida questo pulsante cancella lo schermo.
* Poi, viene confrontato con il **valore 8** (pulsante **START**): In questa sfida controlla se il codice è valido per ottenere la flag.
* In questo caso la variabile **`DAT_030000d8`** viene confrontata con 0xf3 e se il valore è lo stesso viene eseguito del codice.
* In tutti gli altri casi, viene controllato un cont (`DAT_030000d4`). È un cont perché viene aggiunto 1 subito dopo l'ingresso nel codice.\
Se è inferiore a 8, viene fatto qualcosa che coinvolge l'**aggiunta** di valori a **`DAT_030000d8`** (in pratica si aggiungono i valori dei tasti premuti in questa variabile finché il cont è inferiore a 8).

Quindi, in questa sfida, conoscendo i valori dei pulsanti, dovevi **premere una combinazione con una lunghezza inferiore a 8 in modo che l'aggiunta risultante sia 0xf3.**

**Riferimento per questo tutorial:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy

{% embed url="https://www.youtube.com/watch?v=VVbRe7wr3G4" %}

## Corsi

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Deobfuscation binaria)
