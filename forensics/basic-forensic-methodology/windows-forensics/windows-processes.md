<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository GitHub di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


## smss.exe

**Session Manager**.\
La sessione 0 avvia **csrss.exe** e **wininit.exe** (**servizi** **OS**) mentre la sessione 1 avvia **csrss.exe** e **winlogon.exe** (**sessione** **utente**). Tuttavia, dovresti vedere **solo un processo** di quel **binario** senza figli nell'albero dei processi.

Inoltre, sessioni diverse da 0 e 1 potrebbero indicare che sono in corso sessioni RDP.


## csrss.exe

**Client/Server Run Subsystem Process**.\
Gestisce **processi** e **thread**, rende disponibile l'API di Windows ad altri processi e **mappa le lettere delle unità**, crea **file temporanei** e gestisce il **processo di spegnimento**.

Ce n'è uno in esecuzione nella sessione 0 e un altro nella sessione 1 (quindi **2 processi** nell'albero dei processi). Ne viene creato un altro per ogni nuova sessione.


## winlogon.exe

**Windows Logon Process**.\
È responsabile dei **login**/**logout** degli utenti. Avvia **logonui.exe** per richiedere nome utente e password e quindi chiama **lsass.exe** per verificarli.

Successivamente avvia **userinit.exe**, specificato in **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`** con la chiave **Userinit**.

Inoltre, il registro precedente dovrebbe avere **explorer.exe** nella chiave **Shell** o potrebbe essere sfruttato come un **metodo di persistenza del malware**.


## wininit.exe

**Windows Initialization Process**. \
Avvia **services.exe**, **lsass.exe** e **lsm.exe** nella sessione 0. Dovrebbe esserci solo 1 processo.


## userinit.exe

**Userinit Logon Application**.\
Carica **ntuser.dat in HKCU** e inizializza l'**ambiente utente** e esegue **script di login** e **GPO**.

Avvia **explorer.exe**.


## lsm.exe

**Local Session Manager**.\
Collabora con smss.exe per manipolare le sessioni utente: login/logout, avvio della shell, blocco/sblocco del desktop, ecc.

Dopo W7, lsm.exe è stato trasformato in un servizio (lsm.dll).

Dovrebbe esserci solo 1 processo in W7 e da esso viene eseguito un servizio che esegue la DLL.


## services.exe

**Service Control Manager**.\
Carica i **servizi** configurati come **avvio automatico** e i **driver**.

È il processo padre di **svchost.exe**, **dllhost.exe**, **taskhost.exe**, **spoolsv.exe** e molti altri.

I servizi sono definiti in `HKLM\SYSTEM\CurrentControlSet\Services` e questo processo mantiene un database in memoria delle informazioni sui servizi che possono essere interrogate da sc.exe.

Nota come **alcuni servizi** verranno eseguiti in un **processo separato** e altri verranno **eseguiti condividendo un processo svchost.exe**.

Dovrebbe esserci solo 1 processo.


## lsass.exe

**Local Security Authority Subsystem**.\
È responsabile dell'**autenticazione** dell'utente e crea i **token di sicurezza**. Utilizza pacchetti di autenticazione situati in `HKLM\System\CurrentControlSet\Control\Lsa`.

Scrive nel **log eventi di sicurezza** e dovrebbe esserci solo 1 processo.

Tieni presente che questo processo è molto attaccato per il dump delle password.


## svchost.exe

**Generic Service Host Process**.\
Ospita più servizi DLL in un unico processo condiviso.

Di solito, troverai che **svchost.exe** viene avviato con l'opzione `-k`. Questo avvierà una query al registro **HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost** dove ci sarà una chiave con l'argomento menzionato in -k che conterrà i servizi da avviare nello stesso processo.

Ad esempio: `-k UnistackSvcGroup` avvierà: `PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

Se viene utilizzata anche l'opzione **`-s`** con un argomento, svchost viene richiesto di **avviare solo il servizio specificato** in questo argomento.

Ci saranno diversi processi di `svchost.exe`. Se uno di essi **non utilizza l'opzione `-k`**, allora è molto sospetto. Se scopri che **services.exe non è il processo padre**, anche questo è molto sospetto.


## taskhost.exe

Questo processo funge da host per i processi in esecuzione da DLL. Carica anche i servizi in esecuzione da DLL.

In W8 viene chiamato taskhostex.exe e in W10 taskhostw.exe.


## explorer.exe

Questo è il processo responsabile del **desktop dell'utente** e dell'avvio dei file tramite le estensioni dei file.

Dovrebbe essere generato **solo 1** processo **per utente connesso**.

Viene eseguito da **userinit.exe** che dovrebbe essere terminato, quindi **non dovrebbe apparire un processo padre** per questo processo.


# Individuazione dei processi maligni

* Sta eseguendo dal percorso previsto? (Nessun binario di Windows viene eseguito dalla posizione temporanea)
* Sta comunicando con indirizzi IP strani?
* Verifica le firme digitali (gli artefatti di Microsoft dovrebbero essere firmati)
* È scritto correttamente?
* Sta eseguendo con l'SID previsto?
* Il processo padre è quello previsto (se presente)?
* I processi figlio sono quelli previsti? (nessun cmd.exe, wscript.exe, powershell.exe..?)


<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository GitHub di** [**HackTricks**](https://github.com/carlospol
