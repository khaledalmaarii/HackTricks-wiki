{% hint style="success" %}
Impara e pratica l'hacking di AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'hacking di GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) nei repository di github.

</details>
{% endhint %}


## smss.exe

**Gestore sessioni**.\
La Sessione 0 avvia **csrss.exe** e **wininit.exe** (**servizi OS**) mentre la Sessione 1 avvia **csrss.exe** e **winlogon.exe** (**sessione utente**). Tuttavia, dovresti vedere **solo un processo** di quel **binario** senza figli nell'albero dei processi.

Inoltre, sessioni diverse da 0 e 1 potrebbero indicare che si stanno verificando sessioni RDP.


## csrss.exe

**Processo Sottosistema Client/Server**.\
Gestisce **processi** e **thread**, rende disponibile l'**API di Windows** per altri processi e inoltre **mappa le lettere delle unità**, crea **file temporanei** e gestisce il **processo di spegnimento**.

Ce n'è uno in esecuzione nella Sessione 0 e un altro nella Sessione 1 (quindi **2 processi** nell'albero dei processi). Ne viene creato un altro per ogni nuova Sessione.


## winlogon.exe

**Processo di accesso a Windows**.\
È responsabile dei **login**/**logout** degli utenti. Avvia **logonui.exe** per richiedere nome utente e password e quindi chiama **lsass.exe** per verificarli.

Poi avvia **userinit.exe** che è specificato in **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`** con la chiave **Userinit**.

Inoltre, il registro precedente dovrebbe avere **explorer.exe** nella chiave **Shell** o potrebbe essere sfruttato come un **metodo di persistenza del malware**.


## wininit.exe

**Processo di inizializzazione di Windows**. \
Avvia **services.exe**, **lsass.exe** e **lsm.exe** nella Sessione 0. Dovrebbe esserci solo 1 processo.


## userinit.exe

**Applicazione di accesso Userinit**.\
Carica il **ntduser.dat in HKCU** e inizializza l'**ambiente utente** ed esegue **script di accesso** e **GPO**.

Avvia **explorer.exe**.


## lsm.exe

**Gestore sessioni locale**.\
Collabora con smss.exe per manipolare le sessioni utente: login/logout, avvio della shell, blocco/sblocco desktop, ecc.

Dopo W7 lsm.exe è stato trasformato in un servizio (lsm.dll).

Dovrebbe esserci solo 1 processo in W7 e da esso un servizio che esegue il DLL.


## services.exe

**Gestore controllo servizi**.\
**Carica** i **servizi** configurati come **avvio automatico** e i **driver**.

È il processo principale di **svchost.exe**, **dllhost.exe**, **taskhost.exe**, **spoolsv.exe** e molti altri.

I servizi sono definiti in `HKLM\SYSTEM\CurrentControlSet\Services` e questo processo mantiene un database in memoria delle informazioni sui servizi che possono essere interrogate da sc.exe.

Nota come **alcuni** **servizi** verranno eseguiti in un **processo separato** e altri verranno **condivisi in un processo svchost.exe**.

Dovrebbe esserci solo 1 processo.


## lsass.exe

**Sottosistema di autorità di sicurezza locale**.\
È responsabile dell'**autenticazione** dell'utente e crea i **token di sicurezza**. Utilizza pacchetti di autenticazione situati in `HKLM\System\CurrentControlSet\Control\Lsa`.

Scrive nel **log eventi di sicurezza** e dovrebbe esserci solo 1 processo.

Tieni presente che questo processo è molto attaccato per estrarre le password.


## svchost.exe

**Processo host di servizio generico**.\
Ospita più servizi DLL in un unico processo condiviso.

Di solito, troverai che **svchost.exe** viene avviato con il flag `-k`. Questo avvierà una query al registro **HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost** dove ci sarà una chiave con l'argomento menzionato in -k che conterrà i servizi da avviare nello stesso processo.

Ad esempio: `-k UnistackSvcGroup` avvierà: `PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

Se viene utilizzato anche il **flag `-s`** con un argomento, allora a svchost viene chiesto di **avviare solo il servizio specificato** in questo argomento.

Ci saranno diversi processi di `svchost.exe`. Se uno di essi **non utilizza il flag `-k`**, allora è molto sospetto. Se scopri che **services.exe non è il processo padre**, anche questo è molto sospetto.


## taskhost.exe

Questo processo funge da host per i processi in esecuzione da DLL. Carica anche i servizi in esecuzione da DLL.

In W8 questo viene chiamato taskhostex.exe e in W10 taskhostw.exe.


## explorer.exe

Questo è il processo responsabile della **scrivania dell'utente** e del lancio dei file tramite le estensioni dei file.

Dovrebbe essere generato solo **1** processo per utente connesso.

Viene eseguito da **userinit.exe** che dovrebbe essere terminato, quindi **non dovrebbe apparire alcun processo genitore** per questo processo.


# Catturare processi maligni

* Sta eseguendo dal percorso previsto? (Nessun binario di Windows viene eseguito dalla posizione temporanea)
* Sta comunicando con IP strani?
* Controlla le firme digitali (gli artefatti Microsoft dovrebbero essere firmati)
* È scritto correttamente?
* Sta eseguendo sotto l'SID previsto?
* Il processo genitore è quello previsto (se presente)?
* I processi figlio sono quelli attesi? (nessun cmd.exe, wscript.exe, powershell.exe..?)
  

{% hint style="success" %}
Impara e pratica l'hacking di AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'hacking di GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) nei repository di github.

</details>
{% endhint %}
