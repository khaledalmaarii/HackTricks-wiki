# Writable Sys Path +Dll Hijacking Privesc

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) **e** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repository di Github.**

</details>

## Introduzione

Se hai scoperto che puoi **scrivere in una cartella di sistema** (nota che ciò non funzionerà se puoi scrivere in una cartella di utente), è possibile che tu possa **elevare i privilegi** nel sistema.

Per fare ciò, puoi sfruttare un **Dll Hijacking** in cui **intercetti una libreria in fase di caricamento** da parte di un servizio o processo con **privilegi superiori** ai tuoi e, poiché tale servizio sta caricando una Dll che probabilmente non esiste nemmeno nell'intero sistema, cercherà di caricarla dalla cartella di sistema in cui puoi scrivere.

Per ulteriori informazioni su **cosa è il Dll Hijacking**, consulta:

{% content-ref url="../dll-hijacking.md" %}
[dll-hijacking.md](../dll-hijacking.md)
{% endcontent-ref %}

## Privesc con Dll Hijacking

### Trovare una Dll mancante

La prima cosa di cui hai bisogno è **individuare un processo** in esecuzione con **privilegi superiori** ai tuoi che sta cercando di **caricare una Dll dalla cartella di sistema** in cui puoi scrivere.

Il problema in questi casi è che probabilmente questi processi sono già in esecuzione. Per trovare quali Dll mancano ai servizi, è necessario avviare procmon il prima possibile (prima del caricamento dei processi). Quindi, per trovare le .dll mancanti, esegui: 

* **Crea** la cartella `C:\privesc_hijacking` e aggiungi il percorso `C:\privesc_hijacking` alla **variabile di ambiente System Path**. Puoi farlo **manualmente** o con **PS**:
```powershell
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```
* Avvia **`procmon`** e vai su **`Opzioni`** --> **`Abilita registrazione all'avvio`** e premi **`OK`** nella finestra di dialogo.
* Successivamente, **riavvia** il computer. Quando il computer si riavvia, **`procmon`** inizierà a **registrare** gli eventi il prima possibile.
* Una volta che **Windows** è **avviato, esegui nuovamente `procmon`**, ti dirà che è stato in esecuzione e ti **chiederà se vuoi salvare** gli eventi in un file. Rispondi **sì** e **salva gli eventi in un file**.
* **Dopo** che il **file** è **generato**, **chiudi** la finestra di **`procmon`** aperta e **apri il file degli eventi**.
* Aggiungi questi **filtri** e troverai tutte le DLL che alcuni **processi hanno cercato di caricare** dalla cartella del percorso di sistema scrivibile:

<figure><img src="../../../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

### DLL mancanti

Eseguendo questo su una macchina **virtuale (vmware) con Windows 11** ho ottenuto questi risultati:

<figure><img src="../../../.gitbook/assets/image (253).png" alt=""><figcaption></figcaption></figure>

In questo caso, gli .exe sono inutili, quindi ignorali, le DLL mancanti erano da:

| Servizio                       | DLL                | Riga di comando                                                     |
| ------------------------------ | ------------------ | ------------------------------------------------------------------- |
| Task Scheduler (Schedule)      | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`         |
| Diagnostic Policy Service (DPS)| Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS`|
| ???                            | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`               |

Dopo aver trovato questo, ho trovato questo interessante post sul blog che spiega anche come [**abusare di WptsExtensions.dll per l'escalation dei privilegi**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll). Che è quello che **faremo ora**.

### Sfruttamento

Quindi, per **elevare i privilegi**, andremo a dirottare la libreria **WptsExtensions.dll**. Avendo il **percorso** e il **nome**, dobbiamo solo **generare la DLL malevola**.

Puoi [**provare a utilizzare uno di questi esempi**](../dll-hijacking.md#creating-and-compiling-dlls). Puoi eseguire payload come: ottenere una shell reversa, aggiungere un utente, eseguire un beacon...

{% hint style="warning" %}
Nota che **non tutti i servizi vengono eseguiti** con **`NT AUTHORITY\SYSTEM`**, alcuni vengono eseguiti anche con **`NT AUTHORITY\LOCAL SERVICE`** che ha **meno privilegi** e non sarai in grado di creare un nuovo utente sfruttando i suoi permessi.\
Tuttavia, quell'utente ha il privilegio **`seImpersonate`**, quindi puoi utilizzare la [**suite potato per elevare i privilegi**](../roguepotato-and-printspoofer.md). Quindi, in questo caso, una shell reversa è una migliore opzione rispetto al tentativo di creare un utente.
{% endhint %}

Al momento della scrittura, il servizio **Task Scheduler** viene eseguito con **Nt AUTHORITY\SYSTEM**.

Avendo **generato la DLL malevola** (_nel mio caso ho usato una shell reversa x64 e ho ottenuto una shell, ma Defender l'ha uccisa perché proveniva da msfvenom_), salvala nel percorso di sistema scrivibile con il nome **WptsExtensions.dll** e **riavvia** il computer (o riavvia il servizio o fai qualsiasi altra cosa necessaria per eseguire nuovamente il servizio/programma interessato).

Quando il servizio viene riavviato, la **DLL dovrebbe essere caricata ed eseguita** (puoi **riutilizzare** il trucco di **procmon** per verificare se la **libreria è stata caricata come previsto**).

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**repository di HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
