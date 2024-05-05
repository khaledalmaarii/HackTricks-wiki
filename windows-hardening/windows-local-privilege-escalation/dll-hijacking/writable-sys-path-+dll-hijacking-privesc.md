# Percorso Sys Scrivibile + Privesc Dll Hijacking

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**Gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>

## Introduzione

Se hai scoperto che puoi **scrivere in una cartella del Percorso di Sistema** (nota che questo non funzionerà se puoi scrivere in una cartella del Percorso Utente), è possibile che tu possa **elevare i privilegi** nel sistema.

Per fare ciò, puoi sfruttare un **Dll Hijacking** dove andrai a **intercettare una libreria in fase di caricamento** da parte di un servizio o processo con **più privilegi** dei tuoi e poiché quel servizio sta caricando un Dll che probabilmente non esiste nemmeno nell'intero sistema, cercherà di caricarlo dal Percorso di Sistema dove puoi scrivere.

Per ulteriori informazioni su **cosa sia il Dll Hijacking** controlla:

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Privesc con Dll Hijacking

### Trovare un Dll mancante

La prima cosa di cui hai bisogno è **identificare un processo** in esecuzione con **più privilegi** dei tuoi che sta cercando di **caricare un Dll dal Percorso di Sistema** in cui puoi scrivere.

Il problema in questi casi è che probabilmente quei processi sono già in esecuzione. Per trovare quali Dll mancano ai servizi, è necessario avviare procmon il prima possibile (prima che i processi vengano caricati). Quindi, per trovare i .dll mancanti fai:

* **Crea** la cartella `C:\privesc_hijacking` e aggiungi il percorso `C:\privesc_hijacking` alla **variabile di ambiente del Percorso di Sistema**. Puoi farlo **manualmente** o con **PS**:
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
* Successivamente, **riavvia** il sistema. Quando il computer si riavvia, **`procmon`** inizierà a **registrare** gli eventi il prima possibile.
* Una volta che **Windows** è **avviato, esegui `procmon`** di nuovo, ti dirà che è in esecuzione e ti **chiederà se desideri memorizzare** gli eventi in un file. Rispondi **sì** e **memorizza gli eventi in un file**.
* **Dopo** che il **file** è **generato**, **chiudi** la finestra di **`procmon`** aperta e **apri il file degli eventi**.
* Aggiungi questi **filtri** e troverai tutte le Dll che alcuni **processi hanno cercato di caricare** dalla cartella del percorso di sistema scrivibile:

<figure><img src="../../../.gitbook/assets/image (945).png" alt=""><figcaption></figcaption></figure>

### Dll Mancanti

Eseguendo questo su una **macchina virtuale (vmware) Windows 11** gratuita ho ottenuto questi risultati:

<figure><img src="../../../.gitbook/assets/image (607).png" alt=""><figcaption></figcaption></figure>

In questo caso gli .exe sono inutili quindi ignorali, le Dll mancanti provenivano da:

| Servizio                         | Dll                | Riga di comando                                                     |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Dopo aver trovato questo, ho trovato questo interessante post sul blog che spiega anche come [**abusare di WptsExtensions.dll per l'escalation dei privilegi**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll). Che è ciò che **stiamo per fare ora**.

### Sfruttamento

Quindi, per **escalare i privilegi** andremo a dirottare la libreria **WptsExtensions.dll**. Avendo il **percorso** e il **nome** dobbiamo solo **generare la dll malevola**.

Puoi [**provare a utilizzare uno di questi esempi**](./#creating-and-compiling-dlls). Potresti eseguire payload come: ottenere una shell reversa, aggiungere un utente, eseguire un beacon...

{% hint style="warning" %}
Nota che **non tutti i servizi vengono eseguiti** con **`NT AUTHORITY\SYSTEM`** alcuni vengono eseguiti anche con **`NT AUTHORITY\LOCAL SERVICE`** che ha **meno privilegi** e non **sarai in grado di creare un nuovo utente** sfruttando i suoi permessi.\
Tuttavia, quell'utente ha il privilegio **`seImpersonate`**, quindi puoi utilizzare la [**suite potato per escalare i privilegi**](../roguepotato-and-printspoofer.md). Quindi, in questo caso una shell reversa è una scelta migliore rispetto al tentativo di creare un utente.
{% endhint %}

Al momento della scrittura il servizio **Task Scheduler** viene eseguito con **Nt AUTHORITY\SYSTEM**.

Avendo **generato la dll malevola** (_nel mio caso ho usato una shell reversa x64 e ho ottenuto una shell ma Defender l'ha bloccata perché proveniva da msfvenom_), salvala nella cartella del percorso di sistema scrivibile con il nome **WptsExtensions.dll** e **riavvia** il computer (o riavvia il servizio o fai qualsiasi altra azione necessaria per far ripartire il servizio/programma interessato).

Quando il servizio viene riavviato, la **dll dovrebbe essere caricata ed eseguita** (puoi **riutilizzare** il **trucco di procmon** per verificare se la **libreria è stata caricata come previsto**).
