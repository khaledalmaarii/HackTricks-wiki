# Writable Sys Path +Dll Hijacking Privesc

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

## Introduzione

Se hai scoperto che puoi **scrivere in una cartella del System Path** (nota che questo non funzionerà se puoi scrivere in una cartella del User Path) è possibile che tu possa **escalare i privilegi** nel sistema.

Per fare ciò puoi abusare di un **Dll Hijacking** dove andrai a **dirottare una libreria che viene caricata** da un servizio o processo con **più privilegi** dei tuoi, e poiché quel servizio sta caricando una Dll che probabilmente non esiste nemmeno nell'intero sistema, cercherà di caricarla dal System Path dove puoi scrivere.

Per ulteriori informazioni su **cosa è il Dll Hijacking** controlla:

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Privesc con Dll Hijacking

### Trovare una Dll mancante

La prima cosa di cui hai bisogno è **identificare un processo** in esecuzione con **più privilegi** di te che sta cercando di **caricare una Dll dal System Path** in cui puoi scrivere.

Il problema in questi casi è che probabilmente quei processi sono già in esecuzione. Per trovare quali Dll mancano ai servizi, devi avviare procmon il prima possibile (prima che i processi vengano caricati). Quindi, per trovare le .dll mancanti fai:

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
* Avvia **`procmon`** e vai su **`Options`** --> **`Enable boot logging`** e premi **`OK`** nel prompt.
* Poi, **riavvia**. Quando il computer si riavvia, **`procmon`** inizierà a **registrare** eventi il prima possibile.
* Una volta che **Windows** è **avviato, esegui di nuovo `procmon`**, ti dirà che è stato in esecuzione e ti **chiederà se vuoi memorizzare** gli eventi in un file. Rispondi **sì** e **memorizza gli eventi in un file**.
* **Dopo** che il **file** è stato **generato**, **chiudi** la finestra **`procmon`** aperta e **apri il file degli eventi**.
* Aggiungi questi **filtri** e troverai tutti i Dll che alcuni **processi hanno cercato di caricare** dalla cartella del System Path scrivibile:

<figure><img src="../../../.gitbook/assets/image (945).png" alt=""><figcaption></figcaption></figure>

### Dll mancanti

Eseguendo questo su una **macchina virtuale (vmware) Windows 11** gratuita ho ottenuto questi risultati:

<figure><img src="../../../.gitbook/assets/image (607).png" alt=""><figcaption></figcaption></figure>

In questo caso gli .exe sono inutili, quindi ignorali, i Dll mancanti erano da:

| Servizio                         | Dll                | Riga CMD                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Pianificazione) | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Dopo aver trovato questo, ho trovato questo interessante post sul blog che spiega anche come [**abuse WptsExtensions.dll per privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll). Che è ciò che **stiamo per fare ora**.

### Sfruttamento

Quindi, per **escalare i privilegi** stiamo per hijackare la libreria **WptsExtensions.dll**. Avendo il **percorso** e il **nome** dobbiamo solo **generare il dll malevolo**.

Puoi [**provare a usare uno di questi esempi**](./#creating-and-compiling-dlls). Potresti eseguire payload come: ottenere una rev shell, aggiungere un utente, eseguire un beacon...

{% hint style="warning" %}
Nota che **non tutti i servizi vengono eseguiti** con **`NT AUTHORITY\SYSTEM`**, alcuni vengono eseguiti anche con **`NT AUTHORITY\LOCAL SERVICE`** che ha **meno privilegi** e **non sarai in grado di creare un nuovo utente** abusando delle sue autorizzazioni.\
Tuttavia, quell'utente ha il privilegio **`seImpersonate`**, quindi puoi usare il [**potato suite per escalare i privilegi**](../roguepotato-and-printspoofer.md). Quindi, in questo caso una rev shell è una migliore opzione rispetto a cercare di creare un utente.
{% endhint %}

Al momento della scrittura, il servizio **Task Scheduler** è eseguito con **Nt AUTHORITY\SYSTEM**.

Avendo **generato il Dll malevolo** (_nel mio caso ho usato una rev shell x64 e ho ottenuto una shell di ritorno ma Defender l'ha uccisa perché proveniva da msfvenom_), salvalo nel System Path scrivibile con il nome **WptsExtensions.dll** e **riavvia** il computer (o riavvia il servizio o fai tutto il necessario per rieseguire il servizio/programma interessato).

Quando il servizio viene riavviato, il **dll dovrebbe essere caricato ed eseguito** (puoi **riutilizzare** il trucco **procmon** per controllare se la **libreria è stata caricata come previsto**).

{% hint style="success" %}
Impara e pratica Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

</details>
{% endhint %}
