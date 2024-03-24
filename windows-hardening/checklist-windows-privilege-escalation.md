# Kontrol Listesi - Yerel Windows Yetki Yükseltme

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramana öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünleri**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)** takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks ve HackTricks Cloud** github depolarına PR'lar göndererek paylaşın.

</details>

**Try Hard Güvenlik Grubu**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

### **Windows yerel yetki yükseltme vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Sistem Bilgisi](windows-local-privilege-escalation/#system-info)

* [ ] [**Sistem bilgilerini**](windows-local-privilege-escalation/#system-info) edinin
* [ ] **Kernel** [**saldırılarını betikler kullanarak**](windows-local-privilege-escalation/#version-exploits) arayın
* [ ] **Google'ı kullanarak** kernel **saldırıları arayın**
* [ ] **Searchsploit'i kullanarak** kernel **saldırıları arayın**
* [ ] [**Çevre değişkenlerinde**](windows-local-privilege-escalation/#environment) ilginç bilgiler mi var?
* [ ] [**PowerShell geçmişinde**](windows-local-privilege-escalation/#powershell-history) şifreler mi var?
* [ ] [**İnternet ayarlarında**](windows-local-privilege-escalation/#internet-settings) ilginç bilgiler mi var?
* [ ] [**Sürücüler**](windows-local-privilege-escalation/#drives)?
* [ ] [**WSUS saldırısı**](windows-local-privilege-escalation/#wsus)?
* [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [Günlükleme/AV numaralandırma](windows-local-privilege-escalation/#enumeration)

* [ ] [**Denetim** ](windows-local-privilege-escalation/#audit-settings)ve [**WEF** ](windows-local-privilege-escalation/#wef)ayarlarını kontrol edin
* [ ] [**LAPS**](windows-local-privilege-escalation/#laps) kontrol edin
* [ ] [**WDigest** ](windows-local-privilege-escalation/#wdigest) etkin mi?
* [ ] [**LSA Koruma**](windows-local-privilege-escalation/#lsa-protection)?
* [ ] [**Kimlik Bilgileri Koruyucu**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
* [ ] [**Önbelleğe Alınmış Kimlik Bilgileri**](windows-local-privilege-escalation/#cached-credentials)?
* [ ] Herhangi bir [**AV**](windows-av-bypass) var mı?
* [**AppLocker Politikası**](authentication-credentials-uac-and-efs#applocker-policy)?
* [**UAC**](authentication-credentials-uac-and-efs/uac-user-account-control)
* [**Kullanıcı Ayrıcalıkları**](windows-local-privilege-escalation/#users-and-groups) kontrol edin
* [ ] [**Geçerli** kullanıcı **ayrıcalıklarını**](windows-local-privilege-escalation/#users-and-groups) kontrol edin
* [ ] [**Herhangi bir ayrıcalıklı gruba üye misiniz**](windows-local-privilege-escalation/#privileged-groups)?
* [ ] **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** gibi bu belirteçlerden herhangi birini etkinleştirdiniz mi? [**Token Manipülasyonu**](windows-local-privilege-escalation/#token-manipulation)
* [**Kullanıcı Oturumları**](windows-local-privilege-escalation/#logged-users-sessions) kontrol edin
* [**Kullanıcı evleri**](windows-local-privilege-escalation/#home-folders) kontrol edin (erişim?)
* [**Şifre Politikası**](windows-local-privilege-escalation/#password-policy) kontrol edin
* [**Pano içeriğinde**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard) ne var?

### [Ağ](windows-local-privilege-escalation/#network)

* [**Geçerli** ağ **bilgilerini**](windows-local-privilege-escalation/#network) kontrol edin
* Dışa kısıtlı **gizli yerel hizmetleri** kontrol edin

### [Çalışan İşlemler](windows-local-privilege-escalation/#running-processes)

* İşlem ikili dosyaları [**dosya ve klasör izinleri**](windows-local-privilege-escalation/#file-and-folder-permissions) kontrol edin
* [**Bellek Şifre madenciliği**](windows-local-privilege-escalation/#memory-password-mining)
* [**Güvensiz GUI uygulamaları**](windows-local-privilege-escalation/#insecure-gui-apps)
* `ProcDump.exe` aracılığıyla **ilginç işlemlerle kimlik bilgileri çalın** mi? (firefox, chrome, vb ...)

### [Hizmetler](windows-local-privilege-escalation/#services)

* [Herhangi bir hizmeti **değiştirebilir misiniz**?](windows-local-privilege-escalation#permissions)
* [Herhangi bir hizmet tarafından **çalıştırılan ikili** dosyayı **değiştirebilir misiniz**?](windows-local-privilege-escalation/#modify-service-binary-path)
* [Herhangi bir hizmetin **kayıt defterini değiştirebilir misiniz**?](windows-local-privilege-escalation/#services-registry-modify-permissions)
* [Herhangi bir **tırnak işareti olmayan hizmet** ikili **yolundan yararlanabilir misiniz**?](windows-local-privilege-escalation/#unquoted-service-paths)

### [**Uygulamalar**](windows-local-privilege-escalation/#applications)

* **Yüklü uygulamalarda** [**yazma izinleri**](windows-local-privilege-escalation/#write-permissions) kontrol edin
* [**Başlangıç Uygulamaları**](windows-local-privilege-escalation/#run-at-startup)
* **Zararlı** [**Sürücüler**](windows-local-privilege-escalation/#drivers)
### [DLL Hijacking](windows-local-privilege-escalation/#path-dll-hijacking)

* [ ] **PATH** içinde **herhangi bir klasöre yazabilir misiniz**?
* [ ] **Var olmayan bir DLL yüklemeye çalışan** bilinen bir hizmet ikili dosyası var mı?
* [ ] **İkili dosyalar klasörüne yazabilir misiniz**?

### [Ağ](windows-local-privilege-escalation/#network)

* [ ] Ağı numaralandırın (paylaşımlar, arabirimler, rotalar, komşular, ...)
* [ ] Localhost'ta (127.0.0.1) dinleyen ağ hizmetlerine özel bir bakış atın

### [Windows Kimlik Bilgileri](windows-local-privilege-escalation/#windows-credentials)

* [ ] [**Winlogon** ](windows-local-privilege-escalation/#winlogon-credentials)kimlik bilgileri
* [ ] [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) kullanabileceğiniz kimlik bilgileri mi?
* [ ] İlginç [**DPAPI kimlik bilgileri**](windows-local-privilege-escalation/#dpapi) var mı?
* [ ] Kayıtlı [**Wifi ağlarının**](windows-local-privilege-escalation/#wifi) şifreleri?
* [ ] Kaydedilen [**RDP Bağlantılarında**](windows-local-privilege-escalation/#saved-rdp-connections) ilginç bilgiler mi?
* [ ] [**Yakın zamanda çalıştırılan komutlardaki**](windows-local-privilege-escalation/#recently-run-commands) şifreler?
* [ ] [**Uzak Masaüstü Kimlik Bilgileri Yöneticisi**](windows-local-privilege-escalation/#remote-desktop-credential-manager) şifreleri?
* [ ] [**AppCmd.exe** mevcut mu](windows-local-privilege-escalation/#appcmd-exe)? Kimlik bilgileri?
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? DLL Yan Yükleme?

### [Dosyalar ve Kayıt Defteri (Kimlik Bilgileri)](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty:** [**Kimlik Bilgileri**](windows-local-privilege-escalation/#putty-creds) **ve** [**SSH anahtarları**](windows-local-privilege-escalation/#putty-ssh-host-keys)
* [ ] Kayıt defterinde [**SSH anahtarları**](windows-local-privilege-escalation/#ssh-keys-in-registry) var mı?
* [ ] [**Katılımsız dosyalardaki**](windows-local-privilege-escalation/#unattended-files) şifreler?
* [ ] [**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups) yedeklemesi var mı?
* [ ] [**Bulut kimlik bilgileri**](windows-local-privilege-escalation/#cloud-credentials)?
* [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml) dosyası?
* [**Önbelleğe alınmış GPP Şifresi**](windows-local-privilege-escalation/#cached-gpp-pasword) var mı?
* [ ] [**IIS Web yapılandırma dosyasındaki**](windows-local-privilege-escalation/#iis-web-config) şifre?
* [ ] [**Web** **günlüklerinde**](windows-local-privilege-escalation/#logs) ilginç bilgiler mi?
* [ ] Kullanıcıdan [**kimlik bilgileri istemek**](windows-local-privilege-escalation/#ask-for-credentials) ister misiniz?
* [ ] Geri Dönüşüm Kutusundaki [**kimlik bilgileri**](windows-local-privilege-escalation/#credentials-in-the-recyclebin) içinde ilginç [**dosyalar**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)?
* [ ] Diğer [**kimlik bilgileri içeren kayıt defteri**](windows-local-privilege-escalation/#inside-the-registry) içinde mi?
* [ ] Tarayıcı verilerinde (veritabanları, geçmiş, yer imleri, ...) [**Bulunan**](windows-local-privilege-escalation/#browsers-history) ilginç bilgiler?
* [**Dosyalarda ve kayıt defterinde**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry) [**Genel şifre araması**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry)?
* [**Otomatik olarak şifre aramak için**](windows-local-privilege-escalation/#tools-that-search-for-passwords) [**Araçlar**](windows-local-privilege-escalation/#tools-that-search-for-passwords)?

### [Sızdırılan İşleyiciler](windows-local-privilege-escalation/#leaked-handlers)

* [ ] Yönetici tarafından çalıştırılan bir işlemin işleyicisine erişiminiz var mı?

### [İsimli Boru İstemci Taklit](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] Kullanabilir misiniz?

**Try Hard Güvenlik Grubu**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬** [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'da takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks ve HackTricks Cloud** github depolarına PR'lar göndererek paylaşın.

</details>
