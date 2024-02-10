# Kontrol Listesi - Yerel Windows Yetki Yükseltme

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramanlık seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

### **Windows yerel yetki yükseltme vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Sistem Bilgisi](windows-local-privilege-escalation/#system-info)

* [ ] [**Sistem bilgisi**](windows-local-privilege-escalation/#system-info) elde edin
* [ ] Betikleri kullanarak **çekirdek** [**saldırılarını araştırın**](windows-local-privilege-escalation/#version-exploits)
* [ ] Çekirdek saldırılarını aramak için **Google'ı kullanın**
* [ ] Çekirdek saldırılarını aramak için **searchsploit'i kullanın**
* [ ] [**Ortam değişkenlerinde**](windows-local-privilege-escalation/#environment) ilginç bilgiler var mı?
* [ ] [**PowerShell geçmişinde**](windows-local-privilege-escalation/#powershell-history) şifreler var mı?
* [ ] [**İnternet ayarlarında**](windows-local-privilege-escalation/#internet-settings) ilginç bilgiler var mı?
* [ ] [**Sürücüler**](windows-local-privilege-escalation/#drives)?
* [ ] [**WSUS saldırısı**](windows-local-privilege-escalation/#wsus)?
* [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [Günlük/Koruma yazılımı taraması](windows-local-privilege-escalation/#enumeration)

* [ ] [**Denetim**](windows-local-privilege-escalation/#audit-settings) ve [**WEF**](windows-local-privilege-escalation/#wef) ayarlarını kontrol edin
* [ ] [**LAPS**](windows-local-privilege-escalation/#laps) kontrol edin
* [ ] [**WDigest**](windows-local-privilege-escalation/#wdigest) etkin mi?
* [ ] [**LSA Koruma**](windows-local-privilege-escalation/#lsa-protection)?
* [ ] [**Kimlik Bilgileri Koruma**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
* [ ] [**Önbelleğe Alınmış Kimlik Bilgileri**](windows-local-privilege-escalation/#cached-credentials)?
* [ ] Herhangi bir [**AV**](windows-av-bypass) var mı?
* [ ] [**AppLocker Politikası**](authentication-credentials-uac-and-efs#applocker-policy)?
* [ ] [**UAC**](authentication-credentials-uac-and-efs/uac-user-account-control)
* [ ] [**Kullanıcı Yetkileri**](windows-local-privilege-escalation/#users-and-groups)
* [ ] [**Geçerli** kullanıcının **yetkilerini** kontrol edin](windows-local-privilege-escalation/#users-and-groups)
* [ ] Herhangi bir **özel yetkiye sahip** bir **gruba üye** misiniz? (windows-local-privilege-escalation/#privileged-groups)?
* [ ] **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** yetkilerinden herhangi birine sahip misiniz? (windows-local-privilege-escalation/#token-manipulation)
* [**Kullanıcı Oturumları**](windows-local-privilege-escalation/#logged-users-sessions)?
* [ ] [**Kullanıcıların ev dizinlerini**](windows-local-privilege-escalation/#home-folders) kontrol edin (erişim?)
* [ ] [**Parola Politikası**](windows-local-privilege-escalation/#password-policy) nedir?
* [ ] [**Pano içeriği**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard) nedir?

### [Ağ](windows-local-privilege-escalation/#network)

* [ ] **Geçerli** [**ağ bilgilerini**](windows-local-privilege-escalation/#network) kontrol edin
* [ ] Dışa kısıtlı **gizli yerel hizmetleri** kontrol edin

### [Çalışan İşlemler](windows-local-privilege-escalation/#running-processes)

* [ ] İşlem ikili dosyalarının [**dosya ve klasör izinlerini**](windows-local-privilege-escalation/#file-and-folder-permissions) kontrol edin
* [ ] [**Bellek Parolası çalma**](windows-local-privilege-escalation/#memory-password-mining)
* [ ] [**Güvensiz GUI uygulamaları**](windows-local-privilege-escalation/#insecure-gui-apps)

### [Hizmetler](windows-local-privilege-escalation/#services)

* [ ] Herhangi bir hizmeti **değiştirebilir misiniz**? (windows-local-privilege-escalation#permissions)
* [ ] Herhangi bir hizmetin **çalıştırdığı ikili dosyayı değiştirebilir misiniz**? (windows-local-privilege-escalation/#modify-service-binary-path)
* [ ] Herhangi bir hizmetin **kayıt defterini değiştirebilir misiniz**? (windows-local-privilege-escalation/#services-registry-modify-permissions)
* [ ] Herhangi bir **düzgün yazılmamış hizmet** ikili **yolu**ndan yararlanabilir misiniz? (windows-local-privilege-escalation/#unquoted-service-paths)

### [**Uygulamalar**](windows-local-privilege-escalation/#applications)

* [ ] **Yüklü uygulamaların** [**yazma izinlerini**](windows-local-privilege-escalation/#write-permissions) kontrol edin
* [ ] [**Başlangıç Uygulamaları**](windows-local-privilege-escalation/#run-at-startup)
* [ ] **Zararlı** [**Sürücüler**](windows-local-privilege-escalation/#drivers)

### [DLL Kaçırma](windows-local-privilege-escalation/#path-dll-hijacking)

* [ ] PATH içindeki herhangi bir klasöre **yazabilir misiniz**?
* [ ] Bilinen bir hizmet ikilisi, **var olmayan bir DLL** yüklemeye çalışır mı?
* [ ] Herhangi bir **ikili klasörüne yazabilir misiniz**?
### [Ağ](windows-local-privilege-escalation/#network)

* [ ] Ağı sırala (paylaşımlar, arayüzler, rotalar, komşular, ...)
* [ ] Localhost'ta (127.0.0.1) dinleyen ağ servislerine özel bir bakış atın

### [Windows Kimlik Bilgileri](windows-local-privilege-escalation/#windows-credentials)

* [ ] [**Winlogon** ](windows-local-privilege-escalation/#winlogon-credentials)kimlik bilgileri
* [ ] Kullanabileceğiniz [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) kimlik bilgileri?
* [ ] İlginç [**DPAPI kimlik bilgileri**](windows-local-privilege-escalation/#dpapi)?
* [ ] Kaydedilen [**Wifi ağlarının**](windows-local-privilege-escalation/#wifi) şifreleri?
* [ ] Kaydedilen [**RDP Bağlantılarında**](windows-local-privilege-escalation/#saved-rdp-connections) ilginç bilgiler?
* [ ] [**Son çalıştırılan komutlarda**](windows-local-privilege-escalation/#recently-run-commands) şifreler?
* [ ] [**Uzak Masaüstü Kimlik Bilgileri Yöneticisi**](windows-local-privilege-escalation/#remote-desktop-credential-manager) şifreleri?
* [ ] [**AppCmd.exe** mevcut mu](windows-local-privilege-escalation/#appcmd-exe)? Kimlik bilgileri?
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? DLL Yan Yükleme?

### [Dosyalar ve Kayıt Defteri (Kimlik Bilgileri)](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty:** [**Kimlik Bilgileri**](windows-local-privilege-escalation/#putty-creds) **ve** [**SSH anahtarları**](windows-local-privilege-escalation/#putty-ssh-host-keys)
* [ ] Kayıt defterindeki [**SSH anahtarları**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
* [ ] [**Otomatik yapılandırma dosyalarında**](windows-local-privilege-escalation/#unattended-files) şifreler?
* [ ] Herhangi bir [**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups) yedekleme?
* [ ] [**Bulut kimlik bilgileri**](windows-local-privilege-escalation/#cloud-credentials)?
* [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml) dosyası?
* [ ] [**Önbelleğe alınmış GPP Şifresi**](windows-local-privilege-escalation/#cached-gpp-pasword)?
* [ ] [**IIS Web yapılandırma dosyasında**](windows-local-privilege-escalation/#iis-web-config) şifre?
* [ ] [**Web günlüklerinde**](windows-local-privilege-escalation/#logs) ilginç bilgiler?
* [ ] Kullanıcıdan [**kimlik bilgilerini istemek**](windows-local-privilege-escalation/#ask-for-credentials) istiyor musunuz?
* [ ] Çöp Kutusu içindeki [**dosyalar**](windows-local-privilege-escalation/#credentials-in-the-recyclebin) ilginç mi?
* [ ] Kimlik bilgileri içeren diğer [**kayıt defterleri**](windows-local-privilege-escalation/#inside-the-registry)?
* [ ] Tarayıcı verileri içinde (veritabanları, geçmiş, yer imleri, ...) [**Genel şifre araması**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry)?
* [ ] Şifreleri otomatik olarak aramak için [**Araçlar**](windows-local-privilege-escalation/#tools-that-search-for-passwords)?

### [Sızdırılan İşlemler](windows-local-privilege-escalation/#leaked-handlers)

* [ ] Yönetici tarafından çalıştırılan bir işlemin işleyicisine erişiminiz var mı?

### [Pipe İstemci Taklit Etme](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] Kötüye kullanabilir misiniz?

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* **💬 [Discord grubuna](https://discord.gg/hRep4RUj7f) veya [telegram grubuna](https://t.me/peass) katılın veya** bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'da takip edin.**
* **Hacking hilelerinizi paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek** katkıda bulunun.

</details>
