# Kontrol Listesi - Yerel Windows Yetki Yükseltme

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** bizi takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

### **Windows yerel yetki yükseltme vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Sistem Bilgisi](windows-local-privilege-escalation/#system-info)

* [ ] [**Sistem bilgilerini**](windows-local-privilege-escalation/#system-info) edinin
* [ ] **kernel** için [**saldırıları**](windows-local-privilege-escalation/#version-exploits) aramak için **scriptler** kullanın
* [ ] **Google'ı kullanarak** kernel **saldırılarını** arayın
* [ ] **searchsploit kullanarak** kernel **saldırılarını** arayın
* [ ] [**env vars**](windows-local-privilege-escalation/#environment) içinde ilginç bilgiler var mı?
* [ ] [**PowerShell geçmişinde**](windows-local-privilege-escalation/#powershell-history) şifreler var mı?
* [ ] [**Internet ayarlarında**](windows-local-privilege-escalation/#internet-settings) ilginç bilgiler var mı?
* [ ] [**Sürücüler**](windows-local-privilege-escalation/#drives)?
* [ ] [**WSUS saldırısı**](windows-local-privilege-escalation/#wsus)?
* [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [Günlükleme/AV sayımı](windows-local-privilege-escalation/#enumeration)

* [ ] [**Denetim**](windows-local-privilege-escalation/#audit-settings) ve [**WEF**](windows-local-privilege-escalation/#wef) ayarlarını kontrol edin
* [ ] [**LAPS**](windows-local-privilege-escalation/#laps) kontrol edin
* [ ] [**WDigest**](windows-local-privilege-escalation/#wdigest) aktif mi kontrol edin
* [ ] [**LSA Koruması**](windows-local-privilege-escalation/#lsa-protection)?
* [ ] [**Credentials Guard**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
* [ ] [**Önbelleğe alınmış Kimlik Bilgileri**](windows-local-privilege-escalation/#cached-credentials)?
* [ ] Herhangi bir [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md) kontrol edin
* [ ] [**AppLocker Politikası**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
* [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
* [ ] [**Kullanıcı Yetkileri**](windows-local-privilege-escalation/#users-and-groups)
* [ ] [**mevcut** kullanıcı **yetkilerini**](windows-local-privilege-escalation/#users-and-groups) kontrol edin
* [ ] Herhangi bir [**ayrıcalıklı grupta**](windows-local-privilege-escalation/#privileged-groups) üye misiniz?
* [ ] [**Bu tokenlerden herhangi biri etkin mi**](windows-local-privilege-escalation/#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
* [ ] [**Kullanıcı Oturumları**](windows-local-privilege-escalation/#logged-users-sessions)?
* [ ] [**kullanıcı evlerini**](windows-local-privilege-escalation/#home-folders) kontrol edin (erişim?)
* [ ] [**Şifre Politikası**](windows-local-privilege-escalation/#password-policy) kontrol edin
* [ ] [**Panoya**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard) ne var?

### [Ağ](windows-local-privilege-escalation/#network)

* [ ] **mevcut** [**ağ** **bilgilerini**](windows-local-privilege-escalation/#network) kontrol edin
* [ ] Dışarıya kısıtlı **gizli yerel hizmetleri** kontrol edin

### [Çalışan Süreçler](windows-local-privilege-escalation/#running-processes)

* [ ] Süreçlerin ikili [**dosya ve klasör izinleri**](windows-local-privilege-escalation/#file-and-folder-permissions)
* [ ] [**Bellek Şifre madenciliği**](windows-local-privilege-escalation/#memory-password-mining)
* [ ] [**Güvensiz GUI uygulamaları**](windows-local-privilege-escalation/#insecure-gui-apps)
* [ ] `ProcDump.exe` aracılığıyla **ilginç süreçlerle** kimlik bilgilerini çalmak? (firefox, chrome, vb...)

### [Hizmetler](windows-local-privilege-escalation/#services)

* [ ] [Herhangi bir **hizmeti değiştirebilir misiniz**?](windows-local-privilege-escalation/#permissions)
* [ ] [Herhangi bir **hizmet** tarafından **çalıştırılan** **ikiliyi** **değiştirebilir misiniz**?](windows-local-privilege-escalation/#modify-service-binary-path)
* [ ] [Herhangi bir **hizmetin** **kayıt defterini** **değiştirebilir misiniz**?](windows-local-privilege-escalation/#services-registry-modify-permissions)
* [ ] [Herhangi bir **belirtilmemiş hizmet** ikili **yolundan** yararlanabilir misiniz?](windows-local-privilege-escalation/#unquoted-service-paths)

### [**Uygulamalar**](windows-local-privilege-escalation/#applications)

* [ ] **Yüklenmiş uygulamalarda** [**yazma**](windows-local-privilege-escalation/#write-permissions) izinleri
* [ ] [**Başlangıç Uygulamaları**](windows-local-privilege-escalation/#run-at-startup)
* [ ] **Zayıf** [**Sürücüler**](windows-local-privilege-escalation/#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/#path-dll-hijacking)

* [ ] **PATH** içindeki herhangi bir klasöre **yazabilir misiniz**?
* [ ] **Herhangi bir mevcut olmayan DLL'yi yüklemeye çalışan** bilinen bir hizmet ikilisi var mı?
* [ ] **Herhangi bir** ikili klasöre **yazabilir misiniz**?

### [Ağ](windows-local-privilege-escalation/#network)

* Ağı sayın (paylaşımlar, arayüzler, yollar, komşular, ...)
* Yerel ağda (127.0.0.1) dinleyen ağ hizmetlerine özel bir göz atın

### [Windows Kimlik Bilgileri](windows-local-privilege-escalation/#windows-credentials)

* [**Winlogon**](windows-local-privilege-escalation/#winlogon-credentials) kimlik bilgileri
* [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) kimlik bilgileri kullanabilir misiniz?
* İlginç [**DPAPI kimlik bilgileri**](windows-local-privilege-escalation/#dpapi)?
* Kaydedilmiş [**Wifi ağlarının**](windows-local-privilege-escalation/#wifi) şifreleri?
* [**Kaydedilmiş RDP Bağlantılarında**](windows-local-privilege-escalation/#saved-rdp-connections) ilginç bilgiler var mı?
* [**Son çalıştırılan komutlarda**](windows-local-privilege-escalation/#recently-run-commands) şifreler var mı?
* [**Uzak Masaüstü Kimlik Bilgileri Yöneticisi**](windows-local-privilege-escalation/#remote-desktop-credential-manager) şifreleri?
* [**AppCmd.exe** var mı](windows-local-privilege-escalation/#appcmd-exe)? Kimlik bilgileri?
* [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? DLL Yan Yükleme?

### [Dosyalar ve Kayıt Defteri (Kimlik Bilgileri)](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty:** [**Kimlik Bilgileri**](windows-local-privilege-escalation/#putty-creds) **ve** [**SSH ana bilgisayar anahtarları**](windows-local-privilege-escalation/#putty-ssh-host-keys)
* [ ] [**Kayıt defterinde SSH anahtarları**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
* [ ] [**Gözetimsiz dosyalarda**](windows-local-privilege-escalation/#unattended-files) şifreler var mı?
* [ ] Herhangi bir [**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups) yedeği var mı?
* [ ] [**Bulut kimlik bilgileri**](windows-local-privilege-escalation/#cloud-credentials)?
* [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml) dosyası?
* [ ] [**Önbelleğe alınmış GPP Şifresi**](windows-local-privilege-escalation/#cached-gpp-pasword)?
* [ ] [**IIS Web yapılandırma dosyasında**](windows-local-privilege-escalation/#iis-web-config) şifre var mı?
* [ ] [**web** **günlüklerinde**](windows-local-privilege-escalation/#logs) ilginç bilgiler var mı?
* Kullanıcıdan [**kimlik bilgilerini istemek**](windows-local-privilege-escalation/#ask-for-credentials) ister misiniz?
* [**Geri Dönüşüm Kutusundaki**](windows-local-privilege-escalation/#credentials-in-the-recyclebin) ilginç dosyalar var mı?
* [**Kimlik bilgilerini içeren diğer**](windows-local-privilege-escalation/#inside-the-registry) kayıt defterleri var mı?
* [**Tarayıcı verileri**](windows-local-privilege-escalation/#browsers-history) içinde (dbs, geçmiş, yer imleri, ...)?
* [**Dosyalar ve kayıt defterinde genel şifre araması**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry)
* Şifreleri otomatik olarak aramak için [**Araçlar**](windows-local-privilege-escalation/#tools-that-search-for-passwords)

### [Sızdırılan İşleyiciler](windows-local-privilege-escalation/#leaked-handlers)

* Yönetici tarafından çalıştırılan bir sürecin herhangi bir işleyicisine erişiminiz var mı?

### [Pipe İstemci Taklidi](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* Bunu kötüye kullanıp kullanamayacağınızı kontrol edin

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** bizi takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
