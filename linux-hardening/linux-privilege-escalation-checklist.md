# Kontrol Listesi - Linux Yetki Yükseltme

<details>

<summary><strong>A'dan Z'ye AWS hackleme becerilerini öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Bize katılın** 💬 [**Discord grubunda**](https://discord.gg/hRep4RUj7f) veya [**telegram grubunda**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin**.
* **Hacking püf noktalarınızı göndererek HackTricks ve HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>

<figure><img src="../.gitbook/assets/image (377).png" alt=""><figcaption></figcaption></figure>

Deneyimli hackerlar ve ödül avcıları ile iletişim kurmak için [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) sunucusuna katılın!

**Hacking İçgörüleri**\
Hacking'in heyecanını ve zorluklarını inceleyen içeriklerle etkileşime girin

**Gerçek Zamanlı Hack Haberleri**\
Hızla değişen hacking dünyasını gerçek zamanlı haberler ve içgörülerle takip edin

**En Son Duyurular**\
Yeni ödül avı başlatmaları ve önemli platform güncellemeleri hakkında bilgi sahibi olun

**Bize katılın** [**Discord**](https://discord.com/invite/N3FrSbmwdy) ve bugün en iyi hackerlarla işbirliğine başlayın!

### **Linux yerel yetki yükseltme vektörlerini aramak için en iyi araç:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Sistem Bilgileri](privilege-escalation/#system-information)

* [ ] **İşletim sistemi bilgilerini alın**
* [ ] [**PATH**](privilege-escalation/#path)'i kontrol edin, herhangi bir **yazılabilir klasör** var mı?
* [ ] [**Çevre değişkenlerini**](privilege-escalation/#env-info) kontrol edin, herhangi bir hassas detay var mı?
* [ ] [**Kernel açıkları**](privilege-escalation/#kernel-exploits) arayın, betikler kullanarak (DirtyCow?)
* [ ] [**sudo sürümünün zafiyetli olup olmadığını** kontrol edin](privilege-escalation/#sudo-version)
* [ ] [**Dmesg** imza doğrulaması başarısız oldu](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] Daha fazla sistem enum (tarih, sistem istatistikleri, cpu bilgisi, yazıcılar](privilege-escalation/#more-system-enumeration))
* [ ] [Daha fazla savunma önlemi sıralayın](privilege-escalation/#enumerate-possible-defenses)

### [Sürücüler](privilege-escalation/#drives)

* [ ] **Bağlı sürücüleri listele**
* [ ] **Bağlı olmayan sürücü var mı?**
* [ ] **fstab'da kimlik bilgileri var mı?**

### [**Yüklü Yazılım**](privilege-escalation/#installed-software)

* [ ] **Yüklü** [**yararlı yazılımı**](privilege-escalation/#useful-software) kontrol edin
* [ ] **Yüklü** [**zafiyetli yazılımı**](privilege-escalation/#vulnerable-software-installed) kontrol edin

### [İşlemler](privilege-escalation/#processes)

* [ ] **Bilinmeyen yazılım çalışıyor mu**?
* [ ] **Sahip olması gereken yetkilerden fazlasına sahip çalışan yazılım var mı**?
* [ ] Çalışan işlemlerin **açıklarını arayın** (özellikle çalışan sürüm).
* [ ] Herhangi bir çalışan işlemin **ikili dosyasını değiştirebilir misiniz**?
* [ ] **İşlemleri izleyin** ve sık sık çalışan ilginç bir işlem var mı kontrol edin.
* [ ] Bazı ilginç **işlem belleğini okuyabilir misiniz** (şifrelerin kaydedilmiş olabileceği yer)?

### [Zamanlanmış/Cron işleri?](privilege-escalation/#scheduled-jobs)

* [ ] [**PATH** ](privilege-escalation/#cron-path) bir cron tarafından değiştiriliyor mu ve içine **yazabilir** misiniz?
* [ ] Bir cron işinde [**joker karakter** ](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)var mı?
* [ ] **Yürütülen** veya **değiştirilebilir klasörde bulunan** [**değiştirilebilir betik** ](privilege-escalation/#cron-script-overwriting-and-symlink) tespit ettiniz mi?
* [ ] Bazı **betiklerin** çok **sık sık yürütüldüğünü** (her 1, 2 veya 5 dakikada bir) tespit ettiniz mi?

### [Servisler](privilege-escalation/#services)

* [ ] Herhangi bir **yazılabilir .service** dosyası var mı?
* [ ] Bir **servis** tarafından yürütülen **yazılabilir ikili** var mı?
* [ ] Systemd PATH içinde **yazılabilir klasör** var mı?

### [Zamanlayıcılar](privilege-escalation/#timers)

* [ ] Herhangi bir **yazılabilir zamanlayıcı** var mı?

### [Soketler](privilege-escalation/#sockets)

* [ ] Herhangi bir **yazılabilir .socket** dosyası var mı?
* Herhangi bir **soketle iletişim kurabilir misiniz**?
* **İlginç bilgiler içeren** **HTTP soketleri** var mı?

### [D-Bus](privilege-escalation/#d-bus)

* [ ] Herhangi bir **D-Bus ile iletişim kurabilir misiniz**?

### [Ağ](privilege-escalation/#network)

* Nerede olduğunuzu bilmek için ağı sıralayın
* Makine içinde bir kabuk almadan önce erişemediğiniz **açık portlar** var mı?
* `tcpdump` kullanarak **trafiği izleyebilir misiniz**?

### [Kullanıcılar](privilege-escalation/#users)

* Genel kullanıcı/gruplar **sıralaması**
* **Çok büyük bir UID'niz** var mı? **Makine** **savunmasız** mı?
* Bir gruba ait olduğunuz için **yetkileri yükseltebilir misiniz**?
* **Pano** verileri?
* Şifre Politikası?
* Daha önce keşfettiğiniz her **bilinen şifreyi kullanarak** her olası **kullanıcıyla giriş yapmayı deneyin**. Şifresiz de giriş yapmayı deneyin.

### [Yazılabilir PATH](privilege-escalation/#writable-path-abuses)

* Eğer PATH içinde **bir klasöre yazma izniniz varsa** yetkileri yükseltebilirsiniz

### [SUDO ve SUID komutları](privilege-escalation/#sudo-and-suid)

* **sudo ile herhangi bir komutu çalıştırabilir misiniz**? ROOT olarak OKUMA, YAZMA veya YÜRÜTME yapabilir misiniz? ([**GTFOBins**](https://gtfobins.github.io))
* **SUID ikili dosyaları** sömürülebilir mi? ([**GTFOBins**](https://gtfobins.github.io))
* [**sudo** komutları **yol** tarafından **sınırlı mıdır**? kısıtlamaları **atlayabilir misiniz**](privilege-escalation/#sudo-execution-bypassing-paths)?
* [**Belirtilmemiş sudo/SUID ikili dosyası**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
* [**Yol belirtilen SUID ikili dosyası**](privilege-escalation/#suid-binary-with-command-path)? Atlatma
* [**LD\_PRELOAD açığı**](privilege-escalation/#ld\_preload)
* Yazılabilir bir klasörden [**SUID ikili dosyasına .so kütüphanesinin eksikliği**](privilege-escalation/#suid-binary-so-injection) var mı?
* [**SUDO belirteçleri mevcut mu**](privilege-escalation/#reusing-sudo-tokens)? [**SUDO belirteci oluşturabilir misiniz**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
* [**sudoers dosyalarını okuyabilir veya değiştirebilir misiniz**](privilege-escalation/#etc-sudoers-etc-sudoers-d)?
* [**/etc/ld.so.conf.d/**'yi **değiştirebilir misiniz**](privilege-escalation/#etc-ld-so-conf-d)?
* [**OpenBSD DOAS**](privilege-escalation/#doas) komutu
### [Yetenekler](privilege-escalation/#capabilities)

* [ ] Herhangi bir ikili dosya **beklenmeyen yetkiye** sahip mi?

### [ACL'ler](privilege-escalation/#acls)

* [ ] Herhangi bir dosya **beklenmeyen ACL'ye** sahip mi?

### [Açık Shell oturumları](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL Tahmin Edilebilir PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**SSH İlginç yapılandırma değerleri**](privilege-escalation/#ssh-interesting-configuration-values)

### [İlginç Dosyalar](privilege-escalation/#interesting-files)

* [ ] **Profil dosyaları** - Hassas veri okunabilir mi? Privesc'e yazılabilir mi?
* [ ] **passwd/shadow dosyaları** - Hassas veri okunabilir mi? Privesc'e yazılabilir mi?
* [ ] Hassas veri için ilginç klasörleri kontrol edin
* [ ] **Garip Konum/Sahip dosyalar,** erişiminiz olabilir veya yürütülebilir dosyaları değiştirebilirsiniz
* [ ] Son dakikalarda **Değiştirildi**
* [ ] **Sqlite DB dosyaları**
* [ ] **Gizli dosyalar**
* [ ] **Komut Yolu'ndaki** **Betik/Binaryler**
* [ ] **Web dosyaları** (şifreler?)
* [ ] **Yedekler**?
* [ ] **Şifre içeren bilinen dosyalar**: **Linpeas** ve **LaZagne** kullanın
* [ ] **Genel arama**

### [**Yazılabilir Dosyalar**](privilege-escalation/#writable-files)

* [ ] **Python kütüphanesini** değiştirerek keyfi komutlar çalıştırılabilir mi?
* [ ] **Log dosyalarını** değiştirebilir misiniz? **Logtotten** saldırısı
* [ ] **/etc/sysconfig/network-scripts/**'i değiştirebilir misiniz? Centos/Redhat saldırısı
* [ ] [**ini, int.d, systemd veya rc.d dosyalarına yazabilir misiniz**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**Diğer hileler**](privilege-escalation/#other-tricks)

* [ ] **Ayrıcalıkları yükseltmek için NFS'yi** **kötüye kullanabilir misiniz**](privilege-escalation/#nfs-privilege-escalation)?
* [ ] **Kısıtlayıcı bir kabuktan kaçmanız gerekiyor mu**](privilege-escalation/#escaping-from-restricted-shells)?

<figure><img src="../.gitbook/assets/image (377).png" alt=""><figcaption></figcaption></figure>

[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) sunucusuna katılın ve deneyimli hackerlar ve hata avcıları ile iletişim kurun!

**Hacking İçgörüleri**\
Hacking'in heyecanını ve zorluklarını inceleyen içeriklerle etkileşime girin

**Gerçek Zamanlı Hack Haberleri**\
Hızlı tempolu hacking dünyasını gerçek zamanlı haberler ve içgörülerle takip edin

**En Son Duyurular**\
Yeni hata avcılıklarını ve önemli platform güncellemelerini takip edin

**Bize katılın** [**Discord**](https://discord.com/invite/N3FrSbmwdy) ve bugün en iyi hackerlarla işbirliği yapmaya başlayın!

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [Discord grubuna](https://discord.gg/hRep4RUj7f) veya [telegram gruba](https://t.me/peass) katılın veya** Twitter'da 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'ı takip edin.**
* **Hacking hilelerinizi paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
