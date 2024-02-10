# Kontrol Listesi - Linux Yetki Yükseltme

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hacklemeyi öğrenin<strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'ı **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek** paylaşın.

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Deneyimli hackerlar ve ödül avcılarıyla iletişim kurmak için [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) sunucusuna katılın!

**Hacking İçgörüleri**\
Hacking'in heyecanına ve zorluklarına dalmış içeriklerle etkileşim kurun

**Gerçek Zamanlı Hack Haberleri**\
Hızlı tempolu hacking dünyasını gerçek zamanlı haberler ve içgörülerle takip edin

**En Son Duyurular**\
Yeni ödül avcıları başlatmaları ve önemli platform güncellemeleri hakkında bilgi edinin

**Bize katılın** [**Discord**](https://discord.com/invite/N3FrSbmwdy) ve bugün en iyi hackerlarla işbirliği yapmaya başlayın!

### **Linux yerel yetki yükseltme vektörlerini aramak için en iyi araç:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Sistem Bilgisi](privilege-escalation/#sistem-bilgisi)

* [ ] **İşletim sistemi bilgisini** alın
* [ ] [**PATH**](privilege-escalation/#path)'i kontrol edin, herhangi bir **yazılabilir klasör** var mı?
* [ ] [**Çevre değişkenlerini**](privilege-escalation/#env-info) kontrol edin, herhangi bir hassas ayrıntı var mı?
* [ ] [**Kernel açıklarını**](privilege-escalation/#kernel-exploits) (DirtyCow gibi) **betikler kullanarak** arayın
* [ ] [**sudo sürümünün** zafiyetli olup olmadığını](privilege-escalation/#sudo-version) **kontrol edin**
* [ ] [**Dmesg** imza doğrulaması başarısız oldu](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] Daha fazla sistem enum (tarih, sistem istatistikleri, cpu bilgisi, yazıcılar](privilege-escalation/#more-system-enumeration))
* [ ] [Daha fazla savunma](privilege-escalation/#enumerate-possible-defenses) sıralayın

### [Sürücüler](privilege-escalation/#sürücüler)

* [ ] Bağlı olan sürücüleri **listele**
* [ ] Bağlı olmayan bir sürücü var mı?
* [ ] fstab'da herhangi bir kimlik bilgisi var mı?

### [**Yüklü Yazılım**](privilege-escalation/#yüklü-yazılım)

* [ ] **Yararlı yazılım** kontrol edin
* [ ] [**Zafiyetli yazılım**](privilege-escalation/#vulnerable-software-installed) kontrol edin

### [İşlemler](privilege-escalation/#işlemler)

* [ ] Bilinmeyen bir yazılım çalışıyor mu?
* [ ] Yazılım, sahip olması gereken **yetkilerden daha fazla yetkiye sahip** mi?
* [ ] Çalışan işlemlerin **açıklarını arayın** (özellikle çalışan sürüm için)
* [ ] Çalışan herhangi bir işlemin **yürütülebilir dosyasını değiştirebilir misiniz**?
* [ ] İşlemleri **izleyin** ve sık sık çalışan ilginç bir işlem var mı kontrol edin.
* [ ] Bazı ilginç **işlem belleğini** (şifrelerin kaydedilebileceği yer) **okuyabilir misiniz**?

### [Zamanlanmış/Cron görevleri?](privilege-escalation/#zamanlanmış-görevler)

* [ ] Bir cron tarafından [**PATH**](privilege-escalation/#cron-path) değiştiriliyor mu ve içine **yazabilirsiniz** mi?
* [ ] Bir cron görevinde [**joker karakteri**](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection) var mı?
* [ ] **Yürütülen** veya **değiştirilebilir klasörde** bulunan bir [**değiştirilebilir betik**](privilege-escalation/#cron-script-overwriting-and-symlink) var mı?
* [ ] Bazı **betiklerin** çok **sık sık yürütüldüğünü** (her 1, 2 veya 5 dakikada bir) tespit ettiniz mi?

### [Servisler](privilege-escalation/#servisler)

* [ ] Yazılabilir bir **.service** dosyası var mı?
* [ ] Bir **servis** tarafından yürütülen bir **yazılabilir ikili** var mı?
* [ ] Systemd PATH'deki bir **yazılabilir klasör** var mı?

### [Zamanlayıcılar](privilege-escalation/#zamanlayıcılar)

* [ ] Yazılabilir bir **zamanlayıcı** var mı?

### [Soketler](privilege-escalation/#soketler)

* [ ] Yazılabilir bir **.socket** dosyası var mı?
* [ ] Herhangi bir soketle **iletişim kurabilir misiniz**?
* [ ] İlginç bilgiler içeren **HTTP soketleri** var mı?

### [D-Bus](privilege-escalation/#d-bus)

* [ ] Herhangi bir **D-Bus** iletişimi yapabilir misiniz?

### [Ağ](privilege-escalation/#ağ)

* Bulunduğunuz yeri belirlemek için ağı sıralayın
* Makine içinde bir kabuk almadan önce **erişemediğiniz açık portlar** var mı?
* `tcpdump` kullanarak trafiği **dinleyebilir misiniz**?

### [Kullanıcılar](privilege-escalation/#kullanıcılar)

* Genel kullanıcı/grupları **sıralayın**
* **Çok büyük bir UID**'niz var mı? Makine **savunmasız** mı?
* Üye olduğunuz bir grup sayesinde **yetkileri yükseltebilir misiniz**?
* **Pano** verileri?
* Parola Politikası?
* Daha önce keşfettiğ
### [Yetenekler](privilege-escalation/#yetenekler)

* [ ] Herhangi bir ikili dosyanın **beklenmedik bir yeteneği** var mı?

### [ACL'ler](privilege-escalation/#acls)

* [ ] Herhangi bir dosyanın **beklenmedik bir ACL'si** var mı?

### [Açık Kabuk Oturumları](privilege-escalation/#açık-kabuk-oturumları)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL Tahmin Edilebilir PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-tahmin-edilebilir-prng-cve-2008-0166)
* [ ] [**SSH İlginç yapılandırma değerleri**](privilege-escalation/#ssh-ilginç-yapılandırma-değerleri)

### [İlginç Dosyalar](privilege-escalation/#ilginç-dosyalar)

* [ ] **Profil dosyaları** - Hassas veri okunabilir mi? Privesc'e yazılabilir mi?
* [ ] **passwd/shadow dosyaları** - Hassas veri okunabilir mi? Privesc'e yazılabilir mi?
* [ ] Hassas veri içeren yaygın olarak ilginç klasörleri kontrol edin
* [ ] **Garip Konum/Sahipli dosyalar**, yürütülebilir dosyalara erişiminiz olabilir veya değiştirebilirsiniz
* [ ] Son dakikalarda **değiştirilmiş**
* [ ] **Sqlite DB dosyaları**
* [ ] **Gizli dosyalar**
* [ ] **PATH'teki Script/Binary'ler**
* [ ] **Web dosyaları** (şifreler?)
* [ ] **Yedeklemeler**?
* [ ] **Şifre içeren bilinen dosyalar**: **Linpeas** ve **LaZagne** kullanın
* [ ] **Genel arama**

### [**Yazılabilir Dosyalar**](privilege-escalation/#yazılabilir-dosyalar)

* [ ] **Python kütüphanesini** değiştirerek keyfi komutlar çalıştırabilir misiniz?
* [ ] **Günlük dosyalarını** değiştirebilir misiniz? **Logtotten** saldırısı
* [ ] **/etc/sysconfig/network-scripts/**'i değiştirebilir misiniz? Centos/Redhat saldırısı
* [ ] [**ini, int.d, systemd veya rc.d dosyalarına yazabilir misiniz**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**Diğer hileler**](privilege-escalation/#diğer-hileler)

* [ ] **Yetkileri yükseltmek için NFS'yi** kötüye kullanabilir misiniz? (privilege-escalation/#nfs-privilege-escalation)
* [ ] **Kısıtlayıcı bir kabuktan kaçmanız gerekiyor mu**? (privilege-escalation/#escaping-from-restricted-shells)

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Deneyimli hackerlar ve ödül avcıları ile iletişim kurmak için [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) sunucusuna katılın!

**Hacking İçgörüleri**\
Hacking'in heyecanına ve zorluklarına dalmış içeriklerle etkileşim kurun

**Gerçek Zamanlı Hack Haberleri**\
Hızlı tempolu hacking dünyasını gerçek zamanlı haberler ve içgörülerle takip edin

**En Son Duyurular**\
Yeni ödül avı başlatmaları ve önemli platform güncellemeleri hakkında bilgi sahibi olun

Bugün en iyi hackerlarla işbirliği yapmak için [**Discord**](https://discord.com/invite/N3FrSbmwdy) adresimize katılın!

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklam vermek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden oluşan**](https://opensea.io/collection/the-peass-family) koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* **💬 Discord grubuna** (https://discord.gg/hRep4RUj7f) veya **telegram grubuna** (https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'da** takip edin.
* **Hacking hilelerinizi paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek katkıda bulunun.

</details>
