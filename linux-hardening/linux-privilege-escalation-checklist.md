# Kontrol Listesi - Linux Yetki Yükseltme

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünleri**](https://peass.creator-spring.com)'ni edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Bize katılın** 💬 [**Discord grubunda**](https://discord.gg/hRep4RUj7f) veya [**telegram grubunda**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)'ı takip ederek takip edin.
* **Hacking püf noktalarınızı göndererek HackTricks ve HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>

<figure><img src="../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Deneyimli hackerlar ve ödül avcıları ile iletişim kurmak için [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) sunucusuna katılın!

**Hacking İçgörüleri**\
Hacking'in heyecanını ve zorluklarını inceleyen içeriklerle etkileşime girin

**Gerçek Zamanlı Hack Haberleri**\
Hızlı tempolu hacking dünyasında gerçek zamanlı haberler ve içgörülerle güncel kalın

**En Son Duyurular**\
Yeni ödül avı başlatmaları ve önemli platform güncellemeleri hakkında bilgilenin

**Bize katılın** [**Discord**](https://discord.com/invite/N3FrSbmwdy) ve bugün en iyi hackerlarla işbirliğine başlayın!

### **Linux yerel yetki yükseltme vektörlerini aramak için en iyi araç:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Sistem Bilgileri](privilege-escalation/#system-information)

* [ ] **İşletim sistemi bilgilerini alın**
* [ ] [**PATH**](privilege-escalation/#path)'i kontrol edin, herhangi bir **yazılabilir klasör** var mı?
* [ ] [**Çevre değişkenlerini**](privilege-escalation/#env-info) kontrol edin, herhangi bir hassas detay var mı?
* [ ] [**Kernel açıkları**](privilege-escalation/#kernel-exploits) arayın, betikler kullanarak (DirtyCow?)
* [ ] [**sudo sürümünün zafiyetli olup olmadığını** kontrol edin](privilege-escalation/#sudo-version)
* [ ] [**Dmesg** imza doğrulaması başarısız oldu](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] Daha fazla sistem enum (tarih, sistem istatistikleri, cpu bilgisi, yazıcılar)
* [ ] [Daha fazla savunmaları sıralayın](privilege-escalation/#enumerate-possible-defenses)

### [Sürücüler](privilege-escalation/#drives)

* [ ] **Bağlı sürücüleri listele**
* [ ] **Bağlı olmayan sürücü var mı?**
* [ ] **fstab'da kimlik bilgileri var mı?**

### [**Yüklü Yazılım**](privilege-escalation/#installed-software)

* [ ] **Yüklü** [**yararlı yazılımı**](privilege-escalation/#useful-software) kontrol edin
* [ ] **Yüklü** [**zafiyetli yazılımı**](privilege-escalation/#vulnerable-software-installed) kontrol edin

### [İşlemler](privilege-escalation/#processes)

* [ ] **Bilinmeyen yazılım çalışıyor mu**?
* [ ] **Daha fazla ayrıcalığa sahip olması gereken yazılım var mı**?
* [ ] Çalışan işlemlerin **açıklarını arayın** (özellikle çalışan sürüm).
* [ ] Herhangi bir çalışan işlemin **ikili dosyasını değiştirebilir misiniz**?
* [ ] **İşlemleri izleyin** ve sık sık çalışan ilginç işlemleri kontrol edin.
* [ ] Bazı ilginç **işlem belleğini okuyabilir misiniz** (şifrelerin kaydedilmiş olabileceği yer)?

### [Zamanlanmış/Cron işleri?](privilege-escalation/#scheduled-jobs)

* [ ] [**PATH** ](privilege-escalation/#cron-path)bazı cron tarafından değiştiriliyor mu ve içine **yazabilir** misiniz?
* [ ] Bir cron işinde [**joker karakteri** ](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)var mı?
* [ ] **Yürütülen** veya **değiştirilebilir klasörde** olan **değiştirilebilir betik** var mı?
* [ ] Bazı **betiklerin çok sık** (**her 1, 2 veya 5 dakikada bir**) **yürütüldüğünü** (frequent-cron-jobs) tespit ettiniz mi?

### [Servisler](privilege-escalation/#services)

* [ ] Herhangi bir **yazılabilir .service** dosyası var mı?
* [ ] Bir **servis** tarafından yürütülen herhangi bir **yazılabilir ikili** var mı?
* [ ] Systemd PATH'de **yazılabilir klasör** var mı?

### [Zamanlayıcılar](privilege-escalation/#timers)

* [ ] Herhangi bir **yazılabilir zamanlayıcı** var mı?

### [Soketler](privilege-escalation/#sockets)

* [ ] Herhangi bir **yazılabilir .socket** dosyası var mı?
* Herhangi bir soketle **iletişim kurabilir misiniz**?
* **İlginç bilgiler içeren** **HTTP soketleri** var mı?

### [D-Bus](privilege-escalation/#d-bus)

* [ ] Herhangi bir **D-Bus ile iletişim kurabilir misiniz**?

### [Ağ](privilege-escalation/#network)

* Nerede olduğunuzu bilmek için ağı sıralayın
* Makine içinde bir kabuk almadan önce erişemediğiniz **açık portlar** var mı?
* `tcpdump` kullanarak **trafiği dinleyebilir misiniz**?

### [Kullanıcılar](privilege-escalation/#users)

* Genel kullanıcı/gruplar **sıralaması**
* **Çok büyük bir UID'niz** var mı? **Makine** **savunmasız** mı?
* Bir gruba ait olmanız nedeniyle **ayrıcalıkları yükseltebilir misiniz**?
* **Pano** verileri?
* Şifre Politikası?
* Daha önce keşfettiğiniz her **bilinen şifreyi kullanarak** her **mümkün kullanıcıyla giriş yapmayı deneyin**. Şifresiz de giriş yapmayı deneyin.

### [Yazılabilir PATH](privilege-escalation/#writable-path-abuses)

* Eğer PATH'teki bazı klasörler üzerinde **yazma izniniz varsa**, ayrıcalıkları yükseltebilirsiniz

### [SUDO ve SUID komutları](privilege-escalation/#sudo-and-suid)

* **sudo ile herhangi bir komutu çalıştırabilir misiniz**? ROOT olarak OKUMA, YAZMA veya YÜRÜTME yapabilir misiniz? ([**GTFOBins**](https://gtfobins.github.io))
* **SUID binary'si açıklarından yararlanılabilir mi**? ([**GTFOBins**](https://gtfobins.github.io))
* [**sudo** komutları **yol** tarafından **sınırlı mıdır**? kısıtlamaları **atlayabilir misiniz**](privilege-escalation/#sudo-execution-bypassing-paths)?
* [**Yol belirtilmeden Sudo/SUID binary**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
* [**Yol belirtilen SUID binary**](privilege-escalation/#suid-binary-with-command-path)? Atlatma
* [**LD\_PRELOAD açığı**](privilege-escalation/#ld\_preload)
* Yazılabilir bir klasörden [**SUID binary'de .so kütüphanesinin eksikliği**](privilege-escalation/#suid-binary-so-injection) var mı?
* [**SUDO belirteçleri mevcut mu**](privilege-escalation/#reusing-sudo-tokens)? [**SUDO belirteci oluşturabilir misiniz**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
* [**sudoers dosyalarını okuyabilir veya değiştirebilir misiniz**](privilege-escalation/#etc-sudoers-etc-sudoers-d)?
* [**/etc/ld.so.conf.d/**'yi **değiştirebilir misiniz**](privilege-escalation/#etc-ld-so-conf-d)?
* [**OpenBSD DOAS**](privilege-escalation/#doas) komutu
### [Yetenekler](privilege-escalation/#capabilities)

* [ ] Herhangi bir ikili dosya **beklenmeyen yetkiye** sahip mi?

### [ACL'ler](privilege-escalation/#acls)

* [ ] Herhangi bir dosya **beklenmeyen ACL**'ye sahip mi?

### [Açık Shell oturumları](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL Tahmin Edilebilir PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**SSH İlginç yapılandırma değerleri**](privilege-escalation/#ssh-interesting-configuration-values)

### [İlginç Dosyalar](privilege-escalation/#interesting-files)

* [ ] **Profil dosyaları** - Hassas verileri okuyabilir mi? Privesc'e yazabilir mi?
* [ ] **passwd/shadow dosyaları** - Hassas verileri okuyabilir mi? Privesc'e yazabilir mi?
* [ ] **Hassas veriler için genellikle ilginç klasörleri** kontrol edin
* [ ] **Garip Konum/Sahip dosyalar,** erişiminiz olabilir veya yürütülebilir dosyaları değiştirebilirsiniz
* [ ] Son dakikalarda **Değiştirilmiş**
* [ ] **Sqlite DB dosyaları**
* [ ] **Gizli dosyalar**
* [ ] **PATH'teki Komut Dosyaları/Binary'ler**
* [ ] **Web dosyaları** (şifreler?)
* [ ] **Yedekler**?
* [ ] **Şifre içeren bilinen dosyalar**: **Linpeas** ve **LaZagne** kullanın
* [ ] **Genel arama**

### [**Yazılabilir Dosyalar**](privilege-escalation/#writable-files)

* [ ] **Python kütüphanesini** değiştirerek keyfi komutlar çalıştırabilir misiniz?
* [ ] **Log dosyalarını** değiştirebilir misiniz? **Logtotten** saldırısı
* [ ] **/etc/sysconfig/network-scripts/**'i değiştirebilir misiniz? Centos/Redhat saldırısı
* [ ] [**ini, int.d, systemd veya rc.d dosyalarına yazabilir misiniz**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**Diğer hileler**](privilege-escalation/#other-tricks)

* [ ] [**Yetkileri yükseltmek için NFS'i kötüye kullanabilir misiniz**](privilege-escalation/#nfs-privilege-escalation)?
* [ ] [**Kısıtlayıcı bir kabuktan kaçmanız mı gerekiyor**](privilege-escalation/#escaping-from-restricted-shells)?

<figure><img src="../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) sunucusuna katılarak deneyimli hackerlar ve ödül avcıları ile iletişim kurun!

**Hacking İçgörüleri**\
Hacking'in heyecanını ve zorluklarını inceleyen içeriklerle etkileşime girin

**Gerçek Zamanlı Hack Haberleri**\
Hızlı tempolu hacking dünyasını gerçek zamanlı haberler ve içgörülerle takip edin

**En Son Duyurular**\
Yeni ödül avcılarının başlatılmasını ve önemli platform güncellemelerini takip edin

Bugün [**Discord**](https://discord.com/invite/N3FrSbmwdy) üzerinden en iyi hackerlarla işbirliğine başlayın!
