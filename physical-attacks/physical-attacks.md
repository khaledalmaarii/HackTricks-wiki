# Fiziksel Saldırılar

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io), bir şirketin veya müşterilerinin **stealer malwares** tarafından **tehdit edilip edilmediğini** kontrol etmek için **ücretsiz** işlevler sunan bir **karanlık ağ** destekli arama motorudur.

WhiteIntel'in ana hedefi, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye yazılımı saldırılarıyla mücadele etmektir.

Web sitelerini kontrol edebilir ve motorlarını **ücretsiz** deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

---

## BIOS Şifre Kurtarma ve Sistem Güvenliği

**BIOS'u sıfırlamak**, birkaç şekilde gerçekleştirilebilir. Çoğu anakart, çıkarıldığında yaklaşık **30 dakika** boyunca BIOS ayarlarını, şifreyi de içerecek şekilde sıfırlayan bir **pil** içerir. Alternatif olarak, belirli pinleri bağlayarak bu ayarları sıfırlamak için **anakart üzerindeki bir jumper** ayarlanabilir.

Donanım ayarlamalarının mümkün veya pratik olmadığı durumlar için, **yazılım araçları** bir çözüm sunar. **Kali Linux** gibi dağıtımlarla bir **Live CD/USB** üzerinden sistem çalıştırmak, BIOS şifre kurtarma konusunda yardımcı olabilecek **_killCmos_** ve **_CmosPWD_** gibi araçlara erişim sağlar.

BIOS şifresi bilinmediğinde, yanlış girildiğinde genellikle **üç kez** hata kodu ile sonuçlanır. Bu kod, kullanılabilir bir şifre almak için [https://bios-pw.org](https://bios-pw.org) gibi web sitelerinde kullanılabilir.

### UEFI Güvenliği

Geleneksel BIOS yerine **UEFI** kullanan modern sistemler için, **chipsec** aracı, **Secure Boot**'u devre dışı bırakma da dahil olmak üzere UEFI ayarlarını analiz etmek ve değiştirmek için kullanılabilir. Bu, aşağıdaki komutla gerçekleştirilebilir:

`python chipsec_main.py -module exploits.secure.boot.pk`

### RAM Analizi ve Soğuk Başlatma Saldırıları

RAM, güç kesildiğinde verileri kısa bir süre, genellikle **1 ila 2 dakika** boyunca saklar. Bu süre, sıvı nitrojen gibi soğuk maddeler uygulanarak **10 dakikaya** kadar uzatılabilir. Bu uzatılmış süre boyunca, analiz için **dd.exe** ve **volatility** gibi araçlar kullanılarak bir **bellek dökümü** oluşturulabilir.

### Doğrudan Bellek Erişimi (DMA) Saldırıları

**INCEPTION**, **FireWire** ve **Thunderbolt** gibi arayüzlerle uyumlu, **fiziksel bellek manipülasyonu** için tasarlanmış bir araçtır. Herhangi bir şifreyi kabul etmek için belleği yamanarak oturum açma prosedürlerini atlamaya olanak tanır. Ancak, **Windows 10** sistemlerine karşı etkisizdir.

### Sistem Erişimi için Live CD/USB

**_sethc.exe_** veya **_Utilman.exe_** gibi sistem ikili dosyalarını **_cmd.exe_** kopyası ile değiştirmek, sistem ayrıcalıklarıyla bir komut istemcisi sağlayabilir. **chntpw** gibi araçlar, bir Windows kurulumunun **SAM** dosyasını düzenlemek için kullanılabilir ve şifre değişikliklerine olanak tanır.

**Kon-Boot**, Windows çekirdeğini veya UEFI'yi geçici olarak değiştirerek şifreyi bilmeden Windows sistemlerine giriş yapmayı kolaylaştıran bir araçtır. Daha fazla bilgi [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/) adresinde bulunabilir.

### Windows Güvenlik Özelliklerini Yönetme

#### Başlatma ve Kurtarma Kısayolları

- **Supr**: BIOS ayarlarına erişim.
- **F8**: Kurtarma moduna girme.
- Windows banner'ından sonra **Shift** tuşuna basmak, otomatik oturumu atlayabilir.

#### Kötü USB Cihazları

**Rubber Ducky** ve **Teensyduino** gibi cihazlar, hedef bilgisayara bağlandıklarında önceden tanımlanmış yükleri çalıştırabilen **kötü USB** cihazları oluşturmak için platformlar olarak hizmet eder.

#### Hacim Gölge Kopyası

Yönetici ayrıcalıkları, PowerShell aracılığıyla **SAM** dosyası da dahil olmak üzere hassas dosyaların kopyalarını oluşturma olanağı sağlar.

### BitLocker Şifrelemesini Aşma

BitLocker şifrelemesi, **kurtarma şifresi** bir bellek döküm dosyasında (**MEMORY.DMP**) bulunursa potansiyel olarak aşılabilir. Bu amaçla **Elcomsoft Forensic Disk Decryptor** veya **Passware Kit Forensic** gibi araçlar kullanılabilir.

### Kurtarma Anahtarı Ekleme için Sosyal Mühendislik

Yeni bir BitLocker kurtarma anahtarı, bir kullanıcıyı sıfırlardan oluşan yeni bir kurtarma anahtarı ekleyecek bir komutu çalıştırmaya ikna ederek sosyal mühendislik taktikleriyle eklenebilir ve böylece şifre çözme süreci basitleştirilebilir.

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io), bir şirketin veya müşterilerinin **stealer malwares** tarafından **tehdit edilip edilmediğini** kontrol etmek için **ücretsiz** işlevler sunan bir **karanlık ağ** destekli arama motorudur.

WhiteIntel'in ana hedefi, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye yazılımı saldırılarıyla mücadele etmektir.

Web sitelerini kontrol edebilir ve motorlarını **ücretsiz** deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
