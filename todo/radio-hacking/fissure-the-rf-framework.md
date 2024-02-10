# FISSURE - RF Framework

**Frekans Bağımsız SDR Tabanlı Sinyal Anlama ve Tersine Mühendislik**

FISSURE, sinyal tespiti ve sınıflandırma için kancalar, protokol keşfi, saldırı yürütme, IQ manipülasyonu, zayıflık analizi, otomasyon ve AI/ML gibi özelliklere sahip, tüm beceri seviyeleri için tasarlanmış açık kaynaklı bir RF ve tersine mühendislik çerçevesidir. Çerçeve, yazılım modüllerinin, radyoların, protokollerin, sinyal verilerinin, komut dosyalarının, akış grafiklerinin, referans materyallerinin ve üçüncü taraf araçlarının hızlı entegrasyonunu teşvik etmek için oluşturulmuştur. FISSURE, yazılımı tek bir yerde tutan ve ekiplerin aynı kanıtlanmış temel yapılandırmayı paylaşarak kolayca hız kazanmalarını sağlayan bir iş akışı sağlayıcıdır ve belirli Linux dağıtımları için aynı yapılandırmayı paylaşır.

FISSURE ile birlikte gelen çerçeve ve araçlar, RF enerjisinin varlığını tespit etmek, bir sinyalin özelliklerini anlamak, örnekleri toplamak ve analiz etmek, iletim ve/veya enjeksiyon teknikleri geliştirmek ve özel yükler veya mesajlar oluşturmak için tasarlanmıştır. FISSURE, tanımlama, paket oluşturma ve fuzzing için yardımcı olacak bir protokol ve sinyal bilgisi kütüphanesi içerir. Sinyal dosyalarını indirmek ve trafiği simüle etmek ve sistemleri test etmek için çalma listeleri oluşturmak için çevrimiçi arşiv yetenekleri bulunmaktadır.

Dostu Python kod tabanı ve kullanıcı arayüzü, RF ve tersine mühendislikle ilgili popüler araçlar ve teknikler hakkında acemi kullanıcıların hızla öğrenmesine olanak tanır. Siber güvenlik ve mühendislik eğitimcileri, yerleşik materyalden yararlanabilir veya kendi gerçek dünya uygulamalarını göstermek için çerçeveyi kullanabilir. Geliştiriciler ve araştırmacılar, günlük görevlerini yerine getirmek veya keskin çözümlerini daha geniş bir kitleye sunmak için FISSURE'ı kullanabilir. FISSURE'ın toplumda farkındalık ve kullanımı arttıkça, yeteneklerinin kapsamı ve kapsadığı teknolojinin genişliği de artacaktır.

**Ek Bilgiler**

* [AIS Sayfası](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slaytları](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Makalesi](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Videosu](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Sohbeti Metni](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Başlarken

**Desteklenen**

FISSURE içinde dosya gezinmeyi kolaylaştırmak ve kod tekrarını azaltmak için üç dal bulunmaktadır. Python2\_maint-3.7 dalı, Python2, PyQt4 ve GNU Radio 3.7 etrafında oluşturulmuş bir kod tabanına sahiptir; Python3\_maint-3.8 dalı, Python3, PyQt5 ve GNU Radio 3.8 etrafında oluşturulmuştur; ve Python3\_maint-3.10 dalı, Python3, PyQt5 ve GNU Radio 3.10 etrafında oluşturulmuştur.

|   İşletim Sistemi   |   FISSURE Dalı   |
| :------------------: | :----------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**Devam Ediyor (beta)**

Bu işletim sistemleri hala beta durumundadır. Geliştirme aşamasındadırlar ve bazı özelliklerin eksik olduğu bilinmektedir. Yükleyicideki öğeler, mevcut programlarla çakışabilir veya durum kaldırılana kadar yüklenemeyebilir.

|     İşletim Sistemi     |    FISSURE Dalı   |
| :----------------------: | :-----------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

Not: Belirli yazılım araçları her işletim sistemi için çalışmamaktadır. [Yazılım ve Çakışmalar](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md) bölümüne bakınız.

**Kurulum**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
Bu, kurulum GUI'lerini başlatmak için gereken PyQt yazılım bağımlılıklarını yükler (eğer bulunamazsa).

Ardından, işletim sisteminize en iyi uyan seçeneği seçin (eğer işletim sisteminiz bir seçenekle eşleşiyorsa otomatik olarak algılanır).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Mevcut çakışmaları önlemek için FISSURE'ı temiz bir işletim sistemi üzerine kurmanız önerilir. FISSURE içindeki çeşitli araçları kullanırken hataları önlemek için önerilen onay kutularını (Varsayılan düğme) seçin. Kurulum sırasında çoğunlukla yükseltilmiş izinler ve kullanıcı adları isteyen birden fazla iletişim kutusu olacaktır. Bir öğe sonunda "Doğrula" bölümü bulunuyorsa, kurulumcu, takip eden komutu çalıştıracak ve komut tarafından üretilen hatalara bağlı olarak onay kutusu öğesini yeşil veya kırmızı olarak vurgulayacaktır. "Doğrula" bölümü olmayan işaretlenmiş öğeler, kurulumdan sonra siyah kalacaktır.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Kullanım**

Bir terminal açın ve şunu girin:
```
fissure
```
Daha fazla kullanım ayrıntıları için FISSURE Yardım menüsüne başvurun.

## Ayrıntılar

**Bileşenler**

* Gösterge Paneli
* Merkezi Hub (HIPRFISR)
* Hedef Sinyal Tanımlama (TSI)
* Protokol Keşfi (PD)
* Akış Grafiği ve Komut Yürütücü (FGE)

![bileşenler](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Yetenekler**

| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Sinyal Algılayıcı**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ Manipülasyonu**_      | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Sinyal Arama**_          | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Desen Tanıma**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Saldırılar**_           | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Sinyal Oynatma Listeleri**_       | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Resim Galerisi**_  |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Paket Oluşturma**_   | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy Entegrasyonu**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC Hesaplayıcı**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Günlük**_            |

**Donanım**

Aşağıda, farklı entegrasyon seviyelerine sahip "desteklenen" donanım listesi bulunmaktadır:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* 802.11 Adaptörleri
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## Dersler

FISSURE, farklı teknolojiler ve tekniklerle tanışmak için birkaç yardımcı kılavuzla birlikte gelir. Birçok kılavuz, FISSURE'a entegre edilmiş çeşitli araçların kullanım adımlarını içerir.

* [Ders1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Ders2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Ders3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Ders4: ESP Kartları](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Ders5: Radiosonde Takibi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Ders6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Ders7: Veri Tipleri](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Ders8: Özel GNU Radio Blokları](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Ders9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Ders10: Ham Radyo Sınavları](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Ders11: Wi-Fi Araçları](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## Yol Haritası

* [ ] Daha fazla donanım türü, RF protokolleri, sinyal parametreleri, analiz araçları ekleyin
* [ ] Daha fazla işletim sistemi desteği sağlayın
* [ ] FISSURE etrafında sınıf materyali geliştirin (RF Saldırıları, Wi-Fi, GNU Radio, PyQt, vb.)
* [ ] Seçilebilir AI/ML teknikleri ile sinyal düzenleyici, özellik çıkarıcı ve sinyal sınıflandırıcı oluşturun
* [ ] Bilinmeyen sinyallerden bit akışı üretmek için özyinelemeli demodülasyon mekanizmaları uygulayın
* [ ] Ana FISSURE bileşenlerini genel bir sensör düğümü dağıtım şemasına geçirin

## Katkıda Bulunma

FISSURE'ı geliştirmek için önerilerinizi paylaşmanızı şiddetle öneririz. Aşağıdaki konularla ilgili düşünceleriniz varsa, [Tartışmalar](https://github.com/ainfosec/FISSURE/discussions) sayfasında veya Discord Sunucusunda yorum bırakın:

* Yeni özellik önerileri ve tasarım değişiklikleri
* Kurulum adımlarıyla yazılım araçları
* Yeni dersler veya mevcut derslere ek materyal
* İlgilenilen RF protokolleri
* Entegrasyon için daha fazla donanım ve SDR türü
* Python'da IQ analiz betikleri
* Kurulum düzeltmeleri ve iyileştirmeleri

FISSURE'ı geliştirmek için yapılan katkılar, gelişimini hızlandırmak için önemlidir. Yaptığınız her katkı büyük bir takdirle karşılanır. Kod geliştirme yoluyla katkıda bulunmak isterseniz, lütfen repo'yu çatallayın ve bir pull talebi oluşturun:

1. Projeyi çatallayın
2. Özellik dalınızı oluşturun (`git checkout -b feature/AmazingFeature`)
3. Değişikliklerinizi taahhüt edin (`git commit -m 'Add some AmazingFeature'`)
4. Dalı itin (`git push origin feature/AmazingFeature`)
5. Bir pull talebi açın

Hatalara dikkat çekmek için [Sorunlar](https://github.com/ainfosec/FISSURE/issues) oluşturmak da hoş karşılanır.

## İşbirliği

FISSURE işbirliği fırsatlarını önermek ve resmileştirmek için Assured Information Security, Inc. (AIS) İş Geliştirme ile iletişime geçin - bu, yazılımınızı entegre etmeye zaman ayırmak, AIS'nin yetenekli insanlarının teknik zorluklarınıza çözümler geliştirmesini sağlamak veya FISSURE'ı diğer platformlara/uygulamalara entegre etmek olabilir.

## Lisans

GPL-3.0

Lisans ayrıntıları için LICENSE dosyasına bakın.
## İletişim

Discord Sunucusuna Katılın: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Twitter'da Takip Edin: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

İş Geliştirme - Assured Information Security, Inc. - bd@ainfosec.com

## Krediler

Bu geliştiricilere teşekkür ediyoruz:

[Krediler](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Teşekkürler

Bu projeye katkıda bulunan Dr. Samuel Mantravadi ve Joseph Reith'e özel teşekkürler.
