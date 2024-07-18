# KIOSK'lardan Kaçış

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR gönderin.

</details>
{% endhint %}

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) şirketin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **tehlikeye atılıp atılmadığını** kontrol etmek için **ücretsiz** işlevler sunan **dark-web** destekli bir arama motorudur.

WhiteIntel'in başlıca amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve motorlarını **ücretsiz** deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

---

## Fiziksel cihazı kontrol et

|   Bileşen   | Eylem                                                               |
| ----------- | ------------------------------------------------------------------- |
| Güç düğmesi| Cihazı kapatıp açmak başlangıç ekranını ortaya çıkarabilir          |
| Güç kablosu | Gücün kısa süre kesilmesi cihazın yeniden başlatılıp başlatılmadığını kontrol edin |
| USB portları| Daha fazla kısayol içeren fiziksel klavye bağlayın                   |
| Ethernet    | Ağ taraması veya dinleme daha fazla sömürü olanağı sağlayabilir      |


## GUI uygulaması içinde olası eylemleri kontrol et

**Ortak Diyaloglar** bir dosyayı **kaydetme**, bir dosyayı **açma**, bir yazı tipi seçme, bir renk seçme... gibi seçeneklerdir. Bunların çoğu **tam bir Explorer işlevselliği sunacaktır**. Bu, bu seçeneklere erişebilirseniz Explorer işlevlerine erişebileceğiniz anlamına gelir:

* Kapat/Kapat gibi
* Aç/Aç ile
* Yazdır
* Dışa Aktar/İçe Aktar
* Ara
* Tara

Şunları kontrol etmelisiniz:

* Dosyaları değiştirme veya yeni dosyalar oluşturma
* Sembolik bağlantılar oluşturma
* Kısıtlı alanlara erişim sağlama
* Diğer uygulamaları çalıştırma

### Komut Yürütme

Belki de **`Aç ile`** seçeneğini kullanarak bir tür kabuk açabilir/çalıştırabilirsiniz.

#### Windows

Örneğin _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ burada kullanılabilecek daha fazla komut dosyası bulabilirsiniz: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Daha fazlası burada: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Yol kısıtlamalarını atlatma

* **Ortam değişkenleri**: Bazı yollara işaret eden birçok ortam değişkeni vardır
* **Diğer protokoller**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **Sembolik bağlantılar**
* **Kısayollar**: CTRL+N (yeni oturum aç), CTRL+R (Komutları Yürüt), CTRL+SHIFT+ESC (Görev Yöneticisi), Windows+E (explorer'ı aç), CTRL-B, CTRL-I (Favoriler), CTRL-H (Geçmiş), CTRL-L, CTRL-O (Dosya/Aç Diyalogu), CTRL-P (Yazdırma Diyalogu), CTRL-S (Farklı Kaydet)
* Gizli Yönetici menüsü: CTRL-ALT-F8, CTRL-ESC-F9
* **Kabuk URI'ları**: _shell:Yönetici Araçları, shell:Belgeler Kütüphanesi, shell:Kütüphaneler shell:KullanıcıProfilleri, shell:Kişisel, shell:AramaAnaKlasör, shell:Sistemshell:AğYerleriKlasörü, shell:Gönder, shell:KullanıcıProfilleri, shell:Ortak Yönetici Araçları, shell:BilgisayarımKlasörü, shell:İnternetKlasörü_
* **UNC yolları**: Paylaşılan klasörlere bağlanmak için yollar. Yerel makinenin C$'sine bağlanmayı denemelisiniz ("\\\127.0.0.1\c$\Windows\System32")
* **Daha fazla UNC yolu:**

| UNC                       | UNC            | UNC                  |
| ------------------------- | -------------- | -------------------- |
| %ALLUSERSPROFILE%         | %APPDATA%      | %CommonProgramFiles% |
| %COMMONPROGRAMFILES(x86)% | %COMPUTERNAME% | %COMSPEC%            |
| %HOMEDRIVE%               | %HOMEPATH%     | %LOCALAPPDATA%       |
| %LOGONSERVER%             | %PATH%         | %PATHEXT%            |
| %ProgramData%             | %ProgramFiles% | %ProgramFiles(x86)%  |
| %PROMPT%                  | %PSModulePath% | %Public%             |
| %SYSTEMDRIVE%             | %SYSTEMROOT%   | %TEMP%               |
| %TMP%                     | %USERDOMAIN%   | %USERNAME%           |
| %USERPROFILE%             | %WINDIR%       |                      |
### Kısayollar

* Sticky Keys – SHIFT tuşuna 5 kez basın
* Mouse Keys – SHIFT+ALT+NUMLOCK
* Yüksek Kontrast – SHIFT+ALT+PRINTSCN
* Toggle Keys – NUMLOCK tuşunu 5 saniye basılı tutun
* Filtre Tuşları – Sağ SHIFT tuşunu 12 saniye basılı tutun
* WINDOWS+F1 – Windows Arama
* WINDOWS+D – Masaüstünü Göster
* WINDOWS+E – Windows Gezgini'ni Başlat
* WINDOWS+R – Çalıştır
* WINDOWS+U – Kolay Erişim Merkezi
* WINDOWS+F – Arama
* SHIFT+F10 – Bağlam Menüsü
* CTRL+SHIFT+ESC – Görev Yöneticisi
* CTRL+ALT+DEL – Yeni Windows sürümlerinde başlangıç ekranı
* F1 – Yardım F3 – Arama
* F6 – Adres Çubuğu
* F11 – İnternet Explorer içinde tam ekranı aç/kapat
* CTRL+H – İnternet Explorer Geçmişi
* CTRL+T – İnternet Explorer – Yeni Sekme
* CTRL+N – İnternet Explorer – Yeni Sayfa
* CTRL+O – Dosya Aç
* CTRL+S – Kaydet CTRL+N – Yeni RDP / Citrix

### Kaydırma

* Sol kenardan sağa kaydırarak tüm açık Pencereleri görebilir, KIOSK uygulamasını küçülterek tüm işletim sistemine doğrudan erişebilirsiniz;
* Sağ kenardan sola kaydırarak Eylem Merkezi'ni açabilir, KIOSK uygulamasını küçülterek tüm işletim sistemine doğrudan erişebilirsiniz;
* Üst kenardan içeri kaydırarak tam ekran modunda açılan bir uygulama için başlık çubuğunu görünür hale getirebilirsiniz;
* Alt kenardan yukarı kaydırarak tam ekran bir uygulamada görev çubuğunu gösterebilirsiniz.

### İnternet Explorer Hileleri

#### 'Resim Araç Çubuğu'

Tıklanıldığında resmin sol üst köşesinde görünen bir araç çubuğudur. Kaydetme, Yazdırma, Mailto, "Resimlerim"i Gezgini'nde Açma gibi işlemleri yapabilirsiniz. Kiosk'un İnternet Explorer kullanıyor olması gerekmektedir.

#### Shell Protokolü

Explorer görünümü elde etmek için bu URL'leri yazın:

* `shell:Yönetim Araçları`
* `shell:Belgeler Kütüphanesi`
* `shell:Kütüphaneler`
* `shell:Kullanıcı Profilleri`
* `shell:Kişisel`
* `shell:AramaAnaKlasör`
* `shell:AğYerleriKlasörü`
* `shell:Gönder`
* `shell:KullanıcıProfilleri`
* `shell:Ortak Yönetim Araçları`
* `shell:BilgisayarımKlasörü`
* `shell:İnternetKlasörü`
* `Shell:Profil`
* `Shell:ProgramDosyaları`
* `Shell:Sistem`
* `Shell:DenetimMasasıKlasörü`
* `Shell:Windows`
* `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Denetim Masası
* `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> Bilgisayarım
* `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Ağ Yerlerim
* `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> İnternet Explorer

### Dosya Uzantılarını Göster

Daha fazla bilgi için bu sayfaya bakın: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Tarayıcı Hileleri

Yedek iKat sürümleri:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\\

JavaScript kullanarak ortak bir iletişim kutusu oluşturun ve dosya gezginine erişin: `document.write('<input/type=file>')`\
Kaynak: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Jestler ve Düğmeler

* Dört (veya beş) parmakla yukarı kaydırın / Ana düğmeye iki kez dokunun: Çoklu görev görünümünü görmek ve Uygulama değiştirmek için
* Dört veya beş parmakla bir yöne kaydırın: Bir sonraki/önceki Uygulamaya geçmek için
* Beş parmakla ekrana yaklaşın / Ana düğmeye dokunun / Ekrana alttan hızlı bir şekilde bir parmakla yukarı kaydırın: Ana ekrana erişmek için
* Bir parmakla ekranın altından yavaşça 1-2 inç yukarı kaydırın: Dock görünecektir
* Bir parmakla ekranın üstünden aşağı doğru kaydırın: Bildirimlerinizi görmek için
* Ekranın sağ üst köşesinden bir parmakla aşağı doğru kaydırın: iPad Pro'nun kontrol merkezini görmek için
* Ekranın solundan bir parmakla 1-2 inç kaydırın: Bugün görünümünü görmek için
* Ekrandan hızlı bir şekilde sağa veya sola doğru bir parmakla kaydırın: Bir sonraki/önceki Uygulamaya geçmek için
* Üst sağ köşesindeki On/**Kapalı**/Uyku düğmesini basılı tutun + Kaydırıcıyı sağa kadar tüm yol boyunca kaydırın: Kapatmak için
* Üst sağ köşesindeki On/**Kapalı**/Uyku düğmesine ve Ana düğmeye birkaç saniye basılı tutun: Zorla kapatmak için
* Üst sağ köşesindeki On/**Kapalı**/Uyku düğmesine ve Ana düğmeye hızlıca basın: Ekranda sol alt köşede belirecek bir ekran görüntüsü almak için. Her iki düğmeye de aynı anda çok kısa süre basın, birkaç saniye basılı tutarsanız zorla kapatma gerçekleşir.

### Kısayollar

Bir iPad klavyesine veya USB klavye adaptörüne sahip olmalısınız. Sadece uygulamadan kaçmanıza yardımcı olabilecek kısayollar burada gösterilecektir.

| Tuş | Adı          |
| --- | ------------ |
| ⌘   | Komut        |
| ⌥   | Seçenek (Alt)|
| ⇧   | Shift        |
| ↩   | Return       |
| ⇥   | Sekme        |
| ^   | Kontrol      |
| ←   | Sol Ok       |
| →   | Sağ Ok       |
| ↑   | Yukarı Ok    |
| ↓   | Aşağı Ok     |

#### Sistem kısayolları

Bu kısayollar, iPad'in kullanımına bağlı olarak görsel ayarlar ve ses ayarları içindir.

| Kısayol | Eylem                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Ekranı Karart                                                                  |
| F2       | Ekranı Parlakla                                                                |
| F7       | Bir şarkı geriye git                                                           |
| F8       | Oynat/Duraklat                                                                 |
| F9       | Bir şarkı ileri git                                                            |
| F10      | Sessizleştir                                                                   |
| F11      | Ses düzeyini azalt                                                             |
| F12      | Ses düzeyini artır                                                             |
| ⌘ Boşluk| Mevcut dillerin listesini görüntüler; birini seçmek için tekrar boşluğa dokunun. |

#### iPad gezinme

| Kısayol                                           | Eylem                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Ana Ekrana Git                                         |
| ⌘⇧H (Komut-Shift-H)                              | Ana Ekrana Git                                         |
| ⌘ (Boşluk)                                        | Spotlight'ı Aç                                         |
| ⌘⇥ (Komut-Tab)                                   | Son on kullanılan uygulamaları listeler                 |
| ⌘\~                                                | Son Uygulamaya Git                                    |
| ⌘⇧3 (Komut-Shift-3)                              | Ekran Görüntüsü Al (alt sol köşede kaydetme veya işlem yapma) |
| ⌘⇧4                                              | Ekran Görüntüsü Al ve düzenleyicide aç                 |
| ⌘'yi basılı tutun                                 | Uygulama için mevcut kısayolların listesi               |
| ⌘⌥D (Komut-Option/Alt-D)                         | Dock'u açar                                           |
| ^⌥H (Kontrol-Option-H)                           | Ana düğme                                              |
| ^⌥H H (Kontrol-Option-H-H)                       | Çoklu görev çubuğunu göster                            |
| ^⌥I (Kontrol-Option-i)                           | Öğe seçici                                            |
| Escape                                           | Geri düğmesi                                          |
| → (Sağ ok)                                      | Sonraki öğe                                           |
| ← (Sol ok)                                      | Önceki öğe                                           |
| ↑↓ (Yukarı ok, Aşağı ok)                        | Seçili öğeye aynı anda dokun                          |
| ⌥ ↓ (Seçenek-Aşağı ok)                          | Aşağı kaydır                                          |
| ⌥↑ (Seçenek-Yukarı ok)                          | Yukarı kaydır                                         |
| ⌥← veya ⌥→ (Seçenek-Sol ok veya Seçenek-Sağ ok) | Sola veya sağa kaydır                                 |
| ^⌥S (Kontrol-Option-S)                          | VoiceOver konuşmasını aç veya kapat                  |
| ⌘⇧⇥ (Komut-Shift-Tab)                           | Önceki uygulamaya geç                                  |
| ⌘⇥ (Komut-Tab)                                 | Orijinal uygulamaya geri dön                          |
| ←+→, sonra Seçenek + ← veya Seçenek+→           | Dock'tan geçiş yap                                    |
#### Safari kısayolları

| Kısayol                | Eylem                                           |
| ----------------------- | ----------------------------------------------- |
| ⌘L (Command-L)         | Konumu Aç                                      |
| ⌘T                     | Yeni bir sekme aç                              |
| ⌘W                     | Geçerli sekmeyi kapat                          |
| ⌘R                     | Geçerli sekmeyi yenile                         |
| ⌘.                     | Geçerli sekmeyi yüklemeyi durdur               |
| ^⇥                     | Sonraki sekmeye geçiş yap                      |
| ^⇧⇥ (Control-Shift-Tab) | Önceki sekmeye geçiş yap                      |
| ⌘L                     | Metin girişi/URL alanını seçerek düzenleme yap |
| ⌘⇧T (Command-Shift-T)  | Son kapatılan sekmeyi aç (birkaç kez kullanılabilir) |
| ⌘\[                    | Tarayıcı geçmişinde bir sayfa geri git         |
| ⌘]                     | Tarayıcı geçmişinde bir sayfa ileri git        |
| ⌘⇧R                    | Okuyucu Modunu Aktive Et                       |

#### Mail kısayolları

| Kısayol                   | Eylem                       |
| -------------------------- | ---------------------------- |
| ⌘L                        | Konumu Aç                   |
| ⌘T                        | Yeni bir sekme aç           |
| ⌘W                        | Geçerli sekmeyi kapat       |
| ⌘R                        | Geçerli sekmeyi yenile      |
| ⌘.                        | Geçerli sekmeyi yüklemeyi durdur |
| ⌘⌥F (Command-Option/Alt-F) | Posta kutunuzda arama yap   |

## Referanslar

* [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
* [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
* [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
* [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io), **karanlık ağ** destekli bir arama motorudur ve şirketin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **etkilenip etkilenmediğini** kontrol etmek için **ücretsiz** işlevler sunar.

WhiteIntel'in başlıca amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye yazılımı saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve motorlarını **ücretsiz** deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitimi AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitimi GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını göndererek HackTricks ve HackTricks Cloud** github depolarına PR'lar gönderin.

</details>
{% endhint %}
