# KIOSK'lardan Kaçış

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile</strong>!</summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünleri**]'ni edinin (https://peass.creator-spring.com)
* [**PEASS Ailesi**]'ni keşfedin (https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**]'in koleksiyonu
* **Katılın** 💬 [**Discord grubumuza**](https://discord.gg/hRep4RUj7f) veya [**telegram grubumuza**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**]'de takip edin (https://twitter.com/hacktricks\_live)**.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**]'e (https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**]'a (https://github.com/carlospolop/hacktricks-cloud) destek olun.

</details>

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) **karanlık ağ** destekli bir arama motorudur ve şirketin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **tehlikeye atılıp atılmadığını kontrol etmek için ücretsiz** işlevsellikler sunar.

WhiteIntel'in başlıca amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve motorlarını **ücretsiz** deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

---

## Fiziksel cihazı kontrol et

|   Bileşen   | Eylem                                                               |
| ------------- | -------------------------------------------------------------------- |
| Güç düğmesi  | Cihazı kapatıp açmak başlangıç ekranını ortaya çıkarabilir      |
| Güç kablosu   | Gücün kısa süre kesilmesi cihazın yeniden başlatılıp başlatılmadığını kontrol edin   |
| USB bağlantı noktaları     | Daha fazla kısayol ile fiziksel klavye bağlayın                        |
| Ethernet      | Ağ taraması veya dinleme daha fazla istismarı mümkün kılabilir             |


## GUI uygulaması içinde olası eylemleri kontrol et

**Ortak Diyaloglar** bir dosyayı **kaydetme**, bir dosyayı **açma**, bir yazı tipi seçme, bir renk seçme... gibi seçeneklerdir. Bunların çoğu **tam bir Explorer işlevselliği sunacaktır**. Bu, bu seçeneklere erişebilirseniz Explorer işlevselliğine erişebileceğiniz anlamına gelir:

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

Örneğin _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ burada kullanılabilecek daha fazla ikili dosyayı bulun: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Daha fazlası burada: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Yol kısıtlamalarını atlatma

* **Ortam değişkenleri**: Bazı yollara işaret eden birçok ortam değişkeni vardır
* **Diğer protokoller**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **Sembolik bağlantılar**
* **Kısayollar**: CTRL+N (yeni oturum aç), CTRL+R (Komutları Yürüt), CTRL+SHIFT+ESC (Görev Yöneticisi), Windows+E (explorer'ı aç), CTRL-B, CTRL-I (Favoriler), CTRL-H (Geçmiş), CTRL-L, CTRL-O (Dosya/Aç Diyalogu), CTRL-P (Yazdırma Diyalogu), CTRL-S (Farklı Kaydet)
* Gizli Yönetici menüsü: CTRL-ALT-F8, CTRL-ESC-F9
* **Kabuk URI'leri**: _shell:Yönetici Araçları, shell:Belgeler Kütüphanesi, shell:Kütüphaneler shell:KullanıcıProfilleri, shell:Kişisel, shell:AramaAnaKlasör, shell:Sistemshell:AğYerleriKlasörü, shell:Gönder, shell:KullanıcıProfilleri, shell:Ortak Yönetici Araçları, shell:BilgisayarımKlasörü, shell:İnternetKlasörü_
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

### İkili Dosyalarınızı İndirin

Konsol: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Kayıt defteri düzenleyici: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Tarayıcıdan dosya sistemine erişim

| YOL                | YOL              | YOL               | YOL                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |
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
* SHIFT+F10 – İçerik Menüsü
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

### Kaydırmalar

* Sol kenardan sağa kaydırarak tüm açık Pencereleri görebilir, KIOSK uygulamasını küçültebilir ve doğrudan işletim sistemine erişebilirsiniz;
* Sağ kenardan sola kaydırarak Eylem Merkezi'ni açabilir, KIOSK uygulamasını küçültebilir ve doğrudan işletim sistemine erişebilirsiniz;
* Üst kenardan içeri kaydırarak tam ekran modunda açılan bir uygulama için başlık çubuğunu görünür hale getirebilirsiniz;
* Alt kenardan yukarı kaydırarak tam ekran uygulamada görev çubuğunu gösterebilirsiniz.

### İnternet Explorer Hileleri

#### 'Resim Araç Çubuğu'

Resme tıklandığında üst sol köşede görünen bir araç çubuğudur. Kaydetme, Yazdırma, Mailto, "Resimlerim"i Gezgini'nde Açma gibi işlemleri yapabilirsiniz. Kiosk'un Internet Explorer kullanıyor olması gerekmektedir.

#### Shell Protokolü

Explorer görünümü elde etmek için bu URL'leri yazın:

* `shell:Administrative Tools`
* `shell:DocumentsLibrary`
* `shell:Libraries`
* `shell:UserProfiles`
* `shell:Personal`
* `shell:SearchHomeFolder`
* `shell:NetworkPlacesFolder`
* `shell:SendTo`
* `shell:UserProfiles`
* `shell:Common Administrative Tools`
* `shell:MyComputerFolder`
* `shell:InternetFolder`
* `Shell:Profile`
* `Shell:ProgramFiles`
* `Shell:System`
* `Shell:ControlPanelFolder`
* `Shell:Windows`
* `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Denetim Masası
* `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> Bilgisayarım
* `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Ağ Yerlerim
* `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### Dosya Uzantılarını Göster

Daha fazla bilgi için bu sayfaya bakın: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Tarayıcı Hileleri

iKat sürümlerini yedekleyin:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\\

JavaScript kullanarak ortak bir iletişim kutusu oluşturun ve dosya gezginine erişin: `document.write('<input/type=file>')`\
Kaynak: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Jestler ve Düğmeler

* Dört (veya beş) parmakla yukarı kaydırın / Ana düğmeye çift dokunun: Çoklu görev görünümünü görmek ve Uygulama değiştirmek için
* Dört veya beş parmakla bir yöne kaydırın: Bir sonraki/önceki Uygulamaya geçmek için
* Beş parmakla ekrana sıkıştırın / Ana düğmeye dokunun / Ekrana hızlı bir şekilde alttan yukarı doğru bir parmakla kaydırın: Ana ekrana erişmek için
* Ekrana alttan 1-2 inç (yavaşça) bir parmakla kaydırın: Dock görünecektir
* Ekrana üstten 1 parmakla aşağı doğru kaydırın: Bildirimlerinizi görmek için
* Ekranın sağ üst köşesinden 1 parmakla aşağı doğru kaydırın: iPad Pro'nun kontrol merkezini görmek için
* Ekrandan sol kenara doğru 1-2 inçlik bir parmakla kaydırın: Bugün görünümünü görmek için
* Ekrandan hızlıca sağa veya sola doğru 1 parmakla kaydırın: Bir sonraki/önceki Uygulamaya geçmek için
* Üst sağ köşesindeki On/**Off**/Sleep düğmesini basılı tutun + Kaydırmayı sağa doğru hareket ettirin: Kapatmak için
* Üst sağ köşesindeki On/**Off**/Sleep düğmesine ve Ana düğmeye birkaç saniye basın: Zorla kapatmak için
* Üst sağ köşesindeki On/**Off**/Sleep düğmesine ve Ana düğmeye hızlıca basın: Ekranda sol alt köşede belirecek bir ekran görüntüsü almak için. Her iki düğmeye de aynı anda çok kısa süre basın, birkaç saniye basılı tutarsanız zorla kapatma gerçekleşir.

### Kısayollar

Bir iPad klavyeniz veya USB klavye adaptörünüz olmalıdır. Uygulamadan kaçmanıza yardımcı olabilecek yalnızca kısayollar burada gösterilecektir.

| Tuş | İsim         |
| --- | ------------ |
| ⌘   | Komut      |
| ⌥   | Seçenek (Alt) |
| ⇧   | Shift        |
| ↩   | Return       |
| ⇥   | Sekme          |
| ^   | Kontrol      |
| ←   | Sol Ok   |
| →   | Sağ Ok  |
| ↑   | Yukarı Ok     |
| ↓   | Aşağı Ok   |

#### Sistem kısayolları

Bu kısayollar, iPad'in kullanımına bağlı olarak görsel ayarlar ve ses ayarları içindir.

| Kısayol | Eylem                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Ekranı Karart                                                                    |
| F2       | Ekranı Parlakla                                                                |
| F7       | Bir şarkı geri al                                                                  |
| F8       | Oynat/Duraklat                                                                     |
| F9       | Bir sonraki şarkıya atla                                                                      |
| F10      | Sessiz                                                                           |
| F11      | Ses düzeyini azalt                                                                |
| F12      | Ses düzeyini artır                                                                |
| ⌘ Space  | Mevcut dillerin listesini görüntüle; birini seçmek için tekrar boşluğa dokunun. |

#### iPad gezinme

| Kısayol                                           | Eylem                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Ana ekrana git                                              |
| ⌘⇧H (Komut-Shift-H)                              | Ana ekrana git                                              |
| ⌘ (Space)                                          | Spotlight'ı Aç                                          |
| ⌘⇥ (Komut-Tab)                                   | Son on kullanılan uygulamaları listele                                 |
| ⌘\~                                                | Son Uygulamaya Git                                       |
| ⌘⇧3 (Komut-Shift-3)                              | Ekran Görüntüsü Al (alt sol köşede kaydetme veya işlem yapma) |
| ⌘⇧4                                                | Ekran Görüntüsü Al ve düzenleyicide aç                     |
| ⌘'yi basılı tutun                                   | Uygulama için kullanılabilir kısayolların listesi                 |
| ⌘⌥D (Komut-Option/Alt-D)                         | Dock'u aç                                      |
| ^⌥H (Kontrol-Option-H)                             | Ana düğme                                             |
| ^⌥H H (Kontrol-Option-H-H)                         | Çoklu görev çubuğunu göster                                      |
| ^⌥I (Kontrol-Option-i)                             | Öğe seçici                                            |
| Escape                                             | Geri düğmesi                                             |
| → (Sağ ok)                                    | Sonraki öğe                                               |
| ← (Sol ok)                                     | Önceki öğe                                           |
| ↑↓ (Yukarı ok, Aşağı ok)                          | Seçili öğeye aynı anda dokunun                        |
| ⌥ ↓ (Alt-Aşağı ok)                            | Aşağı kaydır                                             |
| ⌥↑ (Alt-Yukarı ok)                               | Yukarı kaydır                                               |
| ⌥← veya ⌥→ (Alt-Sol ok veya Alt-Sağ ok) | Sola veya sağa kaydır                                    |
| ^⌥S (Kontrol-Option-S)                             | VoiceOver konuşmasını aç veya kapat                         |
| ⌘⇧⇥ (Komut-Shift-Tab)                            | Önceki uygulamaya geç                              |
| ⌘⇥ (Komut-Tab)                                   | Orijinal uygulamaya geri dön                         |
| ←+→, sonra Option + ← veya Option+→                   | Dock'ta gezinmek için                                   |
#### Safari kısayolları

| Kısayol                | Eylem                                           |
| ----------------------- | ----------------------------------------------- |
| ⌘L (Command-L)          | Konumu Aç                                      |
| ⌘T                      | Yeni bir sekme aç                              |
| ⌘W                      | Geçerli sekmeyi kapat                          |
| ⌘R                      | Geçerli sekmeyi yenile                         |
| ⌘.                      | Geçerli sekmeyi yüklemeyi durdur               |
| ^⇥                      | Sonraki sekmeye geçiş yap                      |
| ^⇧⇥ (Control-Shift-Tab) | Önceki sekmeye geçiş yap                       |
| ⌘L                      | Metin girişi/URL alanını seçerek düzenleme yap |
| ⌘⇧T (Command-Shift-T)   | Son kapatılan sekmeyi aç (birkaç kez kullanılabilir) |
| ⌘\[                     | Tarayıcı geçmişinde bir sayfa geri git         |
| ⌘]                      | Tarayıcı geçmişinde bir sayfa ileri git        |
| ⌘⇧R                     | Okuyucu Modunu Aktive Et                       |

#### Mail kısayolları

| Kısayol                   | Eylem                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Konumu Aç                   |
| ⌘T                         | Yeni bir sekme aç           |
| ⌘W                         | Geçerli sekmeyi kapat       |
| ⌘R                         | Geçerli sekmeyi yenile      |
| ⌘.                         | Geçerli sekmeyi yüklemeyi durdur |
| ⌘⌥F (Command-Option/Alt-F) | Posta kutunuzda arama yap   |

## Referanslar

* [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
* [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
* [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
* [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io), **karanlık ağ** destekli bir arama motorudur ve şirketin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **etkilenip etkilenmediğini** kontrol etmek için **ücretsiz** işlevsellikler sunar.

WhiteIntel'in başlıca amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye yazılımı saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve motorlarını **ücretsiz** deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**The PEASS Family'yi keşfedin**](https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin
* **💬 [Discord grubuna](https://discord.gg/hRep4RUj7f) katılın veya [telegram grubuna](https://t.me/peass) katılın veya** bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks ve HackTricks Cloud github depolarına PR'lar göndererek paylaşın.**

</details>
