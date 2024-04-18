<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramana öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklam görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünleri**]'ni edinin (https://peass.creator-spring.com)
* [**The PEASS Family**]'yi keşfedin (https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**]'in koleksiyonu
* **Katılın** 💬 [**Discord grubumuza**](https://discord.gg/hRep4RUj7f) veya [**telegram grubumuza**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**]'da takip edin (https://twitter.com/hacktricks_live)**.**
* **Hacking püf noktalarınızı paylaşarak** [**HackTricks**] (https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**] (https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) **karanlık ağ** destekli bir arama motorudur ve şirketin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **kompromize edilip edilmediğini** kontrol etmek için **ücretsiz** işlevler sunar.

WhiteIntel'in başlıca amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye yazılımı saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve motorlarını **ücretsiz** deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

---

# GUI uygulaması içinde olası eylemleri kontrol et

**Ortak Diyaloglar** dosya kaydetme, dosya açma, yazı tipi seçme, renk seçme gibi seçeneklerdir... Çoğu, **tam bir Gezgin işlevselliği sunacaktır**. Bu, şu seçeneklere erişebilirseniz Gezgin işlevselliğine erişebileceğiniz anlamına gelir:

* Kapat/Kapat olarak
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

## Komut Yürütme

Belki de **`Aç ile`** seçeneğini kullanarak bir tür kabuk açabilir/çalıştırabilirsiniz.

### Windows

Örneğin _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ burada kullanılabilecek daha fazla ikili dosyayı bulun: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

### \*NIX __

_bash, sh, zsh..._ Daha fazlası burada: [https://gtfobins.github.io/](https://gtfobins.github.io)

# Windows

## Yol kısıtlamalarını atlatma

* **Çevresel değişkenler**: Bazı yollara işaret eden birçok çevresel değişken vardır
* **Diğer protokoller**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **Sembolik bağlantılar**
* **Kısayollar**: CTRL+N (yeni oturum aç), CTRL+R (Komutları Yürüt), CTRL+SHIFT+ESC (Görev Yöneticisi), Windows+E (gezgini aç), CTRL-B, CTRL-I (Favoriler), CTRL-H (Geçmiş), CTRL-L, CTRL-O (Dosya/Açma Diyalogu), CTRL-P (Yazdırma Diyalogu), CTRL-S (Farklı Kaydet)
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

## İkili Dosyalarınızı İndirin

Konsol: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Gezgin: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Kayıt defteri düzenleyici: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

## Tarayıcıdan dosya sistemine erişim

| YOL                | YOL              | YOL               | YOL                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

## Kısayollar

* Sticky Keys – SHIFT tuşuna 5 kez basın
* Mouse Keys – SHIFT+ALT+NUMLOCK
* Yüksek Kontrast – SHIFT+ALT+PRINTSCN
* Tuşları Değiştir – NUMLOCK'u 5 saniye basılı tutun
* Filtre Tuşları – Sağ SHIFT tuşunu 12 saniye basılı tutun
* WINDOWS+F1 – Windows Arama
* WINDOWS+D – Masaüstünü Göster
* WINDOWS+E – Windows Gezgini Başlat
* WINDOWS+R – Çalıştır
* WINDOWS+U – Kolay Erişim Merkezi
* WINDOWS+F – Arama
* SHIFT+F10 – İçerik Menüsü
* CTRL+SHIFT+ESC – Görev Yöneticisi
* CTRL+ALT+DEL – Yeni Windows sürümlerinde açılış ekranı
* F1 – Yardım F3 – Arama
* F6 – Adres Çubuğu
* F11 – İnternet Explorer içinde tam ekranı aç/kapat
* CTRL+H – İnternet Explorer Geçmişi
* CTRL+T – İnternet Explorer – Yeni Sekme
* CTRL+N – İnternet Explorer – Yeni Sayfa
* CTRL+O – Dosya Aç
* CTRL+S – Kaydet CTRL+N – Yeni RDP / Citrix
## Kaydırma

* Tüm açık Pencereleri görmek için sol taraftan sağa kaydırarak KIOSK uygulamasını küçültün ve doğrudan işletim sistemine erişin;
* Sağ taraftan sola kaydırarak Eylem Merkezi'ni açın, KIOSK uygulamasını küçültün ve doğrudan işletim sistemine erişin;
* Tam ekran modunda açılan bir uygulama için başlık çubuğunu görünür hale getirmek için üst kenardan içeri kaydırın;
* Tam ekran uygulamada görev çubuğunu göstermek için alttan yukarı kaydırın.

## Internet Explorer Hileleri

### 'Resim Araç Çubuğu'

Tıklanıldığında resmin sol üst köşesinde görünen bir araç çubuğudur. Kaydetme, Yazdırma, Mailto, "Resimlerim"i Explorer'da açma gibi işlemleri yapabilirsiniz. Kiosk'un Internet Explorer'ı kullanıyor olması gerekmektedir.

### Shell Protokolü

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

## Dosya Uzantılarını Gösterme

Daha fazla bilgi için bu sayfayı kontrol edin: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

# Tarayıcı Hileleri

iKat sürümlerini yedekleyin:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\

JavaScript kullanarak ortak bir iletişim kutusu oluşturun ve dosya gezgini erişin: `document.write('<input/type=file>')`
Kaynak: https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

# iPad

## Jestler ve Düğmeler

* Dört (veya beş) parmakla yukarı kaydırın / Ana düğmeye çift dokunun: Çoklu görev görünümünü görmek ve Uygulama değiştirmek için

* Dört veya beş parmakla bir yöne kaydırın: Bir sonraki/önceki Uygulamaya geçmek için

* Beş parmakla ekrana sıkıştırın / Ana düğmeye dokunun / Ekrana alttan hızlı bir şekilde yukarı doğru bir parmakla kaydırın: Ana ekrana erişmek için

* Ekrana alttan sadece 1-2 inç (yavaş) bir parmakla yukarı doğru kaydırın: Dock görünecektir

* Ekrana üstten 1 parmakla aşağı doğru kaydırın: Bildirimlerinizi görmek için

* Ekranın sağ üst köşesinden 1 parmakla aşağı doğru kaydırın: iPad Pro'nun kontrol merkezini görmek için

* Ekrandan sol tarafa 1-2 inçlik bir parmakla kaydırın: Bugün görünümünü görmek için

* Ekrandan hızlıca sağa veya sola doğru 1 parmakla kaydırın: Bir sonraki/önceki Uygulamaya geçmek için

* Üst sağ köşesindeki On/**Off**/Sleep düğmesini basılı tutun ve **iPad'ın sağ üst köşesindeki kaydırıcıyı** tamamen sağa kaydırın: Kapatmak için

* **iPad'ın sağ üst köşesindeki On/**Off**/Sleep düğmesine ve Ana düğmesine birkaç saniye basılı tutun**: Zorla kapatmak için

* **iPad'ın sağ üst köşesindeki On/**Off**/Sleep düğmesine ve Ana düğmesine hızlıca basın**: Ekranda sol alt köşede belirecek bir ekran görüntüsü almak için. Her iki düğmeye de aynı anda çok kısa süre basın, birkaç saniye basılı tutarsanız zorla kapatma gerçekleşir.

## Kısayollar

Bir iPad klavyeniz veya USB klavye adaptörünüz olmalıdır. Uygulamadan kaçmak için yararlı olabilecek yalnızca kısayollar burada gösterilecektir.

| Tuş | İsim         |
| --- | ------------ |
| ⌘   | Komut      |
| ⌥   | Seçenek (Alt) |
| ⇧   | Shift        |
| ↩   | Return       |
| ⇥   | Tab          |
| ^   | Kontrol      |
| ←   | Sol Ok   |
| →   | Sağ Ok  |
| ↑   | Yukarı Ok     |
| ↓   | Aşağı Ok   |

### Sistem kısayolları

Bu kısayollar, iPad'in kullanımına bağlı olarak görsel ayarlar ve ses ayarları içindir.

| Kısayol | Eylem                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Ekranı Karart                                                                    |
| F2       | Ekranı Parlakla                                                                |
| F7       | Bir şarkı geriye git                                                                  |
| F8       | Oynat/Duraklat                                                                     |
| F9       | Bir sonraki şarkıya geç                                                                      |
| F10      | Sessiz                                                                           |
| F11      | Ses düzeyini azalt                                                                |
| F12      | Ses düzeyini artır                                                                |
| ⌘ Space  | Mevcut dillerin listesini görüntüler; birini seçmek için tekrar boşluğa dokunun. |

### iPad gezinme

| Kısayol                                           | Eylem                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Ana ekrana git                                              |
| ⌘⇧H (Komut-Shift-H)                              | Ana ekrana git                                              |
| ⌘ (Space)                                          | Spotlight'ı Aç                                              |
| ⌘⇥ (Komut-Tab)                                   | Son on kullanılan uygulamaları listeler                                 |
| ⌘\~                                                | Son Uygulamaya Git                                       |
| ⌘⇧3 (Komut-Shift-3)                              | Ekran Görüntüsü Al (alt sol köşede kaydetme veya işlem yapma) |
| ⌘⇧4                                                | Ekran Görüntüsü Al ve düzenleyicide aç                    |
| ⌘'yi basılı tutun                                   | Uygulama için mevcut kısayolların listesi                 |
| ⌘⌥D (Komut-Option/Alt-D)                         | Dock'u aç                                      |
| ^⌥H (Kontrol-Option-H)                             | Ana düğme                                             |
| ^⌥H H (Kontrol-Option-H-H)                         | Çoklu görev çubuğunu göster                                      |
| ^⌥I (Kontrol-Option-i)                             | Öğe seçici                                            |
| Escape                                             | Geri düğmesi                                             |
| → (Sağ ok)                                    | Sonraki öğe                                               |
| ← (Sol ok)                                     | Önceki öğe                                           |
| ↑↓ (Yukarı ok, Aşağı ok)                          | Seçili öğeye aynı anda dokunun                        |
| ⌥ ↓ (Seçenek-Aşağı ok)                            | Aşağı kaydır                                             |
| ⌥↑ (Seçenek-Yukarı ok)                               | Yukarı kaydır                                               |
| ⌥← veya ⌥→ (Seçenek-Sol ok veya Seçenek-Sağ ok) | Sola veya sağa kaydır                                    |
| ^⌥S (Kontrol-Option-S)                             | VoiceOver konuşmasını aç veya kapat                         |
| ⌘⇧⇥ (Komut-Shift-Tab)                            | Önceki uygulamaya geç                              |
| ⌘⇥ (Komut-Tab)                                   | Orijinal uygulamaya geri dön                         |
| ←+→, sonra Seçenek + ← veya Seçenek+→                   | Dock'ta gezinmek için                                   |
### Safari kısayolları

| Kısayol                | Eylem                                           |
| ----------------------- | ----------------------------------------------- |
| ⌘L (Command-L)          | Konumu Aç                                      |
| ⌘T                      | Yeni bir sekme aç                              |
| ⌘W                      | Geçerli sekme kapat                            |
| ⌘R                      | Geçerli sekme yenile                           |
| ⌘.                      | Geçerli sekmenin yüklenmesini durdur            |
| ^⇥                      | Sonraki sekmeye geç                             |
| ^⇧⇥ (Control-Shift-Tab) | Önceki sekmeye git                             |
| ⌘L                      | Metin girişi/URL alanını seçerek düzenleme yap |
| ⌘⇧T (Command-Shift-T)   | Son kapatılan sekmeyi aç (birkaç kez kullanılabilir) |
| ⌘\[                     | Tarayıcı geçmişinde bir sayfa geri git         |
| ⌘]                      | Tarayıcı geçmişinde bir sayfa ileri git        |
| ⌘⇧R                     | Okuyucu Modunu Aktive Et                       |

### Mail kısayolları

| Kısayol                   | Eylem                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Konumu Aç                   |
| ⌘T                         | Yeni bir sekme aç           |
| ⌘W                         | Geçerli sekme kapat         |
| ⌘R                         | Geçerli sekme yenile        |
| ⌘.                         | Geçerli sekmenin yüklenmesini durdur |
| ⌘⌥F (Command-Option/Alt-F) | Posta kutunuzda arama yap   |

# Referanslar

* [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
* [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
* [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
* [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)


### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) bir **dark-web** destekli arama motorudur ve şirketin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **kompromize edilip edilmediğini** kontrol etmek için **ücretsiz** işlevler sunar.

WhiteIntel'in başlıca amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye yazılımı saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve motorlarını **ücretsiz** deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**The PEASS Family'yi keşfedin**](https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin
* **💬 [Discord grubuna](https://discord.gg/hRep4RUj7f) veya [telegram grubuna](https://t.me/peass) katılın veya** bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'da takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks ve HackTricks Cloud github depolarına PR göndererek paylaşın.**

</details>
