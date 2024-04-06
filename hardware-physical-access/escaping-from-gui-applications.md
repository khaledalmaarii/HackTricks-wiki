<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünleri**](https://peass.creator-spring.com)'ni edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>


# GUI uygulamasından kaçma

**Ortak İletişim Kutuları** dosya kaydetme, dosya açma, yazı tipi seçme, renk seçme gibi seçeneklerdir. Bunların çoğu, tam bir Gezgin işlevselliği sunar. Bu, aşağıdaki seçeneklere erişebiliyorsanız Gezgin işlevselliğine erişebileceğiniz anlamına gelir:

* Kapat/Kapat olarak
* Aç/Aç ile
* Yazdır
* Dışa Aktar/İçe Aktar
* Ara
* Tara

Aşağıdakileri kontrol etmelisiniz:

* Dosyaları değiştirme veya yeni dosyalar oluşturma
* Sembolik bağlantılar oluşturma
* Kısıtlı alanlara erişim elde etme
* Diğer uygulamaları çalıştırma

## Komut Yürütme

Belki de bir `Aç ile` seçeneği kullanarak bir tür kabuk açabilir/çalıştırabilirsiniz.

### Windows

Örneğin _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ burada komutları yürütmek için kullanılabilecek daha fazla ikili bulunur: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

### \*NIX __

_bash, sh, zsh..._ Daha fazlası burada: [https://gtfobins.github.io/](https://gtfobins.github.io)

# Windows

## Yol Kısıtlamalarını Aşma

* **Ortam değişkenleri**: Birçok ortam değişkeni belirli bir yola işaret eder
* **Diğer protokoller**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **Sembolik bağlantılar**
* **Kısayollar**: CTRL+N (yeni oturum aç), CTRL+R (Komutları Yürüt), CTRL+SHIFT+ESC (Görev Yöneticisi),  Windows+E (gezgini aç), CTRL-B, CTRL-I (Favoriler), CTRL-H (Geçmiş), CTRL-L, CTRL-O (Dosya/Aç İletişim Kutusu), CTRL-P (Yazdır İletişim Kutusu), CTRL-S (Farklı Kaydet)
* Gizli Yönetici menüsü: CTRL-ALT-F8, CTRL-ESC-F9
* **Shell URI'ları**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
* **UNC yolları**: Paylaşılan klasörlere bağlanmak için kullanılan yollar. Yerel makinenin C$'sine bağlanmayı denemelisiniz ("\\\127.0.0.1\c$\Windows\System32")
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

## Tarayıcıdan Dosya Sistemine Erişim

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

* Yapışkan Tuşlar – SHIFT tuşuna 5 kez basın
* Fare Tuşları – SHIFT+ALT+NUMLOCK
* Yüksek Kontrast – SHIFT+ALT+PRINTSCN
* Tuşları Değiştir – NUMLOCK'u 5 saniye basılı tutun
* Filtre Tuşları – Sağ SHIFT tuşunu 12 saniye basılı tutun
* WINDOWS+F1 – Windows Arama
* WINDOWS+D – Masaüstünü Göster
* WINDOWS+E – Windows Gezgini'ni Başlat
* WINDOWS+R – Çalıştır
* WINDOWS+U – Kolay Erişim Merkezi
* WINDOWS+F – Arama
* SHIFT+F10 – İçerik Menüsü
* CTRL+SHIFT+ESC – Görev Yöneticisi
* CTRL+ALT+DEL – Yeni Windows sürümlerinde açılış ekranı
* F1 – Yardım F3 – Arama
* F6 – Adres Çubuğu
* F11 – İnternet Explorer içinde tam ekranı açma/kapatma
* CTRL+H – İnternet Explorer Geçmişi
* CTRL+T – İnternet Explorer – Yeni Sekme
* CTRL+N – İnternet Explorer – Yeni Sayfa
* CTRL+O – Dosya Aç
* CTRL+S – Kaydet CTRL+N – Yeni RDP / Citrix
## Kaydırma İşlemleri

* Tüm açık Pencereleri görmek, KIOSK uygulamasını küçültmek ve doğrudan işletim sistemine erişmek için sol taraftan sağa doğru kaydırın;
* Eylem Merkezini açmak, KIOSK uygulamasını küçültmek ve doğrudan işletim sistemine erişmek için sağ taraftan sola doğru kaydırın;
* Tam ekran modunda açılan bir uygulama için başlık çubuğunu görünür yapmak için üst kenardan içeri kaydırın;
* Tam ekran bir uygulamada görev çubuğunu göstermek için alttan yukarı kaydırın.

## Internet Explorer İpuçları

### 'Resim Araç Çubuğu'

Tıklanan bir resmin sol üst köşesinde görünen bir araç çubuğudur. Kaydetme, Yazdırma, Mailto, "Resimlerim"i Gezgin'de Açma işlemlerini yapabilirsiniz. Kiosk, Internet Explorer kullanıyor olmalıdır.

### Shell Protokolü

Aşağıdaki URL'leri kullanarak bir Gezgin görünümü elde edin:

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

# Tarayıcı İpuçları

iKat sürümlerini yedekleyin:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\

JavaScript kullanarak ortak bir iletişim kutusu oluşturun ve dosya gezginine erişin: `document.write('<input/type=file>')`
Kaynak: https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

# iPad

## Jestler ve Düğmeler

* Dört (veya beş) parmakla yukarı kaydırma / Ana düğmeye çift dokunma: Çoklu görev görünümünü görüntülemek ve Uygulama değiştirmek için

* Dört veya beş parmakla bir yöne kaydırma: Bir sonraki/önceki Uygulamaya geçmek için

* Beş parmakla ekrana yakınlaştırma / Ana düğmeye dokunma / Ekrana hızlı bir hareketle aşağıdan yukarıya doğru bir parmakla kaydırma: Ana ekrana erişmek için

* Bir parmakla ekranın altından yavaşça 1-2 inç yukarı kaydırma: Dock görünecektir

* Bir parmakla ekranın üstünden aşağı doğru kaydırma: Bildirimlerinizi görüntülemek için

* Bir parmakla ekranın sağ üst köşesinden aşağı doğru kaydırma: iPad Pro'nun kontrol merkezini görmek için

* Ekranın solundan bir parmakla 1-2 inç kaydırma: Bugünkü görünümü görmek için

* Ekranın merkezinden hızlı bir şekilde sağa veya sola bir parmakla basılı tutma: Bir sonraki/önceki Uygulamaya geçmek için

* Üst sağ köşedeki On/Off/Uyku düğmesini üstteki sağ köşede basılı tutun + **iPad +** Kaydırarak **kapat** kaydırıcısını tamamen sağa doğru hareket ettirin: Kapatmak için

* Üst sağ köşedeki On/Off/Uyku düğmesini üstteki sağ köşede basılı tutun ve Ana düğmesine birkaç saniye basılı tutun: Zorla kapatma yapmak için

* Üst sağ köşedeki On/Off/Uyku düğmesini üstteki sağ köşede basılı tutun ve Ana düğmesine hızlıca basın: Ekranda sol alt köşede belirecek bir ekran görüntüsü almak için. Her iki düğmeyi de aynı anda çok kısa süreli basın, birkaç saniye basılı tutarsanız zorla kapatma yapılır.

## Kısayollar

Bir iPad klavyesine veya USB klavye adaptörüne sahip olmanız gerekmektedir. Burada, uygulamadan kaçmak için yardımcı olabilecek yalnızca kısayollar gösterilecektir.

| Tuş | İsim         |
| --- | ------------ |
| ⌘   | Komut        |
| ⌥   | Seçenek (Alt)|
| ⇧   | Shift        |
| ↩   | Return       |
| ⇥   | Tab          |
| ^   | Kontrol      |
| ←   | Sol Ok       |
| →   | Sağ Ok       |
| ↑   | Yukarı Ok    |
| ↓   | Aşağı Ok     |

### Sistem kısayolları

Bu kısayollar, iPad'in kullanımına bağlı olarak görsel ayarlar ve ses ayarları için kullanılır.

| Kısayol  | Eylem                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Ekranı Karartma                                                               |
| F2       | Ekranı Parlaklaştırma                                                         |
| F7       | Bir önceki şarkıya dön                                                        |
| F8       | Oynat/Duraklat                                                                |
| F9       | Bir sonraki şarkıya geç                                                       |
| F10      | Sesi Kapat                                                                    |
| F11      | Ses düzeyini azalt                                                            |
| F12      | Ses düzeyini artır                                                            |
| ⌘ Space  | Kullanılabilir dillerin bir listesini görüntüler; birini seçmek için tekrar boşluk çubuğuna dokunun. |

### iPad gezinme

| Kısayol                                           | Eylem                                                  |
| ------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                | Ana Ekrana Git                                         |
| ⌘⇧H (Komut-Shift-H)                              | Ana Ekrana Git                                         |
| ⌘ (Boşluk)                                        | Spotlight'ı Aç                                         |
| ⌘⇥ (Komut-Tab)                                   | Son on kullanılan uygulamaları listeler                  |
| ⌘\~                                               | Son Uygulamaya Git                                    |
| ⌘⇧3 (Komut-Shift-3)                              | Ekran Görüntüsü Al (alt sol köşede kaydetme veya üzerinde işlem yapma) |
| ⌘⇧4                                               | Ekran Görüntüsü Al ve düzenleyicide aç                  |
| ⌘ tuşuna basılı tutun                              | Uygulama için mevcut kısayolların listesi               |
| ⌘⌥D (Komut-Option/Alt-D)                         | Dock'u Göster                                          |
| ^⌥H (Kontrol-Option-H)                            | Ana düğme                                              |
| ^⌥H H (Kontrol-Option-H-H)                        | Çoklu görev çubuğunu göster                            |
| ^⌥I (Kontrol-Option-i)                            | Öğe seçici                                             |
| Escape                                            | Geri düğmesi                                           |
| → (Sağ ok)                                       | Sonraki öğe                                            |
| ← (Sol ok)                                       | Önceki öğe                                             |
| ↑↓ (Yukarı ok, Aşağı ok)                          | Seçili öğeye aynı anda dokunma                         |
| ⌥ ↓ (Seçenek-Aşağı ok)                            | Aşağı kaydırma                                         |
| ⌥↑ (Seçenek-Yukarı ok)                            | Yukarı kaydırma                                        |
| ⌥← veya ⌥→ (Seçenek-Sol ok veya Seçenek-Sağ ok) | Sol veya sağa kaydırma                                 |
| ^⌥S (Kontrol-Option-S)                            | VoiceOver konuşmasını açma veya kapatma                 |
| ⌘
### Safari kısayolları

| Kısayol                 | Eylem                                            |
| ----------------------- | ------------------------------------------------- |
| ⌘L (Command-L)          | Konumu Aç                                        |
| ⌘T                      | Yeni bir sekme aç                                |
| ⌘W                      | Geçerli sekmeyi kapat                            |
| ⌘R                      | Geçerli sekmeyi yenile                           |
| ⌘.                      | Geçerli sekmeyi yüklemeyi durdur                 |
| ^⇥                      | Bir sonraki sekmeye geç                           |
| ^⇧⇥ (Control-Shift-Tab) | Önceki sekmeye geç                               |
| ⌘L                      | Metin girişi/URL alanını seçerek düzenleme yapma |
| ⌘⇧T (Command-Shift-T)   | Son kapatılan sekmeyi aç (birkaç kez kullanılabilir) |
| ⌘\[                     | Tarayıcı geçmişinde bir sayfa geri git           |
| ⌘]                      | Tarayıcı geçmişinde bir sayfa ileri git          |
| ⌘⇧R                     | Okuma Modunu etkinleştir                         |

### Mail kısayolları

| Kısayol                   | Eylem                         |
| -------------------------- | ----------------------------- |
| ⌘L                         | Konumu Aç                     |
| ⌘T                         | Yeni bir sekme aç             |
| ⌘W                         | Geçerli sekmeyi kapat         |
| ⌘R                         | Geçerli sekmeyi yenile        |
| ⌘.                         | Geçerli sekmeyi yüklemeyi durdur |
| ⌘⌥F (Command-Option/Alt-F) | Posta kutunuzda arama yap     |

# Referanslar

* [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
* [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
* [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
* [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)


<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u takip edin.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek** paylaşın.

</details>
