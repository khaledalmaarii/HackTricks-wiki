<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzdaki özel [**NFT'leri**](https://opensea.io/collection/the-peass-family) keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek** katkıda bulunun.

</details>


# Bütünlük Seviyeleri

Windows Vista ve sonraki sürümlerde, tüm korunan öğelerin bir **bütünlük seviyesi** etiketi bulunur. Bu yapı, genellikle dosya ve kayıt defteri anahtarlarına "orta" bütünlük seviyesi atar, ancak Internet Explorer 7'nin düşük bütünlük seviyesinde yazabileceği belirli klasörler ve dosyalar hariç. Varsayılan davranış, standart kullanıcılar tarafından başlatılan işlemlerin orta bütünlük seviyesine sahip olmasıdır, hizmetler genellikle sistem bütünlük seviyesinde çalışır. Yüksek bütünlük etiketi kök dizini korur.

Bir kural, nesnelerin, nesnenin seviyesinden daha düşük bir bütünlük seviyesine sahip işlemler tarafından değiştirilemeyeceğidir. Bütünlük seviyeleri şunlardır:

- **Güvenilmeyen**: Bu seviye, anonim oturum açmalara sahip işlemler içindir. %%%Örnek: Chrome%%%
- **Düşük**: Genellikle internet etkileşimleri için, özellikle Internet Explorer'ın Koruma Modu'nda, ilişkili dosyaları ve işlemleri etkiler ve **Geçici İnternet Klasörü** gibi belirli klasörleri etkiler. Düşük bütünlük işlemleri, kayıt defteri yazma erişimi olmaması ve sınırlı kullanıcı profil yazma erişimi dahil olmak üzere önemli kısıtlamalara tabidir.
- **Orta**: Çoğu etkinlik için varsayılan seviye, standart kullanıcılara ve belirli bütünlük seviyelerine sahip olmayan nesnelere atanır. Yöneticiler grubunun üyeleri bile varsayılan olarak bu seviyede çalışır.
- **Yüksek**: Yöneticilere ayrılmış, yüksek bütünlük seviyesindeki nesneleri de dahil olmak üzere daha düşük bütünlük seviyelerindeki nesneleri değiştirmelerine izin verir.
- **Sistem**: Windows çekirdeği ve temel hizmetler için en yüksek işletim seviyesi, hatta yöneticiler için bile erişilemez, önemli sistem işlevlerinin korunmasını sağlar.
- **Yükleyici**: Diğer tüm seviyelerin üzerinde duran benzersiz bir seviye, bu seviyedeki nesnelerin diğer herhangi bir nesneyi kaldırmasına izin verir.

Bir işlemin bütünlük seviyesini **Sysinternals**'den **Process Explorer** kullanarak, işlemin **özelliklerine** erişerek ve "**Güvenlik**" sekmesini görüntüleyerek alabilirsiniz:

![](<../../.gitbook/assets/image (318).png>)

Ayrıca, **mevcut bütünlük seviyenizi** `whoami /groups` kullanarak alabilirsiniz.

![](<../../.gitbook/assets/image (319).png>)

## Dosya Sisteminde Bütünlük Seviyeleri

Dosya sistemi içindeki bir nesne, bir **minimum bütünlük seviyesi gereksinimi** olabilir ve bir işlem bu bütünlük seviyesine sahip değilse onunla etkileşime geçemez.\
Örneğin, bir düzenli kullanıcı konsolundan bir düzenli dosya oluşturup izinleri kontrol edelim:
```
echo asd >asd.txt
icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
```
Şimdi, dosyaya **Yüksek** bir minimum bütünlük seviyesi atayalım. Bu işlem, bir **yönetici olarak çalışan bir konsoldan** yapılmalıdır çünkü **normal bir konsol**, Orta Bütünlük seviyesinde çalıştığı için bir nesneye Yüksek Bütünlük seviyesi atamaya **izin verilmeyecektir**:
```
icacls asd.txt /setintegritylevel(oi)(ci) High
processed file: asd.txt
Successfully processed 1 files; Failed processing 0 files

C:\Users\Public>icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
Mandatory Label\High Mandatory Level:(NW)
```
İşler burada ilginç hale geliyor. Dosyanın üzerinde **TAM yetkilere** sahip olan `DESKTOP-IDJHTKP\user` kullanıcısını görebilirsiniz (aslında bu dosyayı oluşturan kullanıcıdır), ancak uygulanan minimum bütünlük seviyesi nedeniyle dosyayı değiştiremez, yalnızca yüksek bütünlük seviyesinde çalışıyorsa okuyabilir:
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
{% hint style="info" %}
**Bu nedenle, bir dosyanın minimum bütünlük seviyesine sahip olması durumunda, onu değiştirmek için en az o bütünlük seviyesinde çalışmanız gerekmektedir.**
{% endhint %}

## İşletim Sistemlerinde Bütünlük Seviyeleri

`cmd.exe` dosyasının bir kopyasını `C:\Windows\System32\cmd-low.exe` olarak oluşturdum ve **bir yönetici konsolundan düşük bütünlük seviyesine ayarladım:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Şimdi, `cmd-low.exe`'yi çalıştırdığımda, **orta seviye yerine düşük bütünlük seviyesinde çalışacak**:

![](<../../.gitbook/assets/image (320).png>)

Meraklı insanlar için, bir ikiliye yüksek bütünlük seviyesi atarsanız (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), otomatik olarak yüksek bütünlük seviyesinde çalışmaz (varsayılan olarak orta bütünlük seviyesinden çağrılırsa, orta bütünlük seviyesinde çalışır).

## İşlemlerde Bütünlük Seviyeleri

Tüm dosya ve klasörlerin bir minimum bütünlük seviyesi olmayabilir, **ancak tüm işlemler bir bütünlük seviyesi altında çalışır**. Ve dosya sistemiyle olan benzer şekilde, **bir işlem başka bir işleme içeriden yazmak istiyorsa en az aynı bütünlük seviyesine sahip olmalıdır**. Bu, düşük bütünlük seviyesine sahip bir işlemin, orta bütünlük seviyesine sahip bir işleme tam erişimle bir tutamak açamayacağı anlamına gelir.

Bu ve önceki bölümde bahsedilen kısıtlamalar nedeniyle, güvenlik açısından her zaman **bir işlemi mümkün olan en düşük bütünlük seviyesinde çalıştırmak önerilir**.


<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı yapmak veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi HackTricks ve HackTricks Cloud** github depolarına **PR göndererek paylaşın**.

</details>
