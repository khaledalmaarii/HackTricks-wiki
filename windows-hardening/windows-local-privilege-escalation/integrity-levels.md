# Bütünlük Seviyeleri

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramana öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na(https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io), **karanlık ağ** destekli bir arama motorudur ve şirketin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **kompromize edilip edilmediğini** kontrol etmek için **ücretsiz** işlevler sunar.

WhiteIntel'in başlıca amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye yazılımı saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve motorlarını **ücretsiz** deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

***

## Bütünlük Seviyeleri

Windows Vista ve sonraki sürümlerde, tüm korunan öğeler bir **bütünlük seviyesi** etiketi ile gelir. Bu yapı genellikle dosya ve kayıt defteri anahtarlarına "orta" bütünlük seviyesi atar, ancak Internet Explorer 7'nin düşük bütünlük seviyesinde yazabileceği belirli klasörler ve dosyalar hariç. Standart kullanıcılar tarafından başlatılan işlemlerin varsayılan davranışı orta bütünlük seviyesine sahip olmalarıdır, hizmetler genellikle sistem bütünlük seviyesinde çalışır. Yüksek bütünlük etiketi kök dizini korur.

Bir ana kural, nesnelerin, nesnenin seviyesinden daha düşük bir bütünlük seviyesine sahip işlemler tarafından değiştirilemeyeceğidir. Bütünlük seviyeleri şunlardır:

* **Güvenilmeyen**: Bu seviye, anonim girişlerle işlem yapan işlemler içindir. %%%Örnek: Chrome%%%
* **Düşük**: Genellikle internet etkileşimleri için, özellikle Internet Explorer'ın Korunan Modu'nda, ilişkili dosyaları ve işlemleri etkiler ve **Geçici İnternet Klasörü** gibi belirli klasörler. Düşük bütünlük işlemleri, kayıt defteri yazma erişimi olmaksızın ve sınırlı kullanıcı profil yazma erişimi ile karşı karşıya kalır.
* **Orta**: Çoğu etkinlik için varsayılan seviye, standart kullanıcılara ve belirli bütünlük seviyeleri olmayan nesnelere atanır. Yöneticiler grubunun üyeleri bile varsayılan olarak bu seviyede çalışır.
* **Yüksek**: Yöneticiler için ayrılmış, onlara yüksek bütünlük seviyesindeki nesneleri, yüksek seviyedeki nesneleri de dahil olmak üzere daha düşük bütünlük seviyelerinde değiştirmelerine izin verir.
* **Sistem**: Windows çekirdeği ve temel hizmetler için en yüksek işletim seviyesi, hatta yöneticiler için bile ulaşılamaz, önemli sistem işlevlerinin korunmasını sağlar.
* **Yükleyici**: Diğer tüm seviyelerin üzerinde duran benzersiz bir seviye, bu seviyedeki nesnelerin herhangi bir diğer nesneyi kaldırmasına izin verir.

Bir işlemin bütünlük seviyesini **Sysinternals**'den **Process Explorer** kullanarak, işlemin **özelliklerine** erişerek ve "**Güvenlik**" sekmesini görüntüleyerek alabilirsiniz:

![](<../../.gitbook/assets/image (824).png>)

Ayrıca `whoami /groups` kullanarak **mevcut bütünlük seviyenizi** alabilirsiniz.

![](<../../.gitbook/assets/image (325).png>)

### Dosya Sisteminde Bütünlük Seviyeleri

Dosya sistemi içindeki bir nesne, bir **minimum bütünlük seviyesi gereksinimi** olabilir ve bir işlem bu bütünlük seviyesine sahip değilse etkileşimde bulunamaz.\
Örneğin, bir düzenli kullanıcı konsolundan bir dosya oluşturup izinleri kontrol edelim:
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
Şimdi, dosyaya en azından **Yüksek** bütünlük seviyesi atayalım. Bu işlem **yönetici olarak çalışan bir konsoldan yapılmalıdır**, çünkü **normal bir konsol** Orta Bütünlük seviyesinde çalışıyor olacak ve bir nesneye Yüksek Bütünlük seviyesi atamaya **izin verilmeyecektir**:
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
Bu noktada işler ilginç bir hal alıyor. Dosyanın üzerinde **TAM ayrıcalıklara** sahip olduğunu görebilirsiniz (`DESKTOP-IDJHTKP\user` kullanıcısı gerçekten dosyayı oluşturan kullanıcıydı), ancak uygulanan minimum bütünlük seviyesi nedeniyle artık dosyayı değiştiremeyecek, yalnızca Yüksek Bütünlük Seviyesi içinde çalıştığında (not olarak dosyayı okuyabileceğini belirtmek gerekir):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
{% hint style="info" %}
**Bu nedenle, bir dosyanın minimum bütünlük seviyesine sahip olması durumunda, onu değiştirmek için en az o bütünlük seviyesinde çalışıyor olmanız gerekir.**
{% endhint %}

### İkili Dosyalardaki Bütünlük Seviyeleri

`cmd.exe` dosyasının bir kopyasını `C:\Windows\System32\cmd-low.exe` konumuna oluşturdum ve **bir yönetici konsolundan buna düşük bir bütünlük seviyesi atadım:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Şimdi, `cmd-low.exe`'yi çalıştırdığımda **düşük bütünlük seviyesi altında çalışacak**:

![](<../../.gitbook/assets/image (313).png>)

Meraklı insanlar için, bir ikili dosyaya yüksek bütünlük seviyesi atarsanız (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), otomatik olarak yüksek bütünlük seviyesinde çalışmaz (varsayılan olarak orta bütünlük seviyesinden çağrılırsa orta bütünlük seviyesinde çalışır).

### İşlemlerde Bütünlük Seviyeleri

Tüm dosya ve klasörlerin minimum bütünlük seviyesine sahip olmadığını, **ancak tüm işlemlerin bir bütünlük seviyesi altında çalıştığını** belirtmek gerekir. Dosya sisteminde olduğu gibi, **bir işlemin başka bir işlemin içine yazmak istemesi durumunda en az aynı bütünlük seviyesine sahip olması gerekir**. Bu, düşük bütünlük seviyesine sahip bir işlemin, orta bütünlük seviyesine sahip bir işleme tam erişim sağlayan bir tutamaç açamayacağı anlamına gelir.

Bu ve önceki bölümlerde belirtilen kısıtlamalar nedeniyle, güvenlik açısından her zaman **bir işlemi mümkün olan en düşük bütünlük seviyesinde çalıştırmanız önerilir**.

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io), **karanlık ağ** destekli bir arama motorudur ve şirketin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **tehlikeye atılıp atılmadığını** kontrol etmek için **ücretsiz** işlevler sunar.

WhiteIntel'in başlıca amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye yazılımı saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve **ücretsiz** olarak motorlarını deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [Discord grubuna](https://discord.gg/hRep4RUj7f) veya [telegram grubuna](https://t.me/peass) katılın veya** bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks ve HackTricks Cloud github depolarına PR'lar göndererek paylaşın.**

</details>
