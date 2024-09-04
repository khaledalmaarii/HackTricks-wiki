# Integrity Levels

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Integrity Levels

Windows Vista ve sonraki sürümlerde, tüm korunan öğeler bir **bütünlük seviyesi** etiketi ile gelir. Bu yapı, genellikle dosyalara ve kayıt defteri anahtarlarına "orta" bir bütünlük seviyesi atar, Internet Explorer 7'nin düşük bütünlük seviyesinde yazabileceği belirli klasörler ve dosyalar hariç. Varsayılan davranış, standart kullanıcılar tarafından başlatılan süreçlerin orta bir bütünlük seviyesine sahip olmasıdır, oysa hizmetler genellikle bir sistem bütünlük seviyesinde çalışır. Yüksek bir bütünlük etiketi, kök dizini korur.

Ana kural, nesnelerin, nesnenin seviyesinden daha düşük bir bütünlük seviyesine sahip süreçler tarafından değiştirilemeyeceğidir. Bütünlük seviyeleri şunlardır:

* **Güvenilmez**: Bu seviye, anonim oturum açma ile süreçler içindir. %%%Örnek: Chrome%%%
* **Düşük**: Temelde internet etkileşimleri için, özellikle Internet Explorer'ın Korunan Modu'nda, ilişkili dosyaları ve süreçleri etkileyen ve **Geçici İnternet Klasörü** gibi belirli klasörler için. Düşük bütünlük seviyesine sahip süreçler, kayıt defteri yazma erişimi olmaması ve sınırlı kullanıcı profili yazma erişimi dahil olmak üzere önemli kısıtlamalarla karşılaşır.
* **Orta**: Çoğu etkinlik için varsayılan seviye, standart kullanıcılara ve belirli bir bütünlük seviyesine sahip olmayan nesnelere atanır. Yöneticiler grubunun üyeleri bile varsayılan olarak bu seviyede çalışır.
* **Yüksek**: Yöneticiler için ayrılmıştır, onlara daha düşük bütünlük seviyelerindeki nesneleri değiştirme yetkisi verir, bunlar arasında yüksek seviyedeki nesneler de bulunur.
* **Sistem**: Windows çekirdeği ve temel hizmetler için en yüksek operasyonel seviyedir, yöneticiler için bile erişilemez, kritik sistem işlevlerinin korunmasını sağlar.
* **Yükleyici**: Diğer tüm seviyelerin üzerinde yer alan benzersiz bir seviyedir, bu seviyedeki nesnelerin herhangi bir diğer nesneyi kaldırmasına olanak tanır.

Bir sürecin bütünlük seviyesini **Sysinternals**'dan **Process Explorer** kullanarak alabilirsiniz, sürecin **özelliklerine** erişip "**Güvenlik**" sekmesine bakarak:

![](<../../.gitbook/assets/image (824).png>)

Ayrıca `whoami /groups` komutunu kullanarak **mevcut bütünlük seviyenizi** de alabilirsiniz.

![](<../../.gitbook/assets/image (325).png>)

### Integrity Levels in File-system

Dosya sistemindeki bir nesne, bir **minimum bütünlük seviyesi gereksinimi** gerektirebilir ve bir süreç bu bütünlük seviyesine sahip değilse onunla etkileşimde bulunamaz.\
Örneğin, **standart bir kullanıcı konsolundan bir dosya oluşturalım ve izinleri kontrol edelim**:
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
Şimdi, dosyaya **Yüksek** bir minimum bütünlük seviyesi atayalım. Bu **bir yönetici olarak çalışan bir konsoldan** **yapılmalıdır**, çünkü **normal bir konsol** Orta Bütünlük seviyesinde çalışacak ve bir nesneye Yüksek Bütünlük seviyesi atamasına **izin verilmeyecektir**:
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
Bu noktada işler ilginçleşiyor. `DESKTOP-IDJHTKP\user` kullanıcısının dosya üzerinde **TAM yetkileri** olduğunu görebilirsiniz (aslında bu dosyayı oluşturan kullanıcıydı), ancak uygulanan minimum bütünlük seviyesi nedeniyle, artık dosyayı değiştiremeyecek, yalnızca Yüksek Bütünlük Seviyesi içinde çalışıyorsa (not edin ki dosyayı okuyabilecektir):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
{% hint style="info" %}
**Bu nedenle, bir dosyanın minimum bir bütünlük seviyesi olduğunda, onu değiştirmek için en az o bütünlük seviyesinde çalışıyor olmanız gerekir.**
{% endhint %}

### Binaries'deki Bütünlük Seviyeleri

`cmd.exe` dosyasının bir kopyasını `C:\Windows\System32\cmd-low.exe` konumuna aldım ve ona **bir yönetici konsolundan düşük bir bütünlük seviyesi atadım:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Şimdi, `cmd-low.exe` çalıştırdığımda, **orta bir seviyede** yerine **düşük bir bütünlük seviyesinde** çalışacak:

![](<../../.gitbook/assets/image (313).png>)

Meraklılar için, bir ikili dosyaya yüksek bütünlük seviyesi atarsanız (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), otomatik olarak yüksek bütünlük seviyesinde çalışmayacaktır (orta bütünlük seviyesinden çağırırsanız --varsayılan olarak-- orta bütünlük seviyesinde çalışacaktır).

### Süreçlerde Bütünlük Seviyeleri

Tüm dosya ve klasörlerin minimum bir bütünlük seviyesi yoktur, **ancak tüm süreçler bir bütünlük seviyesinde çalışmaktadır**. Ve dosya sistemiyle olan benzer şekilde, **bir süreç başka bir süreç içinde yazmak istiyorsa en az aynı bütünlük seviyesine sahip olmalıdır**. Bu, düşük bütünlük seviyesine sahip bir sürecin, orta bütünlük seviyesine sahip bir sürece tam erişimle bir tanıtıcı açamayacağı anlamına gelir.

Bu ve önceki bölümde belirtilen kısıtlamalar nedeniyle, güvenlik açısından, her zaman **bir süreci mümkün olan en düşük bütünlük seviyesinde çalıştırmak önerilir**.
