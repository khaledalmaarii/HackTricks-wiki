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

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) **karanlık ağ** tarafından desteklenen bir arama motorudur ve bir şirketin veya müşterilerinin **tehdit altına alınıp alınmadığını** kontrol etmek için **ücretsiz** işlevler sunar.

WhiteIntel'in ana hedefi, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye yazılımı saldırılarıyla mücadele etmektir.

Web sitelerini kontrol edebilir ve motorlarını **ücretsiz** deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

***

## Integrity Levels

Windows Vista ve sonraki sürümlerde, tüm korunan öğeler bir **bütünlük seviyesi** etiketi ile gelir. Bu yapılandırma, belirli klasörler ve Internet Explorer 7'nin düşük bütünlük seviyesinde yazabileceği dosyalar hariç, dosyalara ve kayıt defteri anahtarlarına genellikle "orta" bir bütünlük seviyesi atar. Varsayılan davranış, standart kullanıcılar tarafından başlatılan süreçlerin orta bütünlük seviyesine sahip olmasıdır, oysa hizmetler genellikle sistem bütünlük seviyesinde çalışır. Yüksek bir bütünlük etiketi, kök dizini korur.

Ana kural, nesnelerin, nesnenin seviyesinden daha düşük bir bütünlük seviyesine sahip süreçler tarafından değiştirilemeyeceğidir. Bütünlük seviyeleri şunlardır:

* **Güvenilmez**: Bu seviye, anonim oturum açma ile süreçler içindir. %%%Örnek: Chrome%%%
* **Düşük**: Temelde internet etkileşimleri için, özellikle Internet Explorer'ın Korunan Modu'nda, ilişkili dosyaları ve süreçleri etkileyen ve **Geçici İnternet Klasörü** gibi belirli klasörler için. Düşük bütünlük seviyesine sahip süreçler, kayıt defteri yazma erişimi olmaması ve sınırlı kullanıcı profili yazma erişimi dahil olmak üzere önemli kısıtlamalarla karşılaşır.
* **Orta**: Çoğu etkinlik için varsayılan seviye, standart kullanıcılara ve belirli bir bütünlük seviyesine sahip olmayan nesnelere atanır. Yöneticiler grubunun üyeleri bile varsayılan olarak bu seviyede çalışır.
* **Yüksek**: Yöneticiler için ayrılmıştır, onlara daha düşük bütünlük seviyelerine sahip nesneleri değiştirme yetkisi verir, bunlar arasında yüksek seviyedeki nesneler de bulunur.
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
Şimdi, dosyaya **Yüksek** bir minimum bütünlük seviyesi atayalım. Bu **bir yönetici olarak çalışan bir konsoldan** yapılmalıdır çünkü **normal bir konsol** Orta Bütünlük seviyesinde çalışacak ve bir nesneye Yüksek Bütünlük seviyesi atamasına **izin verilmeyecektir**:
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
Bu noktada işler ilginçleşiyor. `DESKTOP-IDJHTKP\user` kullanıcısının dosya üzerinde **TAM yetkileri** olduğunu görebilirsiniz (aslında dosyayı oluşturan kullanıcı buydu), ancak uygulanan minimum bütünlük seviyesi nedeniyle, artık dosyayı değiştiremeyecek, yalnızca Yüksek Bütünlük Seviyesi içinde çalışıyorsa (okuyabileceğini unutmayın):
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

`cmd.exe` dosyasının bir kopyasını `C:\Windows\System32\cmd-low.exe` konumuna aldım ve bunu bir yönetici konsolundan **düşük bir bütünlük seviyesi olarak ayarladım:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Now, when I run `cmd-low.exe` it will **düşük bütünlük seviyesi altında çalışacak** instead of a medium one:

![](<../../.gitbook/assets/image (313).png>)

For curious people, if you assign high integrity level to a binary (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) it won't run with high integrity level automatically (if you invoke it from a medium integrity level --by default-- it will run under a medium integrity level).

### İşlemlerde Bütünlük Seviyeleri

Not all files and folders have a minimum integrity level, **ama tüm işlemler bir bütünlük seviyesi altında çalışmaktadır**. And similar to what happened with the file-system, **eğer bir işlem başka bir işlem içinde yazmak istiyorsa en az aynı bütünlük seviyesine sahip olmalıdır**. This means that a process with low integrity level can’t open a handle with full access to a process with medium integrity level.

Due to the restrictions commented in this and the previous section, from a security point of view, it's always **düşük bütünlük seviyesinde bir işlemi çalıştırmak önerilir**.

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) is a **dark-web** fueled search engine that offers **ücretsiz** functionalities to check if a company or its customers have been **tehdit altına alınmış** by **stealer malwares**.

Their primary goal of WhiteIntel is to combat account takeovers and ransomware attacks resulting from information-stealing malware.

You can check their website and try their engine for **ücretsiz** at:

{% embed url="https://whiteintel.io" %}

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
