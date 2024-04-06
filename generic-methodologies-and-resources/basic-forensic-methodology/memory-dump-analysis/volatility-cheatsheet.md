# Volatility - CheatSheet

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** isterseniz, [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimizden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/), **İspanya**'daki en önemli siber güvenlik etkinliği ve **Avrupa**'daki en önemli etkinliklerden biridir. **Teknik bilginin yayılmasını amaçlayan** bu kongre, her disiplindeki teknoloji ve siber güvenlik profesyonelleri için kaynayan bir buluşma noktasıdır.

{% embed url="https://www.rootedcon.com/" %}

Eğer **hızlı ve çılgınca** bir şey istiyorsanız, birkaç Volatility eklentisini paralel olarak çalıştıracak olan şunu kullanabilirsiniz: [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)

```bash
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -e /home/user/tools/volatility/vol.py # It will use the most important plugins (could use a lot of space depending on the size of the memory)
```

## Kurulum

### volatility3

```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 setup.py install
python3 vol.py —h
```

#### Yöntem 1: Volatility2

Volatility2, bir bellek görüntüsü analiz aracıdır. Aşağıda, Volatility2'nin bazı temel komutlarını ve kullanımlarını bulabilirsiniz:

* **imageinfo**: Bellek görüntüsü hakkında genel bilgileri almak için kullanılır.
* **pslist**: Bellekte çalışan işlemleri listeler.
* **pstree**: İşlem ağacını gösterir.
* **dlllist**: İşlem tarafından yüklenen DLL'leri listeler.
* **handles**: İşlem tarafından kullanılan açık tutulan dosya ve kaynakları listeler.
* **filescan**: Bellekteki dosyaları taramak için kullanılır.
* **malfind**: Potansiyel kötü amaçlı yazılım işaretlerini tespit etmek için kullanılır.
* **cmdscan**: Bellekteki komut istemlerini taramak için kullanılır.
* **netscan**: Ağ bağlantılarını taramak için kullanılır.
* **connections**: Ağ bağlantılarını listeler.
* **dumpfiles**: Bellekteki dosyaları çıkarmak için kullanılır.
* **memdump**: Bellek görüntüsünü çıkarmak için kullanılır.

Volatility2'nin daha fazla komutu ve kullanımı hakkında daha fazla bilgi için, lütfen Volatility2 belgelerine başvurun.

```
Download the executable from https://www.volatilityfoundation.org/26
```

```bash
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python setup.py install
```

## Volatility Komutları

Resmi belgelere [Volatility komut referansı](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan) üzerinden erişebilirsiniz.

### "list" ve "scan" eklentileri hakkında bir not

Volatility'nin iki ana eklenti yaklaşımı vardır ve bazen isimlerinde yansıtılır. "list" eklentileri, Windows Kernel yapıları aracılığıyla işlemler gibi bilgileri almak için gezinmeye çalışır (bellekteki `_EPROCESS` yapılarının bağlantılı listesini bulma ve takip etme), işletim sistemi kollarını (kolları bulma ve listeleme, bulunan herhangi bir işaretçiyi çözme vb.). Onlar, örneğin, işlemleri listelemek istendiğinde Windows API'nin yapacağı gibi davranır.

Bu, "list" eklentilerini oldukça hızlı yapar, ancak kötü amaçlı yazılımlar tarafından Windows API'sine benzer şekilde manipüle edilebilir hale getirir. Örneğin, kötü amaçlı yazılım, bir işlemi `_EPROCESS` bağlantılı listesinden ayırmak için DKOM kullanıyorsa, bu işlem Görev Yöneticisinde görünmeyecek ve pslist'te de görünmeyecektir.

Öte yandan, "scan" eklentileri, bellekte belirli yapılar olarak çözümlendiğinde anlam ifade edebilecek şeyleri aramak için belleği kesmek gibi bir yaklaşım benimser. Örneğin, `psscan`, belleği okur ve ondan `_EPROCESS` nesneleri yapmaya çalışır (ilgi duyulan bir yapının varlığını gösteren 4 baytlık dizeleri arayan havuz etiketi taraması kullanır). Avantajı, çıkmış olan işlemleri ortaya çıkarabilmesi ve kötü amaçlı yazılımın `_EPROCESS` bağlantılı listeyi değiştirse bile, eklenti hala bellekteki yapının etrafta durduğunu bulacaktır (çünkü işlemin çalışması için hala var olması gerekmektedir). Dezavantajı ise "scan" eklentilerinin "list" eklentilerinden biraz daha yavaş olması ve bazen yanlış pozitif sonuçlar verebilmesidir (çok uzun süre önce çıkmış bir işlem ve yapısının diğer işlemler tarafından üzerine yazılması).

Kaynak: [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

## İşletim Sistemi Profilleri

### Volatility3

Readme içinde açıklandığı gibi, desteklemek istediğiniz **işletim sisteminin sembol tablosunu** _volatility3/volatility/symbols_ klasörüne koymalısınız.\
Çeşitli işletim sistemleri için sembol tablo paketleri **indirilebilir** durumdadır:

* [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### Harici Profil

Desteklenen profil listesini almak için aşağıdaki komutu kullanabilirsiniz:

```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```

Eğer **indirdiğiniz yeni bir profil** kullanmak istiyorsanız (örneğin bir linux profil), aşağıdaki klasör yapısını oluşturmanız gerekmektedir: _plugins/overlays/linux_. Ardından, bu klasörün içine profilin bulunduğu zip dosyasını yerleştirin. Sonra, aşağıdaki komutu kullanarak profil sayısını alın:

```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```

Linux ve Mac profillerini [https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles) adresinden indirebilirsiniz.

Önceki bölümde profilin adının `LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64` olduğunu görebilirsiniz ve bunu aşağıdaki gibi kullanabilirsiniz:

```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```

#### Profil Keşfi

```plaintext
volatility -f <memory_dump> imageinfo
```

Bu komut, bellek dökümü dosyasının özelliklerini keşfetmek için kullanılır.

```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```

#### **imageinfo ve kdbgscan arasındaki farklar**

[**Buradan**](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/) alıntılanmıştır: Imageinfo'nun sadece profil önerileri sağladığına karşılık, **kdbgscan**, doğru profili ve doğru KDBG adresini (birden fazla varsa) pozitif olarak tanımlamak için tasarlanmıştır. Bu eklenti, Volatility profillerine bağlı KDBGHeader imzalarını tarar ve yanlış pozitifleri azaltmak için sağlamlık kontrolleri uygular. Çıktının ayrıntısı ve yapılabilen sağlamlık kontrollerinin sayısı, Volatility'nin bir DTB bulup bulamadığına bağlıdır, bu nedenle doğru profili zaten biliyorsanız (veya imageinfo'dan bir profil önerisi varsa), onu kullanmaktan emin olun.

Her zaman **kdbgscan'ın bulduğu işlem sayısına** bakın. Bazen imageinfo ve kdbgscan, birden fazla uygun profil bulabilir, ancak sadece **geçerli olanın bazı işlemle ilgili bilgilere** sahip olacağını unutmayın (Bu, işlemleri çıkarmak için doğru KDBG adresinin gerekliliğinden kaynaklanır).

```bash
# GOOD
PsActiveProcessHead           : 0xfffff800011977f0 (37 processes)
PsLoadedModuleList            : 0xfffff8000119aae0 (116 modules)
```

```bash
# BAD
PsActiveProcessHead           : 0xfffff800011947f0 (0 processes)
PsLoadedModuleList            : 0xfffff80001197ac0 (0 modules)
```

#### KDBG

**Kernel hata ayıklama bloğu** veya Volatility tarafından **KDBG** olarak adlandırılan, Volatility ve çeşitli hata ayıklama araçları tarafından gerçekleştirilen adli görevler için önemlidir. `_KDDEBUGGER_DATA64` türünde olan ve `KdDebuggerDataBlock` olarak tanımlanan bu blok, `PsActiveProcessHead` gibi temel referansları içerir. Bu özel referans, işlem listesinin başını işaret eder ve kapsamlı bellek analizi için temel bir adım olan tüm işlemlerin listelenmesini sağlar.

## İşletim Sistemi Bilgileri

```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```

`banners.Banners` eklentisi, dökümanda Linux banner'larını bulmak için **vol3** içinde kullanılabilir.

## Hash'ler/Parolalar

SAM hash'lerini, [önbelleğe alınmış kimlik bilgilerini](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials) ve [lsa sırlarını](../../../windows-hardening/authentication-credentials-uac-and-efs/#lsa-secrets) çıkarın.

{% tabs %}
{% tab title="undefined" %}
```bash
./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 hashdump -f file.dmp #Grab common windows hashes (SAM+SYSTEM)
volatility --profile=Win7SP1x86_23418 cachedump -f file.dmp #Grab domain cache hashes inside the registry
volatility --profile=Win7SP1x86_23418 lsadump -f file.dmp #Grab lsa secrets
```
{% endtab %}
{% endtabs %}

## Bellek Dökümü

Bir işlemin bellek dökümü, işlemin mevcut durumunun **her şeyini çıkarır**. **procdump** modülü sadece **kodu çıkarır**.

```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) İspanya'daki en önemli siber güvenlik etkinliklerinden biridir ve Avrupa'da da en önemlilerden biridir. Teknik bilginin yayılmasını amaçlayan bu kongre, her disiplindeki teknoloji ve siber güvenlik profesyonelleri için kaynayan bir buluşma noktasıdır.

{% embed url="https://www.rootedcon.com/" %}

## İşlemler

### İşlemleri Listele

**Şüpheli** işlemleri (isimleriyle) veya **beklenmedik** alt **işlemleri** (örneğin iexplorer.exe'nin bir çocuğu olarak cmd.exe) bulmaya çalışın.\
Gizli işlemleri belirlemek için pslist'in sonucunu psscan'in sonucuyla karşılaştırmak ilginç olabilir.

{% tabs %}
{% tab title="undefined" %}
```bash
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```
{% endtab %}
{% endtabs %}

### Dump proc

{% tabs %}
{% tab title="vol3" %}
Bu komut, belirli bir sürecin bellek görüntüsünü almanıza olanak tanır. Aşağıdaki parametreleri kullanabilirsiniz:

* `-p, --pid=<pid>`: Sürecin kimlik numarasını belirtir.
* `-D, --dump-dir=<directory>`: Bellek görüntüsünün kaydedileceği dizini belirtir.
* `--name=<name>`: Sürecin adını belirtir.
* `--offset=<offset>`: Sürecin bellek görüntüsünün başlangıç ofsetini belirtir.
* `--length=<length>`: Sürecin bellek görüntüsünün uzunluğunu belirtir.

Örnek kullanım:

```bash
volatility -f memory_dump.mem --profile=Win7SP1x64 dumpfiles -Q 0x0000000001e4e060 -D dump_dir/
```

Bu komut, `memory_dump.mem` adlı bellek görüntüsünden `0x0000000001e4e060` ofsetindeki sürecin bellek görüntüsünü `dump_dir/` dizinine kaydeder.
{% endtab %}
{% endtabs %}

```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
```

```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```

### Komut satırı

Şüpheli bir şeyler çalıştırıldı mı?

```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```

```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```

`cmd.exe`'de çalıştırılan komutlar **`conhost.exe`** tarafından yönetilir (veya Windows 7'den önceki sistemlerde `csrss.exe` tarafından yönetilir). Bu, bir bellek dökümü elde edilmeden önce saldırgan tarafından **`cmd.exe`** sonlandırılırsa, oturumun komut geçmişinin hala **`conhost.exe`** belleğinden kurtarılabilir olduğu anlamına gelir. Bunun için, konsol modüllerindeki olağandışı aktivite tespit edilirse, ilişkili **`conhost.exe`** işleminin belleği dökülmelidir. Ardından, bu döküm içinde **dizeleri** arayarak, oturumda kullanılan komut satırları potansiyel olarak çıkarılabilir.

### Ortam

Her çalışan işlemin ortam değişkenlerini alın. İlginç değerler olabilir.

```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
```

```bash
volatility --profile=PROFILE envars -f file.dmp [--pid <pid>] #Display process environment variables

volatility --profile=PROFILE -f file.dmp linux_psenv [-p <pid>] #Get env of process. runlevel var means the runlevel where the proc is initated
```

### Token ayrıcalıkları

Beklenmeyen hizmetlerde ayrıcalıklı tokenları kontrol edin.\
Bazı ayrıcalıklı tokenları kullanan işlemleri listelemek ilginç olabilir.

{% tabs %}
{% tab title="undefined" %}
```bash
#Get enabled privileges of some processes
python3 vol.py -f file.dmp windows.privileges.Privs [--pid <pid>]
#Get all processes with interesting privileges
python3 vol.py -f file.dmp windows.privileges.Privs | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{% endtab %}

{% tab title="vol2" %}
```bash
#Get enabled privileges of some processes
volatility --profile=Win7SP1x86_23418 privs --pid=3152 -f file.dmp | grep Enabled
#Get all processes with interesting privileges
volatility --profile=Win7SP1x86_23418 privs -f file.dmp | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{% endtab %}
{% endtabs %}

### SIDs

Her bir işlem tarafından sahip olunan SSID'leri kontrol edin.\
Bir ayrıcalık SSID'sini kullanan işlemleri (ve bazı hizmet SSID'sini kullanan işlemleri) listelemek ilginç olabilir.

```bash
./vol.py -f file.dmp windows.getsids.GetSIDs [--pid <pid>] #Get SIDs of processes
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```

```bash
volatility --profile=Win7SP1x86_23418 getsids -f file.dmp #Get the SID owned by each process
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp #Get the SID of each service
```

### Tutamaçlar

Bir işlemin hangi diğer dosyalara, anahtarlara, iş parçacıklarına, işlemlere... bir **tutamağı olduğunu** (açılmış olduğunu) bilmek için kullanışlıdır.

{% tabs %}
{% tab title="undefined" %}
```bash
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp handles [--pid=<pid>]
```
{% endtab %}
{% endtabs %}

### DLL'ler

{% tabs %}
{% tab title="undefined" %}
```bash
./vol.py -f file.dmp windows.dlllist.DllList [--pid <pid>] #List dlls used by each
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory process
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 dlllist --pid=3152 -f file.dmp #Get dlls of a proc
volatility --profile=Win7SP1x86_23418 dlldump --pid=3152 --dump-dir=. -f file.dmp #Dump dlls of a proc
```
{% endtab %}
{% endtabs %}

### Süreçlere Göre Dizeler

Volatility, bir dizenin hangi sürece ait olduğunu kontrol etmemizi sağlar.

{% tabs %}
{% tab title="undefined" %}
```bash
strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --strings-file /tmp/strings.txt
```
{% endtab %}

{% tab title="vol2" %}
```bash
strings file.dmp > /tmp/strings.txt
volatility -f /tmp/file.dmp windows.strings.Strings --string-file /tmp/strings.txt

volatility -f /tmp/file.dmp --profile=Win81U1x64 memdump -p 3532 --dump-dir .
strings 3532.dmp > strings_file
```
{% endtab %}
{% endtabs %}

Ayrıca, yarascan modülünü kullanarak bir işlem içinde dize araması yapmanıza da olanak sağlar:

{% tabs %}
{% tab title="undefined" %}
```bash
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```
{% endtab %}
{% endtabs %}

### UserAssist

**Windows**, **UserAssist** anahtarları adı verilen bir kayıt defteri özelliğini kullanarak çalıştırdığınız programları takip eder. Bu anahtarlar, her programın kaç kez çalıştırıldığını ve en son ne zaman çalıştırıldığını kaydeder.

```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```

```
volatility --profile=Win7SP1x86_23418 -f file.dmp userassist
```

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​[**RootedCON**](https://www.rootedcon.com/) İspanya'daki en önemli siber güvenlik etkinliklerinden biridir ve Avrupa'da da en önemlilerden biridir. Teknik bilginin yayılmasını amaçlayan bu kongre, her disiplindeki teknoloji ve siber güvenlik profesyonelleri için kaynayan bir buluşma noktasıdır.

{% embed url="https://www.rootedcon.com/" %}

## Hizmetler

{% tabs %}
{% tab title="undefined" %}
```bash
./vol.py -f file.dmp windows.svcscan.SvcScan #List services
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% endtab %}

{% tab title="undefined" %}
```bash
#Get services and binary path
volatility --profile=Win7SP1x86_23418 svcscan -f file.dmp
#Get name of the services and SID (slow)
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp
```
{% endtab %}

{% tab title="undefined" %}
### Ağ
{% endtab %}

{% tab title="undefined" %}
{% tabs %}
{% tab title="undefined" %}
```bash
./vol.py -f file.dmp windows.netscan.NetScan
#For network info of linux use volatility2
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 netscan -f file.dmp
volatility --profile=Win7SP1x86_23418 connections -f file.dmp#XP and 2003 only
volatility --profile=Win7SP1x86_23418 connscan -f file.dmp#TCP connections
volatility --profile=Win7SP1x86_23418 sockscan -f file.dmp#Open sockets
volatility --profile=Win7SP1x86_23418 sockets -f file.dmp#Scanner for tcp socket objects

volatility --profile=SomeLinux -f file.dmp linux_ifconfig
volatility --profile=SomeLinux -f file.dmp linux_netstat
volatility --profile=SomeLinux -f file.dmp linux_netfilter
volatility --profile=SomeLinux -f file.dmp linux_arp #ARP table
volatility --profile=SomeLinux -f file.dmp linux_list_raw #Processes using promiscuous raw sockets (comm between processes)
volatility --profile=SomeLinux -f file.dmp linux_route_cache
```
{% endtab %}
{% endtabs %}
{% endtab %}

{% tab title="undefined" %}
### Kayıt defteri hive
{% endtab %}

{% tab title="undefined" %}
#### Mevcut hiveleri yazdır
{% endtab %}

{% tab title="undefined" %}
{% tabs %}
{% tab title="undefined" %}
```bash
./vol.py -f file.dmp windows.registry.hivelist.HiveList #List roots
./vol.py -f file.dmp windows.registry.printkey.PrintKey #List roots and get initial subkeys
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp hivelist #List roots
volatility --profile=Win7SP1x86_23418 -f file.dmp printkey #List roots and get initial subkeys
```
{% endtab %}
{% endtabs %}
{% endtab %}

{% tab title="undefined" %}
#### Bir değer al
{% endtab %}

{% tab title="undefined" %}
{% tabs %}
{% tab title="undefined" %}
```bash
./vol.py -f file.dmp windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows NT\CurrentVersion"
```
{% endtab %}

{% tab title="undefined" %}
```bash
volatility --profile=Win7SP1x86_23418 printkey -K "Software\Microsoft\Windows NT\CurrentVersion" -f file.dmp
# Get Run binaries registry value
volatility -f file.dmp --profile=Win7SP1x86 printkey -o 0x9670e9d0 -K 'Software\Microsoft\Windows\CurrentVersion\Run'
```
{% endtab %}

{% tab title="undefined" %}
{% tabs %}
{% tab title="Komut" %}
```bash
volatility -f <memory_dump> imageinfo
```
{% endtab %}

{% tab title="Açıklama" %}
Bu komut, bellek dökümü dosyasının bilgilerini görüntüler. Bu bilgiler, bellek dökümünün hangi işletim sistemi ve mimariye ait olduğunu belirlemek için kullanılabilir.
{% endtab %}

{% tab title="Örnek" %}
```bash
volatility -f memdump.raw imageinfo
```
{% endtab %}
{% endtabs %}
{% endtab %}

{% tab title="undefined" %}
```bash
#Dump a hive
volatility --profile=Win7SP1x86_23418 hivedump -o 0x9aad6148 -f file.dmp #Offset extracted by hivelist
#Dump all hives
volatility --profile=Win7SP1x86_23418 hivedump -f file.dmp
```
{% endtab %}

{% tab title="undefined" %}
### Dosya Sistemi
{% endtab %}

{% tab title="undefined" %}
#### Bağlama
{% endtab %}

{% tab title="undefined" %}
{% tabs %}
{% tab title="undefined" %}
```bash
#See vol2
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=SomeLinux -f file.dmp linux_mount
volatility --profile=SomeLinux -f file.dmp linux_recover_filesystem #Dump the entire filesystem (if possible)
```
{% endtab %}
{% endtabs %}
{% endtab %}

{% tab title="undefined" %}
#### Tarama/dump
{% endtab %}

{% tab title="undefined" %}
{% tabs %}
{% tab title="undefined" %}
```bash
./vol.py -f file.dmp windows.filescan.FileScan #Scan for files inside the dump
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --physaddr <0xAAAAA> #Offset from previous command
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 filescan -f file.dmp #Scan for files inside the dump
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -f file.dmp #Dump all files
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -Q 0x000000007dcaa620 -f file.dmp

volatility --profile=SomeLinux -f file.dmp linux_enumerate_files
volatility --profile=SomeLinux -f file.dmp linux_find_file -F /path/to/file
volatility --profile=SomeLinux -f file.dmp linux_find_file -i 0xINODENUMBER -O /path/to/dump/file
```
{% endtab %}
{% endtabs %}
{% endtab %}

{% tab title="undefined" %}
#### Ana Dosya Tablosu
{% endtab %}

{% tab title="undefined" %}
{% tabs %}
{% tab title="undefined" %}
```bash
# I couldn't find any plugin to extract this information in volatility3
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```
{% endtab %}
{% endtabs %}
{% endtab %}

{% tab title="undefined" %}
**NTFS dosya sistemi**, _ana dosya tablosu_ (MFT) olarak bilinen kritik bir bileşen kullanır. Bu tablo, bir birimdeki her dosya için en az bir giriş içerir ve MFT'nin kendisini de kapsar. Her dosya hakkında önemli ayrıntılar, **boyut, zaman damgaları, izinler ve gerçek veriler** gibi, MFT girişlerinin içinde veya bu girişler tarafından referans alınan MFT dışındaki alanlarda kapsüllenmiştir. Daha fazla ayrıntı [resmi belgelerde](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table) bulunabilir.
{% endtab %}

{% tab title="undefined" %}
#### SSL Anahtarları/Sertifikaları
{% endtab %}

{% tab title="undefined" %}
```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
```
{% endtab %}

{% tab title="undefined" %}
```bash
#vol2 allos you to search and dump certificates from memory
#Interesting options for this modules are: --pid, --name, --ssl
volatility --profile=Win7SP1x86_23418 dumpcerts --dump-dir=. -f file.dmp
```
{% endtab %}

{% tab title="undefined" %}
### Zararlı Yazılım
{% endtab %}

{% tab title="undefined" %}
{% tabs %}
{% tab title="undefined" %}
```bash
./vol.py -f file.dmp windows.malfind.Malfind [--dump] #Find hidden and injected code, [dump each suspicious section]
#Malfind will search for suspicious structures related to malware
./vol.py -f file.dmp windows.driverirp.DriverIrp #Driver IRP hook detection
./vol.py -f file.dmp windows.ssdt.SSDT #Check system call address from unexpected addresses

./vol.py -f file.dmp linux.check_afinfo.Check_afinfo #Verifies the operation function pointers of network protocols
./vol.py -f file.dmp linux.check_creds.Check_creds #Checks if any processes are sharing credential structures
./vol.py -f file.dmp linux.check_idt.Check_idt #Checks if the IDT has been altered
./vol.py -f file.dmp linux.check_syscall.Check_syscall #Check system call table for hooks
./vol.py -f file.dmp linux.check_modules.Check_modules #Compares module list to sysfs info, if available
./vol.py -f file.dmp linux.tty_check.tty_check #Checks tty devices for hooks
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp malfind [-D /tmp] #Find hidden and injected code [dump each suspicious section]
volatility --profile=Win7SP1x86_23418 -f file.dmp apihooks #Detect API hooks in process and kernel memory
volatility --profile=Win7SP1x86_23418 -f file.dmp driverirp #Driver IRP hook detection
volatility --profile=Win7SP1x86_23418 -f file.dmp ssdt #Check system call address from unexpected addresses

volatility --profile=SomeLinux -f file.dmp linux_check_afinfo
volatility --profile=SomeLinux -f file.dmp linux_check_creds
volatility --profile=SomeLinux -f file.dmp linux_check_fop
volatility --profile=SomeLinux -f file.dmp linux_check_idt
volatility --profile=SomeLinux -f file.dmp linux_check_syscall
volatility --profile=SomeLinux -f file.dmp linux_check_modules
volatility --profile=SomeLinux -f file.dmp linux_check_tty
volatility --profile=SomeLinux -f file.dmp linux_keyboard_notifiers #Keyloggers
```
{% endtab %}
{% endtabs %}
{% endtab %}

{% tab title="undefined" %}
#### Yara ile tarama
{% endtab %}

{% tab title="undefined" %}
Bu betiği kullanarak github'dan tüm yara kötü amaçlı yazılım kurallarını indirin ve birleştirin: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
_**rules**_ dizinini oluşturun ve betiği çalıştırın. Bu, kötü amaçlı yazılım için tüm yara kurallarını içeren _**malware\_rules.yar**_ adlı bir dosya oluşturacaktır.
{% endtab %}

{% tab title="undefined" %}
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
#Only Windows
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-file /tmp/malware_rules.yar
#All
./vol.py -f file.dmp yarascan.YaraScan --yara-file /tmp/malware_rules.yar
```
{% endtab %}

{% tab title="vol2" %}
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
volatility --profile=Win7SP1x86_23418 yarascan -y malware_rules.yar -f ch2.dmp | grep "Rule:" | grep -v "Str_Win32" | sort | uniq
```
{% endtab %}
{% endtabs %}
{% endtab %}

{% tab title="undefined" %}
### MISC
{% endtab %}

{% tab title="undefined" %}
#### Harici eklentiler
{% endtab %}

{% tab title="undefined" %}
Harici eklentileri kullanmak istiyorsanız, eklentilere ilişkin klasörlerin ilk parametre olarak kullanıldığından emin olun.
{% endtab %}

{% tab title="undefined" %}
```bash
./vol.py --plugin-dirs "/tmp/plugins/" [...]
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatilitye --plugins="/tmp/plugins/" [...]
```
{% endtab %}
{% endtabs %}

#### Autoruns

İndirin: [https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns)

```
volatility --plugins=volatility-autoruns/ --profile=WinXPSP2x86 -f file.dmp autoruns
```

### Mutexler

{% tabs %}
{% tab title="undefined" %}
```
./vol.py -f file.dmp windows.mutantscan.MutantScan
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 mutantscan -f file.dmp
volatility --profile=Win7SP1x86_23418 -f file.dmp handles -p <PID> -t mutant
```
{% endtab %}
{% endtabs %}

### Sembolik Bağlantılar

{% tabs %}
{% tab title="undefined" %}
```bash
./vol.py -f file.dmp windows.symlinkscan.SymlinkScan
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```
{% endtab %}
{% endtabs %}

### Bash

Bellekten bash geçmişini okumak mümkündür. _.bash\_history_ dosyasını da dökümleyebilirsiniz, ancak devre dışı bırakıldıysa bu volatility modülünü kullanabileceğiniz için memnun olacaksınız.

{% tabs %}
{% tab title="undefined" %}
```
./vol.py -f file.dmp linux.bash.Bash
```
{% endtab %}

{% tab title="vol2" %}
```
volatility --profile=Win7SP1x86_23418 -f file.dmp linux_bash
```
{% endtab %}
{% endtabs %}

### Zaman Çizelgesi

{% tabs %}
{% tab title="undefined" %}
```bash
./vol.py -f file.dmp timeLiner.TimeLiner
```
{% endtab %}

{% tab title="vol2" %}
```
volatility --profile=Win7SP1x86_23418 -f timeliner
```
{% endtab %}
{% endtabs %}

### Sürücüler

{% tabs %}
{% tab title="undefined" %}
```
./vol.py -f file.dmp windows.driverscan.DriverScan
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp driverscan
```
{% endtab %}
{% endtabs %}

### Pano al

```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 clipboard -f file.dmp
```

### IE geçmişini al

```bash
volatility -f <memory_dump> --profile=<profile> iehistory
```

Bu komut, bir bellek dökümü dosyasından Internet Explorer (IE) tarayıcısının geçmişini almanıza olanak sağlar. `<memory_dump>` yerine bellek dökümü dosyasının yolunu ve `<profile>` yerine kullanılan profilin adını belirtmelisiniz.

```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 iehistory -f file.dmp
```

### Not Defteri Metnini Al

```bash
volatility -f memory_dump.vmem --profile=PROFILE notepad
```

Bu komut, bir bellek döküm dosyasından not defteri metnini almak için kullanılır. `memory_dump.vmem` bellek döküm dosyasının adını ve `PROFILE` ise analiz edilecek profilin adını temsil eder.

```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 notepad -f file.dmp
```

### Ekran Görüntüsü

```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 screenshot -f file.dmp
```

### Ana Önyükleme Kaydı (MBR)

The Master Boot Record (MBR) is the first sector of a storage device (such as a hard disk) that contains the boot loader and partition table. It plays a crucial role in the boot process of a computer.

Ana Önyükleme Kaydı (MBR), önyükleme yükleyicisini ve bölüm tablosunu içeren bir depolama cihazının (örneğin bir sabit disk) ilk sektörüdür. Bilgisayarın önyükleme sürecinde önemli bir rol oynar.

```bash
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```

**Ana Önyükleme Kaydı (MBR)**, bir depolama ortamının mantıksal bölümlerini yönetmede önemli bir rol oynar. Bu bölümler farklı [dosya sistemleri](https://en.wikipedia.org/wiki/File\_system) ile yapılandırılmıştır. MBR, sadece bölüm düzeni bilgilerini tutmaz, aynı zamanda önyükleme yükleyicisi olarak görev yapan yürütülebilir kodu da içerir. Bu önyükleme yükleyicisi, ya işletim sisteminin ikinci aşama yükleme sürecini doğrudan başlatır (bkz. [ikinci aşama önyükleme yükleyicisi](https://en.wikipedia.org/wiki/Second-stage\_boot\_loader)) ya da her bölümün [hacim önyükleme kaydı](https://en.wikipedia.org/wiki/Volume\_boot\_record) (VBR) ile uyum içinde çalışır. Detaylı bilgi için [MBR Wikipedia sayfasına](https://en.wikipedia.org/wiki/Master\_boot\_record) başvurun.

## Referanslar

* [https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
* [https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
* [https://or10nlabs.tech/cgi-sys/suspendedpage.cgi](https://or10nlabs.tech/cgi-sys/suspendedpage.cgi)
* [https://www.aldeid.com/wiki/Windows-userassist-keys](https://www.aldeid.com/wiki/Windows-userassist-keys) ​\* [https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
* [https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/), **İspanya**'daki en ilgili siber güvenlik etkinliği ve **Avrupa**'nın en önemli etkinliklerinden biridir. Teknik bilginin yayılmasını amaçlayan bu kongre, her disiplindeki teknoloji ve siber güvenlik profesyonelleri için kaynayan bir buluşma noktasıdır.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklam vermek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi Twitter'da 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'ı takip edin.**
* Hacking hilelerinizi göndererek HackTricks ve HackTricks Cloud github depolarına katkıda bulunun.

</details>
