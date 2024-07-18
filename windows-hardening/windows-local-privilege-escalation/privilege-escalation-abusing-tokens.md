# Tokenları Kötüye Kullanma

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter**'da **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

## Tokenlar

Eğer **Windows Erişim Tokenlarının ne olduğunu bilmiyorsanız** devam etmeden önce bu sayfayı okuyun:

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

**Belki de zaten sahip olduğunuz tokenları kötüye kullanarak ayrıcalıkları yükseltebilirsiniz**

### SeImpersonatePrivilege

Bu, herhangi bir tokenın taklit edilmesine (ancak oluşturulmasına değil) izin veren herhangi bir süreç tarafından tutulan bir ayrıcalıktır, yeter ki ona bir referans elde edilebilsin. Ayrıcalıklı bir token, bir Windows hizmetinden (DCOM) bir istismar karşısında NTLM kimlik doğrulaması yapması sağlanarak elde edilebilir ve bu da bir sürecin SYSTEM ayrıcalıklarıyla çalıştırılmasını sağlar. Bu güvenlik açığı, [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (winrm'nin devre dışı bırakılmasını gerektirir), [SweetPotato](https://github.com/CCob/SweetPotato) ve [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) gibi çeşitli araçlar kullanılarak istismar edilebilir.

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="juicypotato.md" %}
[juicypotato.md](juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege

**SeImpersonatePrivilege** ile çok benzer, ayrıcalıklı bir token elde etmek için **aynı yöntemi** kullanır.\
Bu ayrıcalık, **yeni/askıya alınmış bir sürece birincil token atamaya** izin verir. Ayrıcalıklı taklit token ile birincil bir token türetebilirsiniz (DuplicateTokenEx).\
Bu token ile 'CreateProcessAsUser' ile **yeni bir süreç** oluşturabilir veya askıya alınmış bir süreç oluşturup **tokenı ayarlayabilirsiniz** (genel olarak, çalışan bir sürecin birincil tokenını değiştiremezsiniz).

### SeTcbPrivilege

Bu token etkinleştirildiğinde, **KERB\_S4U\_LOGON** kullanarak herhangi bir kullanıcı için **taklit token** alabilirsiniz, **tokena keyfi bir grup** (yönetici) ekleyebilir, tokenın **bütünlük seviyesini** "**orta**" olarak ayarlayabilir ve bu tokenı **mevcut iş parçacığına** atayabilirsiniz (SetThreadToken).

### SeBackupPrivilege

Bu ayrıcalık, herhangi bir dosyaya (okuma işlemleri ile sınırlı) **tüm okuma erişim kontrolünü** vermek için sistemin neden olduğu bir ayrıcalıktır. Yerel Yönetici hesaplarının şifre karma değerlerini kayıt defterinden okumak için kullanılır, ardından "**psexec**" veya "**wmiexec**" gibi araçlar hash ile kullanılabilir (Pass-the-Hash tekniği). Ancak, bu teknik iki koşul altında başarısız olur: Yerel Yönetici hesabı devre dışı bırakıldığında veya uzaktan bağlanan Yerel Yöneticilerden yönetim haklarını kaldıran bir politika mevcut olduğunda.\
Bu ayrıcalığı **kötüye kullanabilirsiniz**:

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec) **IppSec**'i takip ederek
* Ya da **Yedek Operatörleri ile ayrıcalıkları yükseltme** bölümünde açıklandığı gibi:

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### SeRestorePrivilege

Herhangi bir sistem dosyasına, dosyanın Erişim Kontrol Listesi (ACL) ne olursa olsun **yazma erişimi** izni veren bu ayrıcalıktır. Hizmetleri **değiştirme**, DLL Hijacking yapma ve çeşitli diğer teknikler arasında Görüntü Dosyası Yürütme Seçenekleri aracılığıyla **hata ayıklayıcılar** ayarlama gibi birçok yükseltme olanağı sunar.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege, özellikle bir kullanıcının tokenları taklit etme yeteneğine sahip olduğunda güçlü bir izindir, ancak SeImpersonatePrivilege yoksa da kullanışlıdır. Bu yetenek, aynı kullanıcıyı temsil eden ve bütünlük seviyesi mevcut sürecin seviyesini aşmayan bir tokenı taklit etme yeteneğine dayanır.

**Ana Noktalar:**

* **SeImpersonatePrivilege olmadan taklit:** Belirli koşullar altında tokenları taklit ederek EoP için SeCreateTokenPrivilege'i kullanmak mümkündür.
* **Token Taklit Koşulları:** Başarılı taklit, hedef tokenın aynı kullanıcıya ait olmasını ve bütünlük seviyesinin taklit etmeye çalışan sürecin bütünlük seviyesinden az veya eşit olmasını gerektirir.
* **Taklit Tokenların Oluşturulması ve Değiştirilmesi:** Kullanıcılar bir taklit token oluşturabilir ve bunu ayrıcalıklı bir grubun SID'sini (Güvenlik Tanımlayıcısı) ekleyerek geliştirebilir.

### SeLoadDriverPrivilege

Bu ayrıcalık, `ImagePath` ve `Type` için belirli değerlerle bir kayıt defteri girişi oluşturarak **cihaz sürücülerini yükleme ve boşaltma** izni verir. `HKLM` (HKEY\_LOCAL\_MACHINE) üzerinde doğrudan yazma erişimi kısıtlandığından, bunun yerine `HKCU` (HKEY\_CURRENT\_USER) kullanılmalıdır. Ancak, `HKCU`'nun sürücü yapılandırması için çekirdek tarafından tanınabilmesi için belirli bir yol izlenmelidir.

Bu yol `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` şeklindedir, burada `<RID>` mevcut kullanıcının Göreceli Tanımlayıcısıdır. `HKCU` içinde bu tüm yol oluşturulmalı ve iki değer ayarlanmalıdır:

* `ImagePath`, yürütülecek ikili dosyanın yolu
* `Type`, `SERVICE_KERNEL_DRIVER` (`0x00000001`) değeri ile.

**İzlenecek Adımlar:**

1. Kısıtlı yazma erişimi nedeniyle `HKLM` yerine `HKCU`'ya erişin.
2. `HKCU` içinde `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` yolunu oluşturun, burada `<RID>` mevcut kullanıcının Göreceli Tanımlayıcısını temsil eder.
3. `ImagePath`'ı ikilinin yürütme yoluna ayarlayın.
4. `Type`'ı `SERVICE_KERNEL_DRIVER` (`0x00000001`) olarak atayın.
```python
# Example Python code to set the registry values
import winreg as reg

# Define the path and values
path = r'Software\YourPath\System\CurrentControlSet\Services\DriverName' # Adjust 'YourPath' as needed
key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
reg.SetValueEx(key, "ImagePath", 0, reg.REG_SZ, "path_to_binary")
reg.SetValueEx(key, "Type", 0, reg.REG_DWORD, 0x00000001)
reg.CloseKey(key)
```
Daha fazla bu ayrıcalığı kötüye kullanma yolu için [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Bu, **SeRestorePrivilege** ile benzerdir. Temel işlevi, bir sürecin **bir nesnenin mülkiyetini üstlenmesine** izin vermek olup, bu da YAZMA\_SAHİBİ erişim hakları sağlanarak açık bir takdir erişimi gereksinimini aşar. Süreç, önce yazma amacıyla hedef kayıt anahtarının mülkiyetini güvence altına almayı, ardından yazma işlemlerini etkinleştirmek için DACL'yi değiştirmeyi içerir.
```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant <your_username>:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```
### SeDebugPrivilege

Bu ayrıcalık, **diğer süreçleri hata ayıklama** izni verir, buna bellek okuma ve yazma da dahildir. Çoğu antivirüs ve host saldırı önleme çözümlerini atlatabilen çeşitli bellek enjeksiyon stratejileri, bu ayrıcalıkla kullanılabilir.

#### Belleği dökme

Bir sürecin **belleğini yakalamak** için [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) aracını [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) üzerinden kullanabilirsiniz. Özellikle, bir kullanıcının bir sisteme başarıyla giriş yaptıktan sonra kullanıcı kimlik bilgilerini saklamaktan sorumlu olan **Yerel Güvenlik Otoritesi Alt Sistemi Servisi (**[**LSASS**](https://en.wikipedia.org/wiki/Local\_Security\_Authority\_Subsystem\_Service)**)** sürecine uygulanabilir.

Bu dökümü mimikatz'a yükleyerek şifreleri elde edebilirsiniz:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Eğer bir `NT SYSTEM` shell almak istiyorsanız şunları kullanabilirsiniz:

* [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
* [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
* [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
## Yetkileri Kontrol Et
```
whoami /priv
```
**Devre Dışı Görünen Token'lar** etkinleştirilebilir, aslında _Etkin_ ve _Devre Dışı_ token'ları kötüye kullanabilirsiniz.

### Tüm Token'ları Etkinleştir

Eğer devre dışı token'larınız varsa, tüm token'ları etkinleştirmek için [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) script'ini kullanabilirsiniz:
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Or the **script** embed in this [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Full token privileges cheatsheet at [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), summary below will only list direct ways to exploit the privilege to obtain an admin session or read sensitive files.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"Bu, bir kullanıcının token'ları taklit etmesine ve potato.exe, rottenpotato.exe ve juicypotato.exe gibi araçlar kullanarak nt sistemine privesc yapmasına izin verecektir"_                                                                                                                                                                   | Thank you [Aurélien Chalot](https://twitter.com/Defte\_) for the update. I will try to re-phrase it to something more recipe-like soon.                                                                                                                                                                                        |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | `robocopy /b` ile hassas dosyaları okuyun                                                                                                                                                                                                                                                                                                             | <p>- %WINDIR%\MEMORY.DMP dosyasını okuyabiliyorsanız daha ilginç olabilir.<br><br>- <code>SeBackupPrivilege</code> (ve robocopy) açık dosyalarla çalışırken yardımcı değildir.<br><br>- Robocopy, /b parametresi ile çalışmak için hem SeBackup hem de SeRestore gerektir.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | `NtCreateToken` ile yerel yönetici hakları da dahil olmak üzere keyfi bir token oluşturun.                                                                                                                                                                                                                                                        |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | `lsass.exe` token'ını kopyalayın.                                                                                                                                                                                                                                                                                                                   | Script to be found at [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. <code>szkg64.sys</code> gibi hatalı bir çekirdek sürücüsü yükleyin.<br>2. Sürücü açığını istismar edin.<br><br>Alternatif olarak, bu ayrıcalık, <code>ftlMC</code> yerleşik komutunu kullanarak güvenlikle ilgili sürücüleri boşaltmak için kullanılabilir. yani: <code>fltMC sysmondrv</code></p>                                   | <p>1. <code>szkg64</code> açığı <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a> olarak listelenmiştir.<br>2. <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">istismar kodu</a> <a href="https://twitter.com/parvezghh">Parvez Anwar</a> tarafından oluşturulmuştur.</p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. SeRestore ayrıcalığı ile PowerShell/ISE başlatın.<br>2. <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a> ile ayrıcalığı etkinleştirin.<br>3. utilman.exe'yi utilman.old olarak yeniden adlandırın.<br>4. cmd.exe'yi utilman.exe olarak yeniden adlandırın.<br>5. Konsolu kilitleyin ve Win+U tuşlarına basın.</p> | <p>Saldırı bazı AV yazılımları tarafından tespit edilebilir.</p><p>Alternatif yöntem, aynı ayrıcalığı kullanarak "Program Files" içinde depolanan hizmet ikili dosyalarını değiştirmeye dayanır.</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe'yi utilman.exe olarak yeniden adlandırın.<br>4. Konsolu kilitleyin ve Win+U tuşlarına basın.</p>                                                                                                   | <p>Saldırı bazı AV yazılımları tarafından tespit edilebilir.</p><p>Alternatif yöntem, aynı ayrıcalığı kullanarak "Program Files" içinde depolanan hizmet ikili dosyalarını değiştirmeye dayanır.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Token'ları yerel yönetici hakları ile manipüle edin. SeImpersonate gerektirebilir.</p><p>Doğrulanması gerekiyor.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Reference

* Take a look to this table defining Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* Take a look to [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt) about privesc with tokens.

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
