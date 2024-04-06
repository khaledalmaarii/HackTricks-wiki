# Abusing Tokens

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hackleme öğrenin!</summary>

* \*\*Bir siber güvenlik şirketinde mi çalışıyorsunuz? Şirketinizin HackTricks'te reklamını görmek ister misiniz? ya da PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek ister misiniz? [ABONELİK PLANLARI](https://github.com/sponsors/carlospolop)'na göz atın!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* [**Resmi PEASS & HackTricks ürünleri**](https://peass.creator-spring.com)
* **Katılın** [💬](https://emojipedia.org/speech-balloon/) **Discord grubuna** veya [telegram grubuna](https://t.me/peass) katılın veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**'u takip edin.**
* **Hacking püf noktalarınızı paylaşarak** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)'a PR gönderin.

</details>

## Tokenlar

**Windows Erişim Token'larının ne olduğunu bilmiyorsanız**, devam etmeden önce bu sayfayı okuyun:

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

**Belki zaten sahip olduğunuz token'ları kötüye kullanarak ayrıcalıkları yükseltebilirsiniz**

### SeImpersonatePrivilege

Bu ayrıcalık, herhangi bir işlem tarafından herhangi bir token'ın taklit edilmesine (ancak oluşturulmasına değil) izin verir, bir kolu alınabilirse. Bir Windows hizmetinden (DCOM) ayrıcalıklı bir token, bir açığı kullanarak NTLM kimlik doğrulamasını gerçekleştirmeye zorlayarak elde edilebilir, ardından bir işlemi SİSTEM ayrıcalıklarıyla yürütme imkanı sağlar. Bu zayıflık, [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (winrm'nin devre dışı bırakılmasını gerektirir), [SweetPotato](https://github.com/CCob/SweetPotato) ve [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) gibi çeşitli araçlar kullanılarak sömürülebilir.

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="juicypotato.md" %}
[juicypotato.md](juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege

Bu, **SeImpersonatePrivilege** ile çok benzerdir, ayrıcalıklı bir token almak için **aynı yöntemi** kullanacaktır.\
Daha sonra, bu ayrıcalık, bir yeni/askıya alınmış işleme birincil bir token **atanmasına izin verir**. Ayrıcalıklı taklit token'ı kullanarak birincil bir token türetebilirsiniz (DuplicateTokenEx).\
Token ile 'CreateProcessAsUser' ile yeni bir işlem oluşturabilir veya bir işlem askıya alabilir ve **token'ı ayarlayabilirsiniz** (genel olarak, çalışan bir işlemin birincil token'ını değiştiremezsiniz).

### SeTcbPrivilege

Bu token etkinleştirilmişse, **KERB\_S4U\_LOGON** kullanarak herhangi bir kullanıcı için bir **taklit token** alabilir, kimlik bilgilerini bilmeden bir **keyfi grup** (yöneticiler) ekleyebilir, token'ın **bütünlük seviyesini** "**orta**" olarak ayarlayabilir ve bu token'ı **mevcut iş parçacığına** (SetThreadToken) atayabilirsiniz.

### SeBackupPrivilege

Bu ayrıcalık, sistemin bu ayrıcalıkla **tüm okuma erişimini** (okuma işlemleriyle sınırlı) herhangi bir dosyaya vermesine neden olur. Bu, yerel Yönetici hesaplarının şifre karmalarını (registry'den) okumak için kullanılır, ardından "**psexec**" veya "**wmicexec**" gibi araçlar, hash ile kullanılabilir (Pass-the-Hash tekniği). Ancak, bu teknik iki durumda başarısız olur: Yerel Yönetici hesabı devre dışı bırakıldığında veya uzaktan bağlanan Yerel Yöneticilerden yönetici haklarını kaldıran bir politika olduğunda.\
Bu ayrıcalığı şu şekilde **kötüye kullanabilirsiniz**:

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)'de **IppSec**'i takip ederek
* Veya:

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### SeRestorePrivilege

Bu ayrıcalık, dosyanın Erişim Kontrol Listesi'ne (ACL) bakılmaksızın **herhangi bir sistem dosyasına yazma erişimi** sağlar. Bu, **hizmetleri değiştirme**, DLL Hijacking yapma ve **hata ayıklayıcıları** Image File Execution Options aracılığıyla ayarlama gibi çeşitli teknikler için birçok olasılık açar.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege, bir kullanıcının token'ları taklit etme yeteneğine sahip olduğunda özellikle güçlü bir izindir, ancak SeImpersonatePrivilege olmadığında da kullanışlıdır. Bu yetenek, aynı kullanıcıyı temsil eden ve bütünlük seviyesi mevcut işlemin bütünlük seviyesini aşmayan bir token'ı taklit etme yeteneğine dayanır.

**Ana Noktalar:**

* **SeImpersonatePrivilege Olmadan Taklit:** Belirli koşullar altında SeCreateTokenPrivilege'ı EoP için kullanmak mümkündür.
* **Token Taklidi Koşulları:** Başarılı taklit için hedef token'ın aynı kullanıcıya ait olması ve taklit denemesi yapan işlemin bütünlük seviyesinden daha düşük veya eşit bir bütünlük seviyesine sahip olması gerekir.
* **Taklit Token'larının Oluşturulması ve Değiştirilmesi:** Kullanıcılar bir taklit token oluşturabilir ve bir ayrıcalıklı grubun SID'sini (Güvenlik Tanımlayıcısı) ekleyerek geliştirebilir.

### SeLoadDriverPrivilege

Bu ayrıcalık, belirli değerlerle birlikte `ImagePath` ve `Type` için belirli değerlere sahip bir kayıt girdisi oluşturarak **sürücü yüklemesine ve kaldırmasına** izin verir. Doğrudan yazma erişimi `HKLM` (HKEY\_LOCAL\_MACHINE) sınırlı olduğundan, bunun yerine `HKCU` (HKEY\_CURRENT\_USER) kullanılmalıdır. Ancak, sürücü yapılandırması için `HKCU`'yu çekirdeğe tanımlanabilir hale getirmek için belirli bir yol izlenmelidir.

Bu yol, `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` şeklindedir, burada `<RID>`, mevcut kullanıcının Göreceli Kimliğidir. `HKCU` içinde, bu tüm yol oluşturulmalı ve iki değer ayarlanmalıdır:

* `ImagePath`, yürütülecek ikili dosyanın yoludur
* `Type`, `SERVICE_KERNEL_DRIVER` (`0x00000001`) değerine sahip olmalıdır.

**İzlenecek Adımlar:**

1. Sınırlı yazma erişimi nedeniyle `HKLM` yerine `HKCU`'ya erişin.
2. `HKCU` içinde, mevcut kullanıcının Göreceli Kimliğini temsil eden `<RID>` ile `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` yolunu oluşturun.
3. `ImagePath`'i yürütülecek ikilinin yoluna ayarlayın.
4. `Type`'ı `SERVICE_KERNEL_DRIVER` (`0x00000001`) olarak ayarlayın.

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

Daha fazla bu ayrıcalığı kötüye kullanma yöntemi için [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Bu, **SeRestorePrivilege**'a benzer. Başlıca işlevi bir işlemin bir nesnenin **sahipliğini üstlenmesine** izin verir ve WRITE\_OWNER erişim hakları sağlayarak açık bir keyfi erişim gereksinimini atlar. İşlem, öncelikle yazma amaçları için amaçlanan kayıt defteri anahtarının sahipliğini güvence altına almayı, ardından yazma işlemlerini etkinleştirmek için DACL'yi değiştirmeyi içerir.

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

Bu ayrıcalık, diğer işlemleri **hata ayıklama** izni verir, bellekte okuma ve yazma yapmayı içerir. Bu ayrıcalıkla, çoğu antivirüs ve ana bilgisayar saldırı önleme çözümlerinden kaçabilen çeşitli bellek enjeksiyon stratejileri kullanılabilir.

#### Belleği dök

[SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)'den [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)'ı kullanarak bir işlemin belleğini **yakalayabilirsiniz**. Bu özellikle, bu, bir kullanıcının bir sisteme başarılı bir şekilde giriş yaptıktan sonra kullanıcı kimlik bilgilerini depolayan **Yerel Güvenlik Otoritesi Alt Sistemi Hizmeti (**[**LSASS**](https://en.wikipedia.org/wiki/Local\_Security\_Authority\_Subsystem\_Service)**)** işlemi için geçerlidir.

Daha sonra bu dökümü mimikatz'da yükleyerek şifreleri elde edebilirsiniz:

```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

#### Uzaktan Kod Çalıştırma (RCE)

Eğer bir `NT SYSTEM` kabuğuna erişmek istiyorsanız şunları kullanabilirsiniz:

* [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
* [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
* [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)

```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```

## İzinleri kontrol et

```
whoami /priv
```

**Devre Dışı görünen token'lar** etkinleştirilebilir, aslında _Etkin_ ve _Devre Dışı_ token'ları kötüye kullanabilirsiniz.

### Tüm token'ları Etkinleştir

Eğer devre dışı bırakılmış token'larınız varsa, tüm token'ları etkinleştirmek için [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) betiğini kullanabilirsiniz:

```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```

Veya bu [gönderideki](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) **betik**.

## Tablo

Tam token ayrıcalıkları hile yaprağı [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), özet aşağıda ayrıcalığı kötüye kullanmak için doğrudan yolları listeler.

| Ayrıcalık                  | Etki           | Araç                  | Yürütme yolu                                                                                                                                                                                                                                                                                                                                                                                           | Yorumlar                                                                                                                                                                                                                                                                                                                           |
| -------------------------- | -------------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`SeAssignPrimaryToken`** | _**Yönetici**_ | 3. taraf araç         | _"Kullanıcıya tokenları taklit etme ve potato.exe, rottenpotato.exe ve juicypotato.exe gibi araçlar kullanarak nt sistemine yükselme imkanı verir"_                                                                                                                                                                                                                                                    | Güncelleme için [Aurélien Chalot](https://twitter.com/Defte\_)'a teşekkürler. Yakında daha tarif benzeri bir şeye dönüştürmeye çalışacağım.                                                                                                                                                                                        |
| **`SeBackup`**             | **Tehdit**     | _**Dahili komutlar**_ | `robocopy /b` ile hassas dosyaları okuyun                                                                                                                                                                                                                                                                                                                                                              | <p>- %WINDIR%\MEMORY.DMP dosyasını okuyabilirseniz daha ilginç olabilir<br><br>- <code>SeBackupPrivilege</code> (ve robocopy), açık dosyalarla ilgili değildir.<br><br>- Robocopy, /b parametresiyle çalışmak için hem SeBackup hem de SeRestore gerektirir.</p>                                                                   |
| **`SeCreateToken`**        | _**Yönetici**_ | 3. taraf araç         | `NtCreateToken` ile yerel yönetici hakları da dahil olmak üzere keyfi token oluşturun.                                                                                                                                                                                                                                                                                                                 |                                                                                                                                                                                                                                                                                                                                    |
| **`SeDebug`**              | _**Yönetici**_ | **PowerShell**        | `lsass.exe` token'ını kopyalayın.                                                                                                                                                                                                                                                                                                                                                                      | Betik [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1) adresinde bulunabilir.                                                                                                                                                                                                      |
| **`SeLoadDriver`**         | _**Yönetici**_ | 3. taraf araç         | <p>1. <code>szkg64.sys</code> gibi hatalı çekirdek sürücü yükleyin<br>2. Sürücü açığından yararlanın<br><br>Alternatif olarak, ayrıcalık <code>ftlMC</code> dahili komutu ile güvenlikle ilgili sürücüleri boşaltmak için kullanılabilir. Örneğin: <code>fltMC sysmondrv</code></p>                                                                                                                    | <p>1. <code>szkg64</code> açığı <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a> olarak listelenmiştir<br>2. <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">sömürü kodu</a> <a href="https://twitter.com/parvezghh">Parvez Anwar</a> tarafından oluşturulmuştur</p> |
| **`SeRestore`**            | _**Yönetici**_ | **PowerShell**        | <p>1. SeRestore ayrıcalığı mevcut olan PowerShell/ISE'yi başlatın.<br>2. Ayrıcalığı <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a> ile etkinleştirin.<br>3. utilman.exe'yi utilman.old olarak yeniden adlandırın<br>4. cmd.exe'yi utilman.exe olarak yeniden adlandırın<br>5. Konsolu kilitleyin ve Win+U tuşlarına basın</p> | <p>Saldırı bazı AV yazılımları tarafından tespit edilebilir.</p><p>Alternatif yöntem, aynı ayrıcalığı kullanarak "Program Dosyaları" içinde depolanan hizmet ikili dosyalarını değiştirmeye dayanır</p>                                                                                                                            |
| **`SeTakeOwnership`**      | _**Yönetici**_ | _**Dahili komutlar**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe'yi utilman.exe olarak yeniden adlandırın<br>4. Konsolu kilitleyin ve Win+U tuşlarına basın</p>                                                                                                                                                             | <p>Saldırı bazı AV yazılımları tarafından tespit edilebilir.</p><p>Alternatif yöntem, aynı ayrıcalığı kullanarak "Program Dosyaları" içinde depolanan hizmet ikili dosyalarını değiştirmeye dayanır.</p>                                                                                                                           |
| **`SeTcb`**                | _**Yönetici**_ | 3. taraf araç         | <p>Yerel yönetici haklarını içeren tokenları manipüle edin. SeImpersonate gerekebilir.</p><p>Doğrulanması gerekiyor.</p>                                                                                                                                                                                                                                                                               |                                                                                                                                                                                                                                                                                                                                    |

## Referans

* Windows token'ları tanımlayan bu tabloya göz atın: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* Token'larla ayrıcalıkların kötüye kullanımı hakkında [**bu makaleye**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt) bakın.

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* \*\*Bir \*\* \*\*cybersecurity şirketinde mi çalışıyorsunuz? Şirketinizi HackTricks'te \*\* \*\*görmek ister misiniz? veya PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek ister misiniz? [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**The PEASS Ailesi**](https://opensea.io/collection/the-peass-family)'ni keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)'in koleksiyonunu keşfedin
* [**Resmi PEASS & HackTricks ürünlerimizi alın**](https://peass.creator-spring.com)
* [**💬**](https://emojipedia.org/speech-balloon/) **Discord grubuna** katılın veya **Telegram grubuna** katılın veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**'u takip edin.**
* **Hacking hilelerinizi göndererek** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)'a PR göndererek paylaşın.

</details>
