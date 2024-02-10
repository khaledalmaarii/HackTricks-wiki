# Token Kötüye Kullanma

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

* Bir **cybersecurity şirketinde çalışıyor musunuz**? **Şirketinizi HackTricks'te reklamını yapmak** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzdaki özel [**NFT'leri**](https://opensea.io/collection/the-peass-family) keşfedin.
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi** [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)'ya PR göndererek paylaşın.

</details>

## Tokenlar

**Windows Erişim Tokenlarının ne olduğunu bilmiyorsanız**, devam etmeden önce bu sayfayı okuyun:

{% content-ref url="../access-tokens.md" %}
[access-tokens.md](../access-tokens.md)
{% endcontent-ref %}

**Belki de zaten sahip olduğunuz tokenları kötüye kullanarak ayrıcalıkları yükseltebilirsiniz**

### SeImpersonatePrivilege

Bu ayrıcalık, herhangi bir işlem tarafından herhangi bir tokenın taklit edilmesine (ancak oluşturulmasına değil) izin verir, elde edilebilen bir tutamacı olduğu sürece. Bir Windows hizmetinden (DCOM) ayrıcalıklı bir token alınabilir ve ardından bir sürecin SYSTEM ayrıcalıklarıyla çalıştırılmasını sağlamak için NTLM kimlik doğrulamasını gerçekleştirmesi sağlanabilir. Bu zafiyet, [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (winrm'in devre dışı bırakılmasını gerektirir), [SweetPotato](https://github.com/CCob/SweetPotato) ve [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) gibi çeşitli araçlar kullanılarak istismar edilebilir.

{% content-ref url="../roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](../roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="../juicypotato.md" %}
[juicypotato.md](../juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege

Bu, **SeImpersonatePrivilege** ile çok benzerdir, ayrıcalıklı bir token elde etmek için **aynı yöntemi** kullanacaktır.\
Daha sonra, bu ayrıcalık, bir yeni/askıya alınmış sürece birincil bir token **atanmasına izin verir**. Ayrıcalıklı taklit tokeni ile birincil bir token (DuplicateTokenEx) türetilebilir.\
Token ile 'CreateProcessAsUser' ile **yeni bir süreç** oluşturabilir veya bir süreç askıya alınmış ve **tokeni ayarlayabilirsiniz** (genel olarak, çalışan bir sürecin birincil tokenunu değiştiremezsiniz).

### SeTcbPrivilege

Bu token etkinleştirildiyse, **KERB\_S4U\_LOGON** kullanarak kimlik doğrulaması bilgilerini bilmeksizin başka bir kullanıcı için bir **taklit tokeni** alabilir, tokena **keyfi bir grup** (yöneticiler) ekleyebilir, tokenın **bütünlük düzeyini** "**orta**" olarak ayarlayabilir ve bu tokeni **geçerli iş parçacığına** atayabilir (SetThreadToken).

### SeBackupPrivilege

Bu ayrıcalık, sistem tarafından herhangi bir dosyaya (sadece okuma işlemleriyle sınırlı olarak) **tüm okuma erişimi** kontrolü verir. Bu ayrıcalık, yerel Yönetici hesaplarının parola karmalarını (Pass-the-Hash tekniği) kayıttan okumak için kullanılır, ardından "**psexec**" veya "**wmicexec**" gibi araçlarla karma kullanılabilir. Ancak, bu teknik iki durumda başarısız olur: Yerel Yönetici hesabı devre dışı bırakıldığında veya uzaktan bağlanan Yerel Yöneticilerden yönetici haklarını kaldıran bir politika olduğunda.\
Bu ayrıcalığı aşağıdaki yöntemlerle **kötüye kullanabilirsiniz**:

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec) adresindeki **IppSec** tarafından açıklandığı gibi
* Veya aşağıdaki belgedeki **Yedek Operatörleri ile ayrıcalıkların yükseltilmesi** bölümünde açıklandığı gibi:

{% content-ref url="../../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### SeRestorePrivilege

Bu ayrıcalık, dosyanın Erişim Kontrol Listesi'ne (ACL) bakılmaksızın herhangi bir sistem dosyasına **yazma erişimi** sağlar. Bu, hizmetleri **değiştirmek**, DLL Hijacking yapmak ve Image File Execution Options üzerinden **hata ayıklayıcıları** ayarlamak gibi çeşitli teknikler dahil olmak üzere birçok ayrıcalık yükseltme olasılığı sunar.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege, özellikle bir kullanıcının tokenları taklit etme yeteneğine sahip olduğunda, ancak SeImpersonatePrivilege olmadığında güçlü bir izindir. Bu yetenek, aynı kullanıcıyı temsil eden ve bütünlük düzeyi mevcut işlemin bütünlük düzeyini aşmayan bir tokeni taklit etme yeteneğine dayanır.

**Ana Noktalar:**
- **SeImpersonatePrivilege Olmadan Taklit:** Belirli koşullar altında SeCreateTokenPrivilege'ı EoP için token taklit etmek için kullanmak mümkündür.
- **Token Taklit İçin Koşullar:** Başarılı taklit için hedef tokenin aynı kullanıcıya ait olması ve taklit yapmaya çalışan işlemin bütünlük düzeyinden daha düşük veya eşit bir bütünlük düzeyine sahip olması gerekmektedir.
- **Taklit Tokenlerin Oluşturulması ve Değiştirilmesi:** Kullanıcılar taklit bir token oluşturabilir ve bir ayrıcalıklı grubun SID'sini (
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
[https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege) adresinde bu ayrıcalığı kötüye kullanmanın daha fazla yolu bulunmaktadır.

### SeTakeOwnershipPrivilege

Bu, **SeRestorePrivilege** ile benzerdir. Temel işlevi, bir sürecin WRITE_OWNER erişim hakları sağlayarak açıkça takdir edilen erişim gereksinimini atlayarak bir nesnenin sahipliğini **üstlenmesine** olanak tanır. Süreç, öncelikle yazma amaçları için amaçlanan kayıt defteri anahtarının sahipliğini güvence altına alarak başlar, ardından yazma işlemlerini etkinleştirmek için DACL'yi değiştirir.
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

Bu ayrıcalık, diğer işlemleri hata ayıklama yapmak için izin verir, bunun yanı sıra belleğe okuma ve yazma yapabilir. Bu ayrıcalıkla, çoğu antivirüs ve ana bilgisayar saldırı önleme çözümünden kaçabilen çeşitli bellek enjeksiyon stratejileri kullanılabilir.

#### Belleği dökme

[SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)'den [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)'ı kullanarak bir işlemin belleğini yakalayabilirsiniz. Özellikle, bu, bir kullanıcının başarılı bir şekilde bir sisteme giriş yaptıktan sonra kullanıcı kimlik bilgilerini depolayan **Yerel Güvenlik Otoritesi Alt Sistemi Hizmeti ([LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service))** işlemine uygulanabilir.

Daha sonra bu dökümü mimikatz'da yükleyerek şifreleri elde edebilirsiniz:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### Uzaktan Kod Çalıştırma (RCE)

Eğer bir `NT SYSTEM` kabuğu elde etmek istiyorsanız, aşağıdaki yöntemleri kullanabilirsiniz:

* ****[**SeDebugPrivilegePoC**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)****
* ****[**psgetsys.ps1**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)****
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
## İzinleri Kontrol Et

To determine the privileges of a user or process, you can use the following methods:

### 1. Whoami

The `whoami` command displays the username of the current user.

```plaintext
whoami
```

### 2. Whoami /priv

The `whoami /priv` command displays the privileges of the current user.

```plaintext
whoami /priv
```

### 3. Whoami /groups

The `whoami /groups` command displays the group membership of the current user.

```plaintext
whoami /groups
```

### 4. Whoami /all

The `whoami /all` command displays detailed information about the current user, including privileges and group membership.

```plaintext
whoami /all
```

### 5. Process Explorer

Process Explorer is a tool that provides detailed information about running processes, including their privileges. You can download it from the [Microsoft website](https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer).

After launching Process Explorer, locate the process you want to check and right-click on it. Select "Properties" and navigate to the "Security" tab. Here, you can view the privileges associated with the process.

### 6. AccessChk

AccessChk is a command-line tool that allows you to view the effective permissions of a user or process. You can download it from the [Microsoft website](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk).

To check the privileges of a user, use the following command:

```plaintext
accesschk.exe -a <username>
```

To check the privileges of a process, use the following command:

```plaintext
accesschk.exe -p <process_id>
```

Replace `<username>` with the username you want to check and `<process_id>` with the ID of the process you want to check.

By using these methods, you can easily check the privileges of a user or process on a Windows system.
```
whoami /priv
```
**Devre dışı bırakılan tokenler** etkinleştirilebilir ve aslında _Etkinleştirilmiş_ ve _Devre dışı bırakılmış_ tokenlerin kötüye kullanılması mümkündür.

### Tüm tokenleri etkinleştirme

Eğer devre dışı bırakılmış tokenlere sahipseniz, [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) betiğini kullanarak tüm tokenleri etkinleştirebilirsiniz:
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Veya bu [gönderide](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) yer alan **betik**.

## Tablo

Tam token ayrıcalıkları hile yaprağına [buradan](https://github.com/gtworek/Priv2Admin) ulaşabilirsiniz, aşağıda sadece yönetici oturumu elde etmek veya hassas dosyaları okumak için doğrudan kullanılan yöntemler listelenmiştir.

| Ayrıcalık                  | Etki        | Araç                    | Yürütme yolu                                                                                                                                                                                                                                                                                                                                       | Açıklamalar                                                                                                                                                                                                                                                                                                                    |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Yönetici**_ | 3. taraf araç            | _"Bu, bir kullanıcının tokenları taklit etmesine ve potato.exe, rottenpotato.exe ve juicypotato.exe gibi araçlar kullanarak nt sistemine yükselmesine izin verir"_                                                                                                                                                                                     | Güncelleme için [Aurélien Chalot](https://twitter.com/Defte\_)'a teşekkür ederim. Yakında daha tarif benzeri bir şeye dönüştürmeye çalışacağım.                                                                                                                                                                              |
| **`SeBackup`**             | **Tehdit**  | _**Dahili komutlar**_    | `robocopy /b` ile hassas dosyaları okuyun                                                                                                                                                                                                                                                                                                          | <p>- %WINDIR%\MEMORY.DMP dosyasını okuyabiliyorsanız daha ilginç olabilir<br><br>- <code>SeBackupPrivilege</code> (ve robocopy), dosyaları açmak için yararlı değildir.<br><br>- Robocopy, /b parametresiyle çalışmak için hem SeBackup hem de SeRestore gerektirir.</p>                                                                      |
| **`SeCreateToken`**        | _**Yönetici**_ | 3. taraf araç            | `NtCreateToken` ile yerel yönetici hakları dahil olmak üzere isteğe bağlı token oluşturun                                                                                                                                                                                                                                                           |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Yönetici**_ | **PowerShell**          | `lsass.exe` token'ını çoğaltın                                                                                                                                                                                                                                                                                                                     | Betik [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)'de bulunabilir                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Yönetici**_ | 3. taraf araç            | <p>1. `szkg64.sys` gibi hatalı bir çekirdek sürücüsü yükleyin<br>2. Sürücü açığından yararlanın<br><br>Alternatif olarak, ayrıcalık, `ftlMC` dahili komutuyla güvenlikle ilgili sürücüleri boşaltmak için kullanılabilir. Örneğin: `fltMC sysmondrv`</p>                                                                           | <p>1. `szkg64` açığı [CVE-2018-15732](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732) olarak listelenmiştir<br>2. `szkg64` [açık kodu](https://www.greyhathacker.net/?p=1025) [Parvez Anwar](https://twitter.com/parvezghh) tarafından oluşturulmuştur</p> |
| **`SeRestore`**            | _**Yönetici**_ | **PowerShell**          | <p>1. SeRestore ayrıcalığı mevcut olan PowerShell/ISE'yi başlatın<br>2. Ayrıcalığı [Enable-SeRestorePrivilege](https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1) ile etkinleştirin<br>3. utilman.exe'yi utilman.old olarak yeniden adlandırın<br>4. cmd.exe'yi utilman.exe olarak yeniden adlandırın<br>5. Konsolu kilitleyin ve Win+U tuşlarına basın</p> | <p>Saldırı, bazı AV yazılımları tarafından tespit edilebilir.</p><p>Alternatif yöntem, aynı ayrıcalığı kullanarak "Program Dosyaları" içinde depolanan hizmet ikili dosyalarını değiştirmeye dayanır</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Yönetici**_ | _**Dahili komutlar**_    | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe'yi utilman.exe olarak yeniden adlandırın<br>4. Konsolu kilitleyin ve Win+U tuşlarına basın</p>                                                                                                                                       | <p>Saldırı, bazı AV yazılımları tarafından tespit edilebilir.</p><p>Alternatif yöntem, aynı ayrıcalığı kullanarak "Program Dosyaları" içinde depolanan hizmet ikili dosyalarını değiştirmeye dayanır.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Yönetici**_ | 3. taraf araç            | <p>Yerel yönetici haklarını içeren tokenları manipüle edin. SeImpersonate gerektirebilir.</p><p>Doğrulanması gerekmektedir.</p>                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Referans

* Windows token'larını tanımlayan bu tabloya göz atın: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* Token kullanarak ayrıcalık yükseltme hakkında [**bu makaleye**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt) göz atın.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmaya kadar AWS hackleme öğrenin<strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? Şirketinizi **HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuz olan özel [**NFT'lerimizi**](https://opensea.io/collection/the-peass-family) keşfedin
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* **Discord grubuna** [**💬**](https://emojipedia.org/speech-balloon/) [**katılın**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya **Twitter**'da takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking hilelerinizi [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)'ya PR göndererek paylaşın**.

</details>
