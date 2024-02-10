# Skeleton Key

<details>

<summary><strong>AWS hackleme becerilerinizi sıfırdan kahraman seviyesine çıkarın</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>ile</strong>!</summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamını görmek** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## Skeleton Key Saldırısı

**Skeleton Key saldırısı**, saldırganların bir **ana parola enjekte ederek** etkin dizin kimlik doğrulamasını **atlamalarına** olanak tanıyan sofistike bir tekniktir. Bu, saldırganın herhangi bir kullanıcı olarak **parola olmadan kimlik doğrulama yapmasına** ve etkin dizine **sınırsız erişim sağlamasına** olanak tanır.

Bu saldırı [Mimikatz](https://github.com/gentilkiwi/mimikatz) kullanılarak gerçekleştirilebilir. Bu saldırıyı gerçekleştirmek için **Etki Alanı Yöneticisi hakları gereklidir** ve saldırganın kapsamlı bir ihlal için her etkin dizin denetleyicisini hedeflemesi gerekir. Bununla birlikte, saldırının etkisi geçicidir, çünkü **etkin dizin denetleyicisinin yeniden başlatılması kötü amaçlı yazılımı ortadan kaldırır** ve sürekli erişim için yeniden uygulama gerektirir.

**Saldırıyı gerçekleştirmek** için tek bir komut gereklidir: `misc::skeleton`.

## Hafifletme

Bu tür saldırılara karşı hafifletme stratejileri, hizmetlerin kurulumunu veya hassas yetkilerin kullanımını gösteren belirli olay kimliklerini izlemeyi içerir. Özellikle, Sistem Olay Kimliği 7045 veya Güvenlik Olay Kimliği 4673'ü aramak şüpheli faaliyetleri ortaya çıkarabilir. Ayrıca, saldırganların çabalarını önemli ölçüde engellemek için `lsass.exe`'yi korumalı bir süreç olarak çalıştırmak da önerilir, çünkü bu, saldırının karmaşıklığını artıran bir çekirdek mod sürücüsü kullanmalarını gerektirir.

İşte güvenlik önlemlerini geliştirmek için PowerShell komutları:

- Şüpheli hizmetlerin kurulumunu tespit etmek için şu komutu kullanın: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`

- Özellikle Mimikatz'ın sürücüsünü tespit etmek için aşağıdaki komut kullanılabilir: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`

- `lsass.exe`'yi güçlendirmek için, onu korumalı bir süreç olarak etkinleştirmek önerilir: `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`

Koruyucu önlemlerin başarıyla uygulandığını doğrulamak için sistem yeniden başlatmasından sonra doğrulama önemlidir. Bunun için şu komut kullanılabilir: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*`

## Referanslar
* [https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)

<details>

<summary><strong>AWS hackleme becerilerinizi sıfırdan kahraman seviyesine çıkarın</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>ile</strong>!</summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamını görmek** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
