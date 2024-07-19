# Skeleton Key

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

## Skeleton Key Attack

**Skeleton Key saldırısı**, saldırganların **Active Directory kimlik doğrulamasını atlamasına** olanak tanıyan sofistike bir tekniktir; bu, **alan denetleyicisine bir ana şifre enjekte ederek** gerçekleştirilir. Bu, saldırgana **herhangi bir kullanıcı olarak kimlik doğrulama** yapma yetkisi verir ve böylece **alana sınırsız erişim** sağlar.

Bu saldırı [Mimikatz](https://github.com/gentilkiwi/mimikatz) kullanılarak gerçekleştirilebilir. Bu saldırıyı gerçekleştirmek için **Domain Admin hakları gereklidir** ve saldırganın kapsamlı bir ihlal sağlamak için her alan denetleyicisini hedef alması gerekir. Ancak, saldırının etkisi geçicidir; çünkü **alan denetleyicisinin yeniden başlatılması kötü amaçlı yazılımı ortadan kaldırır**, bu da sürdürülebilir erişim için yeniden uygulanmasını gerektirir.

**Saldırıyı gerçekleştirmek** için tek bir komut gereklidir: `misc::skeleton`.

## Mitigations

Bu tür saldırılara karşı önleme stratejileri, hizmetlerin kurulumu veya hassas ayrıcalıkların kullanımıyla ilgili belirli olay kimliklerini izlemeyi içerir. Özellikle, Sistem Olay Kimliği 7045 veya Güvenlik Olay Kimliği 4673'ü aramak, şüpheli faaliyetleri ortaya çıkarabilir. Ayrıca, `lsass.exe`'yi korunan bir işlem olarak çalıştırmak, saldırganların çabalarını önemli ölçüde engelleyebilir; çünkü bu, bir çekirdek modu sürücüsü kullanmalarını gerektirir ve saldırının karmaşıklığını artırır.

Güvenlik önlemlerini artırmak için PowerShell komutları şunlardır:

- Şüpheli hizmetlerin kurulumunu tespit etmek için: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`

- Özellikle Mimikatz'ın sürücüsünü tespit etmek için aşağıdaki komut kullanılabilir: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`

- `lsass.exe`'yi güçlendirmek için, onu korunan bir işlem olarak etkinleştirmek önerilir: `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`

Sistem yeniden başlatıldıktan sonra doğrulama, koruma önlemlerinin başarıyla uygulandığından emin olmak için kritik öneme sahiptir. Bu, şu şekilde gerçekleştirilebilir: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*`

## References
* [https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)

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
