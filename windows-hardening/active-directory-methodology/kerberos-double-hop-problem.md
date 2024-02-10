# Kerberos Çift Atlama Sorunu

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşün</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>ile öğrenin!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT koleksiyonumuz**](https://opensea.io/collection/the-peass-family)
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter**'da beni takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking hilelerinizi** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **göndererek paylaşın**.

</details>

## Giriş

Kerberos "Çift Atlama" sorunu, bir saldırganın **Kerberos kimlik doğrulamasını iki** **atlama** üzerinden kullanmaya çalıştığında ortaya çıkar, örneğin **PowerShell**/**WinRM** kullanarak.

**Kerberos** ile **kimlik doğrulama** gerçekleştiğinde, **kimlik bilgileri** **bellekte önbelleğe alınmaz**. Bu nedenle, mimikatz çalıştırsanız bile, kullanıcının kimlik bilgilerini makinede bulamazsınız, hatta kullanıcı işlemler çalıştırıyorsa bile.

Bunun nedeni, Kerberos ile bağlantı kurulduğunda şu adımların izlenmesidir:

1. Kullanıcı1 kimlik bilgilerini sağlar ve **alan denetleyicisi** Kullanıcı1'e bir Kerberos **TGT** döndürür.
2. Kullanıcı1, Server1'e bağlanmak için bir **hizmet biletiği** talep etmek için **TGT**'yi kullanır.
3. Kullanıcı1, **Server1**'e **bağlanır** ve **hizmet biletiğini** sağlar.
4. **Server1**, Kullanıcı1'in kimlik bilgilerini veya Kullanıcı1'in **TGT**'sini önbelleğe almadığı için, Server1'den ikinci bir sunucuya giriş yapmaya çalıştığında, kimlik doğrulama yapamaz.

### Sınırsız Delege

Eğer PC'de **sınırsız delege** etkinse, bu olmaz çünkü **Sunucu**, üzerine erişen her kullanıcının bir **TGT** alır. Dahası, sınırsız delege kullanılıyorsa, muhtemelen **Etki Alanı Denetleyicisini** etkileyebilirsiniz.\
[Sınırsız delege sayfasında daha fazla bilgi](unconstrained-delegation.md).

### CredSSP

Bu sorunu önlemenin başka bir yolu da [**önemli ölçüde güvensiz olan**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) **Kimlik Güvenlik Destek Sağlayıcısı**'dır. Microsoft'tan:

> CredSSP kimlik doğrulaması, kullanıcı kimlik bilgilerini yerel bilgisayardan uzak bir bilgisayara aktarır. Bu uygulama, uzaktaki işlemin güvenlik riskini artırır. Uzak bilgisayar tehlikeye düştüğünde, kimlik bilgileri ona iletilirse, kimlik bilgileri ağ oturumunu kontrol etmek için kullanılabilir.

CredSSP'nin üretim sistemlerinde, hassas ağlarda ve benzeri ortamlarda güvenlik endişeleri nedeniyle devre dışı bırakılması şiddetle önerilir. CredSSP'nin etkin olup olmadığını belirlemek için `Get-WSManCredSSP` komutu çalıştırılabilir. Bu komut, CredSSP durumunun **kontrol edilmesine** olanak sağlar ve hatta **WinRM** etkinse uzaktan çalıştırılabilir.
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Çözümler

### Invoke Command

Çift atlama sorununu çözmek için, iç içe geçmiş bir `Invoke-Command` yöntemi sunulmaktadır. Bu, sorunu doğrudan çözmez, ancak özel yapılandırmalara ihtiyaç duymadan bir çözüm sunar. Bu yaklaşım, birincil saldıran makineden veya önceden kurulmuş bir PS-Session ile ilk sunucudan bir PowerShell komutu (`hostname`) aracılığıyla ikincil bir sunucuda bir komutun (`hostname`) yürütülmesine izin verir. İşte nasıl yapılır:
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Alternatif olarak, ilk sunucuyla bir PS-Session kurmak ve `$cred` kullanarak `Invoke-Command` çalıştırmak, görevleri merkezileştirmek için önerilir.

### PSSession Yapılandırması Kaydetme

Çift atlama sorununu atlamak için `Register-PSSessionConfiguration` ve `Enter-PSSession` kullanarak bir çözüm önerilmektedir. Bu yöntem, `evil-winrm`'den farklı bir yaklaşım gerektirir ve çift atlama kısıtlamasından etkilenmeyen bir oturum sağlar.
```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### Port Yönlendirme

Ara bir hedef üzerindeki yerel yöneticiler için, port yönlendirme son sunucuya isteklerin gönderilmesine olanak sağlar. `netsh` kullanılarak, port yönlendirme için bir kural eklenir ve yönlendirilen portun izin verilmesi için bir Windows güvenlik duvarı kuralı eklenir.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe`, PowerShell izleme endişesi varsa daha az tespit edilebilir bir seçenek olarak kullanılabilir. Aşağıdaki komut kullanımını göstermektedir:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

İlk sunucuya OpenSSH kurmak, çift atlama sorunu için özellikle atlamalı kutu senaryoları için kullanışlı bir çözüm sağlar. Bu yöntem, OpenSSH'nin Windows için CLI kurulumu ve yapılandırması gerektirir. Parola Kimlik Doğrulama için yapılandırıldığında, aracı sunucunun kullanıcı adına bir TGT almasına izin verir.

#### OpenSSH Kurulum Adımları

1. En son OpenSSH sürümünü indirin ve zip dosyasını hedef sunucuya taşıyın.
2. Zip dosyasını açın ve `Install-sshd.ps1` betiğini çalıştırın.
3. Port 22'yi açmak için bir güvenlik duvarı kuralı ekleyin ve SSH hizmetlerinin çalıştığını doğrulayın.

`Bağlantı sıfırlandı` hatalarını çözmek için, izinlerin OpenSSH dizininde herkese okuma ve çalıştırma erişimi sağlamak için güncellenmesi gerekebilir.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## Referanslar

* [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
* [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
* [https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting)
* [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını yapmak** veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuz olan özel [**NFT'leri**](https://opensea.io/collection/the-peass-family) keşfedin.
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin.**
* **Hacking hilelerinizi** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **ile göndererek paylaşın.**

</details>
