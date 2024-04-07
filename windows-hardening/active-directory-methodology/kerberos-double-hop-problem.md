# Kerberos Çift Atlama Sorunu

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hacklemeyi öğrenin!</summary>

* **Bir siber güvenlik şirketinde mi çalışıyorsunuz? Şirketinizin HackTricks'te reklamını görmek ister misiniz? Ya da PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek ister misiniz?** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* **💬** [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya beni **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'da takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks ve hacktricks-cloud depolarına PR göndererek paylaşın.**

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Giriş

Kerberos "Çift Atlama" sorunu, bir saldırganın **Kerberos kimlik doğrulamasını iki** **atlama** üzerinden kullanmaya çalıştığında ortaya çıkar, örneğin **PowerShell**/**WinRM** kullanarak.

Bir **Kimlik doğrulaması** **Kerberos** üzerinden gerçekleştiğinde, **kimlik bilgileri** **bellekte önbelleğe alınmaz**. Bu nedenle, mimikatz çalıştırsanız bile, kullanıcının makinede çalışan işlemlerini bulamazsınız.

Bu, Kerberos ile bağlandığınızda şu adımların izlendiği için olur:

1. Kullanıcı1 kimlik bilgilerini sağlar ve **alan denetleyicisi** Kullanıcı1'e bir Kerberos **TGT** döndürür.
2. Kullanıcı1, **TGT**'yi kullanarak **Sunucu1'e bağlanmak** için bir **hizmet biletiği** isteğinde bulunur.
3. Kullanıcı1, **Sunucu1'e bağlanır** ve **hizmet biletiğini sağlar**.
4. **Sunucu1**, Kullanıcı1'in kimlik bilgilerini önbelleğe almaz veya Kullanıcı1'in **TGT**'sini bulundurmaz. Bu nedenle, Sunucu1'den ikinci bir sunucuya giriş yapmaya çalıştığında, kimlik doğrulamasını **gerçekleştiremez**.

### Sınırsız Delege

Eğer PC'de **sınırsız delege** etkinse, bu olmaz çünkü **Sunucu**, kendisine erişen her kullanıcının bir **TGT**'sini **alır**. Dahası, sınırsız delege kullanılıyorsa muhtemelen **Etki Alanı Denetleyicisini** tehlikeye atabilirsiniz.\
[Sınırsız delege sayfasında daha fazla bilgi](unconstrained-delegation.md).

### CredSSP

Bu sorunu önlemenin [**önemli derecede güvensiz**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) bir yolu da **Kimlik Güvenlik Destek Sağlayıcısı**'dır. Microsoft'tan:

> CredSSP kimlik doğrulaması, kullanıcı kimlik bilgilerini yerel bilgisayardan uzak bir bilgisayara devreder. Bu uygulama, uzak işlemin güvenlik riskini artırır. Uzak bilgisayar tehlikeye atıldığında, kimlik bilgileri ona iletildiğinde, kimlik bilgileri ağ oturumunu kontrol etmek için kullanılabilir.

Güvenlik endişeleri nedeniyle **CredSSP**'nin üretim sistemlerinde, hassas ağlarda ve benzeri ortamlarda devre dışı bırakılması şiddetle tavsiye edilir. **CredSSP**'nin etkin olup olmadığını belirlemek için `Get-WSManCredSSP` komutu çalıştırılabilir. Bu komut, **CredSSP durumunu kontrol etmeye** olanak tanır ve hatta **WinRM** etkinse uzaktan çalıştırılabilir.
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Çözümler

### Komutu Çağır

Çift atlama sorununu ele almak için, iç içe geçmiş bir `Invoke-Command` yöntemi sunulmaktadır. Bu doğrudan sorunu çözmez ancak özel yapılandırmalara gerek olmadan bir çözüm sunar. Bu yaklaşım, bir komutu (`hostname`) başlangıç saldıran makineden veya önceden kurulmuş bir PS-Session ile ilk sunucudan ikincil bir sunucuda çalıştırmayı sağlar. İşte nasıl yapılır:
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
### PSSession Yapılandırmasını Kaydet

Çift atlama sorununu atlamak için bir çözüm, `Register-PSSessionConfiguration`'ı `Enter-PSSession` ile kullanmaktır. Bu yöntem, `evil-winrm`'den farklı bir yaklaşım gerektirir ve çift atlama kısıtlamasından etkilenmeyen bir oturum sağlar.
```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### Port Yönlendirme

Ara bir hedef üzerindeki yerel yöneticiler için, port yönlendirme isteklerin bir son sunucuya gönderilmesine olanak tanır. `netsh` kullanılarak, bir port yönlendirme kuralı eklenir ve yönlendirilen portu izin veren bir Windows güvenlik duvarı kuralı eklenir.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe`, PowerShell izleme endişesi varsa daha az algılanabilir bir seçenek olarak WinRM isteklerini iletmek için kullanılabilir. Aşağıdaki komut kullanımını göstermektedir:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

İlk sunucuya OpenSSH kurmak, özellikle atlamalı kutu senaryoları için çift atlama sorununa bir çözüm sağlar. Bu yöntem, Windows için OpenSSH'nin CLI kurulumunu ve yapılandırmasını gerektirir. Parola Kimliği Doğrulaması için yapılandırıldığında, bu, aracı sunucunun kullanıcı adına bir TGT almasına izin verir.

#### OpenSSH Kurulum Adımları

1. En son OpenSSH sürümünü indirin ve zip dosyasını hedef sunucuya taşıyın.
2. Zip dosyasını açın ve `Install-sshd.ps1` betiğini çalıştırın.
3. Port 22'yi açmak için bir güvenlik duvarı kuralı ekleyin ve SSH hizmetlerinin çalıştığını doğrulayın.

`Bağlantı sıfırlandı` hatalarını çözmek için, izinlerin OpenSSH dizininde herkesin okuma ve çalıştırma erişimine izin vermek için güncellenmesi gerekebilir.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## Referanslar

* [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
* [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
* [https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting)
* [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Sıfırdan kahraman olana kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* **Bir **<strong>**cybersecurity şirketinde mi çalışıyorsunuz**? **Şirketinizi HackTricks'te** görmek ister misiniz? ya da **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* **Katılın** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya beni **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.** takip edin.
* **Hacking püf noktalarınızı göndererek** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **üzerinden PR'lar göndererek paylaşın.**

</details>
