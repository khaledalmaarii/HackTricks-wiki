# Variáveis de Ambiente do Linux

<details>

<summary><strong>Aprenda hacking na AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

**Grupo de Segurança Try Hard**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Variáveis Globais

As variáveis globais **serão** herdadas pelos **processos filhos**.

Você pode criar uma variável global para sua sessão atual fazendo:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Esta variável será acessível pelas suas sessões atuais e seus processos filhos.

Você pode **remover** uma variável fazendo:
```bash
unset MYGLOBAL
```
## Variáveis locais

As **variáveis locais** só podem ser **acessadas** pelo **shell/script atual**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Listar variáveis atuais

```bash
printenv
```
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Variáveis comuns

De: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** – o display usado pelo **X**. Esta variável geralmente é definida como **:0.0**, o que significa o primeiro display no computador atual.
* **EDITOR** – o editor de texto preferido do usuário.
* **HISTFILESIZE** – o número máximo de linhas contidas no arquivo de histórico.
* **HISTSIZE** – Número de linhas adicionadas ao arquivo de histórico quando o usuário termina sua sessão.
* **HOME** – seu diretório pessoal.
* **HOSTNAME** – o nome do host do computador.
* **LANG** – seu idioma atual.
* **MAIL** – a localização do correio do usuário. Geralmente **/var/spool/mail/USUÁRIO**.
* **MANPATH** – a lista de diretórios para pesquisar páginas do manual.
* **OSTYPE** – o tipo de sistema operacional.
* **PS1** – o prompt padrão no bash.
* **PATH** – armazena o caminho de todos os diretórios que contêm arquivos binários que você deseja executar apenas especificando o nome do arquivo e não o caminho relativo ou absoluto.
* **PWD** – o diretório de trabalho atual.
* **SHELL** – o caminho para o shell de comando atual (por exemplo, **/bin/bash**).
* **TERM** – o tipo de terminal atual (por exemplo, **xterm**).
* **TZ** – seu fuso horário.
* **USER** – seu nome de usuário atual.

## Variáveis interessantes para hacking

### **HISTFILESIZE**

Altere o **valor desta variável para 0**, para que quando você **encerrar sua sessão**, o **arquivo de histórico** (\~/.bash\_history) **seja excluído**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Altere o **valor desta variável para 0**, para que quando você **encerrar sua sessão**, nenhum comando seja adicionado ao **arquivo de histórico** (\~/.bash\_history).
```bash
export HISTSIZE=0
```
### http\_proxy & https\_proxy

Os processos usarão o **proxy** declarado aqui para se conectar à internet através de **http ou https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL\_CERT\_FILE & SSL\_CERT\_DIR

Os processos confiarão nos certificados indicados nestas **variáveis de ambiente**.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

Altere a aparência do seu prompt.

[**Este é um exemplo**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../.gitbook/assets/image (87).png>)

Usuário regular:

![](<../.gitbook/assets/image (88).png>)

Um, dois e três trabalhos em segundo plano:

![](<../.gitbook/assets/image (89).png>)

Um trabalho em segundo plano, um parado e o último comando não terminou corretamente:

![](<../.gitbook/assets/image (90).png>)

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Aprenda hacking na AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
