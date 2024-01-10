# Níveis de Integridade

A partir do Windows Vista, todos os **objetos protegidos são rotulados com um nível de integridade**. A maioria dos arquivos de usuário e sistema e chaves de registro no sistema têm um rótulo padrão de integridade "médio". A principal exceção é um conjunto específico de pastas e arquivos editáveis pelo Internet Explorer 7 com integridade Baixa. **A maioria dos processos** executados por **usuários padrão** são rotulados com **integridade média** (mesmo aqueles iniciados por um usuário dentro do grupo de administradores), e a maioria dos **serviços** são rotulados com **integridade do sistema**. O diretório raiz é protegido por um rótulo de alta integridade.\
Observe que **um processo com um nível de integridade inferior não pode escrever em um objeto com um nível de integridade superior.**\
Existem vários níveis de integridade:

* **Não confiável** – processos que são autenticados anonimamente são automaticamente designados como Não confiáveis. _Exemplo: Chrome_
* **Baixo** – O nível de integridade Baixo é o nível usado por padrão para interação com a Internet. Enquanto o Internet Explorer for executado em seu estado padrão, Modo Protegido, todos os arquivos e processos associados a ele são atribuídos ao nível de integridade Baixo. Algumas pastas, como a **Pasta de Internet Temporária**, também são atribuídas ao nível de **integridade Baixo** por padrão. No entanto, observe que um **processo de baixa integridade** é muito **restrito**, ele **não pode** escrever no **registro** e é limitado de escrever na **maioria dos locais** no perfil do usuário atual.  _Exemplo: Internet Explorer ou Microsoft Edge_
* **Médio** – Médio é o contexto em que **a maioria dos objetos será executada**. Usuários padrão recebem o nível de integridade Médio, e qualquer objeto não explicitamente designado com um nível de integridade inferior ou superior é Médio por padrão. Note que um usuário dentro do grupo de Administradores por padrão usará níveis de integridade médios.
* **Alto** – **Administradores** recebem o nível de integridade Alto. Isso garante que os Administradores sejam capazes de interagir com e modificar objetos designados com níveis de integridade Médio ou Baixo, mas também podem agir em outros objetos com um nível de integridade Alto, o que usuários padrão não podem fazer. _Exemplo: "Executar como Administrador"_
* **Sistema** – Como o nome indica, o nível de integridade do Sistema é reservado para o sistema. O kernel do Windows e os serviços centrais são concedidos o nível de integridade do Sistema. Sendo ainda mais alto que o nível de integridade Alto dos Administradores, protege essas funções centrais de serem afetadas ou comprometidas mesmo por Administradores. Exemplo: Serviços
* **Instalador** – O nível de integridade do Instalador é um caso especial e é o mais alto de todos os níveis de integridade. Em virtude de ser igual ou superior a todos os outros níveis de integridade do WIC, objetos designados com o nível de integridade do Instalador também são capazes de desinstalar todos os outros objetos.

Você pode obter o nível de integridade de um processo usando o **Process Explorer** da **Sysinternals**, acessando as **propriedades** do processo e visualizando a aba "**Segurança**":

![](<../../.gitbook/assets/image (318).png>)

Você também pode obter seu **nível de integridade atual** usando `whoami /groups`

![](<../../.gitbook/assets/image (319).png>)

## Níveis de Integridade no Sistema de Arquivos

Um objeto dentro do sistema de arquivos pode exigir um **requisito mínimo de nível de integridade** e, se um processo não tiver esse nível de integridade, não poderá interagir com ele.\
Por exemplo, vamos **criar um arquivo regular a partir do console de um usuário regular e verificar as permissões**:
```
echo asd >asd.txt
icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
```
Agora, vamos atribuir um nível de integridade mínimo de **High** ao arquivo. Isso **deve ser feito a partir de um console** executado como **administrador**, pois um **console regular** estará executando no nível de integridade Medium e **não será permitido** atribuir o nível de integridade High a um objeto:
```
icacls asd.txt /setintegritylevel(oi)(ci) High
processed file: asd.txt
Successfully processed 1 files; Failed processing 0 files

C:\Users\Public>icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
Mandatory Label\High Mandatory Level:(NW)
```
Aqui é onde as coisas ficam interessantes. Você pode ver que o usuário `DESKTOP-IDJHTKP\user` tem **privilégios COMPLETOS** sobre o arquivo (de fato, foi o usuário que criou o arquivo), no entanto, devido ao nível de integridade mínimo implementado, ele não poderá modificar o arquivo a menos que esteja executando dentro de um Nível de Integridade Alto (note que ele ainda poderá lê-lo):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
{% hint style="info" %}
**Portanto, quando um arquivo tem um nível de integridade mínimo, para modificá-lo você precisa estar executando pelo menos nesse nível de integridade.**
{% endhint %}

## Níveis de Integridade em Binários

Eu fiz uma cópia do `cmd.exe` em `C:\Windows\System32\cmd-low.exe` e defini um **nível de integridade baixo a partir de um console de administrador:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Agora, quando eu executo `cmd-low.exe`, ele **será executado sob um nível de integridade baixo** em vez de um médio:

![](<../../.gitbook/assets/image (320).png>)

Para os curiosos, se você atribuir um nível de integridade alto a um binário (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), ele não será executado automaticamente com nível de integridade alto (se você o invocar de um nível de integridade médio --por padrão-- ele será executado sob um nível de integridade médio).

## Níveis de Integridade em Processos

Nem todos os arquivos e pastas têm um nível de integridade mínimo, **mas todos os processos estão sendo executados sob um nível de integridade**. E, similar ao que aconteceu com o sistema de arquivos, **se um processo deseja escrever dentro de outro processo, ele deve ter pelo menos o mesmo nível de integridade**. Isso significa que um processo com nível de integridade baixo não pode abrir um handle com acesso total a um processo com nível de integridade médio.

Devido às restrições comentadas nesta e na seção anterior, do ponto de vista de segurança, é sempre **recomendado executar um processo no menor nível de integridade possível**.


<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) no github.

</details>
