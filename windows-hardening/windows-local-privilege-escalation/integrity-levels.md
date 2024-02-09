<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>


# Níveis de Integridade

No Windows Vista e versões posteriores, todos os itens protegidos vêm com uma etiqueta de **nível de integridade**. Essa configuração atribui principalmente um nível de integridade "médio" a arquivos e chaves de registro, exceto para determinadas pastas e arquivos nos quais o Internet Explorer 7 pode escrever em um nível de integridade baixo. O comportamento padrão é para processos iniciados por usuários padrão terem um nível de integridade médio, enquanto os serviços geralmente operam em um nível de integridade do sistema. Um rótulo de alta integridade protege o diretório raiz.

Uma regra chave é que objetos não podem ser modificados por processos com um nível de integridade inferior ao nível do objeto. Os níveis de integridade são:

- **Não Confiável**: Este nível é para processos com logins anônimos. %%%Exemplo: Chrome%%%
- **Baixo**: Principalmente para interações na internet, especialmente no Modo Protegido do Internet Explorer, afetando arquivos e processos associados, e certas pastas como a **Pasta de Internet Temporária**. Processos de baixa integridade enfrentam restrições significativas, incluindo nenhum acesso de gravação no registro e acesso limitado de gravação no perfil do usuário.
- **Médio**: O nível padrão para a maioria das atividades, atribuído a usuários padrão e objetos sem níveis de integridade específicos. Mesmo os membros do grupo Administradores operam neste nível por padrão.
- **Alto**: Reservado para administradores, permitindo que eles modifiquem objetos em níveis de integridade inferiores, incluindo aqueles no próprio nível alto.
- **Sistema**: O nível operacional mais alto para o kernel do Windows e serviços principais, fora do alcance até mesmo dos administradores, garantindo a proteção de funções vitais do sistema.
- **Instalador**: Um nível único que se destaca acima de todos os outros, permitindo que objetos neste nível desinstalem qualquer outro objeto.

Você pode obter o nível de integridade de um processo usando o **Process Explorer** da **Sysinternals**, acessando as **propriedades** do processo e visualizando a aba "**Segurança**":

![](<../../.gitbook/assets/image (318).png>)

Você também pode obter seu **nível de integridade atual** usando `whoami /groups`

![](<../../.gitbook/assets/image (319).png>)

## Níveis de Integridade no Sistema de Arquivos

Um objeto dentro do sistema de arquivos pode precisar de um **requisito mínimo de nível de integridade** e se um processo não tiver esse nível de integridade, ele não poderá interagir com ele.\
Por exemplo, vamos **criar um arquivo de console de usuário regular e verificar as permissões**:
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
Agora, vamos atribuir um nível de integridade mínimo de **Alto** ao arquivo. Isso **deve ser feito a partir de um console** sendo executado como **administrador**, pois um **console regular** estará em execução no nível de integridade Médio e **não terá permissão** para atribuir o nível de integridade Alto a um objeto:
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
Aqui é onde as coisas ficam interessantes. Você pode ver que o usuário `DESKTOP-IDJHTKP\user` tem **privilégios COMPLETOS** sobre o arquivo (de fato, este foi o usuário que criou o arquivo), no entanto, devido ao nível mínimo de integridade implementado, ele não poderá mais modificar o arquivo a menos que esteja sendo executado em um Nível de Integridade Alto (observe que ele poderá lê-lo):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
{% hint style="info" %}
**Portanto, quando um arquivo possui um nível mínimo de integridade, para modificá-lo você precisa estar executando pelo menos nesse nível de integridade.**
{% endhint %}

## Níveis de Integridade em Binários

Fiz uma cópia do `cmd.exe` em `C:\Windows\System32\cmd-low.exe` e defini um **nível de integridade baixo a partir de um console de administrador:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Agora, quando eu executar `cmd-low.exe` ele **será executado em um nível de integridade baixo** em vez de médio:

![](<../../.gitbook/assets/image (320).png>)

Para pessoas curiosas, se você atribuir um nível de integridade alto a um binário (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) ele não será executado automaticamente com alto nível de integridade (se você o invocar de um nível de integridade médio --por padrão-- ele será executado em um nível de integridade médio).

## Níveis de Integridade em Processos

Nem todos os arquivos e pastas têm um nível mínimo de integridade, **mas todos os processos estão em execução sob um nível de integridade**. E semelhante ao que aconteceu com o sistema de arquivos, **se um processo deseja escrever dentro de outro processo, ele deve ter pelo menos o mesmo nível de integridade**. Isso significa que um processo com nível de integridade baixo não pode abrir um identificador com acesso total a um processo com nível de integridade médio.

Devido às restrições comentadas nesta e na seção anterior, do ponto de vista da segurança, é sempre **recomendado executar um processo no nível mais baixo de integridade possível**.
