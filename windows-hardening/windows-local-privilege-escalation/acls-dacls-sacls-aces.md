# ACLs - DACLs/SACLs/ACEs

<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e automatizar facilmente fluxos de trabalho com as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenha o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Lista de Controle de Acesso (ACL)**

Uma **ACL é uma lista ordenada de ACEs** que define as proteções que se aplicam a um objeto e suas propriedades. Cada **ACE** identifica um **princípio de segurança** e especifica um **conjunto de direitos de acesso** que são permitidos, negados ou auditados para esse princípio de segurança.

O descritor de segurança de um objeto pode conter **duas ACLs**:

1. Um **DACL** que **identifica** os **usuários** e **grupos** que têm acesso **permitido** ou **negado**
2. Um **SACL** que controla **como** o acesso é **auditado**

Quando um usuário tenta acessar um arquivo, o sistema Windows executa um AccessCheck e compara o descritor de segurança com o token de acesso do usuário e avalia se o usuário tem acesso concedido e que tipo de acesso, dependendo dos ACEs definidos.

### **Lista de Controle de Acesso Discricionário (DACL)**

Um DACL (frequentemente mencionado como ACL) identifica os usuários e grupos aos quais são atribuídas ou negadas permissões de acesso a um objeto. Ele contém uma lista de ACEs emparelhados (Conta + Direito de Acesso) para o objeto seguro.

### **Lista de Controle de Acesso do Sistema (SACL)**

SACLs permitem monitorar o acesso a objetos seguros. ACEs em um SACL determinam **quais tipos de acesso são registrados no Log de Eventos de Segurança**. Com ferramentas de monitoramento, isso pode gerar um alarme para as pessoas certas se usuários maliciosos tentarem acessar o objeto seguro, e em um cenário de incidente, podemos usar os logs para rastrear os passos de volta no tempo. E por último, você pode habilitar o registro para solucionar problemas de acesso.

## Como o Sistema Usa as ACLs

Cada **usuário logado** no sistema **possui um token de acesso com informações de segurança** para aquela sessão de logon. O sistema cria um token de acesso quando o usuário faz o login. **Cada processo executado** em nome do usuário **possui uma cópia do token de acesso**. O token identifica o usuário, os grupos do usuário e os privilégios do usuário. Um token também contém um SID de logon (Identificador de Segurança) que identifica a sessão de logon atual.

Quando uma thread tenta acessar um objeto seguro, o LSASS (Autoridade de Segurança Local) concede ou nega o acesso. Para fazer isso, o **LSASS pesquisa o DACL** (Lista de Controle de Acesso Discricionário) no fluxo de dados SDS, procurando ACEs que se apliquem à thread.

**Cada ACE no DACL do objeto** especifica os direitos de acesso que são permitidos ou negados para um princípio de segurança ou sessão de logon. Se o proprietário do objeto não tiver criado nenhum ACE no DACL para esse objeto, o sistema concede acesso imediatamente.

Se o LSASS encontrar ACEs, ele compara o SID do beneficiário em cada ACE com os SIDs do beneficiário identificados no token de acesso da thread.

### ACEs

Existem **`três` principais tipos de ACEs** que podem ser aplicados a todos os objetos seguráveis no AD:

| **ACE**                  | **Descrição**                                                                                                                                                            |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`ACE de acesso negado`**  | Usado dentro de um DACL para mostrar que um usuário ou grupo é explicitamente negado o acesso a um objeto                                                                                   |
| **`ACE de acesso permitido`** | Usado dentro de um DACL para mostrar que um usuário ou grupo é explicitamente concedido acesso a um objeto                                                                                  |
| **`ACE de auditoria do sistema`**   | Usado dentro de um SACL para gerar logs de auditoria quando um usuário ou grupo tenta acessar um objeto. Ele registra se o acesso foi concedido ou não e que tipo de acesso ocorreu |

Cada ACE é composto pelos seguintes `quatro` componentes:

1. O identificador de segurança (SID) do usuário/grupo que tem acesso ao objeto (ou nome do principal graficamente)
2. Uma flag que denota o tipo de ACE (ACE de acesso negado, permitido ou de auditoria do sistema)
3. Um conjunto de flags que especificam se os contêineres/objetos filhos podem herdar a entrada ACE do objeto primário ou pai
4. Uma [máscara de acesso](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN) que é um valor de 32 bits que define os direitos concedidos a um objeto

O sistema examina cada ACE em sequência até que ocorra um dos seguintes eventos:

* **Um ACE de acesso negado nega explicitamente** qualquer um dos direitos de acesso solicitados a um dos beneficiários listados no token de acesso da thread.
* **Um ou mais ACEs de acesso permitido** para beneficiários listados no token de acesso da thread concedem explicitamente todos os direitos de acesso solicitados.
* Todos os ACEs foram verificados e ainda há pelo menos **um direito de acesso solicitado** que **não foi explicitamente permitido**, nesse caso, o acesso é implicitamente **negado**.
### Ordem dos ACEs

Porque o **sistema para de verificar os ACEs quando o acesso solicitado é explicitamente concedido ou negado**, a ordem dos ACEs em um DACL é importante.

A ordem preferida dos ACEs em um DACL é chamada de "ordem canônica". Para o Windows 2000 e o Windows Server 2003, a ordem canônica é a seguinte:

1. Todos os ACEs **explícitos** são colocados em um grupo **antes** de qualquer ACE **herdado**.
2. Dentro do grupo de ACEs **explícitos**, os ACEs de **negar acesso** são colocados **antes dos ACEs de permitir acesso**.
3. Dentro do grupo **herdado**, os ACEs herdados do **objeto filho vêm primeiro**, e **então** os ACEs herdados do **avô**, **e assim por diante** na árvore de objetos. Depois disso, os ACEs de **negar acesso** são colocados **antes dos ACEs de permitir acesso**.

A figura a seguir mostra a ordem canônica dos ACEs:

### Ordem canônica dos ACEs

![ACE](https://www.ntfs.com/images/screenshots/ACEs.gif)

A ordem canônica garante que o seguinte ocorra:

* Um ACE de **negar acesso explícito é aplicado independentemente de qualquer ACE de permitir acesso explícito**. Isso significa que o proprietário do objeto pode definir permissões que permitem acesso a um grupo de usuários e negam acesso a um subconjunto desse grupo.
* Todos os ACEs **explícitos são processados antes de qualquer ACE herdado**. Isso é consistente com o conceito de controle de acesso discricionário: o acesso a um objeto filho (por exemplo, um arquivo) está a critério do proprietário do filho, não do proprietário do objeto pai (por exemplo, uma pasta). O proprietário de um objeto filho pode definir permissões diretamente no filho. O resultado é que os efeitos das permissões herdadas são modificados.

<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para criar e **automatizar fluxos de trabalho** com facilidade, usando as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje mesmo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### Exemplo de GUI

Esta é a guia de segurança clássica de uma pasta mostrando o ACL, DACL e ACEs:

![](../../.gitbook/assets/classicsectab.jpg)

Se clicarmos no **botão Avançado**, teremos mais opções como herança:

![](../../.gitbook/assets/aceinheritance.jpg)

E se você adicionar ou editar um Principal de Segurança:

![](../../.gitbook/assets/editseprincipalpointers1.jpg)

E por último, temos o SACL na guia Auditoria:

![](../../.gitbook/assets/audit-tab.jpg)

### Exemplo: Acesso negado explícito a um grupo

Neste exemplo, o grupo de acesso permitido é Todos e o grupo de acesso negado é Marketing, um subconjunto de Todos.

Você deseja negar acesso ao grupo de Marketing a uma pasta de Custos. Se os ACEs da pasta de Custos estiverem em ordem canônica, o ACE que nega o acesso ao Marketing vem antes do ACE que permite a Todos.

Durante uma verificação de acesso, o sistema operacional percorre os ACEs na ordem em que eles aparecem no DACL do objeto, para que o ACE de negação seja processado antes do ACE de permissão. Como resultado, os usuários que são membros do grupo de Marketing são negados o acesso. Todos os outros têm acesso ao objeto.

### Exemplo: Explícito antes de herdado

Neste exemplo, a pasta de Custos tem um ACE herdável que nega acesso ao Marketing (objeto pai). Em outras palavras, todos os usuários que são membros (ou filhos) do grupo de Marketing são negados o acesso por herança.

Você deseja permitir acesso a Bob, que é o diretor de Marketing. Como membro do grupo de Marketing, Bob é negado o acesso à pasta de Custos por herança. O proprietário do objeto filho (usuário Bob) define um ACE explícito que permite o acesso à pasta de Custos. Se os ACEs do objeto filho estiverem em ordem canônica, o ACE explícito que permite o acesso de Bob vem antes de qualquer ACE herdado, incluindo o ACE herdado que nega o acesso ao grupo de Marketing.

Durante uma verificação de acesso, o sistema operacional alcança o ACE que permite o acesso de Bob antes de chegar ao ACE que nega o acesso ao grupo de Marketing. Como resultado, Bob tem acesso ao objeto, mesmo sendo membro do grupo de Marketing. Outros membros do grupo de Marketing são negados o acesso.

### Entradas de Controle de Acesso

Como mencionado anteriormente, uma ACL (Lista de Controle de Acesso) é uma lista ordenada de ACEs (Entradas de Controle de Acesso). Cada ACE contém o seguinte:

* Um SID (Identificador de Segurança) que identifica um usuário ou grupo específico.
* Uma máscara de acesso que especifica os direitos de acesso.
* Um conjunto de flags que determinam se os objetos filhos podem herdar o ACE ou não.
* Uma flag que indica o tipo de ACE.

Os ACEs são fundamentalmente semelhantes. O que os diferencia é o grau de controle que eles oferecem sobre a herança e o acesso ao objeto. Existem dois tipos de ACE:

* Tipo genérico que são anexados a todos os objetos seguráveis.
* Tipo específico do objeto que só pode ocorrer em ACLs para objetos do Active Directory.

### ACE Genérico

Um ACE genérico oferece controle limitado sobre os tipos de objetos filhos que podem herdar deles. Essencialmente, eles só podem distinguir entre contêineres e não contêineres.

Por exemplo, o DACL (Lista de Controle de Acesso Discricionário) em um objeto de Pasta no NTFS pode incluir um ACE genérico que permite que um grupo de usuários liste o conteúdo da pasta. Como listar o conteúdo de uma pasta é uma operação que só pode ser realizada em um objeto Contêiner, o ACE que permite a operação pode ser marcado como um ACE de CONTAINER\_INHERIT\_ACE. Apenas objetos Contêiner na pasta (ou seja, outras pastas) herdam o ACE. Objetos não contêineres (ou seja, arquivos) não herdam o ACE do objeto pai.

Um ACE genérico se aplica a um objeto inteiro. Se um ACE genérico dá a um determinado usuário acesso de Leitura, o usuário pode ler todas as informações associadas ao objeto - tanto dados quanto propriedades. Isso não é uma limitação séria para a maioria dos tipos de objetos. Objetos de arquivo, por exemplo, têm poucas propriedades, que são todas usadas para descrever características do objeto, em vez de armazenar informações. A maioria das informações em um objeto de arquivo é armazenada como dados do objeto; portanto, há pouca necessidade de controles separados nas propriedades de um arquivo.

### ACE Específico do Objeto

Um ACE específico do objeto oferece um maior grau de controle sobre os tipos de objetos filhos que podem herdar deles.

Por exemplo, a ACL de um objeto de OU (Unidade Organizacional) pode ter um ACE específico do objeto que é marcado para herança apenas por objetos de Usuário. Outros tipos de objetos, como objetos de Computador, não herdarão o ACE.

Essa capacidade é o motivo pelo qual os ACEs específicos do objeto são chamados de específicos do objeto. Sua herança pode ser limitada a tipos específicos de objetos filhos.

Existem diferenças semelhantes em como as duas categorias de tipos de ACE controlam o acesso aos objetos.

Um ACE específico do objeto pode ser aplicado a qualquer propriedade individual de um objeto ou a um conjunto de propriedades desse objeto. Esse tipo de ACE é usado apenas em uma ACL para objetos do Active Directory, que, ao contrário de outros tipos de objetos, armazenam a maior parte de suas informações em propriedades. Muitas vezes, é desejável colocar controles independentes em cada propriedade de um objeto do Active Directory, e os ACEs específicos do objeto tornam isso possível.

Por exemplo, ao definir permissões para um objeto de Usuário, você pode usar um ACE específico do objeto para permitir que o Principal Self (ou seja, o usuário) tenha acesso de Gravação à propriedade Phone-Home-Primary (homePhone), e você pode usar outros ACEs específicos do objeto para negar o acesso do Principal Self à propriedade Logon-Hours (logonHours) e outras propriedades que definem restrições na conta do usuário.

A tabela abaixo mostra o layout de cada ACE.
### Layout de Entrada de Controle de Acesso (ACE)

| Campo ACE  | Descrição                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tipo        | Sinalizador que indica o tipo de ACE. O Windows 2000 e o Windows Server 2003 suportam seis tipos de ACE: três tipos genéricos de ACE que são anexados a todos os objetos seguráveis. Três tipos de ACE específicos do objeto que podem ocorrer para objetos do Active Directory.                                                                                                                                                                                                                                                            |
| Flags       | Conjunto de bits que controlam a herança e a auditoria.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Tamanho        | Número de bytes de memória alocados para o ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Máscara de acesso | Valor de 32 bits cujos bits correspondem aos direitos de acesso para o objeto. Os bits podem ser ativados ou desativados, mas o significado da configuração depende do tipo de ACE. Por exemplo, se o bit que corresponde ao direito de ler permissões estiver ativado e o tipo de ACE for Negar, o ACE nega o direito de ler as permissões do objeto. Se o mesmo bit estiver ativado, mas o tipo de ACE for Permitir, o ACE concede o direito de ler as permissões do objeto. Mais detalhes da Máscara de Acesso aparecem na tabela a seguir. |
| SID         | Identifica um usuário ou grupo cujo acesso é controlado ou monitorado por este ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Layout da Máscara de Acesso

| Bit (Intervalo) | Significado                            | Descrição/Exemplo                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Direitos de Acesso Específicos do Objeto      | Ler dados, Executar, Anexar dados           |
| 16 - 22     | Direitos de Acesso Padrão             | Excluir, Escrever ACL, Escrever Proprietário            |
| 23          | Pode acessar a ACL de segurança            |                                           |
| 24 - 27     | Reservado                           |                                           |
| 28          | Genérico TODOS (Ler, Escrever, Executar) | Tudo abaixo                          |
| 29          | Genérico Executar                    | Todas as coisas necessárias para executar um programa |
| 30          | Genérico Escrever                      | Todas as coisas necessárias para escrever em um arquivo   |
| 31          | Genérico Ler                       | Todas as coisas necessárias para ler um arquivo       |

## Referências

* [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
* [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para criar e **automatizar fluxos de trabalho** com facilidade, usando as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
