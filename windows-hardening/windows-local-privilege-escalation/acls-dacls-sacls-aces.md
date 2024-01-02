# ACLs - DACLs/SACLs/ACEs

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Lista de Controle de Acesso (ACL)**

Uma **ACL é uma lista ordenada de ACEs** que define as proteções aplicadas a um objeto e suas propriedades. Cada **ACE** identifica um **principal de segurança** e especifica um **conjunto de direitos de acesso** que são permitidos, negados ou auditados para esse principal de segurança.

O descritor de segurança de um objeto pode conter **duas ACLs**:

1. Uma **DACL** que **identifica** os **usuários** e **grupos** que têm acesso **permitido** ou **negado**
2. Uma **SACL** que controla **como** o acesso é **auditado**

Quando um usuário tenta acessar um arquivo, o sistema Windows executa uma verificação de acesso e compara o descritor de segurança com o token de acesso do usuário e avalia se o usuário tem acesso concedido e que tipo de acesso dependendo das ACEs definidas.

### **Lista de Controle de Acesso Discricionário (DACL)**

Uma DACL (frequentemente mencionada como ACL) identifica os usuários e grupos que têm permissões de acesso atribuídas ou negadas a um objeto. Ela contém uma lista de ACEs emparelhadas (Conta + Direito de Acesso) para o objeto protegível.

### **Lista de Controle de Acesso do Sistema (SACL)**

SACLs possibilitam o monitoramento do acesso a objetos protegidos. ACEs em uma SACL determinam **quais tipos de acesso são registrados no Log de Eventos de Segurança**. Com ferramentas de monitoramento, isso pode acionar um alarme para as pessoas certas se usuários maliciosos tentarem acessar o objeto protegido, e em um cenário de incidente, podemos usar os logs para rastrear os passos no tempo. E, por último, você pode habilitar o registro para solucionar problemas de acesso.

## Como o Sistema Usa ACLs

Cada **usuário logado** no sistema **possui um token de acesso com informações de segurança** para aquela sessão de login. O sistema cria um token de acesso quando o usuário faz login. **Todo processo executado** em nome do usuário **tem uma cópia do token de acesso**. O token identifica o usuário, os grupos do usuário e os privilégios do usuário. Um token também contém um SID de login (Identificador de Segurança) que identifica a sessão de login atual.

Quando uma thread tenta acessar um objeto protegível, o LSASS (Autoridade de Segurança Local) concede ou nega acesso. Para fazer isso, o **LSASS pesquisa a DACL** (Lista de Controle de Acesso Discricionário) no fluxo de dados SDS, procurando por ACEs que se aplicam à thread.

**Cada ACE na DACL do objeto** especifica os direitos de acesso que são permitidos ou negados para um principal de segurança ou sessão de login. Se o proprietário do objeto não criou nenhuma ACE na DACL para aquele objeto, o sistema concede acesso imediatamente.

Se o LSASS encontrar ACEs, ele compara o SID do beneficiário em cada ACE com os SIDs dos beneficiários identificados no token de acesso da thread.

### ACEs

Existem **`três` tipos principais de ACEs** que podem ser aplicados a todos os objetos protegíveis no AD:

| **ACE**                  | **Descrição**                                                                                                                                                            |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`ACE de acesso negado`**  | Usado dentro de uma DACL para mostrar que um usuário ou grupo tem acesso explicitamente negado a um objeto                                                                                   |
| **`ACE de acesso permitido`** | Usado dentro de uma DACL para mostrar que um usuário ou grupo tem acesso explicitamente concedido a um objeto                                                                                  |
| **`ACE de auditoria do sistema`**   | Usado dentro de uma SACL para gerar logs de auditoria quando um usuário ou grupo tenta acessar um objeto. Ele registra se o acesso foi concedido ou não e que tipo de acesso ocorreu |

Cada ACE é composto pelos seguintes `quatro` componentes:

1. O identificador de segurança (SID) do usuário/grupo que tem acesso ao objeto (ou nome principal graficamente)
2. Uma bandeira que denota o tipo de ACE (acesso negado, permitido ou auditoria do sistema ACE)
3. Um conjunto de bandeiras que especificam se os contêineres/objetos filhos podem herdar a entrada ACE do objeto primário ou pai
4. Uma [máscara de acesso](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN) que é um valor de 32 bits que define os direitos concedidos a um objeto

O sistema examina cada ACE em sequência até que um dos seguintes eventos ocorra:

* **Uma ACE de acesso negado explicitamente nega** qualquer um dos direitos de acesso solicitados a um dos beneficiários listados no token de acesso da thread.
* **Uma ou mais ACEs de acesso permitido** para beneficiários listados no token de acesso da thread concedem explicitamente todos os direitos de acesso solicitados.
* Todas as ACEs foram verificadas e ainda há pelo menos **um direito de acesso solicitado** que **não foi explicitamente permitido**, caso em que o acesso é implicitamente **negado**.

### Ordem das ACEs

Como o **sistema para de verificar as ACEs quando o acesso solicitado é explicitamente concedido ou negado**, a ordem das ACEs em uma DACL é importante.

A ordem preferida de ACEs em uma DACL é chamada de ordem "canônica". Para o Windows 2000 e o Windows Server 2003, a ordem canônica é a seguinte:

1. Todas as ACEs **explícitas** são colocadas em um grupo **antes** de quaisquer ACEs **herdadas**.
2. Dentro do grupo de ACEs **explícitas**, ACEs de **acesso negado** são colocadas **antes das ACEs de acesso permitido**.
3. Dentro do grupo **herdado**, ACEs que são herdadas do **pai do objeto filho vêm primeiro**, e **depois** ACEs herdadas do **avô**, **e assim** por diante na árvore de objetos. Depois disso, ACEs de **acesso negado** são colocadas **antes das ACEs de acesso permitido**.

A figura a seguir mostra a ordem canônica das ACEs:

### Ordem canônica das ACEs

![ACE](https://www.ntfs.com/images/screenshots/ACEs.gif)

A ordem canônica garante que o seguinte ocorra:

* Uma ACE de **acesso negado explícito é aplicada independentemente de qualquer ACE de acesso permitido explícito**. Isso significa que o proprietário do objeto pode definir permissões que permitem acesso a um grupo de usuários e negar acesso a um subconjunto desse grupo.
* Todas as **ACEs explícitas são processadas antes de qualquer ACE herdada**. Isso é consistente com o conceito de controle de acesso discricionário: o acesso a um objeto filho (por exemplo, um arquivo) está a critério do proprietário do filho, não do proprietário do objeto pai (por exemplo, uma pasta). O proprietário de um objeto filho pode definir permissões diretamente no filho. O resultado é que os efeitos das permissões herdadas são modificados.

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### Exemplo de GUI

Esta é a clássica aba de segurança de uma pasta mostrando a ACL, DACL e ACEs:

![](../../.gitbook/assets/classicsectab.jpg)

Se clicarmos no **botão Avançado**, teremos mais opções como herança:

![](../../.gitbook/assets/aceinheritance.jpg)

E se você adicionar ou editar um Principal de Segurança:

![](../../.gitbook/assets/editseprincipalpointers1.jpg)

E por último temos a SACL na aba de Auditoria:

![](../../.gitbook/assets/audit-tab.jpg)

### Exemplo: Acesso negado explícito a um grupo

Neste exemplo, o grupo com acesso permitido é Todos e o grupo com acesso negado é Marketing, um subconjunto de Todos.

Você quer negar ao grupo de Marketing o acesso a uma pasta de Custos. Se as ACEs da pasta de Custos estiverem em ordem canônica, a ACE que nega o acesso ao Marketing vem antes da ACE que permite a Todos.

Durante uma verificação de acesso, o sistema operacional percorre as ACEs na ordem em que aparecem na DACL do objeto, de modo que a ACE de negação é processada antes da ACE de permissão. Como resultado, os usuários que são membros do grupo de Marketing são negados acesso. Todos os outros têm acesso permitido ao objeto.

### Exemplo: Explícito antes de herdado

Neste exemplo, a pasta de Custos tem uma ACE herdável que nega acesso ao Marketing (o objeto pai). Em outras palavras, todos os usuários que são membros (ou filhos) do grupo de Marketing são negados acesso por herança.

Você quer permitir acesso a Bob, que é o diretor de Marketing. Como membro do grupo de Marketing, Bob é negado acesso à pasta de Custos por herança. O proprietário do objeto filho (usuário Bob) define uma ACE explícita que permite acesso à pasta de Custos. Se as ACEs do objeto filho estiverem em ordem canônica, a ACE explícita que permite o acesso de Bob vem antes de qualquer ACE herdada, incluindo a ACE herdada que nega acesso ao grupo de Marketing.

Durante uma verificação de acesso, o sistema operacional alcança a ACE que permite o acesso de Bob antes de chegar à ACE que nega acesso ao grupo de Marketing. Como resultado, Bob tem acesso permitido ao objeto, embora seja membro do grupo de Marketing. Outros membros do grupo de Marketing são negados acesso.

### Entradas de Controle de Acesso

Como mencionado anteriormente, uma ACL (Lista de Controle de Acesso) é uma lista ordenada de ACEs (Entradas de Controle de Acesso). Cada ACE contém o seguinte:

* Um SID (Identificador de Segurança) que identifica um usuário ou grupo específico.
* Uma máscara de acesso que especifica direitos de acesso.
* Um conjunto de flags de bits que determinam se objetos filhos podem herdar a ACE.
* Uma flag que indica o tipo de ACE.

ACEs são fundamentalmente semelhantes. O que os diferencia é o grau de controle que oferecem sobre herança e acesso a objetos. Existem dois tipos de ACE:

* Tipo genérico que é anexado a todos os objetos protegíveis.
* Tipo específico de objeto que só pode ocorrer em ACLs para objetos do Active Directory.

### ACE Genérico

Um ACE genérico oferece controle limitado sobre os tipos de objetos filhos que podem herdá-los. Essencialmente, eles só podem distinguir entre contêineres e não contêineres.

Por exemplo, a DACL (Lista de Controle de Acesso Discricionário) em um objeto de Pasta no NTFS pode incluir um ACE genérico que permite a um grupo de usuários listar o conteúdo da pasta. Como listar o conteúdo de uma pasta é uma operação que só pode ser realizada em um objeto Contêiner, o ACE que permite a operação pode ser marcado como CONTAINER_INHERIT_ACE. Apenas objetos Contêiner na pasta (ou seja, outros objetos de Pasta) herdam o ACE. Objetos não contêiner (ou seja, objetos de Arquivo) não herdam o ACE do objeto pai.

Um ACE genérico se aplica a um objeto inteiro. Se um ACE genérico concede a um usuário específico acesso de Leitura, o usuário pode ler todas as informações associadas ao objeto — tanto dados quanto propriedades. Isso não é uma limitação séria para a maioria dos tipos de objetos. Objetos de Arquivo, por exemplo, têm poucas propriedades, que são todas usadas para descrever características do objeto em vez de armazenar informações. A maior parte das informações em um objeto de Arquivo é armazenada como dados do objeto; portanto, há pouca necessidade de controles separados sobre as propriedades de um arquivo.

### ACE Específico de Objeto

Um ACE específico de objeto oferece um grau maior de controle sobre os tipos de objetos filhos que podem herdá-los.

Por exemplo, a ACL de um objeto de OU (Unidade Organizacional) pode ter um ACE específico de objeto marcado para herança apenas por objetos de Usuário. Outros tipos de objetos, como objetos de Computador, não herdarão o ACE.

Essa capacidade é a razão pela qual ACEs específicos de objeto são chamados de específicos de objeto. Sua herança pode ser limitada a tipos específicos de objetos filhos.

Existem diferenças semelhantes em como as duas categorias de tipos de ACE controlam o acesso a objetos.

Um ACE específico de objeto pode se aplicar a qualquer propriedade individual de um objeto ou a um conjunto de propriedades desse objeto. Esse tipo de ACE é usado apenas em uma ACL para objetos do Active Directory, que, ao contrário de outros tipos de objetos, armazenam a maior parte de suas informações em propriedades. Muitas vezes é desejável colocar controles independentes em cada propriedade de um objeto do Active Directory, e ACEs específicos de objeto tornam isso possível.

Por exemplo, ao definir permissões para um objeto de Usuário, você pode usar um ACE específico de objeto para permitir que o Principal Self (ou seja, o usuário) tenha acesso de Escrita à propriedade Phone-Home-Primary (homePhone), e você pode usar outros ACEs específicos de objeto para negar ao Principal Self acesso à propriedade Logon-Hours (logonHours) e outras propriedades que estabelecem restrições na conta do usuário.

A tabela abaixo mostra o layout de cada ACE.

### Layout da Entrada de Controle de Acesso

| Campo ACE   | Descrição                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tipo        | Bandeira que indica o tipo de ACE. O Windows 2000 e o Windows Server 2003 suportam seis tipos de ACE: Três tipos de ACE genéricos que são anexados a todos os objetos protegíveis. Três tipos de ACE específicos de objeto que podem ocorrer para objetos do Active Directory.                                                                                                                                                                                                                                                            |
| Flags       | Conjunto de flags de bits que controlam herança e auditoria.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Tamanho        | Número de bytes de memória alocados para o ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Máscara de acesso | Valor de 32 bits cujos bits correspondem a direitos de acesso para o objeto. Os bits podem ser definidos como ligados ou desligados, mas o significado da configuração depende do tipo de ACE. Por exemplo, se o bit que corresponde ao direito de ler permissões estiver lig
