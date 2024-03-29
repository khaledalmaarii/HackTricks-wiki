# ACLs - DACLs/SACLs/ACEs

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir facilmente e **automatizar fluxos de trabalho** com as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Aprenda hacking na AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas dicas de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## **Lista de Controle de Acesso (ACL)**

Uma Lista de Controle de Acesso (ACL) consiste em um conjunto ordenado de Entradas de Controle de Acesso (ACEs) que ditam as proteções para um objeto e suas propriedades. Em essência, uma ACL define quais ações por quais princípios de segurança (usuários ou grupos) são permitidas ou negadas em um determinado objeto.

Existem dois tipos de ACLs:

* **Lista de Controle de Acesso Discricionária (DACL):** Especifica quais usuários e grupos têm ou não têm acesso a um objeto.
* **Lista de Controle de Acesso do Sistema (SACL):** Regula a auditoria de tentativas de acesso a um objeto.

O processo de acesso a um arquivo envolve o sistema verificando o descritor de segurança do objeto em relação ao token de acesso do usuário para determinar se o acesso deve ser concedido e a extensão desse acesso, com base nos ACEs.

### **Componentes Chave**

* **DACL:** Contém ACEs que concedem ou negam permissões de acesso a usuários e grupos para um objeto. É essencialmente a principal ACL que dita os direitos de acesso.
* **SACL:** Usado para auditar o acesso a objetos, onde os ACEs definem os tipos de acesso a serem registrados no Log de Eventos de Segurança. Isso pode ser inestimável para detectar tentativas de acesso não autorizadas ou solucionar problemas de acesso.

### **Interação do Sistema com ACLs**

Cada sessão de usuário está associada a um token de acesso que contém informações de segurança relevantes para essa sessão, incluindo identidades de usuário, grupo e privilégios. Esse token também inclui um SID de logon que identifica unicamente a sessão.

A Autoridade de Segurança Local (LSASS) processa solicitações de acesso a objetos examinando o DACL em busca de ACEs que correspondam ao principal de segurança que está tentando acessar. O acesso é imediatamente concedido se nenhum ACE relevante for encontrado. Caso contrário, o LSASS compara os ACEs com o SID do principal de segurança no token de acesso para determinar a elegibilidade de acesso.

### **Processo Resumido**

* **ACLs:** Definem permissões de acesso por meio de DACLs e regras de auditoria por meio de SACLs.
* **Token de Acesso:** Contém informações de usuário, grupo e privilégio para uma sessão.
* **Decisão de Acesso:** Feita comparando os ACEs do DACL com o token de acesso; SACLs são usados para auditoria.

### ACEs

Existem **três tipos principais de Entradas de Controle de Acesso (ACEs)**:

* **ACE de Acesso Negado**: Este ACE nega explicitamente o acesso a um objeto para usuários ou grupos especificados (em um DACL).
* **ACE de Acesso Permitido**: Este ACE concede explicitamente o acesso a um objeto para usuários ou grupos especificados (em um DACL).
* **ACE de Auditoria do Sistema**: Posicionado dentro de uma Lista de Controle de Acesso do Sistema (SACL), este ACE é responsável por gerar logs de auditoria nas tentativas de acesso a um objeto por usuários ou grupos. Ele documenta se o acesso foi permitido ou negado e a natureza do acesso.

Cada ACE tem **quatro componentes críticos**:

1. O **Identificador de Segurança (SID)** do usuário ou grupo (ou seu nome principal em uma representação gráfica).
2. Uma **bandeira** que identifica o tipo de ACE (acesso negado, permitido ou auditoria do sistema).
3. **Bandeiras de herança** que determinam se os objetos filhos podem herdar o ACE de seu pai.
4. Uma [**máscara de acesso**](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), um valor de 32 bits especificando os direitos concedidos ao objeto.

A determinação de acesso é realizada examinando sequencialmente cada ACE até:

* Um **ACE de Acesso Negado** negar explicitamente os direitos solicitados a um trustee identificado no token de acesso.
* **ACE(s) de Acesso Permitido** conceder explicitamente todos os direitos solicitados a um trustee no token de acesso.
* Após verificar todos os ACEs, se algum direito solicitado **não tiver sido explicitamente permitido**, o acesso é implicitamente **negado**.

### Ordem dos ACEs

A forma como os **ACEs** (regras que dizem quem pode ou não pode acessar algo) são colocados em uma lista chamada **DACL** é muito importante. Isso ocorre porque uma vez que o sistema concede ou nega acesso com base nessas regras, ele para de olhar o restante.

Há uma melhor maneira de organizar esses ACEs, chamada **"ordem canônica"**. Este método ajuda a garantir que tudo funcione de forma suave e justa. Aqui está como funciona para sistemas como **Windows 2000** e **Windows Server 2003**:

* Primeiro, coloque todas as regras feitas **especificamente para este item** antes das que vêm de outro lugar, como uma pasta pai.
* Nas regras específicas, coloque primeiro aquelas que dizem **"não" (negar)** antes das que dizem **"sim" (permitir)**.
* Para as regras que vêm de outro lugar, comece com as mais próximas, como a fonte mais próxima, e depois vá para trás. Novamente, coloque **"não"** antes de **"sim"**.

Essa configuração ajuda de duas maneiras importantes:

* Garante que se houver um **"não"** específico, ele seja respeitado, não importa quais outras regras de **"sim"** estejam lá.
* Permite que o proprietário de um item tenha a **última palavra** sobre quem entra, antes que quaisquer regras de pastas pai ou mais distantes entrem em jogo.

Fazendo as coisas dessa maneira, o proprietário de um arquivo ou pasta pode ser muito preciso sobre quem tem acesso, garantindo que as pessoas certas possam entrar e as erradas não.

![](https://www.ntfs.com/images/screenshots/ACEs.gif)

Portanto, essa **"ordem canônica"** é tudo sobre garantir que as regras de acesso sejam claras e funcionem bem, colocando regras específicas primeiro e organizando tudo de forma inteligente.

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir facilmente e **automatizar fluxos de trabalho** com as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
### Exemplo de GUI

[**Exemplo daqui**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

Esta é a aba de segurança clássica de uma pasta mostrando o ACL, DACL e ACEs:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../.gitbook/assets/classicsectab.jpg)

Se clicarmos no **botão Avançado**, teremos mais opções como herança:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../.gitbook/assets/aceinheritance.jpg)

E se você adicionar ou editar um Principal de Segurança:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../.gitbook/assets/editseprincipalpointers1.jpg)

E por último, temos o SACL na aba de Auditoria:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../.gitbook/assets/audit-tab.jpg)

### Explicando o Controle de Acesso de Maneira Simplificada

Ao gerenciar o acesso a recursos, como uma pasta, usamos listas e regras conhecidas como Listas de Controle de Acesso (ACLs) e Entradas de Controle de Acesso (ACEs). Estas definem quem pode ou não pode acessar determinados dados.

#### Negando Acesso a um Grupo Específico

Imagine que você tem uma pasta chamada Custos e deseja que todos a acessem, exceto a equipe de marketing. Ao configurar as regras corretamente, podemos garantir que a equipe de marketing seja explicitamente negada antes de permitir que todos os outros acessem. Isso é feito colocando a regra de negar acesso à equipe de marketing antes da regra que permite o acesso a todos.

#### Permitindo Acesso a um Membro Específico de um Grupo Negado

Digamos que Bob, o diretor de marketing, precise acessar a pasta Custos, mesmo que a equipe de marketing geralmente não deva ter acesso. Podemos adicionar uma regra específica (ACE) para Bob que concede a ele acesso e colocá-la antes da regra que nega o acesso à equipe de marketing. Dessa forma, Bob obtém acesso apesar da restrição geral em sua equipe.

#### Entendendo as Entradas de Controle de Acesso

As ACEs são as regras individuais em um ACL. Elas identificam usuários ou grupos, especificam quais acessos são permitidos ou negados e determinam como essas regras se aplicam a subitens (herança). Existem dois tipos principais de ACEs:

* **ACEs Genéricas**: Estas se aplicam de forma ampla, afetando todos os tipos de objetos ou distinguindo apenas entre contêineres (como pastas) e não contêineres (como arquivos). Por exemplo, uma regra que permite aos usuários ver o conteúdo de uma pasta, mas não acessar os arquivos dentro dela.
* **ACEs Específicas do Objeto**: Estas fornecem um controle mais preciso, permitindo que regras sejam definidas para tipos específicos de objetos ou até mesmo propriedades individuais dentro de um objeto. Por exemplo, em um diretório de usuários, uma regra pode permitir que um usuário atualize seu número de telefone, mas não suas horas de login.

Cada ACE contém informações importantes como para quem a regra se aplica (usando um Identificador de Segurança ou SID), o que a regra permite ou nega (usando uma máscara de acesso) e como ela é herdada por outros objetos.

#### Principais Diferenças Entre os Tipos de ACE

* As **ACEs Genéricas** são adequadas para cenários simples de controle de acesso, onde a mesma regra se aplica a todos os aspectos de um objeto ou a todos os objetos dentro de um contêiner.
* As **ACEs Específicas do Objeto** são usadas para cenários mais complexos, especialmente em ambientes como o Active Directory, onde pode ser necessário controlar o acesso a propriedades específicas de um objeto de forma diferente.

Em resumo, as ACLs e ACEs ajudam a definir controles de acesso precisos, garantindo que apenas as pessoas ou grupos certos tenham acesso a informações ou recursos sensíveis, com a capacidade de ajustar os direitos de acesso até o nível de propriedades individuais ou tipos de objetos.

### Layout da Entrada de Controle de Acesso

| Campo da ACE | Descrição                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tipo        | Sinalizador que indica o tipo de ACE. O Windows 2000 e o Windows Server 2003 suportam seis tipos de ACE: Três tipos genéricos de ACE que são anexados a todos os objetos seguráveis. Três tipos de ACE específicos do objeto que podem ocorrer para objetos do Active Directory.                                                                                                                                                                                                                                                            |
| Flags       | Conjunto de bits de controle de herança e auditoria.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Tamanho        | Número de bytes de memória alocados para a ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Máscara de Acesso | Valor de 32 bits cujos bits correspondem aos direitos de acesso para o objeto. Os bits podem ser ativados ou desativados, mas o significado da configuração depende do tipo de ACE. Por exemplo, se o bit que corresponde ao direito de ler permissões estiver ativado e o tipo de ACE for Negar, a ACE nega o direito de ler as permissões do objeto. Se o mesmo bit estiver ativado, mas o tipo de ACE for Permitir, a ACE concede o direito de ler as permissões do objeto. Mais detalhes da Máscara de Acesso aparecem na tabela seguinte. |
| SID         | Identifica um usuário ou grupo cujo acesso é controlado ou monitorado por esta ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Layout da Máscara de Acesso

| Bit (Intervalo) | Significado                            | Descrição/Exemplo                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Direitos de Acesso Específicos do Objeto      | Ler dados, Executar, Anexar dados           |
| 16 - 22     | Direitos de Acesso Padrão             | Excluir, Escrever ACL, Escrever Proprietário            |
| 23          | Pode acessar ACL de segurança            |                                           |
| 24 - 27     | Reservado                           |                                           |
| 28          | Genérico TODOS (Ler, Escrever, Executar) | Tudo abaixo                          |
| 29          | Genérico Executar                    | Tudo necessário para executar um programa |
| 30          | Genérico Escrever                      | Tudo necessário para escrever em um arquivo   |
| 31          | Genérico Ler                       | Tudo necessário para ler um arquivo       |

## Referências

* [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
* [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
* [https://www.coopware.in2.info/\_ntfsacl\_ht.htm](https://www.coopware.in2.info/\_ntfsacl\_ht.htm)
