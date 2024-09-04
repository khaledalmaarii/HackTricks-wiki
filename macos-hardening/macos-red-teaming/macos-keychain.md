# macOS Keychain

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}


## Main Keychains

* O **User Keychain** (`~/Library/Keychains/login.keycahin-db`), que é usado para armazenar **credenciais específicas do usuário** como senhas de aplicativos, senhas da internet, certificados gerados pelo usuário, senhas de rede e chaves públicas/privadas geradas pelo usuário.
* O **System Keychain** (`/Library/Keychains/System.keychain`), que armazena **credenciais de sistema** como senhas de WiFi, certificados raiz do sistema, chaves privadas do sistema e senhas de aplicativos do sistema.

### Password Keychain Access

Esses arquivos, embora não tenham proteção inerente e possam ser **baixados**, são criptografados e requerem a **senha em texto claro do usuário para serem descriptografados**. Uma ferramenta como [**Chainbreaker**](https://github.com/n0fate/chainbreaker) pode ser usada para descriptografia.

## Keychain Entries Protections

### ACLs

Cada entrada no keychain é regida por **Listas de Controle de Acesso (ACLs)** que ditam quem pode realizar várias ações na entrada do keychain, incluindo:

* **ACLAuhtorizationExportClear**: Permite que o portador obtenha o texto claro do segredo.
* **ACLAuhtorizationExportWrapped**: Permite que o portador obtenha o texto claro criptografado com outra senha fornecida.
* **ACLAuhtorizationAny**: Permite que o portador execute qualquer ação.

As ACLs são acompanhadas por uma **lista de aplicativos confiáveis** que podem realizar essas ações sem solicitação. Isso pode ser:

* **N`il`** (nenhuma autorização necessária, **todos são confiáveis**)
* Uma lista **vazia** (**ninguém** é confiável)
* **Lista** de **aplicativos** específicos.

Além disso, a entrada pode conter a chave **`ACLAuthorizationPartitionID`,** que é usada para identificar o **teamid, apple,** e **cdhash.**

* Se o **teamid** for especificado, então, para **acessar o valor da entrada** **sem** um **prompt**, o aplicativo usado deve ter o **mesmo teamid**.
* Se o **apple** for especificado, então o aplicativo precisa ser **assinado** pela **Apple**.
* Se o **cdhash** for indicado, então o **aplicativo** deve ter o **cdhash** específico.

### Creating a Keychain Entry

Quando uma **nova** **entrada** é criada usando **`Keychain Access.app`**, as seguintes regras se aplicam:

* Todos os aplicativos podem criptografar.
* **Nenhum aplicativo** pode exportar/descriptografar (sem solicitar ao usuário).
* Todos os aplicativos podem ver a verificação de integridade.
* Nenhum aplicativo pode alterar as ACLs.
* O **partitionID** é definido como **`apple`**.

Quando um **aplicativo cria uma entrada no keychain**, as regras são um pouco diferentes:

* Todos os aplicativos podem criptografar.
* Somente o **aplicativo criador** (ou qualquer outro aplicativo explicitamente adicionado) pode exportar/descriptografar (sem solicitar ao usuário).
* Todos os aplicativos podem ver a verificação de integridade.
* Nenhum aplicativo pode alterar as ACLs.
* O **partitionID** é definido como **`teamid:[teamID aqui]`**.

## Accessing the Keychain

### `security`
```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

{% hint style="success" %}
A **enumeração e extração** do keychain de segredos que **não gerarão um prompt** pode ser feita com a ferramenta [**LockSmith**](https://github.com/its-a-feature/LockSmith)
{% endhint %}

Liste e obtenha **informações** sobre cada entrada do keychain:

* A API **`SecItemCopyMatching`** fornece informações sobre cada entrada e há alguns atributos que você pode definir ao usá-la:
* **`kSecReturnData`**: Se verdadeiro, tentará descriptografar os dados (defina como falso para evitar possíveis pop-ups)
* **`kSecReturnRef`**: Obtenha também referência ao item do keychain (defina como verdadeiro caso mais tarde você veja que pode descriptografar sem pop-up)
* **`kSecReturnAttributes`**: Obtenha metadados sobre as entradas
* **`kSecMatchLimit`**: Quantos resultados retornar
* **`kSecClass`**: Que tipo de entrada do keychain

Obtenha **ACLs** de cada entrada:

* Com a API **`SecAccessCopyACLList`** você pode obter a **ACL para o item do keychain**, e ela retornará uma lista de ACLs (como `ACLAuhtorizationExportClear` e as outras mencionadas anteriormente) onde cada lista tem:
* Descrição
* **Lista de Aplicativos Confiáveis**. Isso pode ser:
* Um app: /Applications/Slack.app
* Um binário: /usr/libexec/airportd
* Um grupo: group://AirPort

Exporte os dados:

* A API **`SecKeychainItemCopyContent`** obtém o texto em claro
* A API **`SecItemExport`** exporta as chaves e certificados, mas pode ser necessário definir senhas para exportar o conteúdo criptografado

E estes são os **requisitos** para poder **exportar um segredo sem um prompt**:

* Se **1+ aplicativos confiáveis** listados:
* Necessita das **autorizações** apropriadas (**`Nil`**, ou ser **parte** da lista de aplicativos permitidos na autorização para acessar as informações secretas)
* Necessita que a assinatura de código corresponda ao **PartitionID**
* Necessita que a assinatura de código corresponda à de um **aplicativo confiável** (ou ser membro do grupo KeychainAccessGroup correto)
* Se **todos os aplicativos confiáveis**:
* Necessita das **autorizações** apropriadas
* Necessita que a assinatura de código corresponda ao **PartitionID**
* Se **sem PartitionID**, então isso não é necessário

{% hint style="danger" %}
Portanto, se houver **1 aplicativo listado**, você precisa **injetar código nesse aplicativo**.

Se **apple** estiver indicado no **partitionID**, você poderia acessá-lo com **`osascript`** então qualquer coisa que esteja confiando em todos os aplicativos com apple no partitionID. **`Python`** também poderia ser usado para isso.
{% endhint %}

### Dois atributos adicionais

* **Invisible**: É um sinalizador booleano para **ocultar** a entrada do aplicativo **UI** do Keychain
* **General**: É para armazenar **metadados** (portanto, NÃO É CRIPTOGRAFADO)
* A Microsoft estava armazenando em texto claro todos os tokens de atualização para acessar endpoints sensíveis.

## Referências

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)


{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
