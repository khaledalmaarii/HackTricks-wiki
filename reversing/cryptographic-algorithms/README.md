# Algoritmos Criptográficos/Compressão

## Algoritmos Criptográficos/Compressão

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

## Identificando Algoritmos

Se você se deparar com um código **usando deslocamentos à direita e à esquerda, xors e várias operações aritméticas**, é altamente provável que seja a implementação de um **algoritmo criptográfico**. Aqui serão mostradas algumas maneiras de **identificar o algoritmo que está sendo usado sem precisar reverter cada passo**.

### Funções da API

**CryptDeriveKey**

Se esta função for usada, você pode descobrir qual **algoritmo está sendo usado** verificando o valor do segundo parâmetro:

![](<../../.gitbook/assets/image (375) (1) (1) (1) (1).png>)

Confira aqui a tabela de possíveis algoritmos e seus valores atribuídos: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Comprime e descomprime um determinado buffer de dados.

**CryptAcquireContext**

Dos [documentos](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): A função **CryptAcquireContext** é usada para adquirir um identificador para um determinado contêiner de chaves dentro de um determinado provedor de serviços criptográficos (CSP). **Esse identificador retornado é usado em chamadas para funções da CryptoAPI** que utilizam o CSP selecionado.

**CryptCreateHash**

Inicia a hash de um fluxo de dados. Se esta função for usada, você pode descobrir qual **algoritmo está sendo usado** verificando o valor do segundo parâmetro:

![](<../../.gitbook/assets/image (376).png>)

\
Confira aqui a tabela de possíveis algoritmos e seus valores atribuídos: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Constantes de código

Às vezes, é realmente fácil identificar um algoritmo graças ao fato de que ele precisa usar um valor especial e único.

![](<../../.gitbook/assets/image (370).png>)

Se você pesquisar a primeira constante no Google, isso é o que você obtém:

![](<../../.gitbook/assets/image (371).png>)

Portanto, você pode assumir que a função decompilada é um **calculador sha256.**\
Você pode pesquisar qualquer uma das outras constantes e provavelmente obterá o mesmo resultado.

### informações de dados

Se o código não tiver nenhuma constante significativa, pode estar **carregando informações da seção .data**.\
Você pode acessar esses dados, **agrupar o primeiro dword** e pesquisá-lo no Google, como fizemos na seção anterior:

![](<../../.gitbook/assets/image (372).png>)

Neste caso, se você procurar **0xA56363C6**, pode descobrir que está relacionado às **tabelas do algoritmo AES**.

## RC4 **(Criptografia Simétrica)**

### Características

É composto por 3 partes principais:

* **Estágio de inicialização/**: Cria uma **tabela de valores de 0x00 a 0xFF** (256bytes no total, 0x100). Esta tabela é comumente chamada de **Caixa de Substituição** (ou SBox).
* **Estágio de embaralhamento**: Irá **percorrer a tabela** criada anteriormente (loop de 0x100 iterações, novamente) modificando cada valor com bytes **semi-aleatórios**. Para criar esses bytes semi-aleatórios, a **chave RC4 é usada**. As **chaves RC4** podem ter **entre 1 e 256 bytes de comprimento**, no entanto, geralmente é recomendado que sejam superiores a 5 bytes. Comumente, as chaves RC4 têm 16 bytes de comprimento.
* **Estágio XOR**: Finalmente, o texto simples ou o texto cifrado é **XORed com os valores criados anteriormente**. A função para criptografar e descriptografar é a mesma. Para isso, um **loop pelos 256 bytes criados** será realizado quantas vezes forem necessárias. Isso geralmente é reconhecido em um código decompilado com um **%256 (mod 256)**.

{% hint style="info" %}
**Para identificar um RC4 em um código desassemblado/decompilado, você pode verificar 2 loops de tamanho 0x100 (com o uso de uma chave) e, em seguida, um XOR dos dados de entrada com os 256 valores criados anteriormente nos 2 loops, provavelmente usando um %256 (mod 256)**
{% endhint %}

### **Estágio de Inicialização/Caixa de Substituição:** (Note o número 256 usado como contador e como um 0 é escrito em cada lugar dos 256 chars)

![](<../../.gitbook/assets/image (377).png>)

### **Estágio de Embaralhamento:**

![](<../../.gitbook/assets/image (378).png>)

### **Estágio XOR:**

![](<../../.gitbook/assets/image (379).png>)

## **AES (Criptografia Simétrica)**

### **Características**

* Uso de **caixas de substituição e tabelas de consulta**
* É possível **distinguir o AES graças ao uso de valores específicos de tabelas de consulta** (constantes). _Note que a **constante** pode ser **armazenada** no binário **ou criada** _**dinamicamente**._
* A **chave de criptografia** deve ser **divisível** por **16** (geralmente 32B) e geralmente um **IV** de 16B é usado.

### Constantes SBox

![](<../../.gitbook/assets/image (380).png>)

## Serpent **(Criptografia Simétrica)**

### Características

* É raro encontrar algum malware usando, mas há exemplos (Ursnif)
* Simples de determinar se um algoritmo é Serpent ou não com base em seu comprimento (função extremamente longa)

### Identificando

Na imagem a seguir, note como a constante **0x9E3779B9** é usada (note que esta constante também é usada por outros algoritmos criptográficos como **TEA** -Tiny Encryption Algorithm).\
Também note o **tamanho do loop** (**132**) e o **número de operações XOR** nas instruções de **desmontagem** e no exemplo de **código**:

![](<../../.gitbook/assets/image (381).png>)

Como mencionado anteriormente, este código pode ser visualizado dentro de qualquer decompilador como uma **função muito longa**, pois **não há saltos** dentro dele. O código decompilado pode parecer o seguinte:

![](<../../.gitbook/assets/image (382).png>)

Portanto, é possível identificar este algoritmo verificando o **número mágico** e os **XORs iniciais**, vendo uma **função muito longa** e **comparando** algumas **instruções** da longa função **com uma implementação** (como o deslocamento à esquerda por 7 e a rotação à esquerda por 22).

## RSA **(Criptografia Assimétrica)**

### Características

* Mais complexo do que algoritmos simétricos
* Não há constantes! (implementações personalizadas são difíceis de determinar)
* KANAL (um analisador criptográfico) falha em mostrar dicas sobre RSA, pois depende de constantes.

### Identificando por comparações

![](<../../.gitbook/assets/image (383).png>)

* Na linha 11 (esquerda) há um `+7) >> 3` que é o mesmo que na linha 35 (direita): `+7) / 8`
* A linha 12 (esquerda) está verificando se `modulus_len < 0x040` e na linha 36 (direita) está verificando se `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Características

* 3 funções: Init, Update, Final
* Funções de inicialização semelhantes

### Identificar

**Init**

Você pode identificar ambos verificando as constantes. Note que o sha\_init tem 1 constante que o MD5 não tem:

![](<../../.gitbook/assets/image (385).png>)

**Transformação MD5**

Note o uso de mais constantes

![](<../../.gitbook/assets/image (253) (1) (1) (1).png>)

## CRC (hash)

* Menor e mais eficiente, pois sua função é encontrar mudanças acidentais nos dados
* Usa tabelas de consulta (então você pode identificar constantes)

### Identificar

Verifique **constantes da tabela de consulta**:

![](<../../.gitbook/assets/image (387).png>)

Um algoritmo de hash CRC se parece com:

![](<../../.gitbook/assets/image (386).png>)

## APLib (Compressão)

### Características

* Constantes não reconhecíveis
* Você pode tentar escrever o algoritmo em python e procurar por coisas semelhantes online

### Identificar

O gráfico é bastante grande:

![](<../../.gitbook/assets/image (207) (2) (1).png>)

Verifique **3 comparações para reconhecê-lo**:

![](<../../.gitbook/assets/image (384).png>)

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
