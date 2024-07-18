{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Treinamento AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Treinamento GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoie o HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}


## Conceitos Básicos

- **Contratos Inteligentes** são programas que executam em uma blockchain quando certas condições são atendidas, automatizando a execução de acordos sem intermediários.
- **Aplicações Descentralizadas (dApps)** são construídas com base em contratos inteligentes, apresentando uma interface amigável para o usuário e um back-end transparente e auditável.
- **Tokens & Moedas** diferenciam-se onde moedas servem como dinheiro digital, enquanto tokens representam valor ou propriedade em contextos específicos.
- **Tokens de Utilidade** concedem acesso a serviços, e **Tokens de Segurança** significam propriedade de ativos.
- **DeFi** significa Finanças Descentralizadas, oferecendo serviços financeiros sem autoridades centrais.
- **DEX** e **DAOs** referem-se a Plataformas de Troca Descentralizadas e Organizações Autônomas Descentralizadas, respectivamente.

## Mecanismos de Consenso

Mecanismos de consenso garantem validações seguras e acordadas de transações na blockchain:
- **Prova de Trabalho (PoW)** depende de poder computacional para verificação de transações.
- **Prova de Participação (PoS)** exige que validadores possuam uma certa quantidade de tokens, reduzindo o consumo de energia em comparação com PoW.

## Conceitos Essenciais do Bitcoin

### Transações

Transações de Bitcoin envolvem a transferência de fundos entre endereços. As transações são validadas por meio de assinaturas digitais, garantindo que apenas o proprietário da chave privada possa iniciar transferências.

#### Componentes Chave:

- As transações consistem em **inputs** (fonte de fundos), **outputs** (destino), **taxas** (pagas aos mineradores) e **scripts** (regras da transação).

### Rede Lightning

Tem como objetivo melhorar a escalabilidade do Bitcoin permitindo múltiplas transações dentro de um canal, transmitindo apenas o estado final para a blockchain.

## Preocupações com a Privacidade do Bitcoin

Ataques à privacidade, como **Propriedade Comum de Inputs** e **Detecção de Endereço de Troco UTXO**, exploram padrões de transações. Estratégias como **Mixers** e **CoinJoin** melhoram o anonimato ao obscurecer os links de transações entre usuários.

## Adquirindo Bitcoins de Forma Anônima

Métodos incluem negociações em dinheiro, mineração e uso de mixers. **CoinJoin** mistura várias transações para complicar a rastreabilidade, enquanto **PayJoin** disfarça CoinJoins como transações regulares para maior privacidade.


# Ataques à Privacidade do Bitcoin

# Resumo dos Ataques à Privacidade do Bitcoin

No mundo do Bitcoin, a privacidade das transações e o anonimato dos usuários são frequentemente motivo de preocupação. Aqui está uma visão simplificada de vários métodos comuns pelos quais os atacantes podem comprometer a privacidade do Bitcoin.

## **Assunção de Propriedade Comum de Inputs**

Geralmente é raro que inputs de diferentes usuários sejam combinados em uma única transação devido à complexidade envolvida. Assim, **dois endereços de input na mesma transação frequentemente são assumidos como pertencentes ao mesmo proprietário**.

## **Detecção de Endereço de Troco UTXO**

Um UTXO, ou **Unspent Transaction Output**, deve ser totalmente gasto em uma transação. Se apenas uma parte dele for enviada para outro endereço, o restante vai para um novo endereço de troco. Observadores podem assumir que este novo endereço pertence ao remetente, comprometendo a privacidade.

### Exemplo
Para mitigar isso, serviços de mistura ou o uso de múltiplos endereços podem ajudar a obscurecer a propriedade.

## **Exposição em Redes Sociais e Fóruns**

Usuários às vezes compartilham seus endereços de Bitcoin online, tornando **fácil vincular o endereço ao seu proprietário**.

## **Análise do Grafo de Transações**

Transações podem ser visualizadas como gráficos, revelando conexões potenciais entre usuários com base no fluxo de fundos.

## **Heurística de Input Desnecessário (Heurística de Troco Ótimo)**

Essa heurística é baseada na análise de transações com múltiplos inputs e outputs para adivinhar qual output é o troco que retorna para o remetente.

### Exemplo
```bash
2 btc --> 4 btc
3 btc     1 btc
```
## **Reutilização Forçada de Endereços**

Os atacantes podem enviar pequenas quantias para endereços usados anteriormente, esperando que o destinatário combine essas com outras entradas em transações futuras, vinculando assim os endereços.

### Comportamento Correto da Carteira
As carteiras devem evitar usar moedas recebidas em endereços já utilizados e vazios para evitar essa exposição de privacidade.

## **Outras Técnicas de Análise de Blockchain**

- **Quantias de Pagamento Exatas:** Transações sem troco provavelmente são entre dois endereços pertencentes ao mesmo usuário.
- **Números Redondos:** Um número redondo em uma transação sugere um pagamento, sendo a saída não redonda provavelmente o troco.
- **Identificação de Carteira:** Diferentes carteiras têm padrões únicos de criação de transações, permitindo que analistas identifiquem o software usado e potencialmente o endereço de troco.
- **Correlações de Quantia e Tempo:** Divulgar horários ou quantias de transação pode tornar as transações rastreáveis.

## **Análise de Tráfego**

Ao monitorar o tráfego de rede, os atacantes podem potencialmente vincular transações ou blocos a endereços IP, comprometendo a privacidade do usuário. Isso é especialmente verdadeiro se uma entidade operar muitos nós Bitcoin, aumentando sua capacidade de monitorar transações.

## Mais
Para uma lista abrangente de ataques e defesas de privacidade, visite [Privacidade do Bitcoin na Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).


# Transações Anônimas de Bitcoin

## Formas de Obter Bitcoins de Forma Anônima

- **Transações em Dinheiro**: Adquirir bitcoin em dinheiro.
- **Alternativas em Dinheiro**: Comprar cartões-presente e trocá-los online por bitcoin.
- **Mineração**: O método mais privado para ganhar bitcoins é através da mineração, especialmente quando feita sozinha, pois os grupos de mineração podem conhecer o endereço IP do minerador. [Informações sobre Grupos de Mineração](https://en.bitcoin.it/wiki/Pooled_mining)
- **Roubo**: Teoricamente, roubar bitcoin poderia ser outro método para adquiri-lo de forma anônima, embora seja ilegal e não recomendado.

## Serviços de Mistura

Ao usar um serviço de mistura, um usuário pode **enviar bitcoins** e receber **bitcoins diferentes em troca**, o que torna difícil rastrear o proprietário original. No entanto, isso requer confiança no serviço para não manter logs e realmente devolver os bitcoins. Opções alternativas de mistura incluem cassinos de Bitcoin.

## CoinJoin

**CoinJoin** mescla várias transações de diferentes usuários em uma só, complicando o processo para quem tenta associar entradas com saídas. Apesar de sua eficácia, transações com tamanhos de entrada e saída únicos ainda podem ser potencialmente rastreadas.

Exemplos de transações que podem ter usado o CoinJoin incluem `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` e `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Para mais informações, visite [CoinJoin](https://coinjoin.io/en). Para um serviço similar no Ethereum, confira [Tornado Cash](https://tornado.cash), que anonimiza transações com fundos de mineradores.

## PayJoin

Uma variante do CoinJoin, **PayJoin** (ou P2EP), disfarça a transação entre duas partes (por exemplo, um cliente e um comerciante) como uma transação regular, sem a característica distintiva de saídas iguais do CoinJoin. Isso torna extremamente difícil de detectar e poderia invalidar a heurística comum de propriedade de entrada usada por entidades de vigilância de transações.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transações como a acima poderiam ser PayJoin, aumentando a privacidade enquanto permanecem indistinguíveis das transações padrão de bitcoin.

**A utilização do PayJoin poderia perturbar significativamente os métodos tradicionais de vigilância**, tornando-se um desenvolvimento promissor na busca pela privacidade transacional.


# Melhores Práticas para Privacidade em Criptomoedas

## **Técnicas de Sincronização de Carteiras**

Para manter a privacidade e segurança, sincronizar carteiras com a blockchain é crucial. Dois métodos se destacam:

- **Nó completo**: Ao baixar toda a blockchain, um nó completo garante máxima privacidade. Todas as transações já feitas são armazenadas localmente, tornando impossível para adversários identificar quais transações ou endereços o usuário está interessado.
- **Filtragem de bloco do lado do cliente**: Este método envolve a criação de filtros para cada bloco na blockchain, permitindo que as carteiras identifiquem transações relevantes sem expor interesses específicos a observadores de rede. Carteiras leves baixam esses filtros, buscando blocos completos apenas quando uma correspondência com os endereços do usuário é encontrada.

## **Utilizando Tor para Anonimato**

Dado que o Bitcoin opera em uma rede peer-to-peer, usar o Tor é recomendado para mascarar seu endereço IP, aumentando a privacidade ao interagir com a rede.

## **Prevenindo Reutilização de Endereços**

Para proteger a privacidade, é vital usar um novo endereço para cada transação. Reutilizar endereços pode comprometer a privacidade ao vincular transações à mesma entidade. Carteiras modernas desencorajam a reutilização de endereços por meio de seu design.

## **Estratégias para Privacidade de Transações**

- **Múltiplas transações**: Dividir um pagamento em várias transações pode obscurecer o valor da transação, frustrando ataques à privacidade.
- **Evitar troco**: Optar por transações que não exigem troco aprimora a privacidade ao interromper métodos de detecção de troco.
- **Múltiplas saídas de troco**: Se evitar troco não for viável, gerar múltiplas saídas de troco ainda pode melhorar a privacidade.

# **Monero: Um Farol de Anonimato**

O Monero aborda a necessidade de anonimato absoluto em transações digitais, estabelecendo um alto padrão de privacidade.

# **Ethereum: Gás e Transações**

## **Compreendendo o Gás**

O Gás mede o esforço computacional necessário para executar operações no Ethereum, precificado em **gwei**. Por exemplo, uma transação custando 2.310.000 gwei (ou 0,00231 ETH) envolve um limite de gás e uma taxa base, com uma gorjeta para incentivar os mineradores. Os usuários podem definir uma taxa máxima para garantir que não paguem a mais, com o excesso sendo reembolsado.

## **Executando Transações**

Transações no Ethereum envolvem um remetente e um destinatário, que podem ser endereços de usuário ou contratos inteligentes. Elas requerem uma taxa e devem ser mineradas. Informações essenciais em uma transação incluem o destinatário, assinatura do remetente, valor, dados opcionais, limite de gás e taxas. Notavelmente, o endereço do remetente é deduzido da assinatura, eliminando a necessidade dele nos dados da transação.

Essas práticas e mecanismos são fundamentais para qualquer pessoa que deseje se envolver com criptomoedas priorizando privacidade e segurança.


## Referências

* [https://en.wikipedia.org/wiki/Proof\_of\_stake](https://en.wikipedia.org/wiki/Proof\_of\_stake)
* [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
* [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
* [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
* [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
* [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced\_address\_reuse)


{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Treinamento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Treinamento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoie o HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
