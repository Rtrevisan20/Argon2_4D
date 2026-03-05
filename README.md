# Argon 2

[Argon2](https://en.wikipedia.org/wiki/Argon2) é um algoritmo de hashing de senhas moderno e seguro, vencedor da [Password Hashing Competition](https://password-hashing.net/) de 2015. Ele protege contra ataques de força bruta, GPUs e ASICs ao exigir alto uso de memória, tempo e paralelismo. A variante principal, Argon2id, é recomendada por equilibrar resistência contra diferentes tipos de ataque.

**Principais características e vantagens:**

- Vencedor da PHC 2015: Considerado o padrão ouro para armazenamento de senhas atualmente.
- Configurável: Permite ajustar o custo de memória, tempo (iterações) e paralelismo (threads).
- Resistente: Projetado para ser difícil de quebrar usando hardware especializado (GPUs) e ataques de canal lateral.
- Variantes
  - Argon2d: Mais resistente a GPUs, ideal para ataques de GPU (criptomoedas).
  - Argon2i: Mais resistente a ataques de canal lateral, ideal para senhas.
  - Argon2id: Híbrido, combina os dois acima e é a recomendação padrão (RFC 9106).

O Argon2 é amplamente considerado superior ao bcrypt e scrypt devido à sua alta configurabilidade e resistência a hardware avançado.

**Por convenção, o Argon2 gera um hash de senha como uma string no formato:**

$Argon2id$v=[version]$m=[memoryKB],t=[type],p=[parallelism]$[salt]$[hash]
  $argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$VGhpcyB3YXMgb25seSBhbiBleGFtcGxlLCBpIGRvbid0IGFjdHVhbGx5IGhhdmUgYSB2YWxpZCBpbXBsZW1udA==

As partes da string são:

| Value    | Meaning                | Notes                                                                 |
| -------- | ---------------------- | --------------------------------------------------------------------- |
| argon2id | Hash algorithm         | "argon2id", "argon2d", argon2i"                                       |
| v=19     | Decimal coded version  | Default is 0x13, which is 19 decimal                                  |
| m=65536  | Memory size in KiB     | Valid range: 8\*Parallelism .. 0x7fffffff, and must be a power of two |
| p=4      | Parallelization Factor | 1-0x00ffffff                                                          |
| salt     | base64 encoded salt    | 0-16 bytes decoded                                                    |
| hash     | base64 encoded hash    | 32-bytes                                                              |

## HDArgon2

HDArgon2 é uma implementação da DLL do Argon2. DLL foi gerada com os arquivos do repositório https://github.com/P-H-C/phc-winner-argon2.

Support: rtinformatica.ti@gmail.com

## Instalação

#### Para instalar em seu projeto usando [boss](https://github.com/HashLoad/boss):

```sh
$ boss install github.com/Rtrevisan20/Argon2_4D
```

#### Instalação Manual

Adicione as seguintes pastas ao seu projeto, em _Project > Options > Delphi Compiler > Search path_

```
../hdargon2/src
```

#### **Uses necessárias**

```
uses HDArgon2.ForD;
```

## **Funções e propriedades**

**Properts**

```
Iterations  = Quantidade de interações
Memory      = Quantidade de memória que será usada em KiB
Parallelism = Quantidade de Threads
```

**Functions**

```
GenerateHash(const aPass: string): string;
VerifyPassword(const aHash, aPass: string): boolean;
IdHashEncoded(const aPass: string): string;
HashEncodedVerify(const aHash, aPass: string): boolean;
```

## Como usar

A DLL testada foi compilada no dia 05/03/2026 na arquitetura X64. Copie a DLL libargon2.dll para a pasta do seu executável do seu sistema, e é só usar a biblioteca.

- Gerando o hash

```delphi
  TArgon2.Iterations  := 4;
  TArgon2.Memory      := 65536 ou 128*1024; //65 mb ou 128 mb
  TArgon2.Parallelism := 4;
  var hash := TArgon2.GenerateHash('SuaSenhaSuperSegura');
```

- Validando a senha com o Hash

```delphi
  if TArgon2.VerifyPassword('HashSalvoNoBancoDeDados', 'SuaSenhaSuperSegura') then
    ShowMessage('Senha está correta') else
    ShowMessage('A senha não est correta');
```
