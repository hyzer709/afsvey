# Unic Client — Servidor de Licenças (Supabase / Postgres)

Servidor próprio para gerenciar as keys, com o banco no **Supabase** (grátis,
Postgres de verdade — não perde as licenças). Faz: geração de chaves únicas,
**1 device por key** (HWID), validação automática, revogar/renovar/expirar/
desvincular, e um **painel admin** web.

> O servidor é **stateless**: todos os dados ficam no Supabase. Por isso ele
> roda em qualquer host (mesmo grátis), sem medo de perder as keys.

---

## 1) Criar o banco no Supabase

1. Crie uma conta em supabase.com e um **New project** (escolha uma senha de banco — guarde).
2. No projeto, clique em **Connect** (topo) → **Connection string** →
   **Connection pooling** → modo **Session**.
3. Copie a URI (troque SENHA pela senha do banco). Ela se parece com:
   `postgresql://postgres.SEU_REF:SENHA@aws-0-REGIAO.pooler.supabase.com:5432/postgres`
   **Essa é a sua DATABASE_URL.**

Não precisa criar tabela à mão — o servidor cria a tabela `licenses` sozinho.

> Use a string do **pooler** (pooler.supabase.com). Funciona em hosts IPv4
> (a conexão "direta" db.SEU_REF.supabase.co pode não conectar em alguns hosts).

---

## 2) Onde hospedar o servidor (grátis)

Recomendado: **Koyeb** (koyeb.com) — instância grátis que **não dorme** e
geralmente não pede cartão. Alternativas: **Fly.io**, **Railway**.

### Passo a passo no Koyeb
1. Suba esta pasta num repositório no **GitHub**.
2. No Koyeb: **Create Web Service** → **GitHub** → escolha o repositório.
3. Run command: `node server.js`.
4. Em **Environment variables**, adicione:
   - `DATABASE_URL` = a URI do Supabase (passo 1)
   - `ADMIN_TOKEN`  = uma senha forte (painel admin)
   - `SIGN_SECRET`  = um segredo aleatório
5. Deploy. Você recebe uma URL pública tipo `https://seu-app.koyeb.app`.

> Ofertas de plano grátis mudam com o tempo — confira os limites atuais do host.

---

## 3) Usar localmente (opcional)

Node 16+.
```
npm install
DATABASE_URL="sua-uri-supabase" ADMIN_TOKEN=seu-token SIGN_SECRET=seu-segredo node server.js
```
Abra http://localhost:8090/admin, cole o ADMIN_TOKEN e gere keys.

| Variável       | Padrão     | Função                                          |
|----------------|------------|-------------------------------------------------|
| DATABASE_URL   | (obrigat.) | Connection string do Supabase/Postgres          |
| ADMIN_TOKEN    | (troque!)  | Senha do painel/admin                           |
| SIGN_SECRET    | (troque!)  | Segredo que assina as respostas (HMAC)          |
| PORT           | 8090       | Porta (hosts costumam injetar automaticamente)  |
| PGSSL          | (ligado)   | Defina `disable` só p/ Postgres local sem SSL   |

---

## Endpoints

Públicos (app): `POST /api/activate`, `POST /api/validate`, `GET /api/health`
Admin (header `Authorization: Bearer <ADMIN_TOKEN>`):
`/admin/genkey {days,count,note}`, `/admin/list`, `/admin/revoke {key}`,
`/admin/unrevoke {key}`, `/admin/renew {key,days}`, `/admin/unbind {key}`,
`/admin/delete {key}`

---

## Próximo passo (integração no app)

Quando o servidor estiver no ar, me passe a URL pública (ex.:
`https://seu-app.koyeb.app`). Eu ploto o UnicClient.exe para ativar em
`/api/activate` e revalidar em `/api/validate`, com tolerância offline.
