# Integrare un'applicazione Ruby on Rails esistente

Questa guida spiega come collegare un'applicazione Rails esistente alla piattaforma IAM. L'obiettivo è:

1. fare l'accesso con SPID, CIE, passkey o password tramite la piattaforma;
2. ricevere nell'applicazione i dati che arrivano da SPID e CIE (nome, cognome, codice fiscale, data di nascita, livello di garanzia);
3. collegare questi dati agli utenti che l'applicazione ha già;
4. passare l'identità dell'utente alle API interne in modo sicuro.

Gli esempi usano lo stack locale di `make dev`. In produzione cambiano solo gli URL e i segreti.

## 1. Come funziona

L'applicazione Rails è un **client OpenID Connect** di Ory Hydra. Non parla mai con SPID o CIE. Il broker di federazione è l'unico Relying Party SPID/CIE, e la piattaforma consegna all'applicazione un ID token OIDC standard.

```
Browser ──► Rails ──(1) redirect /oauth2/auth──► Hydra ──► login-consent ──► Kratos ──► broker ──► IdP SPID/CIE
   ▲                                                                                                     │
   └──(2) redirect /auth/iam/callback?code=...◄─────────────────────────────────────────────────────────┘
Rails ──(3) POST /oauth2/token (code + PKCE + client secret)──► Hydra
Rails ◄──(4) id_token (dati SPID/CIE) + access_token + refresh_token
```

Per questo motivo:

- in Rails non servono librerie SPID, metadati SAML o certificati della federazione;
- basta una libreria OpenID Connect standard;
- se domani si aggiunge un altro metodo di accesso, Rails non cambia.

## 2. Registrare il client in Hydra

Crea un client **confidenziale** dalla console di amministrazione (**Client OAuth2 → Registra nuova applicazione**, `http://localhost:3100/clients`) con questi valori:

| Campo | Valore di esempio |
|---|---|
| Nome | `Gestionale Rails` |
| Tipo | Confidenziale (`client_secret_basic`) |
| Redirect URI | `http://localhost:3000/auth/iam/callback` |
| Post-logout redirect URI | `http://localhost:3000/` |
| Scope | `openid offline_access profile email fiscal_number` |
| Audience | l'API che Rails deve chiamare, se c'è (es. `api-previdenza`) |
| LoA minimo | `urn:iam:loa:substantial` se l'applicazione accetta solo SPID livello 2 o superiore, o CIE |

Copia il `client_id` e il `client_secret`: la console mostra il secret una sola volta.

Per le regole sugli URL autorizzati e sulla gestione di più sistemi, vedi il [README §9](../../README.md#più-applicazioni-chi-può-ricevere-le-callback).

## 3. I dati che l'applicazione riceve

I claim sono nell'**ID token** e dipendono dagli scope che l'utente ha autorizzato. La pagina di consenso permette all'utente di togliere uno scope, quindi l'applicazione deve accettare che un claim manchi.

| Claim | Scope | Contenuto |
|---|---|---|
| `sub` | `openid` | Identificativo stabile dell'utente nella piattaforma. **Usalo come chiave**. |
| `loa` | sempre | Livello di garanzia di **questo** accesso: `urn:iam:loa:none`, `low`, `substantial`, `high`. Vale anche come `acr`. |
| `idp` | sempre, se federato | `spid` o `cie`. Manca per password e passkey. |
| `federated_acr` | sempre, se federato | ACR originale della federazione (es. `https://www.spid.gov.it/SpidL2`). |
| `identity_verified` | sempre | `true` se l'account ha attributi verificati da un accesso SPID/CIE, anche precedente. |
| `given_name`, `family_name`, `name` | `profile` | Dai dati SPID/CIE verificati, se presenti; altrimenti dai dati inseriti dall'utente. |
| `birthdate` | `profile` | Solo da dati SPID/CIE verificati. |
| `email`, `email_verified` | `email` | Email dell'account. |
| `fiscal_number` | `fiscal_number` | Codice fiscale, **solo** se viene da un accesso SPID/CIE verificato. Il broker lo normalizza: maiuscolo, senza il prefisso `TINIT-` (es. `RSSMRA80A01H501U`). |

Esempio di ID token dopo un accesso SPID livello 2:

```json
{
  "iss": "http://localhost:4444/",
  "sub": "5d1e0c8e-2b7a-4f0e-9a51-2f7c1f0b9e11",
  "aud": ["gestionale-rails"],
  "acr": "urn:iam:loa:substantial",
  "amr": ["spid"],
  "loa": "urn:iam:loa:substantial",
  "idp": "spid",
  "federated_acr": "https://www.spid.gov.it/SpidL2",
  "identity_verified": true,
  "given_name": "Mario",
  "family_name": "Rossi",
  "name": "Mario Rossi",
  "birthdate": "1980-01-01",
  "email": "mario.rossi@example.it",
  "email_verified": true,
  "fiscal_number": "RSSMRA80A01H501U"
}
```

Due regole importanti:

- `loa` descrive l'accesso, non la persona. Un accesso con password ha sempre `loa = urn:iam:loa:none`, anche se l'utente ha usato SPID il giorno prima. In quel caso `identity_verified` è `true`, ma il livello resta `none`.
- Se un'operazione richiede un'identità verificata **adesso**, controlla `loa`. Non usare `identity_verified` per questo scopo.

Il modello completo è in [`docs/security/assurance-levels.md`](../security/assurance-levels.md).

## 4. Installare le gem

```ruby
# Gemfile
gem "omniauth", "~> 2.1"
gem "omniauth_openid_connect", "~> 0.8"
gem "omniauth-rails_csrf_protection", "~> 1.0"
```

```sh
bundle install
```

`omniauth-rails_csrf_protection` obbliga a fare partire il login con una richiesta `POST`. Non toglierla: protegge dal login CSRF.

## 5. Configurare OmniAuth

Metti i segreti nelle credentials di Rails, non nel codice:

```sh
bin/rails credentials:edit
```

```yaml
iam:
  issuer: http://localhost:4444/
  client_id: gestionale-rails
  client_secret: "<secret mostrato dalla console>"
  redirect_uri: http://localhost:3000/auth/iam/callback
```

```ruby
# config/initializers/omniauth.rb
iam = Rails.application.credentials.iam
issuer = URI(iam[:issuer])

Rails.application.config.middleware.use OmniAuth::Builder do
  provider :openid_connect,
    name: :iam,
    issuer: iam[:issuer],                 # con la barra finale: deve essere uguale all'issuer di Hydra
    discovery: issuer.scheme == "https",  # in locale (http) gli endpoint sono scritti a mano, vedi sotto
    response_type: :code,
    pkce: true,
    send_nonce: true,
    client_auth_method: :basic,
    scope: %i[openid offline_access profile email fiscal_number],
    # Parametri che un link interno può passare a /auth/iam (step-up, vedi §8)
    allow_authorize_params: %i[acr_values max_age prompt],
    post_logout_redirect_uri: "http://localhost:3000/",
    client_options: {
      identifier: iam[:client_id],
      secret: iam[:client_secret],
      redirect_uri: iam[:redirect_uri],
      scheme: issuer.scheme,
      host: issuer.host,
      port: issuer.port,
      authorization_endpoint: "/oauth2/auth",
      token_endpoint: "/oauth2/token",
      userinfo_endpoint: "/userinfo",
      jwks_uri: URI.join(iam[:issuer], ".well-known/jwks.json").to_s, # URL completo: la gem lo scarica
      end_session_endpoint: "/oauth2/sessions/logout",
    }
end

OmniAuth.config.allowed_request_methods = %i[post]
OmniAuth.config.on_failure = proc { |env| SessionsController.action(:failure).call(env) }
```

Note:

- In produzione l'issuer è `https://...`: la discovery è attiva e gli endpoint arrivano da `/.well-known/openid-configuration`.
- In locale l'issuer è `http://localhost:4444/`. Le librerie OIDC per Ruby fanno la discovery solo su HTTPS, quindi gli endpoint sono scritti a mano.
- Se Rails gira **dentro** Docker, `localhost:4444` non punta a Hydra. Il browser deve usare `localhost:4444` e il backend deve raggiungere lo stesso indirizzo. Avvia Rails sull'host oppure usa `network_mode: host`. Non cambiare l'issuer: deve essere uguale a quello di Hydra.

## 6. Rotte, controller e utenti

### Rotte

```ruby
# config/routes.rb
get  "/auth/iam/callback", to: "sessions#create"
get  "/auth/failure",      to: "sessions#failure"
delete "/logout",          to: "sessions#destroy"
```

### Pulsante di accesso

```erb
<%= button_to "Accedi con SPID, CIE o credenziali", "/auth/iam", method: :post, data: { turbo: false } %>
```

`data: { turbo: false }` serve perché il login fa un redirect verso un altro dominio.

### Migrazione

Aggiungi alla tabella degli utenti esistenti le colonne che servono. Salva solo i dati che l'applicazione usa davvero (minimizzazione, GDPR).

```ruby
class AddIamToUsers < ActiveRecord::Migration[7.2]
  def change
    add_column :users, :iam_sub, :string
    add_column :users, :fiscal_number, :string
    add_column :users, :birthdate, :date
    add_column :users, :identity_verified_at, :datetime
    add_column :users, :last_loa, :string
    add_column :users, :last_idp, :string
    add_index  :users, :iam_sub, unique: true
    add_index  :users, :fiscal_number, unique: true
  end
end
```

### Controller

```ruby
# app/controllers/sessions_controller.rb
class SessionsController < ApplicationController
  skip_before_action :require_login, only: %i[create failure], raise: false

  LOA_RANK = {
    "urn:iam:loa:none" => 0, "urn:iam:loa:low" => 1,
    "urn:iam:loa:substantial" => 2, "urn:iam:loa:high" => 3,
  }.freeze
  MIN_LOA = "urn:iam:loa:none" # metti "urn:iam:loa:substantial" se accetti solo SPID L2+ / CIE

  def create
    auth = request.env.fetch("omniauth.auth")
    claims = id_token_claims(auth)

    if LOA_RANK.fetch(claims["loa"], -1) < LOA_RANK.fetch(MIN_LOA)
      return redirect_to root_path, alert: "Questo servizio richiede un accesso con SPID o CIE."
    end

    user = IamUserLinker.call(claims)
    return redirect_to root_path, alert: "Nessun account associato. Contatta l'assistenza." unless user

    reset_session # evita la session fixation
    session[:user_id] = user.id
    session[:loa] = claims["loa"]
    session[:auth_time] = claims["auth_time"]
    session[:id_token] = auth.credentials.id_token          # serve per il logout
    session[:refresh_token] = auth.credentials.refresh_token # solo se Rails chiama API per conto dell'utente
    redirect_to session.delete(:return_to) || root_path
  end

  def failure
    redirect_to root_path, alert: "Accesso non riuscito (#{params[:message]})."
  end

  def destroy
    id_token = session[:id_token]
    reset_session
    redirect_to iam_logout_url(id_token), allow_other_host: true
  end

  private

  # omniauth_openid_connect ha già verificato firma, issuer, audience, scadenza e nonce
  # dell'ID token. Qui leggiamo solo i claim, senza una seconda verifica.
  def id_token_claims(auth)
    payload = JSON::JWT.decode(auth.credentials.id_token, :skip_verification)
    auth.extra.raw_info.to_h.merge(payload.to_h).stringify_keys
  end

  def iam_logout_url(id_token)
    iam = Rails.application.credentials.iam
    query = { id_token_hint: id_token, post_logout_redirect_uri: "http://localhost:3000/" }.compact
    URI.join(iam[:issuer], "oauth2/sessions/logout").tap { |u| u.query = query.to_query }.to_s
  end
end
```

Con lo store di sessione a cookie, l'ID token e il refresh token rendono il cookie grande e lo mandano al browser. In produzione usa uno store lato server (`activerecord-session_store` o Redis), oppure salva i token in una tabella cifrata.

### Collegare gli utenti esistenti

Questo è il punto più delicato. La regola: **il collegamento automatico si fa solo con il codice fiscale verificato da SPID/CIE**, mai con l'email da sola. L'email è un dato che l'utente può inserire da solo durante la registrazione.

```ruby
# app/services/iam_user_linker.rb
class IamUserLinker
  FEDERATED = %w[spid cie].freeze

  def self.call(claims) = new(claims).call

  def initialize(claims)
    @claims = claims
  end

  def call
    User.transaction do
      user = User.find_by(iam_sub: sub) || link_by_fiscal_number
      return nil unless user

      user.update!(attributes_from_claims(user))
      user
    end
  end

  private

  def sub = @claims.fetch("sub")
  def federated? = FEDERATED.include?(@claims["idp"])
  def fiscal_number = federated? ? @claims["fiscal_number"].presence : nil

  # Primo accesso: cerca l'utente esistente per codice fiscale, solo se viene da SPID/CIE.
  def link_by_fiscal_number
    return nil unless fiscal_number

    user = User.find_by(fiscal_number: fiscal_number, iam_sub: nil)
    user&.tap { _1.iam_sub = sub }
  end

  def attributes_from_claims(user)
    attrs = { iam_sub: sub, last_loa: @claims["loa"], last_idp: @claims["idp"] }
    if federated?
      # Dati verificati: possono aggiornare l'anagrafica.
      attrs[:fiscal_number] = fiscal_number if fiscal_number
      attrs[:first_name] = @claims["given_name"] if @claims["given_name"]
      attrs[:last_name] = @claims["family_name"] if @claims["family_name"]
      attrs[:birthdate] = @claims["birthdate"] if @claims["birthdate"]
      attrs[:identity_verified_at] = Time.current
    end
    attrs[:email] = @claims["email"] if @claims["email_verified"] && user.email.blank?
    attrs
  end
end
```

Comportamento:

| Caso | Risultato |
|---|---|
| L'utente ha già fatto l'accesso una volta | Trovato per `sub`. I dati SPID/CIE aggiornano l'anagrafica. |
| Primo accesso con SPID/CIE, codice fiscale già presente in Rails | Collegato per codice fiscale. Da qui in avanti è trovato per `sub`. |
| Primo accesso con password, nessun collegamento | Nessun utente. Chiedi all'utente di accedere la prima volta con SPID/CIE, oppure prevedi un collegamento manuale. |
| Il codice fiscale è già collegato a un altro `sub` | Nessun collegamento automatico (`iam_sub: nil` nella ricerca). Serve un controllo manuale. |

Se l'applicazione deve creare utenti nuovi al primo accesso, aggiungi un `User.create!` in `link_by_fiscal_number` per i soli accessi federati.

### Proteggere le pagine

```ruby
# app/controllers/application_controller.rb
class ApplicationController < ActionController::Base
  before_action :require_login

  private

  def current_user = @current_user ||= User.find_by(id: session[:user_id])
  helper_method :current_user

  def require_login
    return if current_user

    session[:return_to] = request.fullpath if request.get?
    redirect_to root_path, alert: "Accedi per continuare."
  end
end
```

## 7. Passare l'identità alle API interne

Se Rails chiama un'API interna per conto dell'utente, **non mandare i claim** (nome, codice fiscale) come parametri o header. L'API non può verificarli. Manda l'**access token** di Hydra: l'API lo verifica da sola.

1. Registra l'API come audience (es. `api-previdenza`) e aggiungila al campo **Audience** del client Rails.
2. Chiedi l'audience nel login: aggiungi `extra_authorize_params: { audience: "api-previdenza" }` alla configurazione OmniAuth.
3. Chiama l'API con `Authorization: Bearer <access_token>`. Quando l'access token scade (15 minuti), rinnovalo con il refresh token.

```ruby
# app/services/iam_tokens.rb
class IamTokens
  def self.refresh!(session)
    iam = Rails.application.credentials.iam
    res = Faraday.new(url: iam[:issuer]) { _1.request :authorization, :basic, iam[:client_id], iam[:client_secret] }
      .post("oauth2/token", grant_type: "refresh_token", refresh_token: session[:refresh_token])
    raise "refresh failed: #{res.status}" unless res.success?

    body = JSON.parse(res.body)
    session[:access_token] = body.fetch("access_token")
    session[:refresh_token] = body["refresh_token"] || session[:refresh_token] # Hydra ruota il refresh token
    session[:access_token_expires_at] = Time.current.to_i + body.fetch("expires_in").to_i
  end
end
```

Se l'API interna è anch'essa in Rails, verifica l'access token con la gem `jwt` e le chiavi pubbliche di Hydra:

```ruby
# app/controllers/concerns/iam_bearer_auth.rb
module IamBearerAuth
  extend ActiveSupport::Concern
  ISSUER = "http://localhost:4444/"
  AUDIENCE = "api-previdenza"

  included { before_action :authenticate_bearer! }

  private

  def authenticate_bearer!
    token = request.authorization.to_s.delete_prefix("Bearer ")
    @token, = JWT.decode(token, nil, true,
      algorithms: %w[RS256 ES256], iss: ISSUER, verify_iss: true,
      aud: AUDIENCE, verify_aud: true,
      jwks: ->(opts) { jwks(force: opts[:kid_not_found]) })
  rescue JWT::DecodeError
    head :unauthorized
  end

  def jwks(force: false)
    Rails.cache.fetch("iam_jwks", expires_in: 10.minutes, force: force) do
      JSON.parse(Faraday.get(URI.join(ISSUER, ".well-known/jwks.json")).body, symbolize_names: true)
    end
  end

  # Nell'access token i claim della piattaforma sono sotto "ext": loa, amr, idp, auth_time.
  def token_loa = @token.dig("ext", "loa")
end
```

Il token non contiene il codice fiscale: l'API usa `sub` per trovare l'utente. Se l'API deve verificare che un token sia ancora attivo (non revocato), usa l'introspection di Hydra sulla porta admin `4445`, come fa `services/demo-api`.

## 8. Step-up: chiedere un livello più alto per un'operazione

Per un'operazione sensibile (per esempio una domanda di prestazione), chiedi un nuovo accesso con livello alto. La piattaforma manda l'utente a SPID livello 3 o a CIE.

```erb
<%= button_to "Conferma con SPID L3 o CIE", "/auth/iam",
      params: { acr_values: "urn:iam:loa:high", max_age: 0, prompt: "login consent" },
      method: :post, data: { turbo: false } %>
```

Al ritorno, il controller deve controllare che `loa` sia davvero `urn:iam:loa:high` e che `auth_time` sia recente. Non fidarti del solo fatto che l'hai chiesto:

```ruby
def require_high_loa!(max_age: 5.minutes)
  ok = session[:loa] == "urn:iam:loa:high" && session[:auth_time].to_i >= max_age.ago.to_i
  # step_up_path: una pagina con il pulsante "Conferma con SPID L3 o CIE"
  redirect_to step_up_path, alert: "Serve un accesso con SPID livello 3 o CIE." unless ok
end
```

## 9. Logout

`SessionsController#destroy` cancella la sessione Rails e manda il browser a `/oauth2/sessions/logout` di Hydra con `id_token_hint`. La piattaforma chiede conferma e chiude la sessione per **tutte** le applicazioni. Poi riporta l'utente all'URL `post_logout_redirect_uri`, che deve essere registrato nel client.

Il logout back-channel (Hydra che avvisa Rails quando l'utente esce da un'altra applicazione) oggi non è configurato. Per ora tieni corta la durata della sessione Rails, oppure controlla periodicamente il refresh token: dopo il logout globale Hydra lo rifiuta.

## 10. Prova in locale

1. Avvia la piattaforma con `make dev`.
2. Registra il client come in §2 e scrivi le credentials come in §5.
3. Avvia Rails sull'host: `bin/rails server -p 3000`.
4. Clicca **Accedi**, scegli **Accedi con SPID** e un IdP del simulatore `fedsim`. Gli utenti di test sono in [README §8.1](../../README.md#81-il-simulatore-fedsim).
5. Dopo il ritorno, verifica in console Rails: `User.last.slice(:iam_sub, :fiscal_number, :last_loa, :last_idp)`.

Se Hydra risponde con `invalid_request` e il messaggio parla di `redirect_uri`, l'URL della callback non è uguale a quello registrato nel client. Il confronto è esatto, carattere per carattere.

## 11. Prima della produzione

- [ ] Issuer e callback in HTTPS. Discovery attiva.
- [ ] `client_secret` nelle credentials cifrate o in un secret manager. Un client diverso per ogni ambiente.
- [ ] `MIN_LOA` e `metadata.min_loa` del client coerenti con il servizio.
- [ ] Nessun token e nessun codice fiscale nei log di Rails: aggiungi `:id_token, :access_token, :refresh_token, :code, :fiscal_number` a `config.filter_parameters`.
- [ ] Store di sessione lato server; cookie `secure`, `httponly`, `SameSite=Lax`.
- [ ] Collegamento degli account esistenti provato anche nei casi di conflitto (§6).
- [ ] Valutazione del DPO sui dati SPID/CIE che l'applicazione salva e per quanto tempo.
