# MASTER PROMPT — Build a Complete Self-Hosted IAM Platform with Ory, SPID and CIE

## ROLE AND OBJECTIVE

Act as a principal identity architect, senior Go/TypeScript engineer, OAuth2/OIDC federation specialist, DevSecOps engineer, and security reviewer.

Your task is to **design, implement, test, document, and prepare for production deployment a complete self-hosted Identity and Access Management platform** based on the Ory ecosystem, with native integration capabilities for Italian SPID and CIE digital identities.

You are working as an autonomous coding agent inside a repository.

**Do not stop after producing architecture diagrams, documentation, scaffolding, or examples. Implement the actual working system.**

Work incrementally, execute commands, write code, run tests, fix failures, and maintain a clear record of completed work.

The final result must be a working repository, not a proof-of-concept consisting of mocked authentication flows.

Local development may use simulated identity providers, but production federation code must use real protocol implementations and cryptographic validation.

Never claim that the system is certified, accredited, compliant, or production-ready without corresponding evidence.

---

## 1. PRIMARY GOALS

Build an IAM platform that provides:

1. Centralized user authentication and identity management.
2. OAuth2 and OpenID Connect authorization services.
3. SPID authentication.
4. CIE authentication.
5. Password and passkey authentication through Ory Kratos.
6. A unified identity for each user.
7. Secure identity linking across authentication methods.
8. Authentication assurance level preservation.
9. Single Sign-On across multiple applications.
10. OAuth2 access tokens, refresh tokens, and ID tokens.
11. API authorization and token validation.
12. An administrative interface.
13. An end-user account management interface.
14. Comprehensive audit logging.
15. Automated tests and local federation simulators.
16. Docker Compose development infrastructure.
17. Kubernetes deployment infrastructure.
18. Security hardening and operational documentation.

The system must be designed for multiple applications and APIs.

Support a future multi-tenant architecture without making multi-tenancy an unnecessary dependency of the initial implementation.

## 2. TECHNOLOGY STACK

Use the following technologies unless investigation reveals a concrete incompatibility.

### Core identity

- Ory Kratos for identity and session management.
- Ory Hydra for OAuth2 and OIDC authorization.
- Ory Polis as the preferred federation component, subject to a technical compatibility assessment.
- A custom SPID/CIE federation adapter where Polis lacks required functionality.
- Ory Oathkeeper only if it provides a demonstrable benefit for API protection.
- Ory Keto only if fine-grained relationship-based authorization is actually required.

Do not introduce unnecessary Ory components merely for completeness.

### Application development

- TypeScript with strict type checking.
- Node.js LTS.
- Fastify for backend HTTP services.
- React and Next.js for user-facing applications.
- Go for federation or cryptographic components when suitable.
- OpenAPI for service contracts.
- Zod or an equivalent validation library.

### Infrastructure

- PostgreSQL.
- Docker Compose.
- Kubernetes and Helm.
- Reverse proxy or ingress controller.
- OpenTelemetry.
- Prometheus-compatible metrics.
- Structured JSON logging.
- Secrets supplied through environment variables or a secrets manager.

Use separate database schemas or databases for independently managed services.

Do not expose Ory administrative APIs publicly.

## 3. FIRST TASK: RESEARCH AND VALIDATE THE ARCHITECTURE

Before implementing the federation layer, inspect the current documentation and source code of:

- Ory Kratos.
- Ory Hydra.
- Ory Polis.
- SPID OpenID Connect specifications.
- CIE OpenID Connect specifications.
- OpenID Connect Federation 1.0.
- Applicable Italian federation regulations.

Official sources:

https://github.com/ory/kratos

https://github.com/ory/hydra

https://github.com/ory/polis

https://www.ory.com/docs/

https://docs.italia.it/italia/spid/spid-cie-oidc-docs/it/versione-corrente/index.html

https://www.agid.gov.it/it/piattaforme/spid.html

Verify the current normative versions and identify any newer binding specifications.

Create:

`docs/architecture/federation-compatibility.md`

This document must contain a compatibility matrix covering:

- Generic SAML 2.0.
- Generic OpenID Connect.
- SPID SAML profile.
- SPID OIDC profile.
- CIE OIDC profile.
- OpenID Connect Federation 1.0.
- Entity Statements.
- Trust chain validation.
- Trust Anchors.
- Trust Marks.
- Metadata policies.
- Dynamic client registration.
- Signed authentication requests.
- Supported authentication assurance levels.
- Attribute validation.
- Cryptographic key rotation.
- Federation revocation and trust updates.

For each capability, indicate:

- Supported natively.
- Supported through configuration.
- Requires custom implementation.
- Unsupported.
- Not yet verified.

Reference the source code, documentation, specification section, and version used for every important conclusion.

**Never assume that Ory Polis is automatically compatible with SPID or CIE because it supports SAML or OIDC.**

Determine whether to:

A. Extend Ory Polis.

B. Build a standalone federation adapter integrated with Polis.

C. Implement a standalone SPID/CIE broker exposing a compatible OIDC interface to Kratos.

Prefer the solution with the smallest security-sensitive custom implementation and the clearest maintenance path.

If Polis is unsuitable, do not force its inclusion.

Record the decision in an Architecture Decision Record.

## 4. TARGET ARCHITECTURE

The intended authentication flow is:

Application
→ Ory Hydra
→ Login and Consent Service
→ Ory Kratos
→ Federation Integration Layer
→ SPID or CIE Identity Provider

The reverse path must return a validated identity to Kratos and complete the Hydra authorization flow.

Hydra must remain responsible for OAuth2/OIDC authorization and token issuance.

Kratos must remain responsible for local identities and application authentication sessions.

The federation integration layer must remain responsible for SPID/CIE federation protocols, external authentication validation, and trusted identity claims.

Do not use Hydra as a replacement for a federation Relying Party.

Do not bypass Kratos identity management by maintaining a completely separate user directory.

Design explicit trust boundaries between all services.

## 5. REPOSITORY STRUCTURE

Create a monorepo with a structure similar to:

    apps/
      login-consent/
      identity-portal/
      admin-console/
      demo-web/

    services/
      federation-broker/
      identity-service/
      audit-service/

    packages/
      shared-types/
      oidc-client/
      auth-sdk/
      ui/
      config/

    infrastructure/
      docker/
      kubernetes/
      helm/
      postgres/
      observability/

    config/
      kratos/
      hydra/
      polis/
      federation/

    tests/
      unit/
      integration/
      e2e/
      security/
      conformance/
      fixtures/

    docs/
      architecture/
      federation/
      security/
      operations/
      deployment/
      compliance/

    scripts/

    .github/workflows/

    Makefile
    README.md
    .env.example

Adjust this structure when necessary, but maintain clear service boundaries.

## 6. IMPLEMENT ORY KRATOS

Deploy and configure Ory Kratos.

Implement:

- Identity schemas.
- User registration.
- Login.
- Logout.
- Password recovery.
- Email verification.
- Passkeys/WebAuthn where supported.
- Session management.
- Session invalidation.
- Account settings.
- Identity lookup.
- External identity integration.
- Secure account linking.

Create a user-facing account portal that allows users to:

- View their profile.
- See linked authentication methods.
- Link an additional identity provider.
- Remove eligible linked methods safely.
- Manage active sessions.
- Log out of active sessions.

Do not allow an account to be locked out by removing its final usable authentication method without a verified alternative.

Keep authentication credentials and sensitive identity metadata protected.

## 7. IMPLEMENT ORY HYDRA

Deploy and configure Ory Hydra.

Implement:

- OAuth2 Authorization Code Flow.
- PKCE.
- OpenID Connect.
- Refresh token rotation where supported.
- Token revocation.
- Token introspection.
- Client registration through controlled administrative APIs.
- Confidential clients.
- Public clients.
- Client Credentials Flow for machine-to-machine authentication.
- Scopes and audiences.
- OIDC discovery.
- JWKS.
- Consent handling.
- Logout handling.

Implement a complete Login and Consent Service.

The service must:

1. Receive Hydra login challenges.
2. Inspect the authentication request.
3. Validate the Kratos session.
4. Redirect unauthenticated users to Kratos.
5. Resume the original Hydra flow safely.
6. Accept or reject login challenges through Hydra's administrative API.
7. Handle consent challenges.
8. Enforce client-specific scopes and audiences.
9. Complete the authorization flow.
10. Support logout and session expiration.

Use the Kratos identity UUID as the canonical internal subject unless a documented privacy or pairwise-subject design requires a different approach.

Handle `prompt`, `max_age`, `acr_values`, `auth_time`, and relevant OIDC parameters correctly.

Do not automatically translate a normal Kratos session into a high-assurance SPID/CIE authentication.

## 8. IMPLEMENT THE SPID/CIE FEDERATION LAYER

This is a critical component.

Implement the current applicable Italian OpenID Connect Federation requirements.

Do not implement only generic OIDC and label it SPID/CIE compatible.

The federation layer must support, where required by the selected profiles:

- Federation Entity Configuration.
- The `.well-known/openid-federation` endpoint.
- Signed Entity Statements.
- Trust Anchor configuration.
- Trust chain construction.
- Trust chain verification.
- Federation metadata.
- Metadata policies.
- Trust Marks.
- Federation API operations.
- Dynamic Relying Party registration.
- Authentication request generation.
- Authentication response validation.
- Authorization Code Flow.
- PKCE where required.
- Signed Request Objects.
- PAR where required.
- JARM where required.
- ID token validation.
- UserInfo validation.
- Cryptographic key management.
- Key rotation.
- Trust revocation handling.
- Authentication context validation.
- Attribute normalization.

Determine exact mandatory and optional features from the current SPID/CIE specifications.

Do not assume every standard OAuth2 feature is allowed by the Italian profiles.

Use mature, maintained cryptographic libraries.

Never implement JWT signature algorithms, XML signature verification, or cryptographic primitives from scratch.

Reject:

- Invalid signatures.
- Expired tokens.
- Incorrect issuers.
- Incorrect audiences.
- Invalid nonce.
- Invalid state.
- Replayed authentication responses.
- Invalid or untrusted federation chains.
- Expired or revoked trust information.
- Unsupported algorithms.
- Invalid authentication contexts.
- Unexpected redirect URIs.

Fail closed when federation trust cannot be established.

Implement separate SPID and CIE provider configurations.

Provide a federation configuration schema that supports test and production environments without changing application code.

## 9. SPID AND CIE USER EXPERIENCE

The login page must display:

- Accedi con SPID.
- Entra con CIE.
- Accedi con passkey.
- Other enabled authentication methods.

Use the official SPID/CIE branding only according to the applicable rules.

The SPID flow must support identity-provider selection when required.

The CIE flow must support the authentication methods actually exposed by the selected CIE integration.

Do not invent a custom CIE NFC authentication protocol.

The application must redirect users to the official identity provider or authorized testing environment.

Provide clear handling of:

- Authentication cancellation.
- Session expiration.
- Identity provider unavailability.
- Missing attributes.
- Insufficient authentication assurance.
- Account-linking conflicts.
- Federation validation failures.

Never expose sensitive tokens, assertions, or personal identity data in browser-visible error messages.

## 10. IDENTITY NORMALIZATION AND ACCOUNT LINKING

Create a canonical internal identity model.

The model must distinguish:

- Internal Kratos identity UUID.
- External identity provider.
- External issuer.
- External subject.
- Authentication method.
- Authentication time.
- Authentication assurance level.
- Verified identity attributes.
- Attribute provenance.
- Verification timestamp.
- Account-linking state.

Support Italian identity attributes where permitted and necessary, including:

- Given name.
- Family name.
- Fiscal code.
- Date of birth.
- Email address.
- Other attributes supported by the applicable federation profile.

Do not assume every provider returns every attribute.

Do not use email addresses as reliable unique identity keys.

Do not use the fiscal code as the Kratos primary key.

Design a separate identity-link table with appropriate unique constraints.

Prevent race conditions when two authentication flows attempt to create or link the same account.

Implement explicit account-linking workflows with:

- Reauthentication.
- Proof of control of the existing account.
- Confirmation of the new identity.
- Conflict detection.
- Audit logging.
- Recovery procedures.

Never merge accounts solely because two providers return the same email address or fiscal code.

Document the legal basis and data-minimization considerations for processing fiscal codes and other personal data.

## 11. AUTHENTICATION ASSURANCE

Implement a normalized assurance model.

Preserve the original SPID/CIE authentication context.

Support policy decisions based on:

- Authentication method.
- Authentication time.
- Assurance level.
- Requested assurance level.
- Application requirements.
- Session age.

Implement step-up authentication.

An application must be able to require a stronger authentication level for sensitive operations.

The platform must reject insufficient authentication rather than silently treating all login methods as equivalent.

Define an explicit mapping between federation-specific assurance values and internal policy levels.

Do not assume that different SPID and CIE assurance levels are interchangeable without normative support.

## 12. API SECURITY

Create a demonstration protected API.

The API must:

- Validate Hydra-issued access tokens.
- Verify issuer and audience.
- Verify expiration.
- Enforce scopes.
- Support token introspection when appropriate.
- Distinguish machine and user tokens.
- Reject unauthorized requests.
- Return correct HTTP status codes.

Implement a reusable authentication middleware or SDK for future applications.

Provide an example of a protected endpoint that requires recent high-assurance authentication.

Do not treat a valid access token as sufficient authorization to every resource.

## 13. ADMINISTRATIVE INTERFACE

Create a secure administrative console.

Required capabilities:

- View users.
- Search identities.
- Inspect linked identity providers.
- View session metadata.
- Revoke sessions.
- Manage OAuth2 clients.
- Inspect federation connection status.
- View provider health.
- Inspect authentication failures.
- Review audit events.
- View key rotation status.
- View federation trust status.

Administrative operations must require appropriate authorization.

Implement least-privilege roles.

Protect destructive operations against CSRF, privilege escalation, and accidental execution.

Never display client secrets or sensitive identity tokens after initial controlled provisioning.

## 14. AUDIT AND PRIVACY

Implement structured audit events for:

- Login success.
- Login failure.
- SPID authentication.
- CIE authentication.
- Account linking.
- Account unlinking.
- Session revocation.
- Client configuration changes.
- Administrative actions.
- Federation trust failures.
- Key rotation.

Audit records should include:

- Event identifier.
- Timestamp.
- Correlation identifier.
- Actor identifier where available.
- Event type.
- Outcome.
- Relevant service.
- Minimal security context.

Do not log raw access tokens, refresh tokens, ID tokens, authentication codes, client secrets, full federation assertions, or unnecessary personal information.

Implement configurable retention and deletion policies.

Document GDPR-related design decisions, including data minimization, retention, access control, and handling of data subject requests.

Do not claim GDPR compliance merely because these controls exist.

## 15. LOCAL DEVELOPMENT ENVIRONMENT

Create a complete Docker Compose environment.

It must include:

- Kratos.
- Hydra.
- Federation broker.
- Polis, if selected.
- Login/consent application.
- Identity service.
- PostgreSQL.
- Demo application.
- Administrative interface.
- Local test identity providers.
- Optional observability services.

The entire local environment should start with:

    make dev

Provide commands for:

    make setup
    make dev
    make migrate
    make test
    make test-e2e
    make test-security
    make lint
    make build
    make down

These commands must actually work.

Generate development-only keys and secrets securely.

Do not commit secrets to Git.

Provide an `.env.example` containing descriptions and safe placeholder values.

Use deterministic fixtures where appropriate.

## 16. LOCAL SPID/CIE TESTING

Implement or integrate suitable local federation test providers.

The test environment must support:

- Successful SPID login.
- Successful CIE login.
- Failed login.
- User cancellation.
- Missing attributes.
- Invalid authentication context.
- Expired token.
- Invalid signature.
- Untrusted issuer.
- Invalid trust chain.
- Replay attempts.
- Identity linking.
- Session expiration.

Prefer existing official or community-maintained test tools that match the current specifications.

Do not represent generic OIDC mock providers as proof of SPID/CIE federation conformance.

Clearly distinguish:

1. Generic OIDC integration tests.
2. SPID/CIE protocol integration tests.
3. Official federation conformance tests.
4. Real federation onboarding tests.

Do not use real citizens' identity data in automated tests.

## 17. TESTING REQUIREMENTS

Implement unit, integration, end-to-end, and security tests.

Required scenarios:

- Password login.
- Passkey login.
- SPID login.
- CIE login.
- Hydra authorization flow.
- OAuth2 code exchange.
- Refresh token rotation.
- Token revocation.
- API token validation.
- Account linking.
- Duplicate account prevention.
- Logout.
- Session expiration.
- Step-up authentication.
- Incorrect assurance level.
- CSRF.
- Open redirects.
- OAuth state manipulation.
- Nonce replay.
- JWT algorithm confusion.
- Invalid issuer.
- Invalid audience.
- Federation metadata tampering.
- Federation trust-chain failure.
- Concurrent account linking.

Run all available tests.

Fix failures before declaring a phase complete.

Generate coverage reports and record any untested security-critical paths.

Use real protocol validation in integration tests, not mocked verification functions.

## 18. SECURITY REQUIREMENTS

Apply current OAuth2, OIDC, OWASP, and applicable Italian federation security recommendations.

At minimum:

- HTTPS in production.
- Secure and HttpOnly cookies.
- Appropriate SameSite cookie policies.
- CSRF protection.
- PKCE.
- Strict redirect URI validation.
- State and nonce validation.
- Secure session handling.
- Token expiration.
- Refresh token protection.
- Secret rotation.
- Key rotation.
- Rate limiting.
- Request size limits.
- Input validation.
- Output encoding.
- Least privilege.
- Network segmentation.
- Container hardening.
- Dependency vulnerability scanning.
- Supply-chain security checks.

Implement protections against SSRF in federation metadata retrieval.

Restrict outbound federation requests appropriately while supporting legitimate federation endpoints.

Use safe timeouts, bounded redirects, and response size limits.

Do not disable TLS validation to make integration tests pass.

Do not use wildcard redirect URIs in production.

Do not expose Hydra or Kratos administrative endpoints through the public ingress.

## 19. KUBERNETES DEPLOYMENT

Provide production-oriented Helm charts or equivalent manifests.

Include:

- Deployments.
- Services.
- Ingress.
- ConfigMaps.
- Secret references.
- Readiness probes.
- Liveness probes.
- Resource requests and limits.
- Pod security settings.
- Network policies.
- Database migration jobs.
- Rolling update configuration.
- Persistent storage where required.
- Horizontal scaling guidance.
- TLS configuration.
- Observability integration.

Document external database requirements.

Provide a staging environment configuration.

Provide backup and disaster recovery procedures.

Do not deploy automatically to a real production environment.

## 20. CI/CD

Create GitHub Actions workflows for:

- Formatting.
- Linting.
- Type checking.
- Unit tests.
- Integration tests.
- End-to-end tests.
- Dependency scanning.
- Container image scanning.
- Build.
- Software Bill of Materials generation.
- Container publishing when configured.

Pin dependencies and actions appropriately.

Do not publish images or deploy infrastructure without explicit authorization.

## 21. DOCUMENTATION

Create complete documentation.

Required files:

    docs/architecture/overview.md
    docs/architecture/decisions.md
    docs/architecture/federation-compatibility.md
    docs/federation/spid.md
    docs/federation/cie.md
    docs/federation/onboarding.md
    docs/security/threat-model.md
    docs/security/assurance-levels.md
    docs/security/account-linking.md
    docs/operations/runbook.md
    docs/operations/key-rotation.md
    docs/operations/disaster-recovery.md
    docs/deployment/docker.md
    docs/deployment/kubernetes.md
    docs/compliance/readiness-checklist.md

Include architecture diagrams using Mermaid.

Document every environment variable.

Document the full authentication flow.

Provide API examples.

Explain how to register a new application in Hydra.

Explain how to connect a new protected API.

Explain how to configure SPID and CIE providers.

Explain which operations require official federation onboarding.

## 22. IMPLEMENTATION PHASES

Execute the work in the following phases.

### Phase 0 — Research and architecture

- Inspect the repository.
- Research current specifications.
- Verify Ory version compatibility.
- Evaluate Polis.
- Select the federation strategy.
- Create architecture documentation.
- Create a threat model.
- Identify external accreditation dependencies.

### Phase 1 — Core infrastructure

- Create monorepo.
- Configure PostgreSQL.
- Deploy Kratos.
- Deploy Hydra.
- Configure migrations.
- Establish networking.
- Implement environment management.

### Phase 2 — Authentication platform

- Implement login/consent service.
- Implement Kratos user interface.
- Implement OAuth2/OIDC flows.
- Create demo application.
- Validate end-to-end authentication.

### Phase 3 — Federation foundation

- Integrate Polis or the selected adapter.
- Implement federation interfaces.
- Implement trust management.
- Implement cryptographic validation.
- Implement metadata handling.
- Add local federation test infrastructure.

### Phase 4 — SPID

- Implement SPID-specific configuration.
- Implement required federation behavior.
- Implement identity attribute mapping.
- Implement assurance handling.
- Execute SPID test scenarios.

### Phase 5 — CIE

- Implement CIE-specific configuration.
- Implement required federation behavior.
- Implement identity attribute mapping.
- Implement assurance handling.
- Execute CIE test scenarios.

### Phase 6 — Identity management

- Implement identity normalization.
- Implement secure account linking.
- Implement account management portal.
- Implement administrative interface.
- Implement audit logging.

### Phase 7 — Security and testing

- Complete integration tests.
- Complete end-to-end tests.
- Run vulnerability scans.
- Review OAuth2/OIDC security.
- Review federation trust handling.
- Fix identified issues.

### Phase 8 — Deployment

- Implement Kubernetes manifests.
- Implement CI/CD.
- Add monitoring.
- Document operations.
- Validate staging deployment.

### Phase 9 — Production readiness assessment

- Verify the implementation against the requirements.
- Identify unresolved risks.
- Identify official federation onboarding dependencies.
- Produce an evidence-based readiness report.
- Distinguish completed engineering work from pending external approvals.

## 23. AUTONOMOUS EXECUTION RULES

You are an implementation agent, not merely an advisor.

Follow these rules:

1. Inspect the repository before making changes.
2. Use the current stable compatible versions of dependencies.
3. Verify actual APIs rather than inventing them.
4. Prefer official SDKs and maintained libraries.
5. Make changes in small, testable increments.
6. Run tests after each meaningful phase.
7. Fix errors instead of leaving them for later.
8. Keep code readable and modular.
9. Avoid unnecessary abstractions.
10. Never silently bypass security validation.
11. Never replace real cryptographic verification with mocks in production code.
12. Do not claim a feature is complete when only its interface exists.
13. Record assumptions and unresolved dependencies.
14. Do not invent federation metadata, production trust anchors, certificates, credentials, or approvals.
15. Never perform real federation onboarding or production deployment without authorization.
16. Preserve existing repository work.
17. Do not execute destructive operations against existing infrastructure without approval.
18. Keep the system runnable after each phase.

If external credentials, certificates, agreements, or federation registrations are missing, implement everything that can be implemented locally and document the exact external dependency.

Do not let missing production credentials prevent local development.

## 24. PROGRESS TRACKING

Create and maintain:

    IMPLEMENTATION_PLAN.md
    PROGRESS.md
    DECISIONS.md
    BLOCKERS.md

After each phase, record:

- Implemented functionality.
- Files changed.
- Tests executed.
- Test results.
- Security considerations.
- Remaining work.
- External dependencies.

Mark features as:

- COMPLETE
- PARTIAL
- BLOCKED
- NOT STARTED

Never mark a feature COMPLETE without corresponding implementation and verification.

## 25. ACCEPTANCE CRITERIA

The project is technically complete for local development when:

1. `make dev` starts the complete platform.
2. Kratos login works.
3. Hydra issues valid OAuth2/OIDC tokens.
4. The demo application authenticates through Hydra.
5. The login/consent service correctly integrates Hydra and Kratos.
6. SPID authentication works against an appropriate local federation test environment.
7. CIE authentication works against an appropriate local federation test environment.
8. Federation trust validation is exercised by automated tests.
9. User identities are created correctly.
10. Account linking is secure.
11. Authentication assurance information is preserved.
12. Protected APIs validate tokens.
13. Logout and revocation work as designed.
14. Administrative interfaces enforce authorization.
15. Audit events are recorded.
16. Security tests pass.
17. Kubernetes configurations validate.
18. Documentation explains installation and operation.

Production readiness additionally requires:

- Verified federation conformance.
- Appropriate official registration and onboarding.
- Production trust configuration.
- Security review.
- Operational readiness.
- Approved production credentials and certificates.
- Applicable legal and organizational requirements.

These are separate acceptance gates.

## 26. START NOW

Begin immediately.

First:

1. Inspect the current repository.
2. Identify available development tools.
3. Research and verify the current Ory and SPID/CIE specifications.
4. Produce the federation compatibility matrix.
5. Choose the implementation architecture.
6. Create the monorepo structure.
7. Implement the first working vertical slice:
   - Kratos
   - Hydra
   - Login/consent
   - Demo application
   - Working OAuth2/OIDC login

Then continue through the implementation phases.

Do not stop after the first vertical slice.

If execution context or time limits interrupt progress, leave the repository in a working state and record the exact next task in `PROGRESS.md`.

Ask for human input only when a decision cannot safely be made, a credential or external approval is required, or an irreversible action needs authorization.

**The final deliverable is a functioning, tested, documented self-hosted IAM platform with SPID/CIE federation integration capabilities, not a theoretical design.**

