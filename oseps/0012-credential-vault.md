---
title: Credential Vault and Credential Proxy
authors:
  - "@jwx0925"
creation-date: 2026-05-28
last-updated: 2026-05-28
status: provisional
---

# OSEP-0012: Credential Vault and Credential Proxy

<!-- toc -->
- [Summary](#summary)
- [Motivation](#motivation)
  - [Goals](#goals)
  - [Non-Goals](#non-goals)
- [Requirements](#requirements)
- [Proposal](#proposal)
  - [Notes/Constraints/Caveats](#notesconstraintscaveats)
  - [Risks and Mitigations](#risks-and-mitigations)
- [Design Details](#design-details)
  - [Terminology](#terminology)
  - [Architecture Overview](#architecture-overview)
  - [Request Flow](#request-flow)
  - [API Schema](#api-schema)
  - [Binding Templates](#binding-templates)
  - [Credential Sources](#credential-sources)
  - [Credential Injection](#credential-injection)
  - [Response Redaction and Echo Handling](#response-redaction-and-echo-handling)
  - [Runtime Modes](#runtime-modes)
  - [Policy and Egress Integration](#policy-and-egress-integration)
  - [Observability](#observability)
  - [Component Changes](#component-changes)
- [Test Plan](#test-plan)
- [Drawbacks](#drawbacks)
- [Alternatives](#alternatives)
- [Infrastructure Needed](#infrastructure-needed)
- [Upgrade & Migration Strategy](#upgrade--migration-strategy)
<!-- /toc -->

## Summary

This proposal introduces **Credential Vault**, a brokered credential layer for OpenSandbox, and **Credential Proxy**, the runtime component that injects scoped credentials into approved outbound requests without exposing plaintext credentials inside the sandbox.

Instead of passing secrets through environment variables, files, or command arguments, users attach credential bindings to a sandbox. Credential Proxy evaluates the sandbox identity, destination, method, path, and injection policy before adding credentials to outbound HTTP requests.

## Motivation

AI agents frequently need credentials to call external systems such as GitHub, model APIs, cloud storage, package registries, databases, and internal services. Today the common approach is to place secrets inside the sandbox as environment variables or files. That makes the secret available to every process in the sandbox, and an untrusted or compromised agent can print, persist, exfiltrate, or transform the secret.

OpenSandbox already provides isolated execution and per-sandbox egress control. The next security requirement is brokered credential use: a sandboxed agent should be able to use an approved credential for an approved destination, but it should not be able to read the underlying plaintext credential.

Credential Vault extends OpenSandbox's sandbox security model from:

- where code can run,
- what network destinations it can reach,

to:

- what credentials it can use for those destinations.

### Goals

1. **Brokered credentials**: Let sandboxed workloads use credentials without receiving plaintext secret values through OpenSandbox-managed environment variables, files, lifecycle API responses, diagnostics, or logs.
2. **Declarative binding**: Add a sandbox creation-time credential binding model that describes source, scope, and injection behavior, with operator-approved templates for common patterns.
3. **Policy-aware runtime injection**: Inject credentials only when sandbox identity, destination FQDN, HTTP method, and path all match the binding.
4. **Egress alignment**: Integrate with `networkPolicy.egress` so credential scope and network reachability are consistent.
5. **Runtime agnostic**: Support both Docker and Kubernetes through the existing egress sidecar pattern that shares the sandbox network namespace.
6. **Transparent by default**: Use the existing egress transparent mitmproxy path as Credential Proxy so applications do not need proxy or base URL changes.
7. **Auditable and redacted**: Emit useful audit events and metrics while redacting credential material from logs, diagnostics, and responses.
8. **Backward compatible**: Keep existing sandbox creation and egress behavior unchanged unless credential bindings are explicitly requested.

### Non-Goals

1. **General-purpose secret manager**: Credential Vault is not intended to replace HashiCorp Vault, Infisical, cloud secret managers, or Kubernetes Secret. It brokers credentials from configured sources into sandbox traffic.
2. **Secret lifecycle management**: Rotation, versioning, approval workflows, and cross-environment secret synchronization are out of scope for the initial design.
3. **Plaintext exposure inside sandbox**: This proposal does not add an API for sandbox processes to retrieve raw credential values.
4. **Generic body rewriting as MVP**: Request/response body mutation is out of scope for the MVP; header injection is sufficient for the first set of credential use cases.
5. **Per-process policy**: Credential policies apply to a sandbox, not to individual processes inside that sandbox.
6. **Non-HTTP protocols as MVP**: SSH, database wire protocols, Git smart protocol credential helpers, and arbitrary TCP credential injection are future work.
7. **Replacing egress policy**: Credential Vault complements egress control but does not replace network allow/deny enforcement.

## Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| R1 | Users can attach credential bindings to a sandbox at creation time | Must Have |
| R2 | Plaintext credentials are not exposed through OpenSandbox-managed sandbox env vars, files, lifecycle API responses, diagnostics, or logs | Must Have |
| R3 | Credential Proxy injects credentials only for matching scheme, port, FQDN, HTTP method, and path scope | Must Have |
| R4 | Initial injection supports HTTP request headers | Must Have |
| R5 | Inline ephemeral values can be used as the public credential input | Must Have |
| R6 | Credential-enabled sandboxes require explicit `networkPolicy.egress` coverage for every binding target | Must Have |
| R7 | Audit logs and metrics identify binding usage without logging credential values | Must Have |
| R8 | Docker and Kubernetes runtimes use the same user-facing API semantics | Must Have |
| R9 | Credential Proxy is default-deny for missing, invalid, or non-matching bindings | Must Have |
| R10 | The runtime uses egress transparent mitmproxy as the Credential Proxy implementation | Must Have |
| R11 | Credential-enabled egress startup fails closed when transparent redirect, mitm readiness, CA bootstrap, or egress API auth cannot be configured | Must Have |
| R12 | Users can reference built-in or operator-configured binding templates instead of repeating full scope and injection rules | Should Have |
| R13 | Future secret managers can be added through a provider interface | Should Have |

## Proposal

Add Credential Vault as a lifecycle API and server-side control-plane capability. Add Credential Proxy as the credential-aware runtime behavior of the existing egress transparent mitmproxy path.

The first implementation supports **transparent proxy mode**:

1. The user creates a sandbox with `credentialVault.bindings`.
2. OpenSandbox server validates bindings, resolves source references, and enables egress transparent mitmproxy for the sandbox.
3. The sandbox application container sends normal outbound HTTP/HTTPS traffic, for example to `https://api.github.com/repos/alibaba/OpenSandbox`.
4. Egress transparent mitmproxy intercepts outbound `TCP 80/443` traffic in the sandbox network namespace.
5. Credential Proxy evaluates the intercepted request against the sandbox credential bindings, including scheme and port.
6. If exactly one binding matches and policy allows the request, Credential Proxy fetches or receives the credential material from a trusted source path and injects it into the request.
7. The external service receives the credential-bearing request; the sandbox process only sees the service response.

At a high level:

```
┌───────────────────────────────────────────────────────────────────────┐
│                         OpenSandbox Server                            │
│                                                                       │
│  ┌──────────────────────┐       ┌──────────────────────────────────┐  │
│  │ Lifecycle API         │       │ Credential Vault Control Plane    │  │
│  │ - create sandbox      │──────▶│ - validate binding                │  │
│  │ - store metadata      │       │ - resolve source reference        │  │
│  │ - start runtime       │       │ - provide credential bootstrap    │  │
│  └──────────────────────┘       └──────────────────────────────────┘  │
└──────────────────────────────────────────┬────────────────────────────┘
                                           │ binding config
                                           ▼
┌───────────────────────────────────────────────────────────────────────┐
│                    Sandbox Pod / Network Namespace                    │
│                                                                       │
│  ┌──────────────────────┐          ┌───────────────────────────────┐  │
│  │ Application Container │HTTP(S)│ Egress Sidecar / Credential     │  │
│  │ - no plaintext secret │────────▶│ Proxy (transparent mitmproxy)  │  │
│  │ - no proxy config     │         │ - policy match                 │  │
│  └──────────────────────┘         │ - injection, redaction, audit  │  │
│                                    └───────────────┬───────────────┘  │
└────────────────────────────────────────────────────┼──────────────────┘
                                                     │ authenticated request
                                                     ▼
                                             External Service
```

### Notes/Constraints/Caveats

1. **Credential Proxy is the egress transparent mitmproxy path**: This proposal does not introduce an explicit proxy or local gateway mode. Applications keep using their normal target URLs.
2. **HTTPS interception requires trusted CA setup**: Transparent HTTPS injection depends on the sandbox trusting the mitmproxy root CA. Images or runtime startup must install the OpenSandbox MITM CA, otherwise HTTPS handshakes fail.
3. **Credential source access is control-plane trusted**: Runtime sidecars should not be granted broad cluster secret access. The server should resolve or mint scoped runtime material for only the requested sandbox bindings.
4. **Credential material must be short-lived in memory**: Credential Proxy should not persist plaintext credentials on disk. If temporary files are unavoidable for runtime bootstrap, they must be mounted read-only, scoped to one sandbox, and cleaned up with sandbox deletion.
5. **Binding scope must be covered by egress scope**: A credential-enabled sandbox must include `networkPolicy.egress`, and every credential binding target must be covered by an allow rule. Missing or inconsistent egress policy fails sandbox creation.
6. **Multiple matching bindings are ambiguous**: If more than one binding matches a request and no deterministic precedence is declared, Credential Proxy must fail closed.
7. **Upstream echo is outside the absolute secrecy guarantee**: OpenSandbox prevents its own control plane and runtime surfaces from exposing credentials, but an upstream service can still echo request headers in response bodies or headers. Credential Proxy should redact known credential values from responses where practical, and users should avoid binding credentials to services that echo sensitive request headers.

### Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Sandbox bypasses Credential Proxy | Credential not injected, or traffic reaches destination without policy mediation | Use egress transparent redirect for TCP 80/443 and recommend `networkPolicy.defaultAction=deny` with `dns+nft` |
| Credential leakage through logs | Secret exposure | Central redaction helpers; never log injected headers or rendered values; regression tests for logs |
| Upstream echoes injected credential | Credential appears in sandbox-visible response content | Redact known credential values from response headers and text bodies where practical; document that services which echo sensitive request headers are unsupported unless response redaction is sufficient |
| Inline credential value leaked by lifecycle logging | Secret exposure | Treat inline credential `value` as write-only input; redact request bodies, validation errors, SDK debug logs, and persisted sandbox metadata |
| Credential source over-permissioned to sidecars | Cluster-wide secret access risk | Server resolves sources and passes only sandbox-scoped material; sidecar has no Kubernetes API permission by default |
| Binding and egress policy drift | Credential may be configured for unreachable or unintended destinations | Require `networkPolicy.egress` and fail creation when any binding target is not covered |
| Header injection into wrong host due to redirects | Credential sent to unintended destination | Re-evaluate policy after each redirected request; strip injected credentials on cross-host redirect unless target scope matches |
| Credential injected over cleartext HTTP | Credential exposed on the network | Default binding scope to `schemes: [https]` and `ports: [443]`; require explicit opt-in for any HTTP injection |
| HTTPS CA not trusted by sandbox image | Authenticated HTTPS requests fail | Install/export the OpenSandbox mitmproxy CA during sandbox startup or document image requirements |
| Transparent redirect unavailable | Credential traffic bypasses proxy policy | Fail sandbox creation/readiness when credential bindings are present and mitmproxy, iptables redirect, CA bootstrap, or egress auth cannot be configured |
| Untrusted mitm addon observes injected headers | Future credential exposure if sandbox users can control addon loading | Current egress mitm addons are operator/platform-controlled and are not a sandbox-user API. Preserve that boundary: reject any future sandbox-supplied mitm addons for credential-enabled sandboxes, and allow only operator-configured trusted addons. |
| Egress policy API unauthenticated | Sandbox process rewrites sidecar policy | Always provision `OPENSANDBOX_EGRESS_TOKEN` for credential-enabled sidecars, even when network policy would otherwise be omitted |
| IPv6 bypasses transparent MITM | HTTP(S) traffic avoids inspection, injection, and audit | Short term: fail closed unless IPv6 is disabled or equivalently redirected; long term: support IPv6 through ip6tables/nftables redirect and test coverage |
| Upstream TLS verification disabled | Credential injected into a spoofed upstream peer | Reject `OPENSANDBOX_EGRESS_MITMPROXY_SSL_INSECURE=true` for credential-enabled sandboxes |
| Platform credential authorized for wrong destination | An operator-managed credential is injected into an attacker-controlled target | Do not expose platform credential sources as user-selectable source refs. Operator templates that use platform credentials must constrain allowed targets, methods, paths, schemes, ports, and injection renderings. |
| Multiple bindings match one request | Wrong credential injection | Fail closed unless a single highest-priority binding is configured |
| Long-lived credentials remain in proxy memory | Expanded exposure window | Cache with TTL, zero buffers where practical, prefer short-lived tokens from providers |
| Users expect full secret management | Product confusion | Document Credential Vault as a broker layer, not a standalone secret manager |

## Design Details

### Terminology

- **Credential Vault**: OpenSandbox control-plane capability for declaring, validating, and managing credential bindings on sandboxes.
- **Credential Proxy**: Credential-aware runtime behavior in the egress sidecar's transparent mitmproxy path. It evaluates outbound HTTP/HTTPS requests and injects credentials when policy matches.
- **Credential Binding**: A per-sandbox declaration that connects a credential source to an allowed destination and injection rule.
- **Credential Binding Template**: A built-in or operator-configured template that expands user parameters and a credential source into a full credential binding.
- **Credential Source**: Credential material supplied to Credential Proxy. In the MVP public API this is an inline ephemeral value accepted only at sandbox creation time. Operator-managed credentials may exist behind operator-configured templates, but are not user-selectable source refs.
- **Credential Injection**: The act of adding credential material to an outbound request, for example as an `Authorization` header.

### Architecture Overview

Credential Vault should be modeled as a control-plane extension of sandbox lifecycle. Credential Proxy should be modeled as a credential-aware extension of the existing egress sidecar transparent mitmproxy path:

- Egress sidecar controls which network destinations are reachable.
- Credential Proxy controls which credentials are attached to allowed outbound HTTP/HTTPS requests.

For Kubernetes, this means the existing egress sidecar in the sandbox Pod starts mitmproxy transparent mode and loads OpenSandbox's credential addon. For Docker, this means the existing egress sidecar shares the sandbox network namespace, redirects outbound configured HTTP/HTTPS ports to mitmproxy, and runs the same credential addon. The MVP built-in intercept ports are `80` and `443`.

The egress sidecar already has the transparent MITM primitives required for Credential Proxy:

- starts `mitmdump --mode transparent`,
- redirects outbound configured HTTP/HTTPS destination ports, initially `TCP 80/443`, to the mitmproxy listener using `iptables`,
- loads system and operator-configured mitm addons,
- exports the mitmproxy root CA,
- exposes health readiness so sandboxes do not start before interception is ready.

Credential Vault adds a first-party credential addon and binding bootstrap config to that path.

### Request Flow

For a GitHub read-only token binding:

1. Sandbox process calls `https://api.github.com/repos/alibaba/OpenSandbox` normally.
2. Egress transparent mitmproxy intercepts the request and exposes host `api.github.com`, method `GET`, and path `/repos/alibaba/OpenSandbox` to the Credential Proxy addon.
3. Credential Proxy loads matching bindings for the sandbox.
4. It finds `github-readonly` where:
   - `targets` contains `api.github.com`,
   - `methods` contains `GET`,
   - `paths` contains `/repos/*`,
   - injection type is `header`.
5. It retrieves credential material from the scoped source path.
6. It sends the upstream request with:

```http
Authorization: Bearer <redacted>
```

7. It records an audit event with sandbox ID, binding name, target, method, path pattern, decision, and response status. The credential value is not logged.

### API Schema

Extension to `specs/sandbox-lifecycle.yml`:

```yaml
components:
  schemas:
    CreateSandboxRequest:
      properties:
        credentialVault:
          $ref: '#/components/schemas/CredentialVaultSpec'

    CredentialVaultSpec:
      type: object
      properties:
        mode:
          type: string
          enum: [transparentProxy]
          default: transparentProxy
        bindings:
          type: array
          items:
            $ref: '#/components/schemas/CredentialBinding'
      additionalProperties: false

    CredentialBinding:
      type: object
      required: [name]
      properties:
        name:
          type: string
          description: Sandbox-local credential binding name.
        templateRef:
          $ref: '#/components/schemas/CredentialBindingTemplateRef'
        credential:
          $ref: '#/components/schemas/CredentialSourceRef'
        sourceRef:
          $ref: '#/components/schemas/CredentialSourceRef'
        scope:
          $ref: '#/components/schemas/CredentialScope'
        injection:
          $ref: '#/components/schemas/CredentialInjection'
      additionalProperties: false

    CredentialBindingTemplateRef:
      type: object
      required: [name]
      properties:
        name:
          type: string
          description: Built-in or operator-configured template name.
        params:
          type: object
          additionalProperties:
            type: string
          description: Non-sensitive template parameters. Sensitive values must use credential, not params.
      additionalProperties: false

    CredentialSourceRef:
      type: object
      required: [value]
      properties:
        value:
          type: string
          writeOnly: true
          description: Inline ephemeral credential value accepted only at sandbox creation time. This is the default and only public MVP credential input. Never returned, logged, or persisted as plaintext.
      additionalProperties: false

    CredentialScope:
      type: object
      required: [targets]
      properties:
        schemes:
          type: array
          items:
            type: string
            enum: [https, http]
          default: [https]
          description: URL schemes eligible for credential injection. Defaults to HTTPS only.
        ports:
          type: array
          items:
            type: integer
          default: [443]
          description: Destination ports eligible for credential injection. Defaults to 443.
        targets:
          type: array
          items:
            type: string
          description: FQDN or wildcard domain targets, for example api.github.com or *.example.com.
        methods:
          type: array
          items:
            type: string
          default: [GET, POST, PUT, PATCH, DELETE]
        paths:
          type: array
          items:
            type: string
          default: ["/*"]
      additionalProperties: false

    CredentialInjection:
      type: object
      required: [type, name, value]
      properties:
        type:
          type: string
          enum: [header]
        name:
          type: string
          example: Authorization
        value:
          type: string
          example: Bearer {{ credential }}
      additionalProperties: false
```

Validation rules:

- A `CredentialBinding` must use exactly one of these forms:
  - **Inline full binding**: `sourceRef`, `scope`, and `injection`.
  - **Template binding**: `templateRef` and `credential`.
- `templateRef.params` is for non-sensitive values only and may be logged in validation errors.
- `sourceRef` and `credential` both carry inline ephemeral credential material. Since inline ephemeral is the only public MVP credential input, no `type` discriminator is required.
- Sandbox creators cannot define arbitrary templates in `CreateSandboxRequest`; they can only reference built-in or operator-configured templates.
- The server expands templates before egress validation, ambiguity checks, and runtime bootstrap.

Example full binding request:

```json
{
  "image": "python:3.12",
  "networkPolicy": {
    "defaultAction": "deny",
    "egress": [
      { "action": "allow", "target": "api.github.com" }
    ]
  },
  "credentialVault": {
    "mode": "transparentProxy",
    "bindings": [
      {
        "name": "github-readonly",
        "sourceRef": {
          "value": "ghp_xxx"
        },
        "scope": {
          "schemes": ["https"],
          "ports": [443],
          "targets": ["api.github.com"],
          "methods": ["GET"],
          "paths": ["/repos/*", "/search/*"]
        },
        "injection": {
          "type": "header",
          "name": "Authorization",
          "value": "Bearer {{ credential }}"
        }
      }
    ]
  }
}
```

Example template binding request:

```json
{
  "image": "python:3.12",
  "networkPolicy": {
    "defaultAction": "deny",
    "egress": [
      { "action": "allow", "target": "code.alibaba-inc.com" }
    ]
  },
  "credentialVault": {
    "mode": "transparentProxy",
    "bindings": [
      {
        "name": "code-alibaba-git",
        "templateRef": {
          "name": "git-https-basic",
          "params": {
            "target": "code.alibaba-inc.com",
            "repoPath": "/foo/bar.git"
          }
        },
        "credential": {
          "value": "ZG9tYWluLWFjY291bnQ6cHJpdmF0ZS10b2tlbg=="
        }
      }
    ]
  }
}
```

The template expands this into an internal binding equivalent to:

```json
{
  "scope": {
    "schemes": ["https"],
    "ports": [443],
    "targets": ["code.alibaba-inc.com"],
    "methods": ["GET", "POST"],
    "paths": ["/foo/bar.git", "/foo/bar.git/*"]
  },
  "injection": {
    "type": "header",
    "name": "Authorization",
    "value": "Basic {{ credential }}"
  }
}
```

The sandbox workload can then use the normal unauthenticated repository URL:

```bash
git clone https://code.alibaba-inc.com/foo/bar.git
```

### Binding Templates

Binding templates reduce repeated boilerplate for common credential injection patterns. They are resolved by OpenSandbox server before sandbox creation reaches runtime providers.

Template sources:

1. **Built-in templates**
   - Shipped with OpenSandbox.
   - Cover common protocols listed in the built-in template catalog below.
2. **Operator-configured templates**
   - Defined in server configuration under `[credential_vault]`.
   - Intended for enterprise-specific targets and path constraints.
   - Override or conflict with built-in names only if the operator uses an explicit namespace such as `operator/alibaba-code-git`.

Built-in template catalog:

| Template | Required params | Optional params | Credential input | Injection |
|----------|-----------------|-----------------|------------------|-----------|
| `git-https-basic` | `target`, `repoPath` | none | pre-encoded `base64(username:token)` | `Authorization: Basic {{ credential }}` |
| `generic-bearer` | `target` | `pathPrefix` | bearer token | `Authorization: Bearer {{ credential }}` |
| `generic-basic` | `target` | `pathPrefix` | pre-encoded `base64(username:password)` | `Authorization: Basic {{ credential }}` |
| `openai-bearer` | `target` | `pathPrefix` | API key | `Authorization: Bearer {{ credential }}` |
| `github-token` | `target` | `pathPrefix` | GitHub token | `Authorization: Bearer {{ credential }}` |
| `gitlab-token` | `target` | `pathPrefix`, `mode` | GitLab token | `PRIVATE-TOKEN: {{ credential }}` by default, or `Authorization: Bearer {{ credential }}` when `mode=bearer` |
| `npm-token` | `target` | `pathPrefix` | npm token | `Authorization: Bearer {{ credential }}` |
| `pypi-token` | `target` | `pathPrefix` | pre-encoded `base64(__token__:token)` | `Authorization: Basic {{ credential }}` |

All built-in templates default to:

- `schemes: ["https"]`
- `ports: [443]`
- egress validation against the expanded target
- no credential injection on HTTP unless an operator-configured template explicitly allows it

Built-in template expansion examples:

```yaml
git-https-basic:
  requiredParams: [target, repoPath]
  credentialInput: base64(username:token)
  scope:
    schemes: [https]
    ports: [443]
    targets: ["{{ target }}"]
    methods: [GET, POST]
    paths: ["{{ repoPath }}", "{{ repoPath }}/*"]
  injection:
    type: header
    name: Authorization
    value: "Basic {{ credential }}"

generic-bearer:
  requiredParams: [target]
  optionalParams: [pathPrefix]
  credentialInput: token
  scope:
    schemes: [https]
    ports: [443]
    targets: ["{{ target }}"]
    methods: [GET, POST, PUT, PATCH, DELETE]
    paths: ["{{ pathPrefix | default('/*') }}"]
  injection:
    type: header
    name: Authorization
    value: "Bearer {{ credential }}"
```

Provider-specific notes:

- `openai-bearer` is equivalent to `generic-bearer` with OpenAI-compatible API defaults. Operators should pin `target` for managed deployments.
- `github-token` uses `Authorization: Bearer` by default for modern GitHub API usage.
- `gitlab-token` defaults to GitLab's `PRIVATE-TOKEN` header for API usage; `mode=bearer` is available for deployments that use OAuth/JWT bearer tokens.
- `pypi-token` is intended for PyPI-compatible APIs that accept Basic auth with `__token__` as the username. For the MVP, callers or upper-layer platforms pass the already encoded `base64(__token__:token)` value. Package manager behavior varies, so operators may prefer an operator-configured template for private indexes.
- Built-in templates intentionally do not accept typed template params in the MVP. Method lists and other typed behavior are fixed by template type or by operator-configured templates.
- The MVP renderer supports only `{{ credential }}`. Built-in templates that need Basic auth require callers or upper-layer platforms to pre-encode the credential value before sandbox creation. Future versions may add server-side encoding helpers after the renderer model is explicitly designed.

Example server configuration:

```toml
[credential_vault]
enabled = true

[[credential_vault.binding_templates]]
name = "operator/alibaba-code-git"
type = "git_https_basic"
target = "code.alibaba-inc.com"
allowed_repo_path_prefixes = ["/foo/", "/bar/"]
```

Example use:

```json
{
  "name": "code-alibaba-git",
  "templateRef": {
    "name": "operator/alibaba-code-git",
    "params": {
      "repoPath": "/foo/bar.git"
    }
  },
  "credential": {
    "value": "ZG9tYWluLWFjY291bnQ6cHJpdmF0ZS10b2tlbg=="
  }
}
```

Template safety rules:

- Templates must be built-in or configured by an operator; sandbox creators cannot submit arbitrary template definitions.
- Template params must be schema-validated by the selected template.
- Sensitive values must not be passed through `templateRef.params`; use `credential` so redaction and write-only handling apply.
- Expanded bindings must still pass HTTPS/port defaults, egress policy validation, operator credential constraints, and ambiguity checks.
- Templates should keep targets and paths as narrow as possible. Operator-configured templates may fix `target` and allow only path parameters, which is safer for enterprise deployments.
- Operator-configured templates may internally use platform-managed credentials, but those credentials are selected by the operator template configuration, not by sandbox user input.

### Credential Sources

The MVP exposes one public credential input: an inline ephemeral value.

- Available for cases where a caller or upper-layer platform creates a sandbox-scoped credential at sandbox creation time.
- The inline value is accepted only in `CreateSandboxRequest`.
- Because inline ephemeral is the only public MVP credential input, callers do not declare a `type`.
- The OpenSandbox server must treat the value as write-only: do not return it in lifecycle responses, do not persist it as plaintext, and redact it from logs and validation errors.
- The server converts the value into sandbox-scoped runtime credential material for the egress sidecar / Credential Proxy.
- For Kubernetes, the runtime material may be represented as a generated Secret that is mounted only into the egress sidecar, not the application container.
- Generated runtime Secrets must be labeled with the sandbox identity and cleaned up when the sandbox is deleted. Use `ownerReferences` where possible and finalizers only when external revocation or cross-namespace cleanup is required.
- Platform-level credentials are not exposed through user-selectable `sourceRef` names in the MVP. Platforms that need create-once, reference-many credentials should wrap them behind operator-configured binding templates and enforce template usage authorization at the platform layer.

Example:

```json
{
  "sourceRef": {
    "value": "ghp_xxx"
  }
}
```

Kubernetes Secret is not a user-facing credential source in the MVP. In Kubernetes runtime, it may be used only as a sandbox-scoped runtime delivery mechanism generated by OpenSandbox, mounted only into the egress sidecar, and owned/cleaned up with the sandbox. Sandbox creators cannot reference arbitrary pre-existing Kubernetes Secret names.

Future providers may include HashiCorp Vault, Infisical, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, internal credential brokers, and a Kubernetes Secret provider. Adding any user-selectable source provider requires a separate authorization model, namespace/scope policy, allowlists/selectors, requester authorization, and source-to-destination constraints.

### Credential Injection

The MVP supports request header injection only. Credential Proxy injects the header into intercepted HTTP/HTTPS requests after the transparent mitmproxy path has decoded request metadata:

```yaml
injection:
  type: header
  name: Authorization
  value: "Bearer {{ credential }}"
```

Rules:

- `{{ credential }}` is the only supported template variable in the MVP.
- The MVP renderer does not support filters, functions, string concatenation, arbitrary expressions, or user-defined transforms.
- Credential Proxy must reject templates that do not include `{{ credential }}`.
- Credential Proxy must inject only for HTTPS on port 443 by default.
- Transparent mode supports credential injection only for destination ports that the egress sidecar redirects into mitmproxy. The MVP supports `443` by default and `80` when an operator-configured template or explicit operator policy enables cleartext HTTP injection.
- Any binding scope that uses ports outside `80/443` must be rejected unless the operator explicitly configures those ports as transparent MITM intercept ports and the runtime can install matching redirect rules.
- Credential Proxy must reject attempts to inject hop-by-hop proxy headers unless explicitly allowed by implementation.
- Credential Proxy must remove any existing request header with the same name before injecting a credential, unless a future merge strategy is added.
- On redirect, Credential Proxy must re-evaluate target scope before preserving injected headers.

### Response Redaction and Echo Handling

Credential Proxy should redact known credential values from upstream response headers and text-like response bodies where practical. This protects against common debug endpoints and error handlers that echo request headers.

Redaction must include both source and rendered credential values, including:

- raw `credential` source material,
- rendered injected header values such as `Bearer <token>`,
- rendered Basic header values such as `Basic <base64(username:token)>`.

This redaction is best effort, not an absolute secrecy guarantee:

- Binary, compressed, encrypted, streaming, or very large response bodies may be passed without full body rewriting.
- If response redaction is disabled or not possible, Credential Proxy should at least strip or redact response headers that contain known credential values.
- Operators should not bind credentials to upstream services that intentionally echo sensitive request headers back to callers unless the response path is known to be safely redacted.

The formal guarantee is that OpenSandbox-controlled surfaces do not expose plaintext credentials. It cannot guarantee that arbitrary upstream services will never include an injected credential in application-level response content.

### Runtime Modes

The initial supported runtime mode is **transparent proxy**.

#### Transparent Proxy Mode

The runtime enables egress transparent mitmproxy when `credentialVault.bindings` is present. The application container keeps using normal outbound URLs. Credential Proxy runs as an OpenSandbox-managed mitm addon loaded by the egress sidecar.

Advantages:

- No application proxy or base URL changes.
- Reuses existing egress sidecar network namespace, `iptables` redirect, health gate, and mitmproxy integration.
- Works with existing HTTP clients, SDKs, CLIs, and agent-generated code as long as they use intercepted HTTP/HTTPS ports and trust the sandbox CA. The MVP supported ports are `80/443`.
- Keeps credential policy enforcement at the egress boundary, where network policy is already enforced.

Limitations:

- Requires Linux network namespace support and `CAP_NET_ADMIN` for the egress sidecar.
- Requires the sandbox to trust the mitmproxy CA for HTTPS interception.
- Applies to HTTP/HTTPS traffic on configured transparent MITM intercept ports. The MVP supports `80/443`; additional ports require operator configuration and runtime redirect support. Non-HTTP protocols need future designs.
- Credential-bound targets must not match `ignore_hosts`. Because `ignore_hosts` is pass-through TLS, Credential Proxy cannot inspect, inject, redact, or audit those flows.
- Short term: credential-enabled startup must fail closed unless IPv6 HTTP(S) egress is disabled or covered by equivalent transparent redirect. Long term: IPv6 support should use ip6tables or nftables redirect with the same tests as IPv4.
- Credential-enabled startup must reject upstream TLS-insecure mode such as `OPENSANDBOX_EGRESS_MITMPROXY_SSL_INSECURE=true`.
- Credential-enabled startup must fail closed if mitmproxy, `iptables` redirect, CA bootstrap, credential addon loading, or egress API authentication cannot be configured.
- MITM addon trust boundary: current egress mitm addons are configured by the operator/platform through egress sidecar configuration, not by sandbox users. This is not a credential leak by itself because operator-configured addons are part of the platform trust boundary. Credential-enabled sandboxes must preserve this boundary by rejecting any future sandbox-supplied addon mechanism and by ensuring addon script paths do not come from app-container-writable locations. Operator-configured trusted addons may be loaded and must follow the same credential redaction and audit rules.

### Policy and Egress Integration

Credential-enabled sandboxes must include `networkPolicy.egress`. The server must validate destination consistency before sandbox creation.

Required validation:

- Every credential binding target must be covered by an allow rule in `networkPolicy.egress`.
- More formally, the set of credential binding targets must be a subset of the egress allow targets after template expansion and wildcard normalization.
- `networkPolicy.defaultAction` should be `deny`; if `allow` is accepted for compatibility, the server must still require explicit allow coverage for every binding target and warn that broad outbound access coexists with credential-bearing traffic.
- If `networkPolicy` is omitted, if `egress` is empty, or if a binding target is not reachable under egress policy, sandbox creation must fail with HTTP 400.

Suggested configuration:

```toml
[credential_vault]
enabled = true
egress_validation = "strict"
transparent_intercept_ports = [80, 443]
```

For credential-enabled sandboxes, strict validation is required. Non-strict egress validation would allow credential-bearing traffic to run without an explicit network policy boundary.

`transparent_intercept_ports` defines the destination ports that the egress sidecar must redirect into transparent mitmproxy for credential injection. The default MVP value is `[80, 443]`. Operators may add ports only when the runtime supports redirecting those ports and the deployment has test coverage for them. Sandbox creation must fail if any credential binding `scope.ports` value is not included in `transparent_intercept_ports`.

Credential-enabled sidecars must always provision `OPENSANDBOX_EGRESS_TOKEN` for the egress policy API, including cases where the egress sidecar starts solely because credentials are enabled. The application container must not receive this token.

### Observability

Credential Proxy should emit structured logs and metrics without credential values.

Suggested audit log fields:

- `sandbox_id`
- `credential_binding`
- `source_type`
- `target_host`
- `method`
- `path_pattern`
- `decision` (`injected`, `denied`, `no_match`, `ambiguous_match`, `source_error`)
- `status_code`
- `duration_ms`
- `request_id`

Suggested metrics:

- `opensandbox_credential_proxy_requests_total`
- `opensandbox_credential_proxy_injections_total`
- `opensandbox_credential_proxy_denials_total`
- `opensandbox_credential_proxy_source_errors_total`
- `opensandbox_credential_proxy_request_duration_seconds`

All diagnostics APIs that surface runtime logs must preserve redaction behavior.

### Component Changes

#### Specs

- Add `credentialVault` schemas to `specs/sandbox-lifecycle.yml`.
- Add examples for sandbox creation with credential bindings.
- Consider a future `credential-proxy-api.yaml` only if runtime policy inspection/mutation is exposed separately from the egress API.

#### Server

- Add config model for `[credential_vault]`.
- Add write-only inline credential material handling for sandbox creation.
- Validate `CreateSandboxRequest.credentialVault`.
- Load built-in and operator-configured binding templates.
- Expand template bindings into full bindings before egress validation and runtime bootstrap.
- Require and validate `networkPolicy.egress` for credential-enabled sandboxes.
- Persist credential binding metadata without plaintext credential values.
- Resolve or prepare sandbox-scoped credential material during sandbox creation.
- Redact inline credential values from request logging, validation errors, persisted metadata, and lifecycle responses.
- Enable egress transparent mitmproxy, egress API auth, and credential addon bootstrap for Docker and Kubernetes runtimes when bindings are present.

#### Components / Egress

- Extend `components/egress` transparent mitmproxy support with a first-party credential addon.
- Keep transparent MITM redirect ports configurable. The default credential-enabled intercept set is `80/443`; additional ports require explicit operator configuration and matching redirect rules.
- Load credential binding bootstrap config into the egress sidecar.
- Implement binding evaluation, header injection, redaction, and audit events in the mitm addon path.
- Keep the existing system addon behavior for streaming.
- Reject sandbox-supplied mitm addon loading for credential-enabled sandboxes. Operator-configured trusted addons may run as part of the platform trust boundary.
- Fail readiness/startup when transparent redirect, credential addon loading, CA bootstrap, upstream TLS verification, IPv6 coverage/disablement, or egress API auth is unavailable for a credential-enabled sandbox.

#### Kubernetes

- Enable the egress sidecar with transparent mitmproxy when credential bindings are present.
- Add secret projection or bootstrap delivery for sandbox-scoped credential material.
- For inline credentials, optionally create a generated sandbox-scoped Kubernetes Secret mounted only into the egress sidecar.
- Generated runtime Secrets must use labels and `ownerReferences` when possible; finalizers are reserved for cleanup that Kubernetes garbage collection cannot cover.
- Kubernetes Secrets are runtime delivery artifacts only in the MVP; they are not user-facing credential sources.
- Ensure Credential Proxy has no broad Kubernetes API permissions by default.
- Ensure the mitmproxy CA is trusted by the sandbox application container when HTTPS interception is enabled.
- Ensure generated egress API auth material is available only to the control plane and egress sidecar, not the application container.

#### Docker

- Enable the egress sidecar with transparent mitmproxy sharing the sandbox network namespace.
- Ensure the mitmproxy CA is trusted by the sandbox application container when HTTPS interception is enabled.
- Clean up sidecar and sandbox-scoped credential material when the sandbox is deleted.
- Ensure generated egress API auth material is not exposed to the application container.

#### SDKs and CLI

- Add typed request models for credential bindings.
- Add typed request models for template references and credential values.
- Add examples for common providers such as GitHub and model APIs.
- Add examples for `git-https-basic` and enterprise operator-configured Git templates.
- CLI may include validation helpers, but it should not print credential values.

## Test Plan

### Unit Tests

- Schema validation accepts valid full bindings and rejects full bindings missing `name`, `sourceRef`, `scope`, or `injection`.
- Schema validation accepts valid template bindings and rejects bindings that mix full-binding fields with template fields.
- Template params are validated by template type, and sensitive values in params are rejected.
- Template expansion produces the expected scope and injection policy for every built-in template.
- Provider-specific built-ins such as `gitlab-token` and `pypi-token` validate supported modes and credential rendering.
- Scheme, port, FQDN, wildcard, method, and path matching work as expected.
- Injection defaults to HTTPS/443 only and rejects HTTP injection unless explicitly configured and permitted.
- Binding scopes that use ports outside configured transparent MITM intercept ports are rejected.
- Multiple matching bindings fail closed.
- Existing headers with the injection name are replaced or rejected according to the selected implementation rule.
- Redaction removes credential values from logs and errors.
- Response redaction removes known credential values from response headers and supported text bodies.
- Inline credential `value` is accepted only as write-only create input and never appears in serialized sandbox metadata or API responses.
- Egress validation requires `networkPolicy.egress` and catches binding targets not allowed by policy.
- Operator-configured templates reject repo paths outside allowed prefixes.

### Integration Tests

- Docker sandbox with inline ephemeral source can call a mock HTTP/HTTPS server and cannot recover the inline credential from environment, filesystem, diagnostics, or lifecycle responses.
- Docker sandbox cannot read credential value from environment variables, mounted files, lifecycle API response, or diagnostics.
- Kubernetes sandbox with inline ephemeral source creates sandbox-scoped runtime material mounted only into the egress sidecar and cleans it up on sandbox deletion.
- Kubernetes runtime rejects requests that try to reference arbitrary pre-existing Kubernetes Secret names as credential sources.
- Credential Proxy denies non-matching hosts, paths, and methods.
- Credential-enabled sandbox creation/readiness fails when transparent redirect, mitm readiness, CA bootstrap, credential addon loading, or egress API auth cannot be configured.
- Credential-enabled sandbox creation rejects a binding that targets a non-configured port, and accepts the same port only after the operator configures transparent MITM interception for that port.
- Credential-enabled sidecars require egress API auth even when credentials are the only reason the egress sidecar starts.
- Sandbox-supplied mitm addons are not loaded for credential-enabled sandboxes; operator-configured trusted addons may run.
- Credential-enabled startup fails when IPv6 is enabled without equivalent transparent redirect coverage.
- Credential-enabled startup rejects upstream TLS-insecure mode.
- Credential-enabled startup rejects bindings that match `ignore_hosts`.
- Cross-host redirect strips or re-evaluates injected credentials.
- Sandbox deletion cleans up Credential Proxy and any sandbox-scoped credential material.

### E2E Tests

- Create a sandbox with `networkPolicy.defaultAction=deny`, allow `api.github.com`, bind a read-only GitHub credential, and verify a normal `https://api.github.com/...` call succeeds through Credential Proxy.
- Create a sandbox with a `git-https-basic` template, run `git clone https://code.alibaba-inc.com/foo/bar.git`, and verify the injected Basic auth succeeds without credentials in the URL.
- Verify direct access to a non-allowed domain fails under egress policy.
- Verify logs and diagnostic APIs never contain the credential string.
- Verify a mock upstream that echoes request headers does not expose known credential values in supported response headers or text bodies.
- Verify response redaction covers both raw and rendered injected credential values.

## Drawbacks

- Requires enabling transparent MITM for credential-bearing HTTP/HTTPS traffic.
- Adds a new control-plane surface and a credential-aware path inside egress.
- Requires stricter startup behavior than ordinary egress policy; credential-enabled sandboxes fail closed instead of gracefully degrading when transparent interception is unavailable.
- Keeps MITM addons inside the operator/platform trust boundary; sandbox-supplied addons remain unsupported for credential-enabled sandboxes.
- Cannot provide an absolute secrecy guarantee against arbitrary upstream services that echo credentials in unsupported response encodings or protocols.
- Users may confuse Credential Vault with a full secret management system.
- Debugging outbound requests becomes more complex because credentials are injected outside the application process.
- Header injection covers common API use cases but not all credential workflows, such as SSH private keys or database passwords.

## Alternatives

### Inject Secrets as Environment Variables

This is simple and already common, but it exposes plaintext credentials to the sandbox process. It does not satisfy the primary security goal.

### Mount Secrets as Files

This avoids environment variable leakage but still exposes plaintext credentials to sandbox processes. Agents can read, print, copy, or upload the files.

### Rely Only on External Secret Managers

External secret managers are still needed as sources, but sandbox workloads would need secret manager credentials to fetch secrets directly. That moves the same exposure problem into a different API.

### SDK-only Credential Clients

SDK mediation can be safer and more structured, but it requires language-specific client changes and does not cover existing CLIs, package managers, curl, git-over-HTTPS, or arbitrary agent-generated code. Credential Proxy works at the runtime egress boundary.

### Explicit Proxy or Local Gateway First

Explicit proxy and local gateway modes avoid transparent network interception, but they require application configuration and do not match the current OpenSandbox egress direction. The existing egress transparent mitmproxy path already provides the correct runtime interception point for Credential Proxy.

### User-defined Templates in CreateSandboxRequest

Allowing sandbox creators to define arbitrary templates inline would reduce server configuration work, but templates decide target hosts, path scope, headers, schemes, ports, and credential rendering. Those are security policy surfaces. This proposal only allows built-in and operator-configured templates; sandbox creators may pass validated non-sensitive params and a credential source.

## Infrastructure Needed

- No new Credential Proxy component image for the MVP; Credential Proxy is implemented in the existing egress image through transparent mitmproxy and a first-party credential addon.
- Server configuration for binding templates and optional operator-managed credential backing stores used by those templates.
- Kubernetes permission to create/delete sandbox-scoped runtime Secrets when inline credentials are enabled for Kubernetes runtime.
- CI tests for Docker and Kubernetes runtime paths.
- Documentation and examples for common credential binding patterns.
- Documentation for built-in binding templates and operator-configured templates.
- Sandbox image or runtime support for trusting the OpenSandbox mitmproxy CA.

No new required external service is introduced by the MVP.

## Upgrade & Migration Strategy

Credential Vault is opt-in. Existing sandboxes, SDK calls, egress policies, and runtime behavior remain unchanged when `credentialVault` is omitted.

Recommended rollout:

1. Add schema and server validation behind `[credential_vault].enabled = false` by default.
2. Extend egress transparent mitmproxy with credential addon support and inline credential bootstrap.
3. Implement Kubernetes egress sidecar credential bootstrap using sandbox-scoped runtime material.
4. Add SDK models and CLI examples.
5. Document production guidance: use `networkPolicy.defaultAction=deny`, keep credential targets narrow, avoid broad methods and paths, and monitor audit events.

No migration is required for existing users. Users currently injecting secrets through environment variables can gradually migrate by passing sandbox-scoped inline credentials at creation time, or by using platform-provided binding templates that hide operator-managed credentials behind platform authorization.
