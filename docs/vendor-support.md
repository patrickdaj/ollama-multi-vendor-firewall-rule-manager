# Vendor Support

## Supported vendors

| Vendor | Value | Device type | Ingest method |
|---|---|---|---|
| Palo Alto Networks | `paloalto` | PAN-OS firewall / Panorama | PAN-OS XML API (pan-os-python) |
| Cisco ASA | `cisco_asa` | ASA 9.3+ | ASA REST API |
| Cisco ASA (legacy) | `cisco_asa_ssh` | ASA pre-9.3 | CLI via SSH (netmiko) |
| Cisco FTD | `cisco_ftd` | Firepower Threat Defense | FMC REST API |
| Fortinet FortiGate | `fortinet` | FortiOS 6.4+ | FortiOS REST API v2 |

---

## Object type support by vendor

What each loader actually populates after ingest. `✓` = populated, `—` = not applicable to this vendor, `(gap)` = the model supports it but the loader doesn't parse it yet.

| Object type | `object_type` key | PAN-OS | FortiGate | FTD | ASA |
|---|---|---|---|---|---|
| Security rules | `security_rule` | ✓ | ✓ | ✓ | ✓ |
| NAT rules | `nat_rule` | ✓ | ✓ | ✓ | ✓ |
| Address objects | `address_object` | ✓ | ✓ | ✓ | ✓ |
| Service objects | `service_object` | ✓ | ✓ | ✓ | ✓ |
| Service groups | `service_group` | ✓ | ✓ | — | ✓ |
| Zones | `zone` | ✓ | (gap) | (gap) | — |
| Application objects | `application` | ✓ | — | — | — |
| Application groups | `app_group` | ✓ | ✓ | — | — |
| URL categories | `url_category` | ✓ | ✓ | — | — |
| Auth / captive portal policies | `auth_policy` | ✓ | ✓ | — | — |
| Decryption / SSL rules | `decryption_rule` | ✓ | ✓ | ✓ | — |
| Decryption profiles | `decryption_profile` | ✓ | ✓ | ✓ | — |
| DoS protection policies | `dos_policy` | ✓ | ✓ | — | — |
| EDLs / threat feeds | `edl` | ✓ | ✓ | ✓ | — |
| Security profiles (AV, IPS, etc.) | `security_profile` | (gap) | ✓ | ✓ | — |

**Notes on gaps:**
- **PAN-OS `security_profile`**: the loader parses profile *references* inside security rules, but does not yet extract the individual profile definitions (antivirus, IPS, wildfire, etc.) as standalone objects
- **FortiGate / FTD `zone`**: these vendors have zone concepts but the loaders don't yet extract them as explicit zone objects (zones are implicit from interface configs)
- **ASA**: port-based only — no App-ID, URL categories, decryption policy, DoS policy, or EDLs. This is accurate to what ASA supports

---

## Translation complexity by object type

When pushing group policy to a target vendor, some object types translate deterministically (code handles it) while others require AI-assisted translation with human approval.

| Object type | Translation complexity | Notes |
|---|---|---|
| Address objects (host/network/range) | **Deterministic** | All vendors: identical semantics, syntax-only diff |
| Service objects (tcp/udp/port) | **Deterministic** | All vendors: identical semantics |
| Service groups | **Deterministic** | All vendors: list of service references |
| Zones | **Alias** | Per-device DeviceZoneMapping; no semantic translation needed |
| NAT rules (static/dynamic/PAT) | **Deterministic** | Per-vendor syntax generated from NATRule model fields |
| Security rule (basic fields) | **Deterministic** | action, zones, addresses, services |
| Application objects | **AI-assisted** | App-ID (PAN-OS) ↔ FortiGuard signatures (FortiGate) ↔ OpenAppID (FTD) ↔ port fallback (ASA) |
| Application groups | **AI-assisted** | Depends on member app translations |
| URL categories | **AI-assisted** | PAN-DB ≠ FortiGuard ≠ Talos category names |
| Security profiles (AV, IPS, URL) | **AI-assisted** | Profile concept maps but structure and names differ |
| Decryption rules | **AI-assisted** | Profile references and category scope differ |
| EDLs / threat feeds | **AI-assisted** | URL format and update cadence vary by vendor |
| FQDN address objects | **Deterministic + fallback** | All vendors except ASA (limited support → use IP range) |
| Geography objects | **AI-assisted** | PAN-OS regions ↔ FortiGate geography ↔ FTD geo objects; ASA has no equivalent |
| Auth / captive portal policies | **AI-assisted** | Auth method and redirect mechanism differ |

---

## Profile mode vs. policy mode (intra-vendor)

Two fundamentally different inspection architectures exist within some vendors. This is an **intra-vendor** distinction — the same vendor product can operate in either mode, and the data model, what the loader extracts, and what translation produces all change as a result.

### FortiGate: profile-based vs. NGFW policy-based

| Aspect | Profile-based mode (traditional) | NGFW policy-based mode |
|---|---|---|
| Security profiles | Separate objects: AV profile, IPS sensor, App Control profile, Web Filter profile, etc. | No separate profile objects for App Control or Web Filter |
| Policy structure | `firewall policy` references profile objects by name | Application and URL control configured inline inside the policy itself |
| Object reuse | Profiles are standalone objects, reusable across many policies | App/URL logic lives only inside the policy entry — not a reusable object |
| `security_profile` extraction | Loader extracts each profile as a standalone `security_profile` object | Nothing to extract — inspection config is embedded in the rule |
| Translation source | AI-assisted: source profile → equivalent profile on target vendor | AI-assisted: inline rule fields → target vendor profile or inline equivalent |
| Loader behavior | Full `security_profile` objects + rule references | `security_profile` list is empty; rule `security_profiles` field contains inline app/url entries |

**How to tell which mode a device is in:** FortiOS policy-based NGFW mode is set globally (`config system settings / set inspection-mode policy`). The loader detects this from the config and sets `device.metadata["inspection_mode"]` to `"profile"` or `"policy"`. Check this before assuming security profile objects exist.

**Translation implication:** Cross-mode translation (e.g. FortiGate NGFW policy-mode → PAN-OS, or PAN-OS profile-mode → FortiGate NGFW policy-mode) is always AI-assisted. The structural mismatch — standalone objects vs. inline fields — cannot be resolved deterministically.

---

### PAN-OS: security profiles vs. inline application policy

PAN-OS is always profile-based — there is no "policy mode" equivalent. However, there is a related intra-vendor distinction:

| Aspect | Security Profile Group (standard) | Inline App-ID + URL match in rule |
|---|---|---|
| How app/URL control is applied | Security profile group object attached to rule (`profile-setting`) | Application filter or URL category listed directly as match criteria in the security rule |
| Object type | `security_profile` objects + `ProfileGroup` references | No separate profile — App-ID / URL category is a rule match condition |
| Translation behavior | AI-assisted: profile group → target vendor profile equivalent | Deterministic for App-ID match; AI-assisted for URL categories |

**Practical note:** Many PAN-OS deployments use both — App-ID as a match condition in the rule *and* a security profile group for AV/IPS inspection of allowed traffic. The loader captures both independently.

---

### FortiGate: central NAT vs. integrated (interface) NAT

This is a separate intra-vendor mode from inspection mode and can be set independently.

| Aspect | Central NAT mode | Integrated (interface) NAT mode |
|---|---|---|
| Global setting | `config system settings / set central-nat enable` | `central-nat disable` (default) |
| SNAT configuration | Separate `firewall central-snat-map` table — its own policy list with src/dst/translated-src | `nat enable` checkbox inside each `firewall policy`, optionally referencing an IP pool |
| DNAT / VIP configuration | VIPs defined in `firewall vip`, but are **not** added as destination address in the security policy — the central NAT table handles matching | VIPs defined in `firewall vip` and placed directly as `dstaddr` inside the security policy |
| NAT and security policy coupling | Fully decoupled — security policy permits traffic; NAT policy translates it separately | Tightly coupled — NAT config lives inside the security policy object |
| `nat_rule` extraction | Loader extracts `central-snat-map` entries as standalone `nat_rule` objects; VIPs extracted separately | Loader extracts NAT config embedded in each `security_rule`; VIPs in `dstaddr` are extracted as address objects |
| Rule count | Security policy list tends to be shorter (no per-policy NAT variants needed) | Security policy list can be longer — separate rules often needed for each NAT variant |
| Translation complexity | Deterministic for SNAT/DNAT structure; AI-assisted for IP pool and per-interface overload semantics | Deterministic for basic SNAT/PAT; AI-assisted when IP pool or per-policy overload settings are used |

**How to tell which mode a device is in:** The loader detects this from the global config and sets `device.metadata["nat_mode"]` to `"central"` or `"integrated"`. In central NAT mode, `nat_rule` objects come from the central SNAT table; in integrated mode they are synthesized from the NAT fields inside security rules.

**Translation implication:** Cross-mode translation (e.g. FortiGate central NAT → PAN-OS, or integrated NAT → FortiGate central NAT) requires restructuring the NAT relationship to the security rule. This is handled deterministically for basic cases but AI-assisted when IP pool or per-interface overload semantics are involved.

---

## Per-vendor notes

### Palo Alto Networks (PAN-OS)

**Strengths:** Most complete object type coverage. App-ID is the richest application identification across all supported vendors.

**Inspection model:** PAN-OS is always profile-based — security profiles (AV, IPS, WildFire, DNS Security, URL Filtering) are standalone objects attached to rules via a Security Profile Group. There is no "policy-based" equivalent. App-ID and URL categories can additionally appear as direct match conditions in the rule itself alongside profile-based enforcement. See [Profile mode vs. policy mode](#profile-mode-vs-policy-mode-intra-vendor) above.

**Gaps:**
- Security profile objects (antivirus, IPS, wildfire, DNS security, URL filtering) are referenced in rules but not yet extracted as standalone objects — open issue in the PAN-OS loader
- Dynamic Address Groups (DAGs) are parsed but tag-expression evaluation requires VM-Agent integration

**API:** PAN-OS XML API via `pan-os-python`. API key and/or username/password supported.

---

### Fortinet FortiGate

**Strengths:** Second richest coverage. FortiGuard application signatures + URL categories. Central SNAT and VIP NAT both parsed.

**Inspection mode:** FortiGate can run in **profile-based** or **NGFW policy-based** inspection mode — this changes the data model significantly. The loader detects the mode automatically; `device.metadata["inspection_mode"]` will be `"profile"` or `"policy"`. See [FortiGate: profile-based vs. NGFW policy-based](#fortigate-profile-based-vs-ngfw-policy-based).

**NAT mode:** FortiGate can use **central NAT** (separate SNAT policy table, VIPs decoupled from security policy) or **integrated NAT** (NAT config embedded inside each security policy, VIPs as `dstaddr`). The loader detects this automatically; `device.metadata["nat_mode"]` will be `"central"` or `"integrated"`. See [FortiGate: central NAT vs. integrated NAT](#fortigate-central-nat-vs-integrated-interface-nat).

**Gaps:**
- Zone objects not extracted (zones are implicit in interface config)
- Application signature objects not extracted as standalone `application` type (they appear inside `app_group` members)
- In NGFW policy-based mode, `security_profile` objects will be empty — inspection config is embedded inline in rules

**API:** FortiOS REST API v2. Username/password or API token.

---

### Cisco FTD (Firepower Threat Defense)

**Strengths:** SSL/TLS inspection policy, Security Intelligence (EDL equivalent), Access Control rules.

**Gaps:**
- No URL category objects extracted (referenced in rules but not as standalone objects)
- No Auth/DoS policy extraction
- Zone extraction not implemented
- Application groups not extracted

**API:** FMC REST API. The FTD device itself is managed by FMC; the loader connects to FMC, not directly to the FTD.

---

### Cisco ASA

**Coverage:** Most limited by design — ASA is port-based only and does not support App-ID, URL categories, decryption policy, DoS policy, or threat feeds. All `—` entries in the table above are accurate to what ASA supports.

**Gaps (loader):**
- Only the most recent `show access-list` output is parsed; object-groups for complex ACLs may not be fully resolved

**API:** ASA REST API (9.3+) or SSH via netmiko (pre-9.3). REST API is preferred.

---

## Translation coverage matrix

This matrix tracks which object-vendor pairs have approved translations in a given deployment. Initially empty — translations are built up as devices are added to groups and the AI proposal workflow is completed.

Query current coverage:
```
GET /api/v1/translations/objects?status=approved
GET /api/v1/translations/objects?target_vendor=fortinet&status=approved
```

Query pending gaps:
```
GET /api/v1/proposals?status=pending
GET /api/v1/proposals?status=pending&target_vendor=cisco_asa
```

Trigger gap detection for a group + vendor:
```
POST /api/v1/groups/{id}/gaps/{vendor}
```
