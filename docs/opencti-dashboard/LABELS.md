# Labels manuell zuordnen

Die passenden kurzen Labels am selben Case ergänzen, prüfen und danach die alten technischen Zuordnungen entfernen.
Zusätzlich jedem Shellhound-Case `Webserver Compromise` geben. Das Label allein ist kein technischer Nachweis.
Vor dem Dashboard den aktualisierten Labelkatalog importieren; danach das neue Dashboard importieren.

| Vorhandenes technisches Label | Zusätzliches kurzes Label |
|---|---|
| `shellhound:profile:employee_count:unknown` | `SH Größe: unbekannt` |
| `shellhound:profile:employee_count:0` | `SH Größe: 0` |
| `shellhound:profile:employee_count:1-9` | `SH Größe: 1–9` |
| `shellhound:profile:employee_count:10-49` | `SH Größe: 10–49` |
| `shellhound:profile:employee_count:50-249` | `SH Größe: 50–249` |
| `shellhound:profile:employee_count:250-999` | `SH Größe: 250–999` |
| `shellhound:profile:employee_count:1000+` | `SH Größe: 1000+` |
| `shellhound:profile:hosting_model:unknown` | `SH Hosting: unbekannt` |
| `shellhound:profile:hosting_model:on_premises` | `SH Hosting: vor Ort` |
| `shellhound:profile:hosting_model:colocation` | `SH Hosting: Colocation` |
| `shellhound:profile:hosting_model:dedicated_vps` | `SH Hosting: Server/VPS` |
| `shellhound:profile:hosting_model:shared_hosting` | `SH Hosting: Shared` |
| `shellhound:profile:hosting_model:managed_hosting` | `SH Hosting: Managed` |
| `shellhound:profile:hosting_model:cloud` | `SH Hosting: Cloud` |
| `shellhound:profile:hosting_model:mixed` | `SH Hosting: gemischt` |
| `shellhound:profile:hosting_model:other` | `SH Hosting: sonstige` |
| `shellhound:profile:it_operating_model:unknown` | `SH IT: unbekannt` |
| `shellhound:profile:it_operating_model:internal` | `SH IT: intern` |
| `shellhound:profile:it_operating_model:external` | `SH IT: extern` |
| `shellhound:profile:it_operating_model:mixed` | `SH IT: gemischt` |
| `shellhound:profile:it_operating_model:no_dedicated_support` | `SH IT: keine Betreuung` |
| `shellhound:profile:initial_access:unknown` | `SH Zugang: unbekannt` |
| `shellhound:profile:initial_access:software_vulnerability` | `SH Zugang: Schwachstelle` |
| `shellhound:profile:initial_access:stolen_credentials` | `SH Zugang: Zugangsdaten` |
| `shellhound:profile:initial_access:phishing` | `SH Zugang: Phishing` |
| `shellhound:profile:initial_access:misconfiguration` | `SH Zugang: Fehlkonfig.` |
| `shellhound:profile:initial_access:third_party` | `SH Zugang: Drittpartei` |
| `shellhound:profile:initial_access:other` | `SH Zugang: sonstige` |
| `shellhound:profile:initial_access_status:unknown` | `SH Bewertung: unbekannt` |
| `shellhound:profile:initial_access_status:suspected` | `SH Bewertung: vermutet` |
| `shellhound:profile:initial_access_status:confirmed` | `SH Bewertung: bestätigt` |
| `shellhound:profile:spread:web_application` | `SH Ausbreitung: Webanwendung` |
| `shellhound:profile:spread:web_server` | `SH Ausbreitung: Webserver` |
| `shellhound:profile:spread:other_servers` | `SH Ausbreitung: weitere Server` |
| `shellhound:profile:spread:endpoints` | `SH Ausbreitung: Endgeräte` |
| `shellhound:profile:spread:identity_services` | `SH Ausbreitung: Identität` |
| `shellhound:profile:spread:cloud_saas` | `SH Ausbreitung: Cloud/SaaS` |
| `shellhound:profile:spread:unknown` | `SH Ausbreitung: unbekannt` |
| `shellhound:profile:data_exfiltration:unknown` | `SH Abfluss: unbekannt` |
| `shellhound:profile:data_exfiltration:not_investigated` | `SH Abfluss: nicht untersucht` |
| `shellhound:profile:data_exfiltration:not_observed` | `SH Abfluss: nicht beobachtet` |
| `shellhound:profile:data_exfiltration:suspected` | `SH Abfluss: vermutet` |
| `shellhound:profile:data_exfiltration:confirmed` | `SH Abfluss: bestätigt` |
| `shellhound:profile:attacker_encryption:unknown` | `SH Verschlüss.: unbekannt` |
| `shellhound:profile:attacker_encryption:not_investigated` | `SH Verschlüss.: nicht untersucht` |
| `shellhound:profile:attacker_encryption:not_observed` | `SH Verschlüss.: nicht beobachtet` |
| `shellhound:profile:attacker_encryption:suspected` | `SH Verschlüss.: vermutet` |
| `shellhound:profile:attacker_encryption:confirmed` | `SH Verschlüss.: bestätigt` |
| `shellhound:profile:discovered_by:unknown` | `SH Entdecker: unbekannt` |
| `shellhound:profile:discovered_by:internal_it` | `SH Entdecker: interne IT` |
| `shellhound:profile:discovered_by:employee` | `SH Entdecker: Mitarbeitende` |
| `shellhound:profile:discovered_by:it_provider` | `SH Entdecker: IT-Dienstleister` |
| `shellhound:profile:discovered_by:soc_mdr` | `SH Entdecker: SOC/MDR` |
| `shellhound:profile:discovered_by:customer` | `SH Entdecker: Kunde` |
| `shellhound:profile:discovered_by:authority` | `SH Entdecker: Behörde` |
| `shellhound:profile:discovered_by:attacker` | `SH Entdecker: Angreifer` |
| `shellhound:profile:discovered_by:other` | `SH Entdecker: sonstige` |
| `shellhound:profile:discovery_method:unknown` | `SH Entdeckung: unbekannt` |
| `shellhound:profile:discovery_method:monitoring` | `SH Entdeckung: Monitoring` |
| `shellhound:profile:discovery_method:user_report` | `SH Entdeckung: Nutzermeldung` |
| `shellhound:profile:discovery_method:external_notification` | `SH Entdeckung: extern` |
| `shellhound:profile:discovery_method:ransom_note` | `SH Entdeckung: Erpresserbrief` |
| `shellhound:profile:discovery_method:incidental` | `SH Entdeckung: Zufallsfund` |
| `shellhound:profile:discovery_method:other` | `SH Entdeckung: sonstige` |
| `shellhound:profile:hosting_providers:amazon web services (aws)` | `SH Anbieter: AWS` |
| `shellhound:profile:hosting_providers:microsoft azure` | `SH Anbieter: Azure` |
| `shellhound:profile:hosting_providers:google cloud` | `SH Anbieter: GCP` |
| `shellhound:profile:hosting_providers:hetzner` | `SH Anbieter: Hetzner` |
| `shellhound:profile:hosting_providers:ionos` | `SH Anbieter: IONOS` |
| `shellhound:profile:hosting_providers:ovhcloud` | `SH Anbieter: OVHcloud` |
| `shellhound:profile:hosting_providers:host europe` | `SH Anbieter: Host Europe` |
| `shellhound:profile:hosting_providers:strato` | `SH Anbieter: Strato` |
| `shellhound:profile:hosting_providers:all-inkl` | `SH Anbieter: ALL-INKL` |
| `shellhound:profile:hosting_providers:netcup` | `SH Anbieter: netcup` |
| `shellhound:profile:hosting_providers:digitalocean` | `SH Anbieter: DigitalOcean` |
| `shellhound:profile:hosting_providers:akamai / linode` | `SH Anbieter: Linode` |
| `shellhound:profile:hosting_providers:cloudflare` | `SH Anbieter: Cloudflare` |
| `shellhound:profile:hosting_providers:vercel` | `SH Anbieter: Vercel` |
| `shellhound:profile:hosting_providers:netlify` | `SH Anbieter: Netlify` |
| `shellhound:profile:hosting_providers:unknown` | `SH Anbieter: unbekannt` |
| `shellhound:profile:initial_cve:unknown` | `SH Initial-CVE: unbekannt` |
| `shellhound:profile:initial_cve:cve-2026-12345` | `SH Initial-CVE: CVE-2026-12345` |

Initial-CVE: die konkrete CVE einsetzen. Eigene Anbieter: `SH Anbieter: <Name>` verwenden.
Den Bereich `SH ` für Shellhound reservieren. Änderungen im Case Profile ersetzen alte SH-Labels beim nächsten Transfer.
Datumsfilter für den Vergleich aller Kennzahlen leer lassen.
