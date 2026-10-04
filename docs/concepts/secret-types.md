# Secret Types

The personal `pm` vault currently supports 25 entry types. Every type carries an optional `space` field so entries can be grouped inside the same vault.

## Personal entry types

| Type | Key fields |
| :-- | :-- |
| Password | `account`, `username`, `password`, `website`, `urls[]` |
| TOTP | `account`, `secret` |
| Token | `name`, `token`, `type` |
| Secure note | `name`, `content` |
| API key | `name`, `service`, `key` |
| SSH key | `name`, `private_key` |
| Wi-Fi | `ssid`, `password`, `security_type`, `router_ip` |
| Recovery codes | `service`, `codes[]` |
| Certificate | `label`, `cert_data`, `private_key`, `issuer`, `expiry` |
| Banking item | `label`, `type`, `details`, `cvv`, `expiry` |
| Document | `name`, `file_name`, `content`, `password`, `tags`, `expiry` |
| Government ID | `type`, `id_number`, `name`, `expiry` |
| Medical record | `label`, `insurance_id`, `prescriptions`, `allergies` |
| Travel document | `label`, `ticket_number`, `booking_code`, `loyalty_program` |
| Contact | `name`, `phone`, `email`, `address`, `emergency` |
| Cloud credential | `label`, `access_key`, `secret_key`, `region`, `account_id`, `role`, `expiration` |
| Kubernetes secret | `name`, `cluster_url`, `namespace`, `expiration` |
| Docker registry | `name`, `registry_url`, `username`, `token` |
| SSH config | `alias`, `host`, `user`, `port`, `key_path`, `private_key`, `fingerprint` |
| CI/CD secret | `name`, `webhook`, `env_vars` |
| Software license | `product_name`, `serial_key`, `activation_info`, `expiration` |
| Legal contract | `name`, `summary`, `parties_involved`, `signed_date` |
| Audio | `name`, `file_name`, `content` |
| Video | `name`, `file_name`, `content` |
| Photo | `name`, `file_name`, `content` |

## Practical grouping in `pm add`

The interactive add flow groups these types into:

- Identity and Personal
- Developer and Infrastructure
- Media and Files
- Finance and Legal

You can either choose from the menu or call `pm add <type>` directly with aliases.

## Team edition difference

`pm-team add` supports a similar but smaller shared set. The team binary currently offers 22 shared entry types and does not include the media entry types present in the personal vault.

## Notes

- Binary-bearing entries such as documents, audio, video, and photos are stored inside the vault.
- Trust scoring, history, search, and display behavior vary by entry type.
- Some docs from older versions only listed 22 types; the current personal CLI supports 25.
