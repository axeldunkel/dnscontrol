[Elitedomains](https://elitedomains.de) is a German domain registrar specializing in premium and expired domains.

## Configuration

To use this provider, add an entry to `creds.json` with `TYPE` set to `ELITEDOMAINS`
along with your API token.

**Example:**

{% code title="creds.json" %}
```json
{
  "elitedomains": {
    "TYPE": "ELITEDOMAINS",
    "token": "your-api-token"
  }
}
```
{% endcode %}

## Getting an API Token

API access must be enabled by the Elitedomains support team. Once enabled, you can manage your API tokens in the [Elitedomains Dashboard](https://app.elitedomains.de) under Account Settings.

## Metadata

This provider does not recognize any special metadata fields unique to Elitedomains.

## Usage

Elitedomains can be used as both a DNS provider and a domain registrar.

### As DNS Provider and Registrar

{% code title="dnsconfig.js" %}
```javascript
var REG_ELITEDOMAINS = NewRegistrar("elitedomains");
var DSP_ELITEDOMAINS = NewDnsProvider("elitedomains");

D("example.de", REG_ELITEDOMAINS, DnsProvider(DSP_ELITEDOMAINS),
    A("@", "1.2.3.4"),
    A("www", "1.2.3.4"),
    AAAA("@", "2001:db8::1"),
    MX("@", 10, "mail.example.de."),
    TXT("@", "v=spf1 mx -all"),
    CNAME("ftp", "www.example.de."),
);
```
{% endcode %}

### As Registrar Only (with External DNS)

You can use Elitedomains as a registrar while hosting DNS elsewhere:

{% code title="dnsconfig.js" %}
```javascript
var REG_ELITEDOMAINS = NewRegistrar("elitedomains");
var DSP_CLOUDFLARE = NewDnsProvider("cloudflare");

D("example.de", REG_ELITEDOMAINS, DnsProvider(DSP_CLOUDFLARE),
    A("@", "1.2.3.4"),
    // ...
);
```
{% endcode %}

## Supported Record Types

The following DNS record types are supported:

| Type  | Support |
|-------|---------|
| A     | ✅ |
| AAAA  | ✅ |
| CNAME | ✅ |
| MX    | ✅ |
| TXT   | ✅ |
| SPF   | ✅ |

Other record types (SRV, CAA, etc.) are not currently supported by the Elitedomains API.

## Registrar Features

When used as a registrar, Elitedomains supports updating nameservers for your domains.

### External Nameservers

When switching to external nameservers (e.g., Cloudflare), the Elitedomains API requires **exactly 2 nameservers**. If you specify more than 2, only the first 2 will be used.

{% code title="dnsconfig.js" %}
```javascript
var REG_ELITEDOMAINS = NewRegistrar("elitedomains");
var DSP_CLOUDFLARE = NewDnsProvider("cloudflare");

D("example.de", REG_ELITEDOMAINS, DnsProvider(DSP_CLOUDFLARE),
    // Cloudflare will provide nameservers automatically
    A("@", "1.2.3.4"),
);
```
{% endcode %}

### Switching Back to Elitedomains DNS

To switch a domain back to Elitedomains' own nameservers, simply use Elitedomains as the DNS provider:

{% code title="dnsconfig.js" %}
```javascript
var REG_ELITEDOMAINS = NewRegistrar("elitedomains");
var DSP_ELITEDOMAINS = NewDnsProvider("elitedomains");

D("example.de", REG_ELITEDOMAINS, DnsProvider(DSP_ELITEDOMAINS),
    A("@", "1.2.3.4"),
);
```
{% endcode %}

## Sandbox Mode

For testing purposes, you can enable sandbox mode which prevents any real changes from being made:

{% code title="creds.json" %}
```json
{
  "elitedomains": {
    "TYPE": "ELITEDOMAINS",
    "token": "your-api-token",
    "sandbox": "1"
  }
}
```
{% endcode %}

## API Rate Limits

The Elitedomains API has the following rate limits:

| Time Period | Standard Limit |
|-------------|----------------|
| Per Minute  | 100 requests   |
| Per Day     | 1,000 requests |

**Note:** Between 02:00-04:00 UTC, stricter limits apply (10 requests/minute, 100 total) due to domain catching operations.

## Notes

### Required A Record for Root

**Important:** Elitedomains requires a valid A record for the root domain (`@`) for DNS to be active. Without this, other DNS records may not work. Always include an A record for `@` in your configuration:

{% code title="dnsconfig.js" %}
```javascript
D("example.de", REG_ELITEDOMAINS, DnsProvider(DSP_ELITEDOMAINS),
    A("@", "1.2.3.4"),  // Required!
    TXT("@", "v=spf1 mx -all"),
    // other records...
);
```
{% endcode %}

### DNS Record Management

The Elitedomains API does not support individual record creation, update, or deletion. Instead, all DNS records must be sent as a complete set in a single API call. DNSControl handles this automatically, but it means that any change (even to a single record) will re-submit all records for the domain.

### Default TTL

If no TTL is specified, records default to 3600 seconds (1 hour).

### Domain Creation

DNSControl cannot create new domains via the Elitedomains API. Domains must be registered separately through the [Elitedomains website](https://elitedomains.de) before they can be managed with DNSControl.
