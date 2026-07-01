"""
Catálogo de assinaturas de segredos por provedor — formatos públicos e
documentados de tokens/chaves (mesma natureza de dado que gitleaks/trufflehog
usam: apenas a FORMA do token, não segredos reais). Cada entrada inclui a
regex de detecção, o nome do provedor e a URL onde o token pode ser revogado
(revogação assistida).
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class ProviderSignature:
    provider: str
    secret_type: str
    pattern: re.Pattern
    revoke_url: str
    confidence: str = "HIGH"  # HIGH | MEDIUM | LOW


def _p(provider: str, secret_type: str, regex: str, revoke_url: str,
       confidence: str = "HIGH") -> ProviderSignature:
    return ProviderSignature(provider, secret_type, re.compile(regex), revoke_url, confidence)


PROVIDER_SIGNATURES: List[ProviderSignature] = [
    # ── Cloud (AWS/GCP/Azure) ──────────────────────────────────────────────────
    _p("AWS", "Access Key ID", r'\bAKIA[0-9A-Z]{16}\b', "https://console.aws.amazon.com/iam/home#/security_credentials"),
    _p("AWS", "Secret Access Key", r'(?i)aws_secret_access_key\s*[:=]\s*["\']?[A-Za-z0-9/+=]{40}["\']?', "https://console.aws.amazon.com/iam/home#/security_credentials"),
    _p("AWS", "Session Token", r'\bASIA[0-9A-Z]{16}\b', "https://console.aws.amazon.com/iam/home#/security_credentials"),
    _p("AWS", "MWS Auth Token", r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', "https://sellercentral.amazon.com/gp/mws/registration/register.html"),
    _p("GCP", "API Key", r'\bAIza[0-9A-Za-z\-_]{35}\b', "https://console.cloud.google.com/apis/credentials"),
    _p("GCP", "Service Account JSON", r'"type":\s*"service_account"', "https://console.cloud.google.com/iam-admin/serviceaccounts", confidence="MEDIUM"),
    _p("GCP", "OAuth Client Secret", r'\bGOCSPX-[A-Za-z0-9_-]{28}\b', "https://console.cloud.google.com/apis/credentials"),
    _p("Azure", "Storage Account Key", r'(?i)accountkey\s*=\s*[A-Za-z0-9+/=]{88}', "https://portal.azure.com"),
    _p("Azure", "Connection String", r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}', "https://portal.azure.com"),
    _p("Azure", "SAS Token", r'(?i)sv=\d{4}-\d{2}-\d{2}&s[ri]s?=', "https://portal.azure.com", confidence="MEDIUM"),
    _p("DigitalOcean", "Personal Access Token", r'\bdop_v1_[a-f0-9]{64}\b', "https://cloud.digitalocean.com/account/api/tokens"),
    _p("Linode", "API Token", r'\b[a-f0-9]{64}\b', "https://cloud.linode.com/profile/tokens", confidence="LOW"),
    _p("Heroku", "API Key", r'(?i)heroku[a-z0-9_\-]*[:=]\s*["\']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', "https://dashboard.heroku.com/account"),
    _p("Cloudflare", "API Token", r'\b[A-Za-z0-9_-]{40}\b', "https://dash.cloudflare.com/profile/api-tokens", confidence="LOW"),
    _p("Cloudflare", "Global API Key", r'(?i)cf[_-]?api[_-]?key\s*[:=]\s*["\']?[a-f0-9]{37}', "https://dash.cloudflare.com/profile/api-tokens"),

    # ── VCS / CI ──────────────────────────────────────────────────────────────
    _p("GitHub", "Personal Access Token", r'\bghp_[A-Za-z0-9]{36}\b', "https://github.com/settings/tokens"),
    _p("GitHub", "OAuth Token", r'\bgho_[A-Za-z0-9]{36}\b', "https://github.com/settings/applications"),
    _p("GitHub", "App Token", r'\b(?:ghu|ghs)_[A-Za-z0-9]{36}\b', "https://github.com/settings/apps"),
    _p("GitHub", "Refresh Token", r'\bghr_[A-Za-z0-9]{76}\b', "https://github.com/settings/tokens"),
    _p("GitHub", "Fine-grained PAT", r'\bgithub_pat_[A-Za-z0-9_]{82}\b', "https://github.com/settings/tokens?type=beta"),
    _p("GitLab", "Personal Access Token", r'\bglpat-[A-Za-z0-9_\-]{20}\b', "https://gitlab.com/-/profile/personal_access_tokens"),
    _p("Bitbucket", "App Password", r'(?i)bitbucket[_-]?(?:app)?[_-]?password\s*[:=]\s*["\']?[A-Za-z0-9]{20}', "https://bitbucket.org/account/settings/app-passwords/"),
    _p("CircleCI", "API Token", r'(?i)circle[_-]?ci[_-]?token\s*[:=]\s*["\']?[a-f0-9]{40}', "https://app.circleci.com/settings/user/tokens"),
    _p("Travis CI", "API Token", r'(?i)travis[_-]?token\s*[:=]\s*["\']?[A-Za-z0-9]{22}', "https://app.travis-ci.com/account/preferences"),
    _p("Terraform Cloud", "API Token", r'\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,90}\b', "https://app.terraform.io/app/settings/tokens"),
    _p("npm", "Automation Token", r'\bnpm_[A-Za-z0-9]{36}\b', "https://www.npmjs.com/settings/~/tokens"),
    _p("PyPI", "API Token", r'\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b', "https://pypi.org/manage/account/token/"),
    _p("Docker Hub", "Personal Access Token", r'\bdckr_pat_[A-Za-z0-9_-]{27}\b', "https://hub.docker.com/settings/security"),

    # ── Comunicação ───────────────────────────────────────────────────────────
    _p("Slack", "Bot/User Token", r'\bxox[baprs]-[A-Za-z0-9-]{10,72}\b', "https://api.slack.com/apps"),
    _p("Slack", "Webhook URL", r'https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8,}/B[A-Za-z0-9_]{8,}/[A-Za-z0-9_]{24}', "https://api.slack.com/apps"),
    _p("Discord", "Bot Token", r'\b[MN][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}\b', "https://discord.com/developers/applications"),
    _p("Discord", "Webhook URL", r'https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+', "https://discord.com/developers/applications"),
    _p("Telegram", "Bot Token", r'\b\d{8,10}:[A-Za-z0-9_-]{35}\b', "https://t.me/BotFather"),
    _p("Twilio", "Account SID", r'\bAC[a-f0-9]{32}\b', "https://console.twilio.com/", confidence="MEDIUM"),
    _p("Twilio", "Auth Token", r'(?i)twilio[_-]?(?:auth[_-]?)?token\s*[:=]\s*["\']?[a-f0-9]{32}', "https://console.twilio.com/"),
    _p("Twilio", "API Key", r'\bSK[a-f0-9]{32}\b', "https://console.twilio.com/"),
    _p("SendGrid", "API Key", r'\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b', "https://app.sendgrid.com/settings/api_keys"),
    _p("Mailgun", "API Key", r'\bkey-[a-f0-9]{32}\b', "https://app.mailgun.com/settings/api_security"),
    _p("Mailchimp", "API Key", r'\b[a-f0-9]{32}-us\d{1,2}\b', "https://admin.mailchimp.com/account/api/"),
    _p("Zoom", "JWT API Secret", r'(?i)zoom[_-]?api[_-]?secret\s*[:=]\s*["\']?[A-Za-z0-9]{32}', "https://marketplace.zoom.us/develop/apps"),

    # ── Pagamentos ────────────────────────────────────────────────────────────
    _p("Stripe", "Live Secret Key", r'\bsk_live_[A-Za-z0-9]{24,247}\b', "https://dashboard.stripe.com/apikeys"),
    _p("Stripe", "Live Publishable Key", r'\bpk_live_[A-Za-z0-9]{24,247}\b', "https://dashboard.stripe.com/apikeys", confidence="LOW"),
    _p("Stripe", "Restricted Key", r'\brk_live_[A-Za-z0-9]{24,247}\b', "https://dashboard.stripe.com/apikeys"),
    _p("Square", "Access Token", r'\bsq0atp-[A-Za-z0-9_-]{22}\b', "https://developer.squareup.com/apps"),
    _p("Square", "OAuth Secret", r'\bsq0csp-[A-Za-z0-9_-]{43}\b', "https://developer.squareup.com/apps"),
    _p("PayPal/Braintree", "Access Token", r'\baccess_token\$production\$[A-Za-z0-9]{16}\$[A-Za-z0-9]{32}\b', "https://www.braintreegateway.com/"),
    _p("Shopify", "Access Token", r'\bshpat_[a-f0-9]{32}\b', "https://www.shopify.com/admin/settings/apps"),
    _p("Shopify", "Custom App Token", r'\bshpca_[a-f0-9]{32}\b', "https://www.shopify.com/admin/settings/apps"),
    _p("Shopify", "Private App Password", r'\bshppa_[a-f0-9]{32}\b', "https://www.shopify.com/admin/settings/apps"),

    # ── Dados / Infra ─────────────────────────────────────────────────────────
    _p("MongoDB", "Connection String c/ senha", r'mongodb(?:\+srv)?://[^:\s]+:[^@\s]+@[^\s/]+', "https://cloud.mongodb.com/", confidence="MEDIUM"),
    _p("PostgreSQL", "Connection String c/ senha", r'postgres(?:ql)?://[^:\s]+:[^@\s]+@[^\s/]+', "N/A — gire a senha do banco diretamente", confidence="MEDIUM"),
    _p("MySQL", "Connection String c/ senha", r'mysql://[^:\s]+:[^@\s]+@[^\s/]+', "N/A — gire a senha do banco diretamente", confidence="MEDIUM"),
    _p("Redis", "URI c/ senha", r'redis://[^:\s]*:[^@\s]+@[^\s/]+', "N/A — gire a senha do Redis diretamente", confidence="MEDIUM"),
    _p("RabbitMQ", "URI c/ senha", r'amqp://[^:\s]+:[^@\s]+@[^\s/]+', "N/A — gire a senha do RabbitMQ diretamente", confidence="MEDIUM"),
    _p("Snowflake", "Connection c/ senha", r'(?i)snowflake[_-]?(?:password|pwd)\s*[:=]\s*["\'][^"\']{6,}', "https://app.snowflake.com/"),
    _p("Databricks", "Personal Access Token", r'\bdapi[a-f0-9]{32}\b', "https://accounts.databricks.com/"),
    _p("HashiCorp Vault", "Token", r'\bhvs\.[A-Za-z0-9_-]{24,}\b', "N/A — revogue via 'vault token revoke'"),
    _p("Supabase", "Service Role Key (JWT)", r'\beyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b', "https://app.supabase.com/", confidence="MEDIUM"),
    _p("PlanetScale", "Service Token", r'\bpscale_tkn_[A-Za-z0-9]{43}\b', "https://app.planetscale.com/"),
    _p("Algolia", "Admin API Key", r'(?i)algolia[_-]?(?:admin[_-]?)?(?:api[_-]?)?key\s*[:=]\s*["\']?[a-f0-9]{32}', "https://www.algolia.com/account/api-keys/"),

    # ── AI / LLM ──────────────────────────────────────────────────────────────
    _p("OpenAI", "API Key", r'\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b', "https://platform.openai.com/api-keys"),
    _p("OpenAI", "Project API Key", r'\bsk-proj-[A-Za-z0-9_-]{20,}\b', "https://platform.openai.com/api-keys"),
    _p("Anthropic", "API Key", r'\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{93,}\b', "https://console.anthropic.com/settings/keys"),
    _p("Cohere", "API Key", r'(?i)cohere[_-]?api[_-]?key\s*[:=]\s*["\']?[A-Za-z0-9]{40}', "https://dashboard.cohere.com/api-keys"),
    _p("HuggingFace", "API Token", r'\bhf_[A-Za-z0-9]{34}\b', "https://huggingface.co/settings/tokens"),
    _p("Replicate", "API Token", r'\br8_[A-Za-z0-9]{37}\b', "https://replicate.com/account/api-tokens"),
    _p("Groq", "API Key", r'\bgsk_[A-Za-z0-9]{52}\b', "https://console.groq.com/keys"),
    _p("Mistral", "API Key", r'(?i)mistral[_-]?api[_-]?key\s*[:=]\s*["\']?[A-Za-z0-9]{32}', "https://console.mistral.ai/api-keys"),

    # ── Monitoramento / Observabilidade ─────────────────────────────────────────
    _p("Sentry", "Auth Token", r'\bsntrys_[A-Za-z0-9_]{40,}\b', "https://sentry.io/settings/account/api/auth-tokens/"),
    _p("Datadog", "API Key", r'(?i)datadog[_-]?api[_-]?key\s*[:=]\s*["\']?[a-f0-9]{32}', "https://app.datadoghq.com/organization-settings/api-keys"),
    _p("New Relic", "License Key", r'(?i)new[_-]?relic[_-]?license[_-]?key\s*[:=]\s*["\']?[a-f0-9]{40}', "https://one.newrelic.com/api-keys"),
    _p("PagerDuty", "API Key", r'(?i)pagerduty[_-]?(?:api[_-]?)?key\s*[:=]\s*["\']?[A-Za-z0-9+_-]{20}', "https://app.pagerduty.com/api_keys"),
    _p("Bugsnag", "API Key", r'(?i)bugsnag[_-]?api[_-]?key\s*[:=]\s*["\']?[a-f0-9]{32}', "https://app.bugsnag.com/settings/"),
    _p("Rollbar", "Access Token", r'(?i)rollbar[_-]?(?:access[_-]?)?token\s*[:=]\s*["\']?[a-f0-9]{32}', "https://rollbar.com/settings/tokens/"),
    _p("Honeybadger", "API Key", r'(?i)honeybadger[_-]?api[_-]?key\s*[:=]\s*["\']?[a-f0-9]{32}', "https://app.honeybadger.io/"),

    # ── Analytics / Produto ───────────────────────────────────────────────────
    _p("Segment", "Write Key", r'(?i)segment[_-]?write[_-]?key\s*[:=]\s*["\']?[A-Za-z0-9]{32}', "https://app.segment.com/"),
    _p("Mixpanel", "API Secret", r'(?i)mixpanel[_-]?(?:api[_-]?)?secret\s*[:=]\s*["\']?[a-f0-9]{32}', "https://mixpanel.com/settings/project"),
    _p("Amplitude", "API Key", r'(?i)amplitude[_-]?api[_-]?key\s*[:=]\s*["\']?[a-f0-9]{32}', "https://analytics.amplitude.com/"),

    # ── Identidade / Auth ─────────────────────────────────────────────────────
    _p("Auth0", "Client Secret", r'(?i)auth0[_-]?client[_-]?secret\s*[:=]\s*["\']?[A-Za-z0-9_-]{64}', "https://manage.auth0.com/#/applications"),
    _p("Okta", "API Token", r'\b00[A-Za-z0-9_-]{40}\b', "https://login.okta.com/", confidence="LOW"),
    _p("Firebase", "Cloud Messaging Key", r'\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b', "https://console.firebase.google.com/"),
    _p("Google OAuth", "Client Secret", r'(?i)GOCSPX-[A-Za-z0-9_-]{28}', "https://console.cloud.google.com/apis/credentials"),
    _p("Facebook", "Access Token", r'\bEAACEdEose0cBA[A-Za-z0-9]+\b', "https://developers.facebook.com/apps/"),
    _p("Twitter/X", "Bearer Token", r'\bAAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{20,}\b', "https://developer.twitter.com/en/portal/dashboard", confidence="MEDIUM"),

    # ── Colaboração / Suporte ──────────────────────────────────────────────────
    _p("Atlassian/Jira", "API Token", r'(?i)atlassian[_-]?(?:api[_-]?)?token\s*[:=]\s*["\']?[A-Za-z0-9]{24}', "https://id.atlassian.com/manage-profile/security/api-tokens"),
    _p("Zendesk", "API Token", r'(?i)zendesk[_-]?(?:api[_-]?)?token\s*[:=]\s*["\']?[A-Za-z0-9]{40}', "https://support.zendesk.com/hc/en-us/articles/4408886858522"),
    _p("Intercom", "Access Token", r'(?i)intercom[_-]?(?:access[_-]?)?token\s*[:=]\s*["\']?[A-Za-z0-9=_-]{60,}', "https://app.intercom.com/"),
    _p("Asana", "Personal Access Token", r'\b[0-9]{16}:[a-f0-9]{32}\b', "https://app.asana.com/0/my-apps"),
    _p("Trello", "API Token", r'(?i)trello[_-]?token\s*[:=]\s*["\']?[a-f0-9]{64}', "https://trello.com/app-key"),
    _p("Dropbox", "Access Token", r'\bsl\.[A-Za-z0-9_-]{130,150}\b', "https://www.dropbox.com/developers/apps"),
    _p("Box", "Developer Token", r'(?i)box[_-]?developer[_-]?token\s*[:=]\s*["\']?[A-Za-z0-9]{32}', "https://app.box.com/developers/console"),

    # ── Genéricos ─────────────────────────────────────────────────────────────
    _p("JWT", "Token genérico", r'\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b', "N/A — invalide o token no serviço emissor", confidence="MEDIUM"),
    _p("SSH", "Private Key", r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----', "N/A — remova a chave de todo host autorizado (~/.ssh/authorized_keys)"),
    _p("PGP", "Private Key Block", r'-----BEGIN PGP PRIVATE KEY BLOCK-----', "N/A — revogue via seu certificado de revogação PGP"),
    _p("Generic", "API Key/Secret Atribuído", r'(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*["\'][A-Za-z0-9_\-/+=]{16,}["\']', "N/A — revise manualmente o serviço correspondente", confidence="LOW"),
    _p("Generic", "Basic Auth em URL", r'https?://[^:\s/]+:[^@\s/]+@[^\s/]+', "N/A — remova credenciais embutidas na URL", confidence="LOW"),

    # ── Expansão adicional de provedores ────────────────────────────────────────
    _p("Vercel", "Access Token", r'(?i)vercel[_-]?(?:api[_-]?)?token\s*[:=]\s*["\']?[A-Za-z0-9]{24}', "https://vercel.com/account/tokens"),
    _p("Netlify", "Access Token", r'(?i)netlify[_-]?(?:auth[_-]?|access[_-]?)?token\s*[:=]\s*["\']?[A-Za-z0-9_-]{40,64}', "https://app.netlify.com/user/applications"),
    _p("Render", "API Key", r'\brnd_[A-Za-z0-9]{20,}\b', "https://dashboard.render.com/u/settings#api-keys"),
    _p("Fly.io", "API Token", r'(?i)fly[_-]?api[_-]?token\s*[:=]\s*["\']?[A-Za-z0-9_/=+]{40,}', "https://fly.io/user/personal_access_tokens"),
    _p("Postman", "API Key", r'\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b', "https://web.postman.co/settings/me/api-keys"),
    _p("Contentful", "Management Token", r'(?i)contentful[_-]?(?:management[_-]?)?token\s*[:=]\s*["\']?[A-Za-z0-9_-]{40,}', "https://app.contentful.com/account/profile/cma_tokens"),
    _p("Sanity", "API Token", r'\bsk[a-zA-Z0-9]{60,80}\b', "https://www.sanity.io/manage", confidence="LOW"),
    _p("LaunchDarkly", "SDK Key", r'\bsdk-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', "https://app.launchdarkly.com/settings/projects"),
    _p("Split.io", "API Key", r'(?i)split[_-]?api[_-]?key\s*[:=]\s*["\']?[a-z0-9]{32,40}', "https://app.split.io/"),
    _p("Statuspage", "API Key", r'(?i)statuspage[_-]?api[_-]?key\s*[:=]\s*["\']?[A-Za-z0-9_-]{20,}', "https://manage.statuspage.io/"),
    _p("Freshdesk", "API Key", r'(?i)freshdesk[_-]?api[_-]?key\s*[:=]\s*["\']?[A-Za-z0-9]{15,}', "https://support.freshdesk.com/"),
    _p("HubSpot", "API Key/Token", r'(?i)hubspot[_-]?(?:api[_-]?key|token)\s*[:=]\s*["\']?[a-f0-9-]{36}', "https://app.hubspot.com/private-apps/"),
    _p("Salesforce", "Session ID/Token", r'(?i)salesforce[_-]?(?:session[_-]?id|token)\s*[:=]\s*["\']?[A-Za-z0-9._!]{60,}', "https://login.salesforce.com/"),
    _p("Zapier", "Webhook Secret", r'https://hooks\.zapier\.com/hooks/catch/\d+/[A-Za-z0-9]+', "https://zapier.com/app/settings", confidence="MEDIUM"),
    _p("Airtable", "API Key", r'\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b', "https://airtable.com/create/tokens"),
    _p("Coinbase", "API Secret", r'(?i)coinbase[_-]?(?:api[_-]?)?secret\s*[:=]\s*["\']?[A-Za-z0-9]{64,}', "https://www.coinbase.com/settings/api"),
    _p("Binance", "API Secret", r'(?i)binance[_-]?(?:api[_-]?)?secret\s*[:=]\s*["\']?[A-Za-z0-9]{64}', "https://www.binance.com/en/my/settings/api-management"),
    _p("Plaid", "Secret", r'(?i)plaid[_-]?secret\s*[:=]\s*["\']?[a-f0-9]{30,}', "https://dashboard.plaid.com/team/keys"),
    _p("Twitch", "Client Secret", r'(?i)twitch[_-]?client[_-]?secret\s*[:=]\s*["\']?[a-z0-9]{30}', "https://dev.twitch.tv/console/apps"),
    _p("Spotify", "Client Secret", r'(?i)spotify[_-]?client[_-]?secret\s*[:=]\s*["\']?[a-f0-9]{32}', "https://developer.spotify.com/dashboard"),
    _p("Notion", "Integration Token", r'\bntn_[A-Za-z0-9]{40,50}\b', "https://www.notion.so/my-integrations"),
    _p("Linear", "API Key", r'\blin_api_[A-Za-z0-9]{40}\b', "https://linear.app/settings/api"),
    _p("Figma", "Personal Access Token", r'\bfigd_[A-Za-z0-9_-]{40,}\b', "https://www.figma.com/developers/api#access-tokens"),
    _p("CloudAMQP", "URI c/ senha", r'amqps://[^:\s]+:[^@\s]+@[^\s/]+\.cloudamqp\.com', "https://customer.cloudamqp.com/"),
    _p("Elastic Cloud", "API Key", r'(?i)elastic[_-]?(?:cloud[_-]?)?api[_-]?key\s*[:=]\s*["\']?[A-Za-z0-9+/=]{40,}', "https://cloud.elastic.co/"),
    _p("Grafana", "API Key", r'\bglc_[A-Za-z0-9+/=]{40,}\b', "https://grafana.com/profile/api-keys"),
    _p("Grafana", "Service Account Token", r'\bglsa_[A-Za-z0-9]{32}_[A-Za-z0-9]{8}\b', "https://grafana.com/profile/api-keys"),
    _p("1Password", "Service Account Token", r'\bops_eyJ[A-Za-z0-9_-]{200,}\b', "https://my.1password.com/"),
    _p("Doppler", "Service Token", r'\bdp\.st\.[A-Za-z0-9_]{40,44}\b', "https://dashboard.doppler.com/workplace/settings/tokens"),
    _p("Infura", "Project ID", r'(?i)infura[_-]?(?:project[_-]?)?id\s*[:=]\s*["\']?[a-f0-9]{32}', "https://app.infura.io/"),
    _p("Alchemy", "API Key", r'(?i)alchemy[_-]?api[_-]?key\s*[:=]\s*["\']?[A-Za-z0-9_-]{32}', "https://dashboard.alchemy.com/apps"),
    _p("Etherscan", "API Key", r'(?i)etherscan[_-]?api[_-]?key\s*[:=]\s*["\']?[A-Za-z0-9]{34}', "https://etherscan.io/myapikey"),
]


def classify_secret(text: str) -> List[Tuple[str, str, str, str]]:
    """Retorna [(provider, secret_type, matched_text, revoke_url), ...] para
    todas as assinaturas que casarem no texto."""
    results = []
    for sig in PROVIDER_SIGNATURES:
        for m in sig.pattern.finditer(text):
            results.append((sig.provider, sig.secret_type, m.group(0), sig.revoke_url))
    return results


def provider_count() -> int:
    return len({s.provider for s in PROVIDER_SIGNATURES})


def signature_count() -> int:
    return len(PROVIDER_SIGNATURES)
