# запрещаем опасные методы вне /api
resource "cloudflare_filter" "block_bad_methods_outside_api" {
  zone_id     = var.zone_id
  description = "Block non-GET/HEAD methods outside /api"
  expression  = <<-EOT
    (not starts_with(http.request.uri.path, "/api")) and
    (http.request.method in {"POST" "PUT" "PATCH" "DELETE"})
  EOT
}

resource "cloudflare_firewall_rule" "block_bad_methods_outside_api" {
  zone_id     = var.zone_id
  filter_id   = cloudflare_filter.block_bad_methods_outside_api.id
  action      = "block"
  description = "Block dangerous HTTP methods outside /api"
}

# подозрительно длинные query у GET
resource "cloudflare_filter" "challenge_long_query" {
  zone_id     = var.zone_id
  description = "JS Challenge for suspicious long GET queries"
  expression  = <<-EOT
    (http.request.method eq "GET") and
    (len(http.request.uri.query) gt 256)
  EOT
}

resource "cloudflare_firewall_rule" "challenge_long_query" {
  zone_id     = var.zone_id
  filter_id   = cloudflare_filter.challenge_long_query.id
  action      = "js_challenge"
  description = "JS challenge on long query strings"
}
