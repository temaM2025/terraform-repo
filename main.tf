
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

###
resource "cloudflare_filter" "block_http"{
  zone_id     = var.zone_id
  description = "Block plain HTTP traffic"
  expression  = "(not ssl)"	
}

resource "cloudflare_firewall_rule" "block_http" {

 zone_id    = var.zone_id
  filter_id   = cloudflare_filter.block_http.id
  description = "HTTPS only"
  action      = "block"
}
