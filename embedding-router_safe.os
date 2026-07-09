#! Embedding router — untrusted a text chunk can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires routeEmbed — the embedding router sink
#! @effect io
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant routeEmbed

type EmbedModel = Tiny | Base | Huge
type Decision = Route(EmbedModel) | Skip

let raw = fetch<web>  # UNTRUSTED a text chunk — tainted
quarantined { let d = extract<Decision>(raw) }  # only a fixed Decision (payloads too) crosses
privileged { routeEmbed(d) }  # act on the trusted decision only
