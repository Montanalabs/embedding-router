#! VULNERABLE embedding-router — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant routeEmbed

let raw = fetch<web>
privileged { routeEmbed(raw) }  # tainted -> tool: REJECTED
