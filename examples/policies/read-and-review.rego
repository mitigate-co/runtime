# Example only: the gateway must independently require matching grants, current
# schemas and any approval. This policy alone does not enable tool invocation.
package mitigate.mcp

default decision := "deny"

decision := "deny" if {
    input.grant == "denied"
} else := "deny" if {
    input.schema_changed
} else := "deny" if {
    input.principal == null
} else := "require_approval" if {
    input.grant == "explicit"
    "delete_data" in input.capabilities
} else := "allow" if {
    input.grant == "explicit"
    "read_data" in input.capabilities
    count(input.capabilities) == 1
}
