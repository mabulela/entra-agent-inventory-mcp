"""MCP prompts: reusable instructions that chain the tools in a sensible order.
(Pattern taken from arunksingh16/azure-entra-mcp.)"""

from .validation import check_guid


def register(server) -> None:

    @server.prompt()
    def migration_readiness(object_id: str) -> str:
        """Full pre-migration review of one legacy service principal or managed identity."""
        oid = check_guid(object_id, "object_id")
        return (
            f"Assess whether Entra principal {oid} is ready to migrate to an agent identity.\n"
            "Call these tools in order and keep every finding tied to its evidence:\n"
            f"1. classify_principal(object_id='{oid}') - what it is, agent likelihood, priority, contact, wave.\n"
            f"2. get_credential_inventory(object_id='{oid}') - credentials and expiry.\n"
            f"3. get_access_footprint(object_id='{oid}') - permissions, roles, owners, blockers.\n"
            f"4. get_conditional_access_coverage(object_id='{oid}') - CA policies to recreate.\n"
            f"5. get_principal_changes(object_id='{oid}', min_severity='medium') - recent changes.\n"
            "Then summarise: migration wave, blockers, CA policies to map to agent policies, "
            "permissions to grant the new identity, owners to notify, and anything that came "
            "back 'not_permitted'. Present the agent likelihood as a heuristic, not a fact."
        )

    @server.prompt()
    def coexistence_review(legacy_object_id: str, new_object_id: str) -> str:
        """Cutover check for a legacy identity and its replacement agent identity."""
        legacy = check_guid(legacy_object_id, "legacy_object_id")
        new = check_guid(new_object_id, "new_object_id")
        return (
            f"Review the coexistence of legacy identity {legacy} and agent identity {new}.\n"
            f"1. compare_coexistence(legacy_object_id='{legacy}', new_object_id='{new}').\n"
            f"2. get_conditional_access_coverage(object_id='{new}').\n"
            f"3. get_access_footprint(object_id='{new}') and compare its permissions with "
            f"get_access_footprint(object_id='{legacy}').\n"
            "Report: calls still only on the legacy identity, permission differences, CA "
            "policies failing or only report-only on the new identity, and any sensitive change "
            "to the legacy identity during coexistence. Give a cutover recommendation with the "
            "evidence behind it; the tool's cutover_signal is indicative only."
        )
