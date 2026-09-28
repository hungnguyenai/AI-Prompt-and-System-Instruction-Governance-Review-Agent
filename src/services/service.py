"""AgentCore Platform v1.0"""

# Service layer: domain queries, external API wrappers, data aggregation.
# Must NOT contain business logic, routing, or credentials.
# Nodes call this; this calls shared/services/ for external integrations.
#
# CMN-C1-074 note: the governance scanner uses an inline pattern baseline + config
# toggles (config/agent.yaml → agent.config.governance_checks). Wire an external
# injection-pattern library loader here if production needs runtime-updatable patterns.
