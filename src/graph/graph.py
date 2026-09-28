"""AgentCore Platform v1.0"""

# CMN-C1-074 — AI Prompt & System Instruction Governance Review Agent
#
# Cat 1 — generic governance scanner on the standard 3-slot AgentBaseGraph backbone.
#   Pipeline: START → initialize → pre_process → main → {route} → post_process → finalize → END
#   Slots   : pre_process — S-2 PII mask + S-1 sanitise/frame + tokenize (PromptIngest + PromptTokenize)
#             main         — composite: 5-check scan → aggregate → severity grade → rewrite suggest
#             post_process — governance report build + S-3 output gate (GovernanceReportGenerate + OutputGate)
#
# add_edges() / route() are NOT overridden — backbone wiring belongs to the framework.

from framework.graph.agent_base_graph import AgentBaseGraph
from src.nodes.pre_process_node import PreProcessNode
from src.nodes.main_node import MainNode
from src.nodes.post_process_node import PostProcessNode
from src.schemas.state import State


class PromptGovernanceReviewAgent(AgentBaseGraph):
    """Cat 1 outer graph for CMN-C1-074.

    Class name matches config/agent.yaml `class:`. The governance-check toggles are
    config-driven (config/agent.yaml → agent.config.governance_checks); the pattern
    library is generic (no industry assumption) — Cat 1 purity.
    """

    @property
    def name(self) -> str:
        return "cmn_c1_074"

    @property
    def state_schema(self) -> type:
        return State

    def register_nodes(self) -> None:
        super().register_nodes()  # injects InitializeNode + FinalizeNode

        cfg = getattr(self, "config", None) or {}

        self._nodes["pre_process"] = PreProcessNode()
        self._nodes["main"] = MainNode(cfg)
        self._nodes["post_process"] = PostProcessNode()
