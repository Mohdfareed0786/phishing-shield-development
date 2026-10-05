from services.threat_intelligence import ThreatIntelligenceService


class ReputationService:
    def __init__(self) -> None:
        self.providers = ThreatIntelligenceService()

    async def lookup(self, original_url: str, normalized_url: str, hostname: str, *, ip_literal: bool) -> dict:
        return await self.providers.lookup(original_url, normalized_url, hostname, ip_literal=ip_literal)
