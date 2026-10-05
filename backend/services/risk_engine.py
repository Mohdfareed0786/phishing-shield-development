from dataclasses import dataclass


@dataclass(frozen=True)
class RiskFactor:
    key: str
    title: str
    details: str
    evidence: str
    points: int

    def as_dict(self) -> dict:
        return {
            'key': self.key,
            'title': self.title,
            'details': self.details,
            'evidence': self.evidence,
            'points': self.points,
        }


CLASSIFICATIONS = (
    (80, 'CRITICAL RISK'),
    (60, 'HIGH RISK'),
    (30, 'MEDIUM RISK'),
    (0, 'LOW RISK'),
)


class RiskEngine:
    @staticmethod
    def score(factors: list[RiskFactor]) -> tuple[int, str]:
        score = min(100, max(0, sum(max(0, factor.points) for factor in factors)))
        classification = next(label for threshold, label in CLASSIFICATIONS if score >= threshold)
        return score, classification

    @staticmethod
    def coverage(*, structural: bool, dns_performed: bool, provider_responses: int, provider_count: int) -> int:
        score = (30 if structural else 0) + (15 if dns_performed else 0)
        if provider_count:
            score += round(55 * min(provider_responses, provider_count) / provider_count)
        return min(100, score)
