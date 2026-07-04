class ConfidenceEngine:
    @staticmethod
    def calculate_score(rule_score: float, evidence_score: float, agent_score: float, historical_similarity: float) -> float:
        """
        Calculates the overall confidence score of an investigation.
        Weights:
        - Rule score: 40%
        - Evidence score: 30%
        - Agent score: 20%
        - Historical similarity: 10%
        """
        score = (
            (rule_score * 0.4) +
            (evidence_score * 0.3) +
            (agent_score * 0.2) +
            (historical_similarity * 0.1)
        )
        
        breakdown = [
            {"label": "Detection Rule Match", "score": int(rule_score * 0.4 * 100)},
            {"label": "Evidence Quality", "score": int(evidence_score * 0.3 * 100)},
            {"label": "AI Threat Assessment", "score": int(agent_score * 0.2 * 100)},
            {"label": "Historical Similarity", "score": int(historical_similarity * 0.1 * 100)}
        ]
        
        return min(max(round(score, 2), 0.0), 1.0), breakdown
