"""
Election service for SecureVote.
Manages election metadata, candidates, and election results.
"""
from typing import Dict, Any, List
from database.db import get_db, log_event


class ElectionService:
    """Provides election metadata, candidate roster, and certified results."""

    ELECTION_METADATA = {
        "title": "Student Council General Election 2026",
        "description": "Annual democratic election for the Executive President of the Student Council.",
        "status": "OPEN",
        "start_time": "2026-11-20 08:00:00 UTC",
        "end_time": "2026-11-30 20:00:00 UTC",
        "jurisdiction": "University Student Governance Association",
        "eligibility_rule": "Registered students in good standing (1 vote per registered student)"
    }

    @classmethod
    def get_election_details(cls) -> Dict[str, Any]:
        """Returns official election metadata."""
        conn = get_db()
        candidate_count = conn.execute("SELECT COUNT(*) as count FROM candidates;").fetchone()["count"]
        total_votes = conn.execute("SELECT COUNT(*) as count FROM votes;").fetchone()["count"]
        conn.close()

        details = dict(cls.ELECTION_METADATA)
        details["candidate_count"] = candidate_count
        details["total_votes_cast"] = total_votes
        return details

    @staticmethod
    def get_all_candidates() -> List[Dict[str, Any]]:
        """Retrieves candidate list ordered by ID."""
        conn = get_db()
        rows = conn.execute("SELECT * FROM candidates ORDER BY id ASC;").fetchall()
        conn.close()
        return [dict(r) for r in rows]

    @staticmethod
    def get_candidate(candidate_id: int) -> Dict[str, Any]:
        """Retrieves single candidate by ID."""
        conn = get_db()
        row = conn.execute("SELECT * FROM candidates WHERE id = ?;", (candidate_id,)).fetchone()
        conn.close()
        return dict(row) if row else None

    @staticmethod
    def get_results() -> Dict[str, Any]:
        """
        Retrieves official vote tallies and breakdown.
        Voter identities are completely decoupled from individual vote rows (Ballot Secrecy).
        """
        conn = get_db()
        cursor = conn.cursor()

        tallies = cursor.execute("""
            SELECT c.id, c.name, c.position, c.affiliation, COUNT(v.id) as vote_count
            FROM candidates c
            LEFT JOIN votes v ON c.id = v.candidate_id
            GROUP BY c.id, c.name, c.position, c.affiliation
            ORDER BY vote_count DESC, c.id ASC;
        """).fetchall()

        total_votes = cursor.execute("SELECT COUNT(*) as count FROM votes;").fetchone()["count"]

        recent_votes = cursor.execute("""
            SELECT id, voter_hash, candidate_id, encrypted_vote, hmac_tag, timestamp, status
            FROM votes
            ORDER BY id DESC LIMIT 15;
        """).fetchall()

        conn.close()

        tallies_list = []
        for row in tallies:
            count = row["vote_count"]
            percentage = round((count / total_votes * 100), 1) if total_votes > 0 else 0.0
            tallies_list.append({
                "id": row["id"],
                "name": row["name"],
                "position": row["position"],
                "affiliation": row["affiliation"],
                "vote_count": count,
                "percentage": percentage
            })

        return {
            "election": ElectionService.ELECTION_METADATA,
            "total_votes": total_votes,
            "tallies": tallies_list,
            "recent_ballots": [dict(v) for v in recent_votes]
        }

    @staticmethod
    def reset_election():
        """Clears cast votes and voter status for testing/evaluation."""
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM votes;")
        cursor.execute("UPDATE voters SET has_voted = 0;")
        conn.commit()
        conn.close()
        log_event("ELECTION_DATA_RESET", "ADMIN", "All ballot records reset and voter eligibility restored for evaluation.", "SUCCESS")
