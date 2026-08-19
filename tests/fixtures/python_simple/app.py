class UserService:
    def __init__(self, db):
        self.db = db

    def get_user_by_id(self, user_id):
        """Get a user by their ID."""
        return self.db.find_one({"id": user_id})

    def fetch_user(self, user_id):
        """Duplicate of get_user_by_id."""
        return self.db.find_one({"id": user_id})

    def _format_legacy_date(self, date):
        """Dead code - never called."""
        from datetime import datetime
        return datetime.fromisoformat(date).strftime("%Y-%m-%d")


def calculate_total(items):
    total = 0
    for item in items:
        total += item["price"]
    return total


def legacy_helper():
    """Dead function - never called."""
    return "deprecated"
