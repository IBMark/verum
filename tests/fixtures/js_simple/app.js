class UserService {
    constructor(db) {
        this.db = db;
    }

    async getUserById(id) {
        return this.db.findOne({ id });
    }

    async fetchUser(id) {
        // Duplicate of getUserById
        return this.db.findOne({ id });
    }

    formatDate(date) {
        // Dead code - never called
        return new Date(date).toISOString();
    }
}

function calculateTotal(items) {
    let total = 0;
    for (const item of items) {
        total += item.price;
    }
    return total;
}

function legacyHelper() {
    // Dead function
    return "deprecated";
}

module.exports = { UserService, calculateTotal };
