const mongoose = require('mongoose');

const watchHistorySchema = new mongoose.Schema({
    userId: {
        type: String,
        required: true,
        unique: true
    },
    movies: [{
        type: mongoose.Schema.Types.Mixed
    }],
    createdAt: {
        type: Date,
        default: Date.now,
    },
});

const WatchHistory = mongoose.model('WatchHistory', watchHistorySchema);

module.exports = WatchHistory;
