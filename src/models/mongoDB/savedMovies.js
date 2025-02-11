const mongoose = require('mongoose');

const savedMoviesSchema = new mongoose.Schema({
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


const SavedMovies = mongoose.model('SavedMovies', savedMoviesSchema);

module.exports = SavedMovies;
