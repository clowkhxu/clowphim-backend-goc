const express = require('express')
const moviesController = require("../controller/moviesController")

const route = express.Router()

route.get('/get-all-movies', moviesController.getAllMovies)
route.post('/add-movie', moviesController.addMovie)
route.post('/delete-movie', moviesController.deleteMovie)
route.post('/delete-all-movie', moviesController.deleteAllMovies)


module.exports = route
