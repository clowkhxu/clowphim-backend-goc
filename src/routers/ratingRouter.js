const express = require('express')
const ratingController = require("../controller/ratingController")

const route = express.Router()


route.post('/get-ratings', ratingController.getRatings)
route.post('/add-rating', ratingController.addRating)

module.exports = route
