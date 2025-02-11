const express = require('express')
const searchHistoryController = require("../controller/searchHistoryController")

const route = express.Router()

route.get('/get-search-history/:userId', searchHistoryController.getSearchHistory)
route.post('/add-search-history', searchHistoryController.addSearchHistory)
route.post('/delete-search-history', searchHistoryController.deleteSearchHistory)
route.post('/delete-all-search-history', searchHistoryController.deleteAllSearchHistory)

module.exports = route
