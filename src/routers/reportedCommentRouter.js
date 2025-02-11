const express = require('express')
const reportedCommentController = require('../controller/reportedComment')
const route = express.Router()

route.post('/add-reported-comment', reportedCommentController.addReportedComment)

module.exports = route
