const express = require('express')
const activityLogController = require("../controller/activityLogController")

const route = express.Router()

route.get('/get-activity-log/:userId', activityLogController.getActivityLog)
route.post('/add-activity-log', activityLogController.addActivityLog)
route.post('/delete-activity-log', activityLogController.deleteActivityLog)


module.exports = route
