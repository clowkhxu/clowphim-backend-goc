const express = require('express')

const route = express.Router()

route.use('/', (req, res) => {
    res.json("Hello world")
})

module.exports = route