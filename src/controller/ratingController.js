const ratingService = require('../service/ratingServicer')

const getRatings = async (req, res) => {
    try {
        const data = await ratingService.handleGetRating(req.body)

        return res.json({
            EC: data.EC,
            EM: data.EM,
            DT: data.DT
        })
    } catch (error) {
        console.log(error)
        return res.status(500).json({
            EC: -1,
            EM: 'Lỗi không xác định!'
        })
    }
}

const addRating = async (req, res) => {
    try {
        const data = await ratingService.handleAddRating(req.body)

        return res.json({
            EC: data.EC,
            EM: data.EM
        })
    } catch (error) {
        console.log(error)
        return res.status(500).json({
            EC: -1,
            EM: 'Lỗi không xác định!'
        })
    }
}

module.exports = {
    addRating,
    getRatings
}