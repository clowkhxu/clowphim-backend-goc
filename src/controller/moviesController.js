const moviesService = require("../service/moviesService")

const getAllMovies = async (req, res) => {
    try {
        const { type, userId } = req.query

        if (!type || !userId) {
            return res.json({
                EC: -1,
                EM: 'type hoặc userId không tồn tai!',
                DT: {
                    type: 'saved-movies',
                    movies: []
                }
            })
        }

        const data = await moviesService.handleGetALlMovies(req.query)

        return res.json({
            EC: data.EC,
            EM: data.EM,
            data: data.DT
        })

    } catch (error) {
        console.log(error)
        return res.status(500).json({
            EC: -1,
            EM: 'Lỗi không xác định!'
        })
    }
}

const addMovie = async (req, res) => {
    try {
        const data = await moviesService.handleAddMovie(req.body)

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

const deleteMovie = async (req, res) => {
    try {
        const data = await moviesService.handleDeleteMovie(req.body)

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

const deleteAllMovies = async (req, res) => {
    try {
        const data = await moviesService.handleDeleteAll(req.body)

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
    deleteAllMovies,
    getAllMovies,
    addMovie,
    deleteMovie
}