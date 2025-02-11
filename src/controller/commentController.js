const commentService = require("../service/commentService")

const getComments = async (req, res) => {
    try {
        const { movieSlug, sortOrder } = req.params

        if (!movieSlug || !sortOrder) {
            return res.json({
                EC: -1,
                EM: "movieSlug hoặc sortOrder không tồn tại!",
                DT: []
            })
        }

        const data = await commentService.handleGetComments({
            movieSlug, sortOrder
        })
        
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

const addComment = async (req, res) => {
    try {
        const data = await commentService.handleAddComment(req.body)

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

const deleteComment = async (req, res) => {
    try {

        const data = await commentService.handleDeleteComment(req.body.id);

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

const updateComment = async (req, res) => {
    try {
        const data = await commentService.handleUpdateComment(req.body);

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
    addComment,
    deleteComment,
    updateComment,
    getComments
}