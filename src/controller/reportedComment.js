const reportedCommentService = require("../service/reportedCommentService")

const addReportedComment = async (req, res) => {
    try {
        const data = await reportedCommentService.handleAddReportedComment(req.body)

        return res.json({
            EC: data?.EC,
            EM: data?.EM
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
    addReportedComment
}