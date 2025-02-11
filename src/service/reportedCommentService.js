const db = require('../models/mysql/index')
const { v4: uuidv4 } = require('uuid');

const handleAddReportedComment = async (rawData) => {
    try {
        const response = await db.ReportedComments.create({
            id: uuidv4(),
            id_comment: rawData?.idComment,
            reporting_reason: rawData?.reportingReason
        })

        if (response?.isNewRecord) {
            return {
                EC: -1,
                EM: 'Thêm báo cáo bình luận thành công!'
            }
        } else {
            return {
                EC: 0,
                EM: 'Thêm báo cáo bình luận thất bại!'
            }
        }
    } catch (error) {
        console.log(error)
        return {
            EC: -1,
            EM: 'Lỗi không xác định!'
        }
    }
}

module.exports = {
    handleAddReportedComment
}