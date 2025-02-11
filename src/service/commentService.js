const db = require('../models/mysql/index')
const { v4: uuidv4 } = require('uuid');

const handleGetComments = async (rawData) => {
    try {
        const { movieSlug, sortOrder } = rawData
        const comments = await db.Comments.findAll({
            where: { movie_slug: movieSlug },
            include: [{ model: db.Users, as: 'user', attributes: ['username'] }],
            order: [['createdAt', sortOrder]],
            raw: true
        });

        return {
            EC: 0,
            EM: 'Lấy danh sách bình luận thành công',
            DT: comments
        }


    } catch (error) {
        console.log(error)
        return {
            EC: -1,
            EM: 'Lỗi không xác định!'
        }
    }
}


const handleAddComment = async (rawData) => {
    try {
        const response = await db.Comments.create({
            id: uuidv4(),
            user_id: rawData.userId,
            movie_slug: rawData.movieSlug,
            content: rawData.content
        })

        if (response?.isNewRecord) {
            return {
                EC: -1,
                EM: 'Thêm bình luận thất bại!'
            }
        } else {
            return {
                EC: 0,
                EM: 'Thêm bình luận thành công!'
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

const handleDeleteComment = async (idComment) => {
    try {
        const rows = await db.Comments.destroy({
            where: { id: idComment }
        })

        if (rows === 0) {
            return {
                EC: -1,
                EM: "Xoá bình luận thất bại!"
            }
        } else {
            return {
                EC: 0,
                EM: "Xoá bình luận thành công"
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

const handleUpdateComment = async (rawData) => {
    try {
        const rows = await db.Comments.update(
            { content: rawData.content },
            { where: { id: rawData.idComment } }
        )

        if (rows[0] === 0) {
            return {
                EC: -1,
                EM: "Chỉnh sửa bình luận thất bại!"
            }
        } else {
            return {
                EC: 0,
                EM: "Chỉnh sửa bình luận thành công"
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
    handleAddComment,
    handleDeleteComment,
    handleUpdateComment,
    handleGetComments
}