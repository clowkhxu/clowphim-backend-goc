const db = require('../models/mysql/index')
const { v4: uuidv4 } = require('uuid');

const handleGetSearchHistory = async (userId) => {
    try {
        const response = await db.SearchHistory.findAll({
            where: { user_id: userId },
            order: [['createdAt', 'DESC']],
            raw: true
        });

        return {
            EC: 0,
            EM: 'Lấy danh sách tìm kiếm thành công!',
            DT: response
        };

    } catch (error) {
        console.log(error)
        return {
            EC: -1,
            EM: 'Lỗi không xác định!'
        }
    }
}

const handleAddSearchHistory = async (rawData) => {
    try {

        const { userId, type, keyword } = rawData;
        const idSearchHistory = rawData?.idSearchHistory ?? ""

        if (!userId || !type || !keyword) {
            return {
                EC: -1,
                EM: 'Thông tin đầu vào không đầy đủ!'
            };
        }

        const searchHisory = await db.SearchHistory.findOne({
            where: { id: idSearchHistory }
        })

        if (searchHisory) {
            await db.SearchHistory.update(
                { type: 'favourite' },
                { where: { id: idSearchHistory } }
            )
            return {
                EC: 0,
                EM: "Đã yêu thích lịch sử tìm kiếm!"
            }
        } else {
            await db.SearchHistory.create({
                id: uuidv4(),
                user_id: userId,
                type: type,
                keyword: keyword
            })

            return {
                EC: 0,
                EM: "Đã lưu lịch sử tìm kiếm!"
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

const handleDeleteSearchHistory = async (idSearchHistory) => {
    try {
        await db.SearchHistory.destroy({
            where: { id: idSearchHistory }
        })

        return {
            EC: 0,
            EM: "Xoá lịch sử tìm kiếm thành công!"
        }
    } catch (error) {
        console.log(error)
        return {
            EC: -1,
            EM: 'Lỗi không xác định!'
        }
    }
}

const handleDeleteAllSearchHistory = async (userId) => {
    try {
        await db.SearchHistory.destroy({
            where: { user_id: userId }
        })

        return {
            EC: 0,
            EM: "Xoá tất cả lịch sử tìm kiếm thành công!"
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
    handleAddSearchHistory,
    handleGetSearchHistory,
    handleDeleteSearchHistory,
    handleDeleteAllSearchHistory
}