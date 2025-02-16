const db = require('../models/mysql/index')
const { v4: uuidv4 } = require('uuid');

const handleGetActivityLog = async (userId) => {
    try {
        const activityLogs = await db.ActivityLogs.findAll({
            where: { user_id: userId },
            include: [{ model: db.Users, as: 'user', attributes: ['username'] }],
            order: [['createdAt', "DESC"]],
            raw: true
        });

        return {
            EC: 0,
            EM: 'Lấy danh sách lịch sử hoạt động thành công!',
            DT: activityLogs
        }


    } catch (error) {
        console.log(error)
        return {
            EC: -1,
            EM: 'Lỗi không xác định!'
        }
    }
}


const handleAddActivityLog = async (rawData) => {
    try {
        const response = await db.ActivityLogs.create({
            id: uuidv4(),
            user_id: rawData.userId,
            action: rawData.action
        })

        if (response?.isNewRecord) {
            return {
                EC: -1,
                EM: 'Lưu lịch sử hoạt động thất bại!'
            }
        } else {
            return {
                EC: 0,
                EM: 'Lưu lịch sử hoạt động thành công!'
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

const handleDeleteActivityLog = async (userId) => {
    try {
        const rows = await db.ActivityLogs.destroy({
            where: { user_id: userId }
        });

        if (rows === 0) {
            return {
                EC: -1,
                EM: "Xoá lịch sử hoạt động thất bại!"
            }
        } else {
            return {
                EC: 0,
                EM: "Xoá lịch sử hoạt động thành công"
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
    handleAddActivityLog,
    handleDeleteActivityLog,
    handleGetActivityLog
}