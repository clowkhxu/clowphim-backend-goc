const { Sequelize } = require('sequelize');
require('dotenv').config()

// kết nối db clever clound
const sequelize = new Sequelize(
    process.env.DB_NAME,
    process.env.DB_USERNAME,
    process.env.DB_PASSWORD, {
    host: process.env.DB_HOST,
    dialect: process.env.DB_DIALECT
})

// kiểm tra kết nối
const connectionMySql = async () => {
    try {
        await sequelize.authenticate();
        console.log('Kết nối mysql thành công!');
    } catch (error) {
        console.error('Kết nối mysql thất bại!', error);
    }
}

module.exports = connectionMySql