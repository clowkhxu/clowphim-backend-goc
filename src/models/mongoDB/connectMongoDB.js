require('dotenv').config()
const mongoose = require('mongoose');

const connectionMongoDB = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI);
        console.log('Kết nối đến MongoDB thành công!');
    } catch (err) {
        console.error('Lỗi kết nối tới MongoDB:', err);
    }
}

module.exports = connectionMongoDB