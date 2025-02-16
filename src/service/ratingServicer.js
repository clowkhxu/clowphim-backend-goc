const db = require('../models/mysql/index')
const { v4: uuidv4 } = require('uuid');

const handleGetRating = async (rawData) => {
    try {

        const { movieSlug, userId } = rawData
        const response = await db.Ratings.findAll({
            where: { movie_slug: movieSlug },
            include: [{ model: db.Users, as: 'user', attributes: ['username'] }],
            raw: true
        });

        console.log(response)

        const listUserRating = response.map(rating => {
            return {
                userId: rating?.user_id,
                username: rating?.['user.username'],
                rating: rating?.rating
            }
        })

        if (response.length === 0) {
            return {
                EC: 0,
                EM: 'Không có đánh giá nào.',
                DT: {
                    listUserRating,
                    ratingWidthUser: 0,
                    averageRating: 0,
                    countRating: 0
                }
            };
        }

        const ratingCurrentUser = await db.Ratings.findOne({
            where: { user_id: userId, movie_slug: movieSlug },
            raw: true
        })

        const totalRating = response.reduce((acc, rating) => acc + rating.rating, 0);
        const averageRating = (totalRating / response.length).toFixed(1);
        const countRating = response.length;

        return {
            EC: 0,
            EM: 'Lấy danh sách đánh giá thành công!',
            DT: {
                listUserRating,
                ratingWidthUser: ratingCurrentUser?.rating,
                averageRating: averageRating,
                countRating: countRating
            }
        };

    } catch (error) {
        console.log(error)
        return {
            EC: -1,
            EM: 'Lỗi không xác định!'
        }
    }
}

const handleAddRating = async (rawData) => {
    try {


        const { userId, movieSlug, rating } = rawData

        const response = await db.Ratings.findOne({
            where: { movie_slug: movieSlug, user_id: userId }
        })

        if (!response) {
            await db.Ratings.create({
                id: uuidv4(),
                user_id: userId,
                movie_slug: movieSlug,
                rating: rating
            })

        } else {
            await db.Ratings.update(
                { rating: rawData.rating },
                { where: { user_id: userId, movie_slug: movieSlug } }
            )
        }

        return {
            EC: 0,
            EM: "Đánh giá phim thành công!"
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
    handleAddRating,
    handleGetRating
}