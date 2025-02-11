'use strict';
/** @type {import('sequelize-cli').Migration} */
module.exports = {
    async up(queryInterface, Sequelize) {
        await queryInterface.createTable('Ratings', {
            id: {
                allowNull: false,
                primaryKey: true,
                type: Sequelize.STRING
            },
            user_id: {
                type: Sequelize.STRING,
                references: {
                    model: 'Users',
                    key: 'id'
                },
            },
            movie_slug: {
                type: Sequelize.STRING
            },
            rating: {
                type: Sequelize.INTEGER
            },
            createdAt: {
                allowNull: false,
                type: Sequelize.DATE
            },
            updatedAt: {
                allowNull: false,
                type: Sequelize.DATE
            }
        });
    },
    async down(queryInterface, Sequelize) {
        await queryInterface.dropTable('Ratings');
    }
};