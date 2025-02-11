'use strict';
/** @type {import('sequelize-cli').Migration} */
module.exports = {
    async up(queryInterface, Sequelize) {
        await queryInterface.createTable('SearchHistories', {
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
            keyword: {
                type: Sequelize.STRING
            },
            type: {
                type: Sequelize.STRING
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
        await queryInterface.dropTable('SearchHistories');
    }
};