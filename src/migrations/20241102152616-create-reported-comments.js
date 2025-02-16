'use strict';
/** @type {import('sequelize-cli').Migration} */
module.exports = {
    async up(queryInterface, Sequelize) {
        await queryInterface.createTable('ReportedComments', {
            id: {
                allowNull: false,
                primaryKey: true,
                type: Sequelize.STRING
            },
            id_comment: {
                type: Sequelize.STRING, 
                allowNull: false,
                references: {
                    model: 'Comments',  
                    key: 'id'  
                },
                onDelete: 'CASCADE',  
            },
            reporting_reason: {
                type: Sequelize.STRING, 
                allowNull: false
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
        await queryInterface.dropTable('ReportedComments');
    }
};
