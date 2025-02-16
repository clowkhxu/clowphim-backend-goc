'use strict';
const {
    Model
} = require('sequelize');
module.exports = (sequelize, DataTypes) => {
    class ReportedComments extends Model {
        /**
         * Helper method for defining associations.
         * This method is not a part of Sequelize lifecycle.
         * The `models/index` file will call this method automatically.
         */
        static associate(models) {
            ReportedComments.belongsTo(models.Comments, {
                foreignKey: 'id_comment',
                as: 'comment'
            });

            ReportedComments.belongsTo(models.Users, {
                foreignKey: 'reporter',
                as: 'reporter_user'
            });
        }
    }
    ReportedComments.init({
        id_comment: {
            type: DataTypes.STRING,
            allowNull: false,
            references: {
                model: 'Comments',  
                key: 'id'  
            },
            onDelete: 'CASCADE',
        },
        reporting_reason: {
            type: DataTypes.STRING,
            allowNull: false
        }
    }, {
        sequelize,
        modelName: 'ReportedComments',
    });
    return ReportedComments;
};
