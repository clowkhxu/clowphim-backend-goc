'use strict';
const {
    Model
} = require('sequelize');
module.exports = (sequelize, DataTypes) => {
    class ActivityLogs extends Model {
        /**
         * Helper method for defining associations.
         * This method is not a part of Sequelize lifecycle.
         * The `models/index` file will call this method automatically.
         */
        static associate(models) {
            // define association here
            ActivityLogs.belongsTo(models.Users, {
                foreignKey: 'user_id',
                as: 'user'
            });
        }
    }
    ActivityLogs.init({
        email: DataTypes.STRING,
        user_id: DataTypes.STRING,
        action: DataTypes.STRING
    }, {
        sequelize,
        modelName: 'ActivityLogs',
    });
    return ActivityLogs;
};