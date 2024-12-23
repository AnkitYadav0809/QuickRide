const mongoose = require('mongoose');
const bcrypt= require('bcrypt');
const jwt = require('jsonwebtoken');
const userSchema = new mongoose.Schema(
    {
        fullname: {
            firstname:{
                type:String,
                required: true,
                minlength: [3, 'first name must be at least 3 charracter'],
            },
            lastname:{
                type:String,
                //required: true,
                minlength: [3, 'first name must be at least 3 charracter'],
            }
        },
        email: 
        {
            type: String,
            required : true,
            unique: true,
            minlength : [5, "email must be atleast 5 char"],
        },
        password:
        {
            type:String,
            required: true,
            select : false,
        },
        socketId:
        {
            type: String,
        },

    }
)
userSchema.methods.generateAuthToken = function()
{
    const token = jwt.sign({_id: this._id}, process.env.JWT_SECRET);
    return token;
}
userSchema.methods.comparePassword = async function (password)
{
    return await bcrypt.compare(password, this.password);
}

userSchema.statics.hashPassword = async function (password)
{
    return await bcrypt.compare(password, 10);
}
const usermodel = mongoose.model('user', userSchema);
module.exports=usermodel
