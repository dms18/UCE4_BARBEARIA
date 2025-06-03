import {Schema, model} from "mongoose"

const userModel = new Schema({
    name:{
        type:String,
        required:true
    },
    email:{
        type:String,
        required:true,
        unique: true
    },
    password:{
        type:String,
        required:true
    },
    celular:{
        type:String,
        required:true
    },
    cpf: {
        type:String,
        required:true
    },
    endereco: {
        type:String,
        required:true
    }
})

export default model("User", userModel)