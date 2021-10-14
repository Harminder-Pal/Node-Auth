const express= require('express');
const path = require('path');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const User = require('./model/user');
const bcrypt = require('bcryptjs');
const jwt = require ('jsonwebtoken');
const JWT_SECRET = 'hjgtsdfxhggkjouiudfdxkjlhgghjgytdytf';


mongoose.connect('mongodb://localhost:27017/login-app-db',{
    useNewUrlParser: true,
    useUnifiedTopology: true
    //useCreateIndex: true
})
const app = express();
app.use('/',express.static(path.join(__dirname, 'static')));
app.use(bodyParser.json()) //middleware

app.post('/api/login', async(req, res) =>{

    const { username, password} = req.body


    const user = await User.findOne({username , password}).lean()

    if(!user){
        return res.json({status: 'error', error: 'Invalid username/password'})
    }

    if(await bcrypt.compare(password, user.password)){

        const token = jwt.sign({
            id: user.id, 
            username:user.username
        }, JWT_SECRET)

        return res.json({status: 'error', data: token })
    }


    res.json({status: 'error', error:'Invalid username/password'})
})
app.post('/api/register', async(req, res)=>{
    //console.log(req.body);
    //const {username, password}= req.body;
    const{ username, password: plainTextPassword} = req.body;

    if(!username || typeof username !== 'string'){
        return res.json({status: 'error', error: 'Invalid username'})
    }

    if(!plainTextPassword || typeof plainTextPassword !== 'string'){
        return res.json({status: 'error', error: 'Invalid password'})
    }

    if(plainTextPassword.length<5){
        return res.json({status: 'error', error: 'Password ahould not be less tha 6 charcters'})
    }
    const password = await bcrypt.hash(plainTextPassword, 10);


    try{
        const response = await User.create({
            username,
            password
        });
        console.log("user created successfully",response);
    }catch(error) {
        if(error.code ===11000){
            return res.json({status: 'error', error:'Username already in use'})
        }
        throw error
    }
    res.json({status: "ok"})
})

app.listen(9999, () => {
    console.log(`Server is running at port 9999`)
})
