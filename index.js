import express from 'express';
import cors from 'cors';
import mysql from 'mysql';
import morgan from 'morgan';
import bodyParser from 'body-parser';
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv'

//for deployment
import path from 'path';

dotenv.config()

//for deployment
const __dirname = path.resolve();

const app = express();
app.use(cors(
    {
        credentials: true,
        origin: ['http://localhost:5173',process.env.FRONTEND_HOST]
    }
));
app.use(morgan('dev'));
app.use(express.json());
app.use(bodyParser.json());
app.use(cookieParser())

const mysqlDB = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
});

app.get('/', async(req, res)=>{
    try{
        const mysql_code = 'SELECT * FROM usermodel';
       await mysqlDB.query(mysql_code, (err, ans)=>{
            if(err){
                return res.json({msg: err});
            }
            return res.json(ans);
        })
    }catch(err){
        console.log(err)
    }
});

app.get('/getid/:id', async(req, res)=>{
    try{
        const id = req.params.id
        const sql = 'SELECT * FROM usermodel WHERE id = ?';
        mysqlDB.query(sql, [id], (err, ans)=>{
            if(err){
                return res.json({msg: err})
            }
            return res.json(ans)
        })
    }catch(err){
        console.log(err)
    }
});

app.post('/create', async(req, res)=>{
    try{
        const {username, age} = req.body
        const sql = 'INSERT INTO usermodel (`username`,`age`) VALUES (?, ?)';
        await mysqlDB.query(sql, [username, age], (err, ans)=>{
            if(err){
                return res.json({msg: err})
            }
            const sql2 = 'SELECT * FROM usermodel WHERE id = ?';
            mysqlDB.query(sql2, [ans.insertId], (err, data)=>{
                if(err){
                    return res.json({msg: err})
                }
                return res.json(data)
            })
        })
    }catch(err){
        console.log(err)
    }
});

app.put('/update/:id', async(req, res)=>{
    try{
        const id = req.params.id
        const {username, age} = req.body
        const sql = 'UPDATE usermodel SET username = ?, age = ? WHERE id = ?';
        mysqlDB.query(sql, [username, age, id], (err, ans)=>{
            if(err){
                return res.json({msg: err})
            }
            return res.json(ans)
        })
    }catch(err){
        console.log(err)
    }
});

app.delete('/delete/:id', async(req, res)=>{
    try{
        const id = req.params.id
        const sql = 'DELETE FROM usermodel WHERE id = ?';
        mysqlDB.query(sql, [id], (err, ans)=>{
            if(err){
                return res.json({msg: err})
            }
            return res.json(ans)
        })
    }catch(err){
        console.log(err)
    }
});

app.post('/register', async(req, res)=>{
    const {username, email, password} = req.body
    try{
        if(!username || !email || !password){
            return res.json('Please add all col.')
        }
        const sqlcode = 'SELECT myid FROM mymodels WHERE email = ? '
        mysqlDB.query(sqlcode, [email], (err, data)=>{
            if(err) return res.json(err)
            if(data[0]) return res.json("user used.")
            
            const sqlcode2 = 'INSERT INTO mymodels (username, email, password) VALUES (?, ?, ?)'
            const passHash = bcrypt.hashSync(password, 10)
            mysqlDB.query(sqlcode2, [username, email, passHash], (err, data2)=>{
                if(err) return res.json(err)
                return res.json({status: 'ok'})
            })
        })
    }catch(err){
        console.log(err)
    }
});

app.post('/login', async(req, res)=>{
    const {email, password} = req.body
    try{
        if(!email || !password) return res.json('Please add all col.')

        const sqlCheckUser = 'SELECT * FROM mymodels WHERE email = ?'
        mysqlDB.query(sqlCheckUser, [email], (err, data)=>{
            if(err) return res.json(err)
            if(!data[0]){
                return res.json('user not found.')
            }
            bcrypt.compare(password, data[0].password, (err, match)=>{
                if(err) return res.json(err)
                if(match){
                   const token =  jwt.sign({email: data[0].email}, 'my-secrect',{expiresIn: '1h'})
                   return res.cookie('mytoken', token,{httpOnly:true}).json({status: 'login success.'})
                }
                return res.json('password is wrong.')
            })
        })
    }catch(err){
        console.log(err)
    }
});

app.get('/logout', async(req, res)=>{
    try{
        return res.clearCookie('mytoken').json('logout success.')
    }catch(err){
        console.log(err)
    }
});

app.post('/middleware', async(req, res)=>{
    const token = req.cookies.mytoken
    try{
        if(!token){
            return res.json('no token')
        }
        const data = jwt.verify(token, 'my-secrect')
        return res.json(data)
    }catch(err){
        console.log(err)
    }
})

//for deployment
app.use(express.static(path.join(__dirname, '../frontend/dist')))
app.get('*', (req, res)=>{
    res.sendFile(path.join(__dirname, '../frontend/dist','index.html'))
})

const Port = 5000;

app.listen(Port, ()=>{
    console.log(`Server is running on PORT ${Port}`)
});