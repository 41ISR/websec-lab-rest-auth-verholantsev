const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const db = require("./db")
const express = require("express")

const SECRET = "this-is-for-JWT"

const app = express()

const authMiddleware = (req, res, next) => {
    const authHeader = req.headers.authorization
    if (!authHeader) res.status(401).json({error: "Нет токена авторизации"})
    if (!(authHeader.split(" ")[1])) res.status(401).json({error: "Неверный формат токена"})

    try {
        const token = authHeader.split(" ")[1]
        
        const decoded = jwt.verify(token, SECRET)
        req.users = decoded
        next()
    } catch (error) {
        console.error(error)
    }
}

app.use(express.json())

app.get("/api/auth/profile", authMiddleware, (req ,res) => {
    const { id } = req.users
    const data = db.prepare("SELECT * FROM users WHERE id = ?").get(id)

    if (!data)
        res.status(404).json({ error: "Пользователь не был найден" })
    
    res.json(data)
})

app.post("/api/auth/register", (req, res) => {
    const { email, username, password } = req.body

    try {
        if (!email || !username || !password) {
            return res.status(400).json({ error: "Не хватает данных" })
        }
        const syncSalt = bcrypt.genSaltSync(10)
        const hashed = bcrypt.hashSync(password, syncSalt)
        const query = db.prepare(
            `INSERT INTO users (email, username, password, role) VALUES (?, ?, ?, ?)`
        )
        const info = query.run(email, username, hashed, "admin")
        const newUser = db
            .prepare(`SELECT * FROM users WHERE ID = ?`)
            .get(info.lastInsertRowid)
        res.status(201).json(newUser)
    } catch (error) {
        console.error(error)
        res.status(401).json({error: "Неправильный токен"})
    }
})

app.post("/api/auth/login", (req, res) => {
    try {
        const { email, password } = req.body

        const users = db
            .prepare(`SELECT * FROM users WHERE email = ?`)
            .get(email)

        if (!users) res.status(401).json({ error: "Неправильные данные" })

        const valid = bcrypt.compareSync(password, users.password)

        if (!valid) res.status(401).json({ error: "Неправильные данные" })

        const token = jwt.sign({ ...users }, SECRET, { expiresIn: "24h" })

        const { password: p, ...response } = users

        res.status(200).json({ token: token, ...response })
    } catch (error) {
        console.error(error)
    }
})

app.get("/api/books", (_, res) => {
    const data = db.prepare("SELECT * FROM books").all()
    res.json(data)
})

app.get("/api/books/:id", (req, res) => {
    const { id } = req.params
    const data = db.prepare('SELECT * FROM books WHERE ID = ?').get(id)

     if (!data) res.status(404).json({ error: "Неверный Id" })

    res.json(data)
})

app.post("/api/books", authMiddleware, (req, res) => {
    const { title, year, genre, description } = req.body

    try {
        if (!title || !year || !genre || !description) {
            return res.status(400).json({ error: "Не хватает данных" })
        }
        const query = db.prepare(
            `INSERT INTO books (title, year, genre, description, createdBy) VALUES (?, ?, ?, ?, ?)`
        )
        const info = query.run(title, year, genre, description, req.users.id)
        const newBook = db
            .prepare(`SELECT * FROM books WHERE ID = ?`)
            .get(info.lastInsertRowid)
        res.status(201).json(newBook)
    } catch (error) {
        console.error(error)
    }
})

app.listen("3000", () => {
    console.log("Сервер запущен на порту 3000")
})