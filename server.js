require("dotenv").config()
const sanitizeHTML = require("sanitize-html")
const jwt = require("jsonwebtoken")
const bcrypt = require("bcrypt")
const cookieParser = require("cookie-parser")
const express = require("express")
const sqlitedb = require("better-sqlite3")("sql.db")
sqlitedb.pragma("journal_mode = WAL")

// database scheme and setup
const createTables = sqlitedb.transaction(() => {
    sqlitedb.prepare("DROP TABLE IF EXISTS comments").run(); 

    sqlitedb.prepare(`
        CREATE TABLE IF NOT EXISTS user(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )`).run();

    sqlitedb.prepare(`
        CREATE TABLE IF NOT EXISTS comments(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            title TEXT NOT NULL,
            text TEXT NOT NULL,
            createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,  
            author_id INTEGER, 
            FOREIGN KEY (author_id) REFERENCES user(id)  
        )`).run();
});



createTables();



const app = express()


app.set("view engine", "ejs")
app.use(express.urlencoded({ extended: false }))
app.use(express.static("public"))
app.use(cookieParser())

app.use(function (req, res , next){
    res.locals.errors = []

    // try to decode incoming cookie
    try {
        const decoded = jwt.verify(req.cookies.myAuth, process.env.JWTSECRET)
        req.user = decoded;
    }
    catch{
        req.user = false
    }

    res.locals.user = req.user
    console.log(req.user)
    next()
})

app.get("/", (req, res) => {
    if (req.user) {
        const posts = sqlitedb.prepare("SELECT * FROM comments ORDER BY createdAt DESC").all();
        return res.render("dashboard", { user: req.user, posts: posts }); // ✅ Pass posts correctly
    }
    res.render("homepage");
});

// use function loogedIn for otherprojects so only logged in people can comment


function sharedPostValidation(req) {
    const errors = [];

    if (typeof req.body.title !== "string") req.body.title = "";
    if (typeof req.body.body !== "string") req.body.body = "";

    req.body.title = sanitizeHTML(req.body.title.trim(), { allowedTags: [], allowedAttributes: {} });
    req.body.body = sanitizeHTML(req.body.body.trim(), { allowedTags: [], allowedAttributes: {} });

    if (!req.body.title) errors.push("You must provide a title for the comment.");
    if (!req.body.body) errors.push("You must provide content for the comment.");

    return errors;
}

app.get("/create-post", (req, res) => {
    const comments = sqlitedb.prepare("SELECT * FROM comments").all();

    res.render("create-post", { user: req.user, comments: comments || [], errors: [] });
});

app.get("/post/:id", (req, res) => {
    const statement = sqlitedb.prepare(`
        SELECT 
            comments.id AS comment_id, 
            comments.title, 
            comments.text, 
            comments.createdAt, 
            user.id AS user_id, 
            user.username 
        FROM comments 
        INNER JOIN user ON comments.author_id = user.id 
        WHERE comments.id = ?
    `);
    
    const post = statement.get(req.params.id);
    if (!post) {
        return res.redirect("/");
    }

    res.render("single-post", { Comments: post });
});

app.post("/create-post", (req, res) => {
    const errors = sharedPostValidation(req);

    if (errors.length) {
        return res.render("create-post", { user: req.user, comments: [], errors: errors });
    }

    const insertStatement = sqlitedb.prepare("INSERT INTO comments (username, title, text, author_id) VALUES (?, ?, ?, ?)");
    const result = insertStatement.run(req.user.username, req.body.title, req.body.body, req.user.userid);

    // Get the last inserted row
    const lastInsertId = sqlitedb.prepare("SELECT last_insert_rowid() as id").get().id;
    const realPost = sqlitedb.prepare("SELECT * FROM comments WHERE id = ?").get(lastInsertId);

    res.redirect(`/post/${realPost.id}`);
});
app.post("/delete-post/:id", (req, res) => {
    if (!req.user) {
        return res.redirect("/login"); // Only logged-in users can delete posts
    }

    // Get the post to check ownership
    const post = sqlitedb.prepare("SELECT * FROM comments WHERE id = ?").get(req.params.id);
    
    if (!post) {
        return res.redirect("/"); // If post doesn't exist, redirect to dashboard
    }

    // Check if the logged-in user is the author of the post
    if (post.username !== req.user.username) {
        return res.redirect("/"); // Users can only delete their own posts
    }

    // Delete the post from the database
    sqlitedb.prepare("DELETE FROM comments WHERE id = ?").run(req.params.id);

    // Redirect back to the dashboard
    res.redirect("/");
});

app.get("/login", (req, res) => {
    res.render("login")
})
app.get("/logout", (req, res) => {
    res.clearCookie("myAuth")
    res.redirect("/")
})


app.post("/update-post/:id", (req, res) => {
    if (!req.user) {
        return res.redirect("/login"); // Ensure the user is logged in
    }

    const errors = [];
    if (typeof req.body.title !== "string") req.body.title = "";
    if (typeof req.body.body !== "string") req.body.body = "";

    req.body.title = sanitizeHTML(req.body.title.trim(), { allowedTags: [], allowedAttributes: {} });
    req.body.body = sanitizeHTML(req.body.body.trim(), { allowedTags: [], allowedAttributes: {} });

    if (!req.body.title) errors.push("You must provide a title.");
    if (!req.body.body) errors.push("You must provide content.");

    if (errors.length) {
        return res.render("edit-post", { user: req.user, post: req.body, errors });
    }

    // Check if the post exists
    const post = sqlitedb.prepare("SELECT * FROM comments WHERE id = ?").get(req.params.id);
    
    if (!post) {
        return res.redirect("/");
    }

    // Ensure only the author can update
    if (post.username !== req.user.username) {
        return res.redirect("/");
    }

    // Update the post in the database
    sqlitedb.prepare("UPDATE comments SET title = ?, text = ? WHERE id = ?")
        .run(req.body.title, req.body.body, req.params.id);

    // Redirect back to the post page
    res.redirect(`/post/${req.params.id}`);
});

app.post("/login", (req, res) => {
    let errors = []; // Define the errors array

    if (typeof req.body.username !== "string") req.body.username = "";
    if (typeof req.body.password !== "string") req.body.password = "";

    req.body.username = req.body.username.trim(); // Trim username

    if (req.body.username === "") errors.push("Invalid username/ password.");

    if (errors.length) {
        return res.render("login", { errors });
    }

    const userInQuestionStatement = sqlitedb.prepare("SELECT * FROM user WHERE username = ?")
    const userInQuestion = userInQuestionStatement.get(req.body.username)


    if (!userInQuestion) {
        errors = ["Invalid user name / password"]
        return res.render("login", { errors });
    }

    const match = bcrypt.compareSync(req.body.password, userInQuestion.password);
    if (!match) {
        errors = ["Invalid user name / password"];
        return res.render("login", { errors });
    }

    // Create a new JWT token
    const TokenValue = jwt.sign(
        { 
          exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, 
          skyColor: "red", 
          userid: userInQuestion.id,  
          username: userInQuestion.username  
        },
        process.env.JWTSECRET
    );

    res.cookie("myAuth", TokenValue, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24
    });
    res.redirect("/")
   
});

app.get("/edit-post/:id", (req, res) => {
    if (!req.user) {
        return res.redirect("/login"); // Ensure the user is logged in
    }

    // Fetch the post by ID
    const post = sqlitedb.prepare("SELECT * FROM comments WHERE id = ?").get(req.params.id);
    
    if (!post) {
        return res.redirect("/");
    }

    // Ensure only the author can edit
    if (post.username !== req.user.username) {
        return res.redirect("/");
    }

    // Render the edit form
    res.render("edit-post", { user: req.user, post: post });
});


app.get("/register", (req, res) => {
    res.render("register"); // Ensure you have register.ejs inside the 'views' folder
});

app.post("/register", (req, res) => {
    const errors = [];

    if (!req.body.username || !req.body.password) {
        errors.push({ msg: "Please enter all fields" });
    }

    if (typeof req.body.username !== "string") req.body.username = "";
    if (typeof req.body.password !== "string") req.body.password = "";

    req.body.username = req.body.username.trim();

    if (!req.body.username) errors.push("You must provide a username");
    if (req.body.username.length < 3) errors.push("Your username must be more than 3 characters");
    if (req.body.username.length > 20) errors.push("Username can't have more than 10 characters");
    if (!req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push("Username can only contain letters and numbers");
    if (!req.body.password) errors.push("You must provide a password");
    if (req.body.password.length < 8) errors.push("Password must be at least 8 characters long");
    if (req.body.password.length > 20) errors.push("Password is too long");

    if (errors.length) {
        return res.render("homepage", { errors });
    }

    // Check if username already exists
    const existingUser = sqlitedb.prepare("SELECT * FROM user WHERE username = ?").get(req.body.username);
    if (existingUser) {
        errors.push("Username already taken. Please choose a different one.");
        return res.render("homepage", { errors });
    }

    const salt = bcrypt.genSaltSync(10);
    req.body.password = bcrypt.hashSync(req.body.password, salt);

    try {
        const MyStatement = sqlitedb.prepare("INSERT INTO user (username, password) VALUES (?, ?)");
        const result = MyStatement.run(req.body.username, req.body.password);

        const lookupStatement = sqlitedb.prepare("SELECT * FROM user WHERE ROWID = ?");
        const user = lookupStatement.get(result.lastInsertRowid);

        const TokenValue = jwt.sign(
            { 
              exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, 
              skyColor: "red", 
              userid: user.id, 
              username: user.username 
            },
            process.env.JWTSECRET
        );

        res.cookie("myAuth", TokenValue, {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            maxAge: 1000 * 60 * 60 * 24
        });

        res.redirect("/")
    } catch (error) {
        console.error("Error during user registration:", error); // Log error
        let errors = [];
        errors.push("An unexpected error occurred.");
        res.render("homepage", { errors });
    }
});
        

app.listen(3000)