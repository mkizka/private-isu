import bodyParser from "body-parser";
import multer from "multer";
import express from "express";
import session from "express-session";
import flash from "express-flash";
import ejs from "ejs";
import mysql from "mysql2/promise";
import { exec } from "child_process";
import crypto from "crypto";
import connectMemcached from "connect-memcached";
const memcacheStore = connectMemcached(session);

declare module "express-session" {
  interface SessionData {
    userId: number;
    csrfToken: string;
  }
}

interface User {
  id: number;
  account_name: string;
  passhash: string;
  authority: 1 | 0;
  del_flg: 1 | 0;
  created_at: Date;
}

interface Post {
  id: number;
  user_id: number;
  mime: string;
  imgdata: Buffer;
  body: string;
  created_at: Date;
  comment_count?: number;
  comments?: Comment[];
  user?: User;
  csrfToken?: string;
}

interface Comment {
  id: number;
  post_id: number;
  user_id: number;
  comment: string;
  created_at: Date;
  user?: User;
}

const app = express();
const upload = multer({});

const POSTS_PER_PAGE = 20;
const UPLOAD_LIMIT = 10 * 1024 * 1024; // 10mb

const _db = mysql.createPool({
  host: process.env.ISUCONP_DB_HOST || "localhost",
  port: parseInt(process.env.ISUCONP_DB_PORT || "3306"),
  user: process.env.ISUCONP_DB_USER || "root",
  password: process.env.ISUCONP_DB_PASSWORD,
  database: process.env.ISUCONP_DB_NAME || "isuconp",
  connectionLimit: 1,
  charset: "utf8mb4",
});

const db = {
  query: async <T>(sql: string, values?: any) => {
    const [rows] = await _db.query(sql, values);
    return rows as T[];
  },
};

app.engine("ejs", ejs.renderFile);
app.use(bodyParser.urlencoded({ extended: true }));
app.set("etag", false);

app.use(
  session({
    resave: true,
    saveUninitialized: true,
    secret: process.env.ISUCONP_SESSION_SECRET || "sendagaya",
    store: new memcacheStore({
      hosts: [process.env.ISUCONP_MEMCACHED_ADDRESS || "127.0.0.1:11211"],
    }),
  })
);

app.use(flash());

function getSessionUser(req: express.Request) {
  return new Promise<User | undefined>((done, reject) => {
    if (!req.session.userId) {
      // @ts-ignore
      done();
      return;
    }
    db.query<User>("SELECT * FROM `users` WHERE `id` = ?", [req.session.userId])
      .then((users) => {
        let user = users[0];
        if (user) {
          // TODO: 他言語にない処理なので消せるかも
          // @ts-ignore
          user.csrfToken = req.session.csrfToken;
        }
        done(user);
      })
      .catch(reject);
  });
}

function digest(src: string) {
  return new Promise<string>((resolve, reject) => {
    // TODO: shellescape対策
    exec(
      'printf "%s" ' + src + " | openssl dgst -sha512 | sed 's/^.*= //'",
      (err, stdout, stderr) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(stdout.replace(/^\s*(.+)\s*$/, "$1"));
      }
    );
  });
}

function validateUser(accountName: string, password: string) {
  if (
    !(
      /^[0-9a-zA-Z_]{3,}$/.test(accountName) &&
      /^[0-9a-zA-Z_]{6,}$/.test(password)
    )
  ) {
    return false;
  } else {
    return true;
  }
}

function calculatePasshash(accountName: string, password: string) {
  return new Promise<string>((resolve, reject) => {
    digest(accountName)
      .then((salt) => {
        digest(`${password}:${salt}`).then(resolve, reject);
      })
      .catch(reject);
  });
}

function tryLogin(accountName: string, password: string) {
  return new Promise<User | void>((resolve, reject) => {
    db.query<User>(
      "SELECT * FROM users WHERE account_name = ? AND del_flg = 0",
      accountName
    )
      .then((users) => {
        let user = users[0];
        if (!user) {
          resolve();
          return;
        }
        calculatePasshash(accountName, password).then((passhash) => {
          if (passhash === user.passhash) {
            resolve(user);
          } else {
            resolve();
          }
        });
      })
      .catch(reject);
  });
}

function getUser(userId: number) {
  return new Promise<User>((resolve, reject) => {
    db.query<User>("SELECT * FROM `users` WHERE `id` = ?", [userId])
      .then((users) => {
        resolve(users[0]);
      })
      .catch(reject);
  });
}

function dbInitialize() {
  return new Promise<void>((resolve, reject) => {
    let sqls: string[] = [];
    sqls.push("DELETE FROM users WHERE id > 1000");
    sqls.push("DELETE FROM posts WHERE id > 10000");
    sqls.push("DELETE FROM comments WHERE id > 100000");
    sqls.push("UPDATE users SET del_flg = 0");

    Promise.all(sqls.map((sql) => db.query(sql))).then(() => {
      db.query("UPDATE users SET del_flg = 1 WHERE id % 50 = 0")
        .then(() => {
          resolve();
        })
        .catch(reject);
    });
  });
}

function imageUrl(post: Post) {
  let ext = "";

  switch (post.mime) {
    case "image/jpeg":
      ext = ".jpg";
      break;
    case "image/png":
      ext = ".png";
      break;
    case "image/gif":
      ext = ".gif";
      break;
  }

  return `/image/${post.id}${ext}`;
}

function makeComment(comment: Comment) {
  return new Promise<Comment>((resolve, reject) => {
    getUser(comment.user_id)
      .then((user) => {
        comment.user = user;
        resolve(comment);
      })
      .catch(reject);
  });
}

function makePost(post: Post, options: { allComments?: boolean }) {
  return new Promise<Post>((resolve, reject) => {
    db.query<{ count: number }>(
      "SELECT COUNT(*) AS `count` FROM `comments` WHERE `post_id` = ?",
      [post.id]
    )
      .then((commentCount) => {
        // TODO: `commentCount`は配列かも
        // @ts-ignore
        post.comment_count = commentCount.count || 0;
        var query =
          "SELECT * FROM `comments` WHERE `post_id` = ? ORDER BY `created_at` DESC";
        if (!options.allComments) {
          query += " LIMIT 3";
        }
        return db
          .query<Comment>(query, [post.id])
          .then((comments) => {
            return Promise.all(
              comments.map((comment) => {
                return makeComment(comment);
              })
            ).then((comments) => {
              post.comments = comments;
              return post;
            });
          })
          .then((post) => {
            return getUser(post.user_id).then((user) => {
              post.user = user;
              return post;
            });
          })
          .then(resolve, reject);
      })
      .catch(reject);
  });
}

function filterPosts(posts: Post[]) {
  return posts
    .filter((post) => post.user!.del_flg === 0)
    .slice(0, POSTS_PER_PAGE);
}

function makePosts(posts: Post[], options?: { allComments?: boolean }) {
  if (typeof options === "undefined") {
    options = {};
  }
  if (typeof options.allComments === "undefined") {
    options.allComments = false;
  }
  return new Promise<Post[]>((resolve, reject) => {
    if (posts.length === 0) {
      resolve([]);
      return;
    }
    Promise.all(
      posts.map((post) => {
        return makePost(post, options!);
      })
    ).then(resolve, reject);
  });
}

app.get("/initialize", (req, res) => {
  dbInitialize()
    .then(() => {
      res.send("OK");
    })
    .catch((error) => {
      console.log(error);
      res.status(500).send(error);
    });
});

app.get("/login", (req, res) => {
  getSessionUser(req).then((me) => {
    if (me) {
      res.redirect("/");
      return;
    }
    res.render("login.ejs", { me });
  });
});

app.post("/login", (req, res) => {
  getSessionUser(req).then((me) => {
    if (me) {
      res.redirect("/");
      return;
    }
    tryLogin(req.body.account_name || "", req.body.password || "")
      .then((user) => {
        if (user) {
          req.session.userId = user.id;
          req.session.csrfToken = crypto.randomBytes(16).toString("hex");
          res.redirect("/");
        } else {
          req.flash("notice", "アカウント名かパスワードが間違っています");
          res.redirect("/login");
        }
      })
      .catch((error) => {
        console.log(error);
        res.status(500).send(error);
      });
  });
});

app.get("/register", (req, res) => {
  getSessionUser(req).then((me) => {
    if (me) {
      res.redirect("/");
      return;
    }
    res.render("register.ejs", { me });
  });
});

app.post("/register", (req, res) => {
  getSessionUser(req).then((me) => {
    if (me) {
      res.redirect("/");
      return;
    }
    let accountName = req.body.account_name || "";
    let password = req.body.password || "";
    let validated = validateUser(accountName, password);
    if (!validated) {
      req.flash(
        "notice",
        "アカウント名は3文字以上、パスワードは6文字以上である必要があります"
      );
      res.redirect("/register");
      return;
    }

    db.query("SELECT 1 FROM users WHERE `account_name` = ?", accountName).then(
      (rows) => {
        if (rows[0]) {
          req.flash("notice", "アカウント名がすでに使われています");
          res.redirect("/register");
          return;
        }

        calculatePasshash(accountName, password).then((passhash) => {
          let query =
            "INSERT INTO `users` (`account_name`, `passhash`) VALUES (?, ?)";
          db.query(query, [accountName, passhash]).then(() => {
            db.query<User>(
              "SELECT * FROM `users` WHERE `account_name` = ?",
              accountName
            ).then((users) => {
              let me = users[0];
              req.session.userId = me.id;
              req.session.csrfToken = crypto.randomBytes(16).toString("hex");
              res.redirect("/");
            });
          });
        });
      }
    );
  });
});

app.get("/logout", (req, res) => {
  // @ts-ignore
  req.session.destroy();
  res.redirect("/");
});

app.get("/", (req, res) => {
  getSessionUser(req)
    .then((me) => {
      db.query<Post>(
        "SELECT `id`, `user_id`, `body`, `created_at`, `mime` FROM `posts` ORDER BY `created_at` DESC"
      )
        .then((posts) => {
          return makePosts(posts.slice(0, POSTS_PER_PAGE * 2));
        })
        .then((posts) => {
          res.render("index.ejs", {
            posts: filterPosts(posts),
            me: me,
            imageUrl: imageUrl,
          });
        });
    })
    .catch((error) => {
      console.log(error);
      res.status(500).send(error);
    });
});

interface Context {
  user: User;
  posts: Post[];
  commentCount?: number;
  postCount?: number;
  commentedCount?: number;
  me?: User;
}

app.get("/@:accountName/", (req, res) => {
  db.query<User>(
    "SELECT * FROM `users` WHERE `account_name` = ? AND `del_flg` = 0",
    req.params.accountName
  )
    .then((users) => {
      let user = users[0];
      if (!user) {
        res.status(404).send("not_found");
        return Promise.reject();
      }
      return user;
    })
    .then((user) => {
      return db
        .query<Post>(
          "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `user_id` = ? ORDER BY `created_at` DESC",
          user.id
        )
        .then((posts) => makePosts(posts))
        .then((posts) => {
          return { user, posts };
        });
    })
    .then((context: Context) => {
      return db
        .query<{ count: number }>(
          "SELECT COUNT(*) AS count FROM `comments` WHERE `user_id` = ?",
          context.user.id
        )
        .then((commentCount) => {
          context.commentCount = commentCount[0] ? commentCount[0].count : 0;
          return context;
        });
    })
    .then((context: Context) => {
      return db
        .query<Post>(
          "SELECT `id` FROM `posts` WHERE `user_id` = ?",
          context.user.id
        )
        .then((postIdRows) => {
          return postIdRows.map((row) => row.id);
        })
        .then((postIds) => {
          context.postCount = postIds.length;
          if (context.postCount === 0) {
            context.commentedCount = 0;
            return context;
          } else {
            return db
              .query<{ count: number }>(
                "SELECT COUNT(*) AS count FROM `comments` WHERE `post_id` IN (?)",
                [postIds]
              )
              .then((commentedCount) => {
                context.commentedCount = commentedCount[0]
                  ? commentedCount[0].count
                  : 0;
                return context;
              });
          }
        });
    })
    .then((context: Context) => {
      return getSessionUser(req).then((me) => {
        context.me = me;
        return context;
      });
    })
    .then((context) => {
      res.render("user.ejs", {
        me: context.me,
        user: context.user,
        posts: filterPosts(context.posts),
        post_count: context.postCount,
        comment_count: context.commentCount,
        commented_count: context.commentedCount,
        imageUrl: imageUrl,
      });
    })
    .catch((error) => {
      if (error) {
        res.status(500).send("ERROR");
        throw error;
      }
    });
});

app.get("/posts", (req, res) => {
  // @ts-ignore
  let max_created_at = new Date(req.query.max_created_at);
  if (max_created_at.toString() === "Invalid Date") {
    max_created_at = new Date();
  }
  db.query<Post>(
    "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `created_at` <= ? ORDER BY `created_at` DESC",
    max_created_at
  ).then((posts) => {
    makePosts(posts.slice(0, POSTS_PER_PAGE * 2)).then((posts) => {
      getSessionUser(req).then((me) => {
        res.render("posts.ejs", { me, imageUrl, posts: filterPosts(posts) });
      });
    });
  });
});

app.get("/posts/:id", (req, res) => {
  db.query<Post>(
    "SELECT * FROM `posts` WHERE `id` = ?",
    req.params.id || ""
  ).then((posts) => {
    makePosts(posts, { allComments: true }).then((posts) => {
      let post = posts[0];
      if (!post) {
        res.status(404).send("not found");
        return;
      }
      getSessionUser(req).then((me) => {
        res.render("post.ejs", { imageUrl, post: post, me: me });
      });
    });
  });
});

app.post("/", upload.single("file"), (req, res) => {
  getSessionUser(req).then((me) => {
    if (!me) {
      res.redirect("/login");
      return;
    }

    if (req.body.csrf_token !== req.session.csrfToken) {
      res.status(422).send("invalid CSRF Token");
      return;
    }

    if (!req.file) {
      req.flash("notice", "画像が必須です");
      res.redirect("/");
      return;
    }

    let mime = "";
    if (req.file.mimetype.indexOf("jpeg") >= 0) {
      mime = "image/jpeg";
    } else if (req.file.mimetype.indexOf("png") >= 0) {
      mime = "image/png";
    } else if (req.file.mimetype.indexOf("gif") >= 0) {
      mime = "image/gif";
    } else {
      req.flash("notice", "投稿できる画像形式はjpgとpngとgifだけです");
      res.redirect("/");
      return;
    }

    if (req.file.size > UPLOAD_LIMIT) {
      req.flash("notice", "ファイルサイズが大きすぎます");
      res.redirect("/");
      return;
    }

    let query =
      "INSERT INTO `posts` (`user_id`, `mime`, `imgdata`, `body`) VALUES (?,?,?,?)";
    db.query(query, [me.id, mime, req.file.buffer, req.body.body]).then(
      (result) => {
        // @ts-ignore
        res.redirect(`/posts/${encodeURIComponent(result.insertId)}`);
        return;
      }
    );
  });
});

app.get("/image/:id.:ext", (req, res) => {
  db.query<Post>("SELECT * FROM `posts` WHERE `id` = ?", req.params.id)
    .then((posts) => {
      let post = posts[0];
      if (!post) {
        res.status(404).send("image not found");
        return;
      }
      if (
        (req.params.ext === "jpg" && post.mime === "image/jpeg") ||
        (req.params.ext === "png" && post.mime === "image/png") ||
        (req.params.ext === "gif" && post.mime === "image/gif")
      ) {
        res.append("Content-Type", post.mime);
        res.send(post.imgdata);
      }
    })
    .catch((error) => {
      console.log(error);
      res.status(500).send(error);
    });
});

app.post("/comment", (req, res) => {
  getSessionUser(req).then((me) => {
    if (!me) {
      res.redirect("/login");
      return;
    }

    if (req.body.csrf_token !== req.session.csrfToken) {
      res.status(422).send("invalid CSRF Token");
    }

    if (!req.body.post_id || !/^[0-9]+$/.test(req.body.post_id)) {
      res.send("post_idは整数のみです");
      return;
    }
    let query =
      "INSERT INTO `comments` (`post_id`, `user_id`, `comment`) VALUES (?,?,?)";
    db.query(query, [req.body.post_id, me.id, req.body.comment || ""]).then(
      () => {
        res.redirect(`/posts/${encodeURIComponent(req.body.post_id)}`);
      }
    );
  });
});

app.get("/admin/banned", (req, res) => {
  getSessionUser(req).then((me) => {
    if (!me) {
      res.redirect("/login");
      return;
    }
    if (me.authority === 0) {
      res.status(403).send("authority is required");
      return;
    }

    db.query(
      "SELECT * FROM `users` WHERE `authority` = 0 AND `del_flg` = 0 ORDER BY `created_at` DESC"
    ).then((users) => {
      res.render("banned.ejs", { me, users });
    });
  });
});

type BannedRequest = express.Request<
  any,
  any,
  { uid: number[]; csrf_token: string }
>;

app.post("/admin/banned", (req: BannedRequest, res) => {
  getSessionUser(req).then((me) => {
    if (!me) {
      res.redirect("/");
      return;
    }

    if (me.authority === 0) {
      res.status(403).send("authority is required");
      return;
    }

    if (req.body.csrf_token !== req.session.csrfToken) {
      res.status(422).send("invalid CSRF Token");
      return;
    }

    let query = "UPDATE `users` SET `del_flg` = ? WHERE `id` = ?";
    Promise.all(
      req.body.uid.map((userId) => {
        db.query(query, [1, userId]);
      })
    ).then(() => {
      res.redirect("/admin/banned");
      return;
    });
  });
});

app.use(express.static("../public", {}));

app.listen(8080);
