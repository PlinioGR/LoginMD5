const bcrypt = require('bcrypt');
const md5 = require('md5');
function login(req, res) {
  if (req.session.loggedin != true) {
    res.render('login/index');
  } else {
    res.redirect('/');
  }
}

function auth(req, res) {
  const data = req.body;
  req.getConnection((err, conn) => {
    conn.query(
      'SELECT * FROM users WHERE email = ?',
      [data.email],
      (err, userdata) => {
        if (userdata.length > 0) {
          userdata.forEach((element) => {
            data.password = md5(data.password);

            if (data.password != element.password) {
              res.render('login/index', {
                error: 'Error: incorrect password !',
              });
            } else {
              req.session.loggedin = true;
              req.session.name = element.name;

              res.redirect('/');
            }
          });
        } else {
          res.render('login/index', { error: 'Error: user not exists !' });
        }
      }
    );
  });
}

function register(req, res) {
  if (req.session.loggedin != true) {
    res.render('login/register');
  } else {
    res.redirect('/');
  }
}

function storeUser(req, res) {
  const data = req.body;

  req.getConnection((err, conn) => {
    conn.query(
      'SELECT * FROM users WHERE email = ?',
      [data.email],
      (err, userdata) => {
        if (userdata.length > 0) {
          res.render('login/register', {
            error: 'Error: user alredy exists !',
          });
        } else {
          data.password = md5(data.password);
          req.getConnection((err, conn) => {
            conn.query('INSERT INTO users SET ?', [data], (err, rows) => {
              req.session.loggedin = true;
              req.session.name = data.name;

              res.redirect('/');
            });
          });
        }
      }
    );
  });
}

function logout(req, res) {
  if (req.session.loggedin == true) {
    req.session.destroy();
  }
  res.redirect('/login');
}

module.exports = {
  login,
  register,
  storeUser,
  auth,
  logout,
};
