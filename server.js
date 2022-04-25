var express = require("express")
var app = express()
var db = require("./database.js")
var bp = require("body-parser");
var se = require("speakeasy");
var qr = require("qrcode");
require('dotenv').config()

app.use(bp.json());
app.use(bp.urlencoded({ extended: true }));

// QR Code Domain
var TOTP_DOMAIN= process.env.TOTP_DOMAIN || "totp.meyatools.eu"
// Server port
var HTTP_PORT = process.env.HTTP_PORT || 8080
// Start server
app.listen(HTTP_PORT, () => {
    console.log("Server running on port %PORT%".replace("%PORT%",HTTP_PORT))
});
// Root endpoint
app.get("/", (req, res, next) => {
    res.json({"message":"totp demo api"})
});

// Validate OTP
app.post("/otp", (req, res, next) => {
    var username = req.body.username;
    var otp = req.body.otp;
    var sql = "select * from user where username = ?";
    db.get(sql, username, (err, row) => {
        if (err) {
          res.status(400).json({"error":err.message});
          return;
        }
	if (!row) {
	    res.status(400).json({"error":"user not found"});
	    return;
	}
	if (!se.totp.verify({secret: row.secret,encoding: "base32",token: otp,window:2})) {
	    res.status(400).json({"error":"invalid otp"});
	    return;
	}
	res.json({
	    "message":"success"
	})
    });
});

// Create User
app.post("/users", (req, res, next) => {
    var username = req.body.username;
    var secret = se.generateSecret({ length: 20 });
    var secret32 = secret.base32;
    var otpauth_url = se.otpauthURL({ secret: secret.ascii, label: username+"@"+TOTP_DOMAIN});
    var qr_url;
    qr.toDataURL(otpauth_url, function (err, url) {
        qr_url = url
    });
    var params = [username, secret32];
    var sql = "INSERT INTO user (username, secret) VALUES (?,?)";
    db.run(sql,params, function (err, result) {
        if (err) {
	    res.status(400).json({"error":err.message});
	    return;
	}
	res.json({
	    "message":"success",
	    "username":req.body.username,
	    "secret":secret32,
	    "qr_url":qr_url
	});
    });
});

// Get User
app.get("/users/:username", (req, res, next) => {
    var sql = "select username from user where username = ?"
    var params = [req.params.username]
    db.get(sql, params, (err, row) => {
        if (err) {
          res.status(400).json({"error":err.message});
          return;
        }
        if (!row) {
            res.status(400).json({"error":"user not found"});
            return;
        }
        res.json({
            "message":"success",
            "data":row
        })
      });
});

// Get all users
app.get("/users", (req, res, next) => {
    var sql = "select username from user"
    var params = []
    db.all(sql, params, (err, rows) => {
        if (err) {
          res.status(400).json({"error":err.message});
          return;
        }
        res.json({
            "message":"success",
            "data":rows
        })
      });
});

app.delete("/users/:username", (req, res, next) => {
    var sql = "delete from user where username = ?"
    var params = [req.params.username]
    db.get(sql, params, (err, row) => {
        if (err) {
          res.status(400).json({"error":err.message});
          return;
        }
        res.json({
            "message":"success"
        })
      });
});

// Default response for any other request
app.use(function(req, res){
    res.status(404);
});