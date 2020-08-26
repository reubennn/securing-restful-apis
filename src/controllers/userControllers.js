import mongoose from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { UserSchema } from "../models/userModel";

const User = mongoose.model("User", UserSchema);

// Check a user is logged in
export const loginRequired = (req, res, next) => {
    if (req.user) { // If we have a logged in user
        next(); // GET, POST, DELETE etc.
    } else {
        return res.status(401).json({ message: "Unauthorised user!" });
    }
};

// Register a new user
export const register = (req, res) => {
    const newUser = new User(req.body);
    // Encrypt the password before passing it to the database
    newUser.hashPassword = bcrypt.hasSync(req.body.password, 10); // 10 = hashSync algorithm
    // Now save the user to the database
    newUser.save((err, user) => {
        if (err) {
            return res.status(400).send({
                message: err
            });
        } else {
            user.hashPassword = undefined; // We don't want to pass the password back, as this could be used for hacking
            return res.json(user);
        }
    });
};

export const login = (req, res) => {
    User.findOne({
        email: req.body.email
    }, (err, user) => {
        if (err) throw err;
        if (!user) { // If not user is found
            res.status(401).json({ message: "Authentication failed. No user found." });
        } else if (user) { // If the user is found
            if (!user.comparePassword(req.body.password, user.hashPassword)) { // If the passwords do not match
                res.status(401).json({ message: "Authentication failed. Password is incorrect." });
            } else { // The user is authenticated
                // Send as a response the signed token
                return res.json({ token: jwt.sign({ email: user.email, username: user.username, _id: user.id }, "RESTFULAPIs") }) // Secret word to sign the web token
            }
        }
    })
}